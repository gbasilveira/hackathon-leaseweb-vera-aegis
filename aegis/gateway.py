"""The execution gateway: sole holder of a writable control plane.

The gateway is the only component that can change the world, and it is
deliberately the dumbest. It accepts a capability identifier and a nonce. It
never reads a proposal's prose, an event payload or any model output, so there
is no text channel through which an attacker or a confused planner can reach
the actuator.

Two properties matter here and neither survives the original in-process design.

Consumption is committed before actuation. A SQLite write can be rolled back; a
hypervisor cannot. If the process dies between spending the capability and
completing the action, the capability is still spent, and the outcome is
reported as indeterminate rather than assumed. The failure mode is a refused
retry, never a second execution.

Authority is revalidated against the plane, not against stored state. The
context digest is recomputed from what the hypervisor reports at the instant of
consumption, so a world that moved since the decision costs the capability its
authority and the refusal names the node responsible.
"""

import fcntl
import json
import os
import socket
import socketserver
import time
from contextlib import contextmanager

from .chain import link, verify_chain
from .controlplane import REVERSIBLE, PlaneError
from .policy import decide
from .scope import explain, scoped_digest
from . import privsep

#: What each action must have produced, read back from the plane independently.
EFFECTS = {
    "network.isolate": lambda before, after: after.get("isolated") is True,
    "network.restore": lambda before, after: after.get("isolated") is False,
    "vm.suspend": lambda before, after: after.get("state") == "paused",
    "vm.resume": lambda before, after: after.get("state") == "running",
    "vm.snapshot": lambda before, after: (after.get("snapshots") or 0)
    > (before.get("snapshots") or 0),
}


class Gateway:
    def __init__(self, plane, store, *, clock=time.time, enforce_privsep=True):
        self.privileges = privsep.assert_role(
            "gateway", getattr(plane, "uri", "qemu:///system"), enforce=enforce_privsep
        )
        self.plane = plane
        self.store = store
        self.clock = clock

    def _refuse(self, capability, reason, detail=()):
        capability["status"] = "expired" if reason == "DENY_EXPIRED" else "revoked"
        capability["refused_reason"] = reason
        self.store.put(capability)
        return self.store.journal(
            {
                "event_type": "gateway.refused",
                "outcome": reason,
                "capability_id": capability["id"],
                "target_id": capability["target_id"],
                "action_type": capability["action_type"],
                "reasons": list(detail),
            }
        ) | {"result": reason, "reasons": list(detail)}

    def revalidate(self, capability):
        """Why this capability may not be spent right now, or None.

        A capability record lives in a store the planner can write to, so it is
        a request and never an authority. Everything below that could have been
        written by the planner is therefore treated as a claim, and the gateway
        settles every question that matters from the hypervisor it alone can
        read.

        An earlier version of this method checked only that the world had not
        *changed* since whatever digest the record claimed. A compromised
        planner could compute an honest digest of the current world, write a
        capability for an action the policy forbids, and the gateway would
        execute it. A sabotage test now asserts that it cannot.
        """
        if capability["status"] != "issued":
            return f"DENY_{capability['status'].upper()}", []
        if capability["expires_at"] <= self.clock():
            return "DENY_EXPIRED", []

        # Tampered history disables the actuator. The journal is the evidence a
        # decision rests on, so if its chain is broken the gateway has no
        # grounds to act on anything.
        chain = verify_chain(self.store.entries)
        if not chain["ok"]:
            return "DENY_EVIDENCE_TAMPERED", [
                f"journal chain broken at index {chain['broken_at']}: {chain['detail']}"
            ]

        # Evidence must exist in the sealed journal, and at least one piece of
        # it must concern the target being acted on. This does not establish
        # that containment was warranted, which is a detection question; it
        # establishes that the action is tied to observations that were really
        # recorded about that guest, rather than to a reference invented
        # alongside the handle.
        refs = set(capability.get("evidence_refs") or [])
        sealed, about_target = set(), set()
        for entry in self.store.entries:
            if entry.get("event_type") != "hypervisor.observed":
                continue
            sealed.add(entry.get("id"))
            if entry.get("target_id") == capability["target_id"]:
                about_target.add(entry.get("id"))
        if (unknown := sorted(refs - sealed)):
            return "DENY_EVIDENCE_UNKNOWN", [
                f"cited evidence is not in the sealed journal: {', '.join(unknown)}"
            ]
        if refs and not refs & about_target:
            return "DENY_EVIDENCE_UNRELATED", [
                f"no cited evidence concerns {capability['target_id']}"
            ]

        topology = self.plane.discover()

        # Drift first. Both this and the policy re-decision below run, and both
        # must pass, so a forged record carrying an honest digest of the
        # current world still has to survive the policy. Drift is checked first
        # only because its explanation names the node that cost this handle its
        # authority, which tells an operator more than a rule name does.
        observed_digest, observed = scoped_digest(
            topology["nodes"], topology["edges"], capability["target_id"]
        )
        if observed_digest != capability["context_digest"]:
            return "HOLD_CONTEXT_CHANGED", explain(
                capability.get("context") or {}, observed
            )

        # The authoritative check. The gateway runs the policy itself against
        # the topology it just read, so authority cannot be invented by
        # whoever wrote the record.
        verdict = decide(
            topology,
            capability["action_type"],
            capability["target_id"],
            capability.get("evidence_refs") or [],
        )
        if verdict["result"] != "ALLOW":
            return f"DENY_POLICY_{verdict['reason']}", [
                f"the gateway re-ran the policy and got {verdict['result']}",
                f"blast radius: {verdict['facts']['tenant_count']} tenant(s) "
                f"{verdict['facts']['blast_tenants']}",
                f"closure: {verdict['facts']['closure']}",
            ]
        if verdict["policy_digest"] != capability.get("policy_digest"):
            return "HOLD_POLICY_CHANGED", [
                "the rules in force are not the rules this handle was issued under"
            ]
        return None, []

    def consume(self, capability_id, nonce):
        capability = self.store.get(capability_id)
        if capability is None:
            return {"result": "DENY_UNKNOWN_CAPABILITY", "reasons": []}
        if not nonce or nonce != capability.get("nonce"):
            return self._refuse(capability, "DENY_BAD_NONCE")
        reason, detail = self.revalidate(capability)
        if reason:
            return self._refuse(capability, reason, detail)

        target, action = capability["target_id"], capability["action_type"]
        before = self.plane.read_state(target)

        # Spend first. An actuator that cannot be rolled back must never be
        # reachable twice by the same handle, even if this process dies now.
        capability["status"] = "consuming"
        capability["consumed_at"] = self.clock()
        self.store.put(capability)

        try:
            effect = self.plane.actuate(action, target)
        except PlaneError as error:
            capability["status"] = "consumed"
            self.store.put(capability)
            return self.store.journal(
                {
                    "event_type": "defense.failed",
                    "outcome": "INDETERMINATE",
                    "capability_id": capability_id,
                    "target_id": target,
                    "action_type": action,
                    "detail": str(error),
                    "reversible": action in REVERSIBLE,
                }
            ) | {"result": "INDETERMINATE", "reasons": [str(error)]}

        capability["status"] = "consumed"
        self.store.put(capability)
        after = self.plane.read_state(target)
        # Three-valued on purpose. A target that cannot be re-read is not a
        # failed containment, it is an unknown one, and saying so is the whole
        # point of verifying independently of the actuator's return value.
        checks = (
            {"target_observed": None, "effect_observed": None}
            if not after
            else {"target_observed": True, "effect_observed": EFFECTS[action](before, after)}
        )
        result = (
            "FAILED"
            if False in checks.values()
            else "INDETERMINATE"
            if None in checks.values()
            else "VERIFIED"
        )
        return self.store.journal(
            {
                "event_type": "outcome.verified",
                "outcome": result,
                "capability_id": capability_id,
                "target_id": target,
                "action_type": action,
                "checks": checks,
                "before": before,
                "after": after,
                "effect": effect,
            }
        ) | {"result": result, "checks": checks, "before": before, "after": after}


class MemoryStore:
    """Capability and sealed-journal store, used by tests and the demo driver."""

    def __init__(self):
        self.capabilities = {}
        self.entries = []

    def get(self, capability_id):
        return self.capabilities.get(capability_id)

    def put(self, capability):
        self.capabilities[capability["id"]] = capability
        return capability

    def journal(self, entry):
        sealed = link(
            dict(entry, sequence=len(self.entries) + 1, at=time.time()),
            self.entries[-1]["hash"] if self.entries else "0" * 64,
        )
        self.entries.append(sealed)
        return {"journal_hash": sealed["hash"]}


class FileStore:
    """Capability and sealed-journal store shared between the three processes.

    The planner issues handles and the gateway spends them, so the store has to
    outlive a single process. Writes take an exclusive lock and land through
    `os.replace`, so a reader never sees a half-written file and two writers
    never interleave. SQLite would also do; a single JSON document keeps the
    deployment inspectable with `cat`, which matters more during a demo.
    """

    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        if not os.path.exists(path):
            self._write({"capabilities": {}, "entries": [], "topology": None})

    def _read(self):
        try:
            with open(self.path) as handle:
                return json.load(handle)
        except (OSError, ValueError):
            return {"capabilities": {}, "entries": [], "topology": None}

    def _write(self, data):
        temporary = f"{self.path}.tmp"
        with open(temporary, "w") as handle:
            json.dump(data, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.path)

    @contextmanager
    def _locked(self):
        with open(f"{self.path}.lock", "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                data = self._read()
                yield data
                self._write(data)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    @property
    def entries(self):
        return self._read()["entries"]

    @property
    def capabilities(self):
        return self._read()["capabilities"]

    def topology(self):
        """The last topology the sensor published.

        The planner reads the world from here because it has no hypervisor of
        its own. That its view may be stale is not a defect to be fixed: the
        gateway revalidates against live libvirt at the instant of
        consumption, so a planner reasoning from an out-of-date or even a
        tampered snapshot cannot cause an action the current world forbids.
        """
        return self._read().get("topology")

    def publish_topology(self, topology):
        with self._locked() as data:
            data["topology"] = topology
        return topology

    def get(self, capability_id):
        return self._read()["capabilities"].get(capability_id)

    def put(self, capability):
        with self._locked() as data:
            data["capabilities"][capability["id"]] = capability
        return capability

    def journal(self, entry):
        with self._locked() as data:
            previous = data["entries"][-1]["hash"] if data["entries"] else "0" * 64
            sealed = link(
                dict(entry, sequence=len(data["entries"]) + 1, at=time.time()), previous
            )
            data["entries"].append(sealed)
        return {"journal_hash": sealed["hash"]}


def serve(plane, store, socket_path, enforce_privsep=True):
    """Listen for consumption requests on a unix socket.

    The protocol has exactly one operation. There is no way to submit a
    proposal, change a policy or pass free text through this socket, so a
    compromised planner can ask for an action it was already granted and
    nothing else.
    """
    gateway = Gateway(plane, store, enforce_privsep=enforce_privsep)

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            for raw in self.rfile:
                try:
                    request = json.loads(raw)
                    if request.get("op") != "consume":
                        raise ValueError(f"unsupported op {request.get('op')!r}")
                    answer = gateway.consume(
                        str(request["capability_id"]), str(request.get("nonce", ""))
                    )
                except (ValueError, KeyError, TypeError) as error:
                    answer = {"result": "DENY_MALFORMED_REQUEST", "detail": str(error)}
                self.wfile.write((json.dumps(answer) + "\n").encode())
                self.wfile.flush()

    class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        allow_reuse_address = True
        daemon_threads = True

    if os.path.exists(socket_path):
        os.unlink(socket_path)
    os.makedirs(os.path.dirname(socket_path) or ".", exist_ok=True)
    server = Server(socket_path, Handler)
    # Group-readable only, so no local user outside the shared group can even
    # attempt a consumption.
    try:
        import grp

        os.chown(socket_path, -1, grp.getgrnam("aegis").gr_gid)
    except (ImportError, KeyError, PermissionError, OSError):
        pass
    os.chmod(socket_path, 0o660)
    return server


def request(socket_path, payload, timeout=60):
    """Ask the gateway for something, over its one-operation socket."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(timeout)
        client.connect(socket_path)
        client.sendall((json.dumps(payload) + "\n").encode())
        with client.makefile("r") as stream:
            line = stream.readline()
    if not line:
        raise PlaneError(f"the gateway at {socket_path} closed without answering")
    return json.loads(line)
