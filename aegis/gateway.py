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
import socketserver
import time
from contextlib import contextmanager

from .chain import link
from .controlplane import REVERSIBLE, PlaneError
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
        """Why this capability may not be spent right now, or None."""
        if capability["status"] != "issued":
            return f"DENY_{capability['status'].upper()}", []
        if capability["expires_at"] <= self.clock():
            return "DENY_EXPIRED", []
        topology = self.plane.discover()
        observed_digest, observed = scoped_digest(
            topology["nodes"], topology["edges"], capability["target_id"]
        )
        if observed_digest != capability["context_digest"]:
            return "HOLD_CONTEXT_CHANGED", explain(capability["context"], observed)
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
            self._write({"capabilities": {}, "entries": []})

    def _read(self):
        try:
            with open(self.path) as handle:
                return json.load(handle)
        except (OSError, ValueError):
            return {"capabilities": {}, "entries": []}

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
    # Group-readable only: the planner's account is the only other member, so
    # no other local user can even attempt a consumption.
    os.chmod(socket_path, 0o660)
    return server
