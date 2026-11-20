"""Live incident path over a real control plane.

The fixture path in `aegis.core` remains the offline fallback. This module is
the real system: topology is measured, policy facts are derived from that
measurement rather than from the name of the action, and authority is bound to
the subgraph the action can harm.

The policy is deliberately short. Every fact it reads is something the plane
observed, which is the difference between "the fixture declared this host
critical" and "two tenants were observed attached to this bridge, so denying a
broad action here is arithmetic".
"""

import argparse
import json
import sys
import time

from .chain import verify_chain
from .controlplane import ACTIONS, REVERSIBLE
from .gateway import Gateway, MemoryStore
from .scope import explain, scoped_digest, sha

#: Priority-ordered rules. The first match wins, and the default is denial.
POLICY = [
    (100, "DENY_UNPUBLISHED_ACTION", "DENY", lambda f: not f["published"]),
    (90, "DENY_SHARED_RESOURCE", "DENY", lambda f: f["target_shared"]),
    (85, "DENY_CRITICAL_SHARED_DEPENDENCY", "DENY", lambda f: f["critical_shared"]),
    (80, "DENY_CROSS_TENANT_BLAST", "DENY", lambda f: f["tenant_count"] > 1),
    (70, "DENY_UNKNOWN_TARGET", "DENY", lambda f: not f["target_known"]),
    (60, "HOLD_NO_EVIDENCE", "HOLD", lambda f: not f["evidence_ok"]),
    (50, "REQUIRE_APPROVAL_IRREVERSIBLE", "REQUIRE_APPROVAL", lambda f: not f["reversible"]),
    (40, "ALLOW_SCOPED_REVERSIBLE", "ALLOW", lambda f: f["reversible"]),
    (0, "DENY_DEFAULT", "DENY", lambda f: True),
]
POLICY_DIGEST = sha([[priority, reason, result] for priority, reason, result, _ in POLICY])
CAPABILITY_TTL = 300


def facts(topology, action, target, evidence=()):
    """Authority facts, every one of them derived from observation."""
    nodes, edges = topology["nodes"], topology["edges"]
    _, observed = scoped_digest(nodes, edges, target)
    node = nodes.get(target, {})
    owner = node.get("tenant_id")
    blast = [tenant for tenant in observed["tenants"] if tenant != "infrastructure"]
    return {
        "action": action,
        "published": action in ACTIONS,
        "reversible": action in REVERSIBLE,
        "target_known": bool(node),
        "target_tenant": owner,
        "target_shared": bool(node.get("shared")),
        "critical_shared": any(
            nodes[member].get("shared") and nodes[member].get("criticality") == "critical"
            for member in observed["members"]
            if member in nodes
        ),
        "tenant_count": len(blast),
        "blast_tenants": blast,
        "closure": observed["members"],
        "evidence_ok": bool(evidence),
    }


def decide(topology, action, target, evidence=()):
    """Evaluate a proposal against measured context."""
    derived = facts(topology, action, target, evidence)
    digest, observed = scoped_digest(topology["nodes"], topology["edges"], target)
    for priority, reason, result, predicate in POLICY:
        if predicate(derived):
            return {
                "result": result,
                "reason": reason,
                "priority": priority,
                "policy_digest": POLICY_DIGEST,
                "context_digest": digest,
                "context": observed,
                "facts": derived,
                "at": time.time(),
            }
    raise AssertionError("the default rule must always match")


class LiveIncident:
    """Planner, governance and gateway, wired to one plane.

    In deployment these are three processes and the planner holds no plane at
    all. This class is the single-process driver used for the walkthrough and
    the tests; `privsep` is what keeps the deployed split honest.
    """

    def __init__(
        self,
        plane=None,
        store=None,
        clock=time.time,
        enforce_privsep=False,
        topology=None,
    ):
        self.plane = plane
        self.store = store or MemoryStore()
        self.clock = clock
        self._topology = topology
        # Without a plane there is no gateway here: the planner runs in a
        # process that holds no hypervisor access at all and reaches the real
        # gateway over its socket instead.
        self.gateway = (
            Gateway(plane, self.store, clock=clock, enforce_privsep=enforce_privsep)
            if plane is not None
            else None
        )
        self.issued = 0

    def topology(self):
        """Where this process gets its picture of the world.

        The planner is given a snapshot the sensor published, because it cannot
        open libvirt. That snapshot may be stale, and it does not matter: the
        gateway recomputes the scoped digest from live libvirt when the handle
        is spent, so a planner reasoning from an old or even a doctored view
        cannot produce an action the current world forbids.
        """
        if self._topology is not None:
            return self._topology() if callable(self._topology) else self._topology
        if self.plane is None:
            raise RuntimeError("no topology source: pass a plane or a published one")
        return self.plane.discover()

    def propose(self, action, target, rationale, evidence=()):
        proposal = {
            "action_type": action,
            "target_id": target,
            "rationale": rationale,
            "evidence_refs": list(evidence),
            "proposed_by": "response-planner",
        }
        proposal["hash"] = sha(proposal)
        self.store.journal(
            dict(proposal, event_type="proposal.submitted", outcome="PROPOSED")
        )
        return proposal

    def evaluate(self, proposal):
        decision = decide(
            self.topology(),
            proposal["action_type"],
            proposal["target_id"],
            proposal["evidence_refs"],
        )
        decision["proposal_hash"] = proposal["hash"]
        self.store.journal(
            {
                "event_type": "governance.decision",
                "outcome": decision["result"],
                "reason": decision["reason"],
                "target_id": proposal["target_id"],
                "action_type": proposal["action_type"],
                "blast_tenants": decision["facts"]["blast_tenants"],
                "closure": decision["facts"]["closure"],
            }
        )
        return decision

    def issue(self, proposal, decision):
        """Mint a single-use handle bound to the request and the observed world."""
        if decision["result"] != "ALLOW":
            return None
        self.issued += 1
        capability = {
            "id": f"cap-{self.issued}",
            "nonce": sha([proposal["hash"], self.issued, self.clock()])[:32],
            "action_type": proposal["action_type"],
            "target_id": proposal["target_id"],
            "proposal_hash": proposal["hash"],
            "policy_digest": decision["policy_digest"],
            "context_digest": decision["context_digest"],
            "context": decision["context"],
            "status": "issued",
            "issued_at": self.clock(),
            "expires_at": self.clock() + CAPABILITY_TTL,
        }
        self.store.put(capability)
        self.store.journal(
            {
                "event_type": "capability.issued",
                "outcome": "ISSUED",
                "capability_id": capability["id"],
                "target_id": capability["target_id"],
                "action_type": capability["action_type"],
                "scope": decision["context"]["members"],
            }
        )
        return capability

    def execute(self, capability):
        if self.gateway is None:
            raise RuntimeError("this process holds no plane; use execute_remote")
        return self.gateway.consume(capability["id"], capability["nonce"])

    def execute_remote(self, capability, socket_path):
        """Ask the gateway process to spend a handle on our behalf.

        All that crosses the socket is an identifier and a nonce. The rationale,
        the evidence and anything else the planner wrote stay on this side, so
        there is no text channel from the planner into the actuator.
        """
        from .gateway import request

        return request(
            socket_path,
            {
                "op": "consume",
                "capability_id": capability["id"],
                "nonce": capability["nonce"],
            },
        )

    def evidence(self):
        report = verify_chain(self.store.entries)
        return {"chain": report, "entries": self.store.entries}


# -- operator console --------------------------------------------------------


def _plane(args, writable=True):
    """Open the plane with the least access the command needs.

    `writable=False` is not a convenience. Only the gateway's account holds
    libvirt's writable socket, so a command that merely reads must ask for the
    read-only one or it fails on a correctly configured host, which is exactly
    what happened the first time `topology` ran as an unprivileged operator.
    """
    from .libvirt_plane import LibvirtControlPlane

    return LibvirtControlPlane(
        args.uri,
        read_only=args.read_only or not writable,
        catalogue=args.catalogue,
    )


#: Nodes the walkthrough writes into the catalogue, and only these are ever
#: removed from it: an operator's real service entries are not ours to delete.
DEMO_NODES = ("svc-unrelated", "svc-billing")


def _catalogue_read(path):
    try:
        return json.loads(open(path).read())
    except (OSError, ValueError):
        return {"nodes": {}, "edges": []}


def _catalogue_write(path, declared):
    open(path, "w").write(json.dumps(declared, indent=2))


def _catalogue_drop(path, names):
    declared = _catalogue_read(path)
    declared["nodes"] = {
        key: value
        for key, value in declared.get("nodes", {}).items()
        if key not in names
    }
    declared["edges"] = [
        edge for edge in declared.get("edges", []) if edge.get("source") not in names
    ]
    _catalogue_write(path, declared)


def _catalogue_add(path, entry):
    """Write a service entry the way a CMDB update would."""
    declared = _catalogue_read(path)
    declared.setdefault("nodes", {}).update(entry.get("nodes", {}))
    declared.setdefault("edges", []).extend(entry.get("edges", []))
    _catalogue_write(path, declared)


def _say(text=""):
    print(text, flush=True)


def _act(number, title):
    _say()
    _say(f"\033[1m── Act {number} · {title}\033[0m")


def cmd_topology(args):
    topology = _plane(args, writable=False).discover()
    _say(f"host: {topology['host']}")
    _say()
    _say(f"{'node':<34} {'kind':<14} {'tenant':<16} shared  criticality")
    for node_id, node in sorted(topology["nodes"].items()):
        _say(
            f"{node_id:<34} {node.get('kind',''):<14} {node.get('tenant_id',''):<16} "
            f"{str(bool(node.get('shared'))):<7} {node.get('criticality','')}"
            + (
                f"   observed tenants: {', '.join(node['observed_tenants'])}"
                if node.get("observed_tenants")
                else ""
            )
        )
    _say()
    for edge in topology["edges"]:
        origin = " (catalogue)" if edge.get("source_of_truth") else ""
        _say(f"  {edge['source']} -{edge.get('relation', edge.get('type'))}-> {edge['target']}{origin}")
    return 0


def cmd_privileges(args):
    from .privsep import matrix

    for row in matrix(args.uri):
        state = (
            "ok"
            if row["ok"]
            else "VIOLATION"
            if row["violations"]
            else "NOT OPERATIONAL"
        )
        _say(f"\033[1m{row['role']}\033[0m  {row['summary']}  [{state}]")
        _say(
            f"  libvirt: may hold {row['libvirt_expected']!r}, observed "
            f"{row['libvirt_observed']!r} on {row['uri']}"
        )
        _say(
            f"  model credentials: {'allowed' if row['model_credentials_allowed'] else 'forbidden'}"
            f", present: {row['model_credentials_present'] or 'none'}"
        )
        for violation in row["violations"]:
            _say(f"  \033[31m! {violation}\033[0m")
        for shortfall in row["shortfalls"]:
            _say(f"  \033[33m? {shortfall}\033[0m")
    return 0


def cmd_demo(args):
    plane = _plane(args)
    incident = LiveIncident(plane)
    target, action = args.target, args.action
    catalogue = args.catalogue if isinstance(args.catalogue, str) else None

    def reset():
        if catalogue:
            _catalogue_drop(catalogue, DEMO_NODES)

    def mutate(entry):
        if not catalogue:
            raise SystemExit("--catalogue is required for the drift acts")
        _catalogue_add(catalogue, entry)

    reset()
    topology = plane.discover()
    _act(1, "Measured topology")
    shared = [n for n in topology["nodes"].values() if n.get("shared")]
    _say(f"{len(topology['nodes'])} nodes, {len(topology['edges'])} edges on {topology['host']}")
    for node in shared:
        _say(
            f"  {node['id']} is shared and therefore critical: observed tenants "
            f"{', '.join(node.get('observed_tenants', []))}"
        )
    if not shared:
        _say("  no shared infrastructure observed (single tenant host)")

    _act(2, "The broad action the alert asked for")
    broad = next((n["id"] for n in shared if n["kind"] == "net"), None)
    wide = "network.isolate" if broad else "host.stop"
    broad = broad or topology["host"]
    proposal = incident.propose(
        wide, broad, "An untrusted log asked for a wide containment.", ["obs-1"]
    )
    decision = incident.evaluate(proposal)
    _say(f"proposal: {wide} on {broad}")
    _say(f"  -> {decision['result']} / {decision['reason']}")
    _say(f"  blast radius: {decision['facts']['tenant_count']} tenant(s) {decision['facts']['blast_tenants']}")
    _say(f"  closure: {decision['facts']['closure']}")

    _act(3, "The scoped action, and the handle it earns")
    proposal = incident.propose(
        action, target, "Contain the implicated guest only.", ["obs-1"]
    )
    decision = incident.evaluate(proposal)
    _say(f"proposal: {action} on {target}")
    _say(f"  -> {decision['result']} / {decision['reason']}")
    capability = incident.issue(proposal, decision)
    if not capability:
        _say("  no capability issued; nothing further to execute")
        return 1
    _say(f"  capability {capability['id']} bound to scope {decision['context']['members']}")
    _say(f"  context digest {capability['context_digest'][:32]}…")

    _act(4, "An unrelated change must not cost authority")
    closure = set(decision["context"]["members"])
    outside = next(
        (
            node_id
            for node_id, node in sorted(topology["nodes"].items())
            if node_id not in closure and node.get("kind") == "domain"
        ),
        next((node_id for node_id in sorted(topology["nodes"]) if node_id not in closure), None),
    )
    if outside:
        mutate(
            {
                "nodes": {"svc-unrelated": {"kind": "service", "tenant_id": "tenant-a"}},
                "edges": [
                    {"source": "svc-unrelated", "target": outside, "relation": "depends_on"}
                ],
            }
        )
        _say(f"a tenant-a service now depends on {outside}")
        _say(f"  closure of {target} is {sorted(closure)}, so {outside} is outside it")
        reason, _ = incident.gateway.revalidate(capability)
        _say(f"  revalidation: {reason or 'still authorised'}")
    else:
        _say("  every observed node is inside the closure; nothing unrelated to change")

    _act(5, "Execute, then verify by re-reading the hypervisor")
    result = incident.execute(capability)
    _say(f"  gateway: {result['result']}")
    if "after" in result:
        _say(f"  before: {result['before']}")
        _say(f"  after : {result['after']}")
        _say(f"  checks: {result['checks']}")
    for line in result.get("reasons", []):
        _say(f"    · {line}")

    _act(6, "A change inside the closure revokes a pending handle")
    restore = incident.propose(
        "network.restore" if action == "network.isolate" else "vm.resume",
        target,
        "Release containment after review.",
        ["obs-1"],
    )
    decision = incident.evaluate(restore)
    pending = incident.issue(restore, decision)
    if pending:
        _say(f"  {pending['id']} issued for {restore['action_type']} on {target}")
        mutate(
            {
                "nodes": {
                    "svc-billing": {
                        "kind": "service",
                        "tenant_id": "tenant-c",
                        "criticality": "critical",
                    }
                },
                "edges": [{"source": "svc-billing", "target": target, "relation": "depends_on"}],
            }
        )
        _say(f"  a critical tenant-c service now depends on {target}")
        refused = incident.execute(pending)
        _say(f"  gateway: {refused['result']}")
        for line in refused.get("reasons", []):
            _say(f"    · {line}")
        _act(7, "Re-evaluated under the new world")
        again = incident.evaluate(restore)
        _say(f"  -> {again['result']} / {again['reason']}")
        _say(f"  blast radius is now {again['facts']['tenant_count']} tenant(s) {again['facts']['blast_tenants']}")
    else:
        _say(f"  {decision['result']} / {decision['reason']} — no handle to revoke")

    _act(8, "Evidence")
    evidence = incident.evidence()
    _say(f"  {evidence['chain']['length']} sealed entries, head {evidence['chain']['head'][:32]}…")
    _say(f"  chain: {evidence['chain']['detail']}")
    tampered = [dict(entry) for entry in evidence["entries"]]
    if len(tampered) > 2:
        tampered[1]["outcome"] = f"TAMPERED_{tampered[1].get('outcome')}"
        broken = verify_chain(tampered)
        _say(
            f"  editing entry 1 breaks the chain at index {broken['broken_at']} "
            f"({broken['detail']})"
        )
    if args.json:
        _say()
        _say(json.dumps(evidence["entries"], indent=2))
    return 0


def cmd_observe(args):
    """Hypervisor sensor loop: collect signal, seal it, and change nothing."""
    from .gateway import FileStore
    from .controlplane import authority_facts
    from .privsep import assert_role

    assert_role("sensor", args.uri, enforce=not args.no_privsep)
    plane = _plane(args)
    store = FileStore(args.store)
    while True:
        store.publish_topology(plane.discover())
        separated = authority_facts(plane.observe())
        for fact in separated["facts"]:
            store.journal(dict(fact, event_type="hypervisor.observed", outcome="observed"))
        for ignored in separated["excluded"]:
            store.journal(
                dict(ignored, event_type="guest.reported", outcome="excluded_from_decisions")
            )
        _say(
            f"published topology, sealed {len(separated['facts'])} hypervisor "
            f"observation(s), excluded {len(separated['excluded'])} guest report(s)"
        )
        if args.once:
            return 0
        time.sleep(args.interval)


def cmd_gateway(args):
    """Run the gateway as its own process, holding the only writable plane."""
    from .gateway import FileStore, serve

    plane = _plane(args)
    server = serve(
        plane, FileStore(args.store), args.socket, enforce_privsep=not args.no_privsep
    )
    _say(f"gateway listening on {args.socket} for {plane.name}")
    _say("the only accepted operation is capability consumption")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
    return 0


def _suspect(entries, topology):
    """Pick a containment target from sealed hypervisor observations.

    This is a placeholder for a model, and a deliberately crude one. It keys on
    the signal the bulk-capture pattern actually leaves on a hypervisor, a
    climbing snapshot count, and it reads nothing a guest could have written.

    Detection quality is the weakest part of this system and nothing here
    claims otherwise. What the architecture guarantees is that a wrong answer
    from this function cannot produce an action policy forbids.
    """
    latest = {}
    for entry in entries:
        if entry.get("event_type") == "hypervisor.observed" and entry.get("target_id"):
            latest[entry["target_id"]] = entry
    best, reason = None, ""
    for target, observation in sorted(latest.items()):
        node = topology.get("nodes", {}).get(target, {})
        if node.get("link") == "down":
            continue  # already contained
        count = observation.get("snapshots") or 0
        if count and (best is None or count > (latest[best].get("snapshots") or 0)):
            best = target
            reason = f"{count} snapshots observed on this guest"
    return best, reason


def cmd_plan(args):
    """Propose containment from sealed observations, holding no hypervisor.

    This process cannot open libvirt, cannot actuate and cannot approve. It
    reads what the sensor published, proposes, evaluates against that published
    view, mints a handle and asks the gateway to spend it. Every one of those
    steps is checked again on the other side of the socket.
    """
    from .gateway import FileStore
    from .privsep import assert_role

    assert_role("planner", args.uri, enforce=not args.no_privsep)
    store = FileStore(args.store)
    while True:
        topology = store.topology()
        if not topology:
            _say("no topology published yet; is the sensor running?")
        else:
            incident = LiveIncident(store=store, topology=topology)
            target, why = _suspect(store.entries, topology)
            if not target:
                _say("no anomaly in the sealed hypervisor observations")
            else:
                _say(f"suspect {target}: {why}")
                proposal = incident.propose(
                    args.action, target, why, [f"libvirt:{target}"]
                )
                decision = incident.evaluate(proposal)
                _say(f"  -> {decision['result']} / {decision['reason']}")
                capability = incident.issue(proposal, decision)
                if capability is None:
                    _say("  no handle issued; nothing is asked of the gateway")
                else:
                    try:
                        answer = incident.execute_remote(capability, args.socket)
                        _say(f"  gateway: {answer['result']}")
                        for line in answer.get("reasons", []):
                            _say(f"    · {line}")
                    except OSError as error:
                        _say(f"  gateway unreachable at {args.socket}: {error}")
        if args.once:
            return 0
        time.sleep(args.interval)


def cmd_release(args):
    """Lift containment, once the world allows it.

    Act 6 refuses to release isolation while a critical service in another
    tenant depends on the target, and act 7 denies the proposal outright. That
    refusal is conditional, not permanent, which is the part an audience will
    ask about: the guest is not bricked. When the dependency goes away the same
    proposal is allowed and the same handle mechanism executes it.

    It is also how an operator cleans up after a demonstration, and it goes
    through the full governance path rather than around it. Reaching for virsh
    would work and would prove nothing.
    """
    plane = _plane(args)
    incident = LiveIncident(plane)
    catalogue = args.catalogue if isinstance(args.catalogue, str) else None

    _say(f"state now: {plane.read_state(args.target)}")
    if catalogue and not args.keep_catalogue:
        _catalogue_drop(catalogue, DEMO_NODES)
        _say(f"removed the walkthrough's catalogue entries: {', '.join(DEMO_NODES)}")
        _say("the dependency that revoked the pending handle is gone")

    proposal = incident.propose(
        args.action, args.target, "Release containment after review.", ["obs-1"]
    )
    decision = incident.evaluate(proposal)
    _say()
    _say(f"proposal: {args.action} on {args.target}")
    _say(f"  -> {decision['result']} / {decision['reason']}")
    _say(
        f"  blast radius: {decision['facts']['tenant_count']} tenant(s) "
        f"{decision['facts']['blast_tenants']}"
    )
    capability = incident.issue(proposal, decision)
    if not capability:
        _say("  no handle issued, so containment stays in place")
        _say("  that is the correct outcome: a human decides from here")
        return 1
    result = incident.execute(capability)
    _say(f"  gateway: {result['result']}")
    if "after" in result:
        _say(f"  after : {result['after']}")
    for line in result.get("reasons", []):
        _say(f"    · {line}")
    return 0 if result["result"] == "VERIFIED" else 1


def main(argv=None):
    parser = argparse.ArgumentParser(prog="aegis.live", description=__doc__)
    parser.add_argument("--uri", default="qemu:///system")
    parser.add_argument("--catalogue", default=None, help="service dependency JSON")
    parser.add_argument("--read-only", action="store_true")
    parser.add_argument("--store", default="/var/lib/aegis/state.json")
    parser.add_argument("--socket", default="/run/aegis/gateway.sock")
    parser.add_argument("--no-privsep", action="store_true",
                        help="observe privilege violations without refusing to start")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("topology").set_defaults(run=cmd_topology)
    sub.add_parser("privileges").set_defaults(run=cmd_privileges)
    observe = sub.add_parser("observe")
    observe.add_argument("--interval", type=float, default=5.0)
    observe.add_argument("--once", action="store_true")
    observe.set_defaults(run=cmd_observe)
    sub.add_parser("gateway").set_defaults(run=cmd_gateway)
    plan = sub.add_parser("plan")
    plan.add_argument("--action", default="network.isolate", choices=sorted(ACTIONS))
    plan.add_argument("--interval", type=float, default=15.0)
    plan.add_argument("--once", action="store_true")
    plan.set_defaults(run=cmd_plan)
    release = sub.add_parser("release")
    release.add_argument("--target", required=True)
    release.add_argument("--action", default="network.restore", choices=sorted(ACTIONS))
    release.add_argument("--keep-catalogue", action="store_true")
    release.set_defaults(run=cmd_release)
    demo = sub.add_parser("demo")
    demo.add_argument("--target", required=True)
    demo.add_argument("--action", default="network.isolate", choices=sorted(ACTIONS))
    demo.add_argument("--json", action="store_true")
    demo.set_defaults(run=cmd_demo)
    args = parser.parse_args(argv)
    return args.run(args)


if __name__ == "__main__":
    sys.exit(main())
