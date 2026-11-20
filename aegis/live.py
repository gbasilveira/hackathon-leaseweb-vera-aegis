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
from .policy import CAPABILITY_TTL, POLICY_DIGEST, decide, facts
from .scope import explain, scoped_digest, sha

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
            "evidence_refs": list(proposal["evidence_refs"]),
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


def _seal_observations(plane, store):
    """Seal the plane's current hypervisor observations, as the sensor would.

    The walkthrough and the release path run without the sensor service, but
    the gateway checks that cited evidence exists in the sealed journal and
    concerns the target. Fabricating an identifier here would be the exact
    thing tests/test_sabotage.py forbids, so these paths record real
    observations instead.
    """
    from .controlplane import authority_facts

    sealed = {}
    for fact in authority_facts(plane.observe())["facts"]:
        store.journal(dict(fact, event_type="hypervisor.observed", outcome="observed"))
        sealed[fact["target_id"]] = fact["id"]
    return sealed


def _say(text=""):
    print(text, flush=True)


def _act(number, title):
    _say()
    _say(f"\033[1m── Act {number} · {title}\033[0m")


def cmd_topology(args):
    topology = _plane(args, writable=False).discover()
    _say(f"host: {topology['host']}")
    _say()
    _say(
        f"{'node':<30} {'kind':<10} {'tenant':<16} {'shared':<7} {'criticality':<12} link"
    )
    for node_id, node in sorted(topology["nodes"].items()):
        link = node.get("link")
        contained = link == "down"
        _say(
            f"{node_id:<30} {node.get('kind',''):<10} {node.get('tenant_id',''):<16} "
            f"{str(bool(node.get('shared'))):<7} {node.get('criticality',''):<12} "
            + (f"\033[31m{link} (contained)\033[0m" if contained else (link or ""))
            + (
                f"   observed tenants: {', '.join(node['observed_tenants'])}"
                if node.get("observed_tenants")
                else ""
            )
        )
    if any(node.get("link") == "down" for node in topology["nodes"].values()):
        _say()
        _say("Guests showing 'contained' have had their interface link dropped.")
        _say("Release one with: aegis.live release --target <guest>")
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
    evidence = _seal_observations(plane, incident.store)
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
    if topology["nodes"].get(target, {}).get("link") == "down":
        _say()
        _say(f"\033[31m{target} is already contained, so act 5 would show no change.\033[0m")
        _say("Release it first and run this again:")
        _say(f"  sudo ./deploy/reset-demo.sh    # or: aegis.live release --target {target}")
        return 1

    _act(2, "The broad action the alert asked for")
    broad = next((n["id"] for n in shared if n["kind"] == "net"), None)
    wide = "network.isolate" if broad else "host.stop"
    broad = broad or topology["host"]
    proposal = incident.propose(
        wide,
        broad,
        "An untrusted log asked for a wide containment.",
        [evidence.get(broad)] if evidence.get(broad) else [],
    )
    decision = incident.evaluate(proposal)
    _say(f"proposal: {wide} on {broad}")
    _say(f"  -> {decision['result']} / {decision['reason']}")
    _say(f"  blast radius: {decision['facts']['tenant_count']} tenant(s) {decision['facts']['blast_tenants']}")
    _say(f"  closure: {decision['facts']['closure']}")

    _act(3, "The scoped action, and the handle it earns")
    proposal = incident.propose(
        action, target, "Contain the implicated guest only.", [evidence[target]]
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
        if result.get("no_change_required"):
            _say("  \033[33mnothing required changing: the target was already in this state\033[0m")
    for line in result.get("reasons", []):
        _say(f"    · {line}")

    _act(6, "A change inside the closure revokes a pending handle")
    restore = incident.propose(
        "network.restore" if action == "network.isolate" else "vm.resume",
        target,
        "Release containment after review.",
        [evidence[target]],
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
    # The journal records changes, not a heartbeat. Sealing every poll would add
    # one entry per guest every few seconds, and since the store is rewritten
    # whole on each append, an afternoon of running would make it slow and its
    # evidence unreadable. Byte counters are excluded from the comparison
    # because they always differ; what is compared is what could carry
    # authority.
    seen = {}
    while True:
        store.publish_topology(plane.discover())
        separated = authority_facts(plane.observe())
        changed = []
        for fact in separated["facts"]:
            signature = (fact.get("state"), fact.get("snapshots"), tuple(sorted((fact.get("links") or {}).items())))
            if seen.get(fact["target_id"]) == signature:
                continue
            seen[fact["target_id"]] = signature
            changed.append(fact)
            store.journal(dict(fact, event_type="hypervisor.observed", outcome="observed"))
        for ignored in separated["excluded"]:
            store.journal(
                dict(ignored, event_type="guest.reported", outcome="excluded_from_decisions")
            )
        _say(
            f"published topology for {len(separated['facts'])} guest(s); sealed "
            f"{len(changed)} change(s)"
            + (f": {', '.join(f['target_id'] for f in changed)}" if changed else "")
            + (f"; excluded {len(separated['excluded'])} guest report(s)"
               if separated["excluded"] else "")
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
            spec, notes = _candidate(args, store, topology)
            for note in notes:
                _say(f"  {note}")
            if spec is None:
                _say("nothing proposed this cycle")
            else:
                _say(f"proposing {spec['action_type']} on {spec['target_id']}")
                _say(f"  because: {spec['rationale']}")
                incident = LiveIncident(store=store, topology=topology)
                proposal = incident.propose(
                    spec["action_type"],
                    spec["target_id"],
                    spec["rationale"],
                    spec["evidence_refs"],
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


def _candidate(args, store, topology):
    """What to propose this cycle, and how it was arrived at.

    With `--planner claude` the model does the reasoning. With `auto` it does,
    and the deterministic heuristic covers a cycle where the model is
    unavailable, declines or fails, so a planner loop degrades instead of
    dying. Either way the proposal goes through the identical deterministic
    path afterwards, and the gateway re-runs the policy against live libvirt
    before anything happens.
    """
    notes = []
    if args.planner in ("auto", "claude"):
        from .claude_planner import plan as claude_plan

        spec, claude_notes = claude_plan(store, topology)
        notes.extend(claude_notes)
        if spec is not None:
            notes.append("source: claude")
            return spec, notes
        if args.planner == "claude":
            return None, notes
        notes.append("falling back to the deterministic heuristic")
    target, why = _suspect(store.entries, topology)
    if not target:
        notes.append("no anomaly in the sealed hypervisor observations")
        return None, notes
    notes.append("source: deterministic heuristic")
    return {
        "action_type": args.action,
        "target_id": target,
        "rationale": why,
        "evidence_refs": [f"libvirt:{target}"],
    }, notes


def cmd_compare(args):
    """Run both planners on the same observations, and execute neither.

    This exists to answer the question an autonomous defence always gets:
    what stops it from containing a legitimate workload? The honest answer is
    that the counter-based heuristic does not, and that judging whether
    containment is warranted is what the model is for. Showing both on
    identical evidence is more useful than claiming either is right.

    Nothing is executed. Both columns stop at the policy verdict.
    """
    from .gateway import FileStore

    store = FileStore(args.store)
    topology = store.topology()
    if not topology:
        _say("no topology published yet; is the sensor running?")
        return 1

    observations = [
        entry for entry in store.entries
        if entry.get("event_type") == "hypervisor.observed"
    ]
    excluded = [
        entry for entry in store.entries if entry.get("event_type") == "guest.reported"
    ]
    _say(f"{len(observations)} sealed hypervisor observation(s)")
    _say(f"{len(excluded)} guest report(s), excluded from decision facts")

    def verdict(spec):
        if spec is None:
            return None
        return decide(
            topology, spec["action_type"], spec["target_id"], spec["evidence_refs"]
        )

    _act("A", "Deterministic heuristic")
    target, why = _suspect(store.entries, topology)
    heuristic = (
        {
            "action_type": args.action,
            "target_id": target,
            "rationale": why,
            "evidence_refs": [f"libvirt:{target}"],
        }
        if target
        else None
    )
    if heuristic:
        _say(f"would propose {args.action} on {target}")
        _say(f"  reasoning: {why}")
        outcome = verdict(heuristic)
        _say(f"  policy: {outcome['result']} / {outcome['reason']}")
        if outcome["result"] == "ALLOW":
            _say("  \033[33mthis would have contained a running workload\033[0m")
    else:
        _say("would propose nothing")

    _act("B", "Claude")
    from .claude_planner import plan as claude_plan

    spec, notes = claude_plan(store, topology)
    for note in notes:
        _say(f"  {note}")
    if spec:
        _say(f"would propose {spec['action_type']} on {spec['target_id']}")
        outcome = verdict(spec)
        _say(f"  policy: {outcome['result']} / {outcome['reason']}")
    else:
        _say("would propose nothing")

    _act("C", "What this shows")
    if heuristic and not spec:
        _say("The counter fired and the model did not.")
        _say("Snapshotting is ordinary maintenance; a count is not a compromise.")
        _say("Judging that is the model's job. Bounding the damage is the policy's.")
    elif spec and heuristic and spec["target_id"] == heuristic["target_id"]:
        _say("Both reached the same target. The model explained why; the counter did not.")
    elif spec and not heuristic:
        _say("The model saw something the counter has no way to express.")
    else:
        _say("Neither proposed containment on this evidence.")
    _say()
    _say("Neither column executed anything. The gateway re-runs this policy")
    _say("against live libvirt before any handle is spent, whoever proposed it.")
    return 0


def cmd_board(args):
    """Serve a read-only console over the live path.

    The simulator's browser interface reads the fixture engine, with its own
    digest and its own policy. Showing that beside a hypervisor running this
    one would put a picture of the wrong system on screen, which is worse than
    showing no picture. This serves the live path and nothing else, and it has
    no write path: acting goes through the gateway.
    """
    from .board import serve

    server = serve(args.store, args.uri, host=args.host, port=args.port)
    _say(f"live console on http://{args.host}:{args.port}")
    _say(f"reading {args.store}")
    if args.host == "127.0.0.1":
        _say("loopback only; from a laptop use:")
        _say(f"  ssh -L {args.port}:127.0.0.1:{args.port} ubuntu@<host>")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
    return 0


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

    evidence = _seal_observations(plane, incident.store)
    if args.target not in evidence:
        _say(f"no hypervisor observation for {args.target}; is the guest defined?")
        return 1
    proposal = incident.propose(
        args.action, args.target, "Release containment after review.", [evidence[args.target]]
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
    board = sub.add_parser("board")
    board.add_argument("--host", default="127.0.0.1")
    board.add_argument("--port", type=int, default=8780)
    board.set_defaults(run=cmd_board)
    compare = sub.add_parser("compare")
    compare.add_argument("--action", default="network.isolate", choices=sorted(ACTIONS))
    compare.set_defaults(run=cmd_compare)
    plan = sub.add_parser("plan")
    plan.add_argument("--action", default="network.isolate", choices=sorted(ACTIONS))
    plan.add_argument("--interval", type=float, default=15.0)
    plan.add_argument("--once", action="store_true")
    plan.add_argument(
        "--planner",
        default="auto",
        choices=["auto", "claude", "heuristic"],
        help="auto uses Claude and falls back to the heuristic for a cycle",
    )
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
