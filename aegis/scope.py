"""Scoped context binding for capability authority.

A capability must commit to the part of the world that can change its meaning,
and to nothing else.

The original implementation digested every tenant, asset, session, identity and
dependency into one `context_digest`. That is conservative but unusable against
a live hypervisor, where state moves continuously: every pending grant would be
invalidated within seconds of issue, before any operator could consume it.

This module computes the *impact closure* of a decision and digests only that.
Edge direction follows the existing convention, `source` depends on `target`,
so the blast radius of acting on a node is its reverse reachability. A change
outside that closure cannot alter who the action harms, and therefore must not
revoke authority. A change inside it must.

The closure deliberately excludes what the target itself depends on. Isolating
a guest does not harm the bridge it sits on, so bridge load is not authority
relevant. The wiring that attaches the target to its dependencies is still
committed to, because losing or gaining an attachment does change the action.
"""

import hashlib
import json

#: Node fields that participate in an authority decision. Volatile telemetry
#: (CPU time, byte counters, timestamps) is deliberately absent: it changes on
#: every observation and would reintroduce the thrashing this module removes.
SCOPED_FIELDS = (
    "id",
    "kind",
    "type",
    "tenant_id",
    "criticality",
    "state",
    "status",
    "shared",
    "link",
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def _relation(edge):
    return edge.get("relation") or edge.get("type") or "depends_on"


def dependents(edges, roots):
    """Every node that transitively depends on `roots`, including the roots."""
    incoming = {}
    for edge in edges:
        incoming.setdefault(edge["target"], []).append(edge["source"])
    seen = set(roots)
    stack = list(roots)
    while stack:
        for source in incoming.get(stack.pop(), ()):
            if source not in seen:
                seen.add(source)
                stack.append(source)
    return seen


def scope_of(nodes, edges, target):
    """Ids whose state or wiring can change the meaning of acting on `target`."""
    return (dependents(edges, [target]) & set(nodes)) | {target}


def observation(nodes, edges, target):
    """The scoped projection a capability commits to.

    `members` is the closure, `nodes` their authority-relevant fields, `wiring`
    the edges incident to the closure and `tenants` the blast radius expressed
    as owners. Adding an edge into the closure grows `members`, so a new
    dependant is caught by membership as well as by wiring.
    """
    closure = scope_of(nodes, edges, target)
    return {
        "target": target,
        "members": sorted(closure),
        "nodes": {
            node: {
                field: nodes[node][field]
                for field in SCOPED_FIELDS
                if field in nodes[node]
            }
            for node in sorted(closure)
            if node in nodes
        },
        "wiring": sorted(
            [edge["source"], _relation(edge), edge["target"]]
            for edge in edges
            if edge["source"] in closure or edge["target"] in closure
        ),
        "tenants": sorted(
            {
                nodes[node].get("tenant_id")
                for node in closure
                if node in nodes and nodes[node].get("tenant_id")
            }
        ),
    }


def scoped_digest(nodes, edges, target):
    """Return (digest, observation) for a decision about `target`."""
    observed = observation(nodes, edges, target)
    return sha(observed), observed


def explain(before, after):
    """Why two scoped observations differ, as operator-readable reasons.

    The gateway uses this to name the node that cost a capability its
    authority, instead of reporting an opaque digest mismatch.
    """
    if before == after:
        return []
    reasons = []
    old, new = set(before.get("members", ())), set(after.get("members", ()))
    for node in sorted(new - old):
        tenant = after.get("nodes", {}).get(node, {}).get("tenant_id", "unknown")
        reasons.append(f"{node} ({tenant}) now depends on {after.get('target')}")
    for node in sorted(old - new):
        reasons.append(f"{node} no longer depends on {before.get('target')}")
    for node in sorted(old & new):
        was = before.get("nodes", {}).get(node, {})
        now = after.get("nodes", {}).get(node, {})
        for field in sorted(set(was) | set(now)):
            if was.get(field) != now.get(field):
                reasons.append(
                    f"{node}.{field} changed from {was.get(field)!r} to {now.get(field)!r}"
                )
    was_wiring = {tuple(edge) for edge in before.get("wiring", ())}
    now_wiring = {tuple(edge) for edge in after.get("wiring", ())}
    for source, relation, target in sorted(now_wiring - was_wiring):
        reasons.append(f"new edge {source} -{relation}-> {target}")
    for source, relation, target in sorted(was_wiring - now_wiring):
        reasons.append(f"removed edge {source} -{relation}-> {target}")
    old_tenants, new_tenants = before.get("tenants", []), after.get("tenants", [])
    if old_tenants != new_tenants:
        reasons.append(
            f"blast radius moved from {len(old_tenants)} to {len(new_tenants)} tenant(s): "
            f"{', '.join(new_tenants) or 'none'}"
        )
    return reasons
