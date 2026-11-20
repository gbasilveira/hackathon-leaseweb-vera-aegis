"""The authorisation policy.

This lives apart from the planner on purpose. The gateway has to run it too,
and it must not depend on any code the planner could influence.
"""

import time

from .controlplane import ACTIONS, REVERSIBLE
from .scope import scoped_digest, sha


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
