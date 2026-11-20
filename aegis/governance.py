"""Deterministic proposal, approval and single-use execution boundary."""

import hashlib
import json
import operator
import secrets
import time

from .verifier import verify
from .models import Decision, Manifest, Proposal

WRITES = {
    "vm.stop",
    "vm.start",
    "vm.snapshot",
    "session.suspend",
    "identity.suspend",
    "identity.restore",
}
COLLECTIONS = (
    "proposals",
    "decisions",
    "approvals",
    "capabilities",
    "executions",
    "verifications",
)


def digest(value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(data.encode()).hexdigest()


def token():
    return secrets.token_urlsafe(24)


def matches(expr, facts):
    ((op, args),) = expr.items()
    if op == "all":
        return all(matches(x, facts) for x in args)
    if op == "any":
        return any(matches(x, facts) for x in args)
    if op == "not":
        return not matches(args, facts)
    name, right = args
    left = facts[name]
    return {
        "eq": operator.eq,
        "ne": operator.ne,
        "gt": operator.gt,
        "gte": operator.ge,
        "lt": operator.lt,
        "lte": operator.le,
        "in": lambda x, y: x in y,
        "contains": operator.contains,
    }[op](left, right)


class Governance:
    def __init__(self, core):
        self.core = core

    def rows(self, c, key):
        return self.core.get(c, key, [])

    def add(self, c, key, row):
        self.core.put(c, key, self.rows(c, key) + [row])
        return row

    def find(self, c, key, ident):
        for row in self.rows(c, key):
            if row["id"] == ident:
                return row
        raise ValueError("Unknown " + key)

    def submit(self, proposal: Proposal) -> str:
        with self.core.tx() as c:
            s = self.core.snapshot(c)
            p = {
                k: proposal.get(k, default)
                for k, default in (
                    ("action_type", ""),
                    ("target_id", ""),
                    ("parameters", {}),
                    ("evidence_refs", []),
                    ("rationale", ""),
                    ("expected_effect", ""),
                    ("assumptions", []),
                )
            }
            if (
                p["parameters"] != {}
                or any(
                    not isinstance(p[k], str) or len(p[k]) > 4096
                    for k in (
                        "action_type",
                        "target_id",
                        "rationale",
                        "expected_effect",
                    )
                )
                or any(
                    not isinstance(p[k], list)
                    or len(p[k]) > 128
                    or not all(isinstance(x, str) and len(x) <= 4096 for x in p[k])
                    for k in ("assumptions", "evidence_refs")
                )
            ):
                raise ValueError("Invalid proposal parameters or text")
            p.update(
                id=token(),
                proposed_by="response-planner",
                incident_id=s["incident_id"],
                tenant_id=s["scenario"]["incident"]["tenant_id"],
            )
            self.add(c, "proposals", p)
            self.core.event(
                c,
                "proposal.submitted",
                p["proposed_by"],
                p["target_id"],
                "PROPOSED",
                {"proposal_id": p["id"]},
            )
            self.core.transition(c, "planning")
            return p["id"]

    def assess(self, c, p) -> Decision:
        s = self.core.snapshot(c)
        target = next(
            (
                x
                for group in ("assets", "identities", "sessions")
                for x in s[group]
                if x["id"] == p["target_id"]
            ),
            {},
        )
        action = p["action_type"]
        impact = {"tenants": [], "affected": [], "critical_shared": False}
        if target:
            try:
                impact = self.core.impact(c, action, p["target_id"])
            except ValueError:
                pass
        policies = s["scenario"]["policies"]
        context = digest(
            [
                s[k]
                for k in (
                    "revision",
                    "dependencies",
                    "assets",
                    "sessions",
                    "identities",
                    "tenants",
                )
            ]
        )
        facts = dict(
            action=action,
            unknown=action not in WRITES,
            destructive=action.endswith(".delete"),
            shared=target.get("shared", False)
            or target.get("tenant_id") in (None, "shared"),
            cross_tenant=target.get("tenant_id") not in (None, "shared", p["tenant_id"])
            or any(t not in ("shared", p["tenant_id"]) for t in impact["tenants"]),
            critical_shared=bool(impact["critical_shared"]),
            sensitive=action not in {"session.suspend", "identity.suspend"},
            limited=action in {"session.suspend", "identity.suspend"},
            evidence_ok=bool(p["evidence_refs"])
            and set(p["evidence_refs"])
            <= (
                {x["id"] for x in s["events"]}
                & {x["id"] for x in s["scenario"]["events"]}
            ),
        )
        result, reason, policy, version = "DENY", "DENY_DEFAULT", "baseline", "1"
        try:
            rules = sorted(
                ((r, pol) for pol in policies for r in pol["rules"]),
                key=lambda x: x[0]["priority"],
                reverse=True,
            )
            for rule, pol in rules:
                if matches(rule["when"], facts):
                    result, reason, policy, version = (
                        rule["result"],
                        rule["reason"],
                        pol["id"],
                        pol["version"],
                    )
                    break
            if result in ("ALLOW", "REQUIRE_APPROVAL"):
                appropriate = (
                    action.startswith("vm.")
                    and target.get("type") in ("vm", "virtual_machine")
                    or action.startswith("identity.")
                    and target in s["identities"]
                    or action.startswith("session.")
                    and target in s["sessions"]
                )
                if (
                    action not in WRITES
                    or not appropriate
                    or facts["shared"]
                    or facts["cross_tenant"]
                ):
                    result, reason = "DENY", "DENY_SCOPE"
                elif not facts["evidence_ok"]:
                    result, reason = "HOLD", "HOLD_EVIDENCE"
            if result not in ("ALLOW", "DENY", "HOLD", "REQUIRE_APPROVAL"):
                raise ValueError("Unsupported policy outcome")
        except (ValueError, TypeError, KeyError):
            result, reason = "DENY", "DENY_POLICY_ERROR"
        return dict(
            id=token(),
            proposal_id=p["id"],
            result=result,
            reason_codes=[reason],
            policy_id=policy,
            policy_version=version,
            policy_digest=digest(policies),
            context_revision=s["revision"],
            context_digest=context,
            impact=impact,
            timestamp=time.time(),
        )

    def record(self, c, p, d):
        d["proposal_hash"] = digest(p)
        self.core.transition(c, "evaluating")
        self.add(c, "decisions", d)
        self.core.transition(
            c,
            {
                "ALLOW": "authorized",
                "DENY": "denied",
                "REQUIRE_APPROVAL": "waiting_approval",
                "HOLD": "evaluating",
            }[d["result"]],
        )
        old = self.rows(c, "capabilities")
        for cap in old:
            if cap["proposal_id"] == p["id"] and cap["status"] == "issued":
                cap["status"] = "revoked"
        self.core.put(c, "capabilities", old)
        self.core.event(
            c, "governance.decision", "governance", p["target_id"], d["result"], d
        )
        if d["result"] == "ALLOW":
            cap = dict(
                id=token(),
                nonce=token(),
                proposal_id=p["id"],
                proposal_hash=digest(p),
                tenant_id=p["tenant_id"],
                action_type=p["action_type"],
                target_id=p["target_id"],
                policy_digest=d["policy_digest"],
                context_digest=d["context_digest"],
                context_revision=d["context_revision"],
                issued_at=time.time(),
                expires_at=time.time() + 300,
                status="issued",
                decision_id=d["id"],
            )
            self.add(c, "capabilities", cap)
        return d

    def evaluate(self, ident):
        with self.core.tx() as c:
            p = self.find(c, "proposals", ident)
            return self.record(c, p, self.assess(c, p))

    def approve(self, ident, actor, accept=True):
        with self.core.tx() as c:
            p = self.find(c, "proposals", ident)
            s = self.core.snapshot(c)
            human = next((x for x in s["identities"] if x["id"] == actor), {})
            if (
                actor == p["proposed_by"]
                or human.get("type") != "human"
                or human.get("status") != "active"
                or human.get("tenant_id") != p["tenant_id"]
                or "incident_owner" not in human.get("roles", [])
            ):
                raise ValueError("Unauthorized approver")
            d = self.assess(c, p)
            last = next(
                (
                    x
                    for x in reversed(self.rows(c, "decisions"))
                    if x["proposal_id"] == ident
                ),
                {},
            )
            if (
                d["result"] != "REQUIRE_APPROVAL"
                or last.get("result") != d["result"]
                or any(last.get(k) != d[k] for k in ("context_digest", "policy_digest"))
                or last.get("proposal_hash") != digest(p)
            ):
                raise ValueError("Approval requires a current matching request")
            self.add(
                c,
                "approvals",
                dict(
                    id=token(),
                    proposal_id=ident,
                    request_hash=digest(p),
                    approver_id=actor,
                    approver_role="incident_owner",
                    decision="approve" if accept else "reject",
                    created_at=time.time(),
                    expires_at=time.time() + 300,
                ),
            )
            d.update(
                result="ALLOW" if accept else "DENY",
                reason_codes=["HUMAN_APPROVED" if accept else "HUMAN_REJECTED"],
            )
            return self.record(c, p, d)

    def execute(self, ident):
        with self.core.tx() as c:
            caps = self.rows(c, "capabilities")
            cap = next((x for x in caps if x["id"] == ident), None)
            if not cap:
                raise ValueError("Unknown capability")
            p = self.find(c, "proposals", cap["proposal_id"])
            d = self.assess(c, p)
            reason = None
            if cap["status"] != "issued":
                reason = "DENY_" + cap["status"].upper()
            elif cap["expires_at"] <= time.time():
                reason = "DENY_EXPIRED"
            elif digest(p) != cap["proposal_hash"]:
                reason = "DENY_REQUEST_CHANGED"
            elif d["policy_digest"] != cap["policy_digest"]:
                reason = "HOLD_POLICY_CHANGED"
            elif d["context_digest"] != cap["context_digest"]:
                reason = "HOLD_CONTEXT_CHANGED"
            if reason:
                if cap["status"] == "issued":
                    cap["status"] = "expired" if reason == "DENY_EXPIRED" else "revoked"
                self.core.put(c, "capabilities", caps)
                self.core.event(
                    c,
                    "gateway.refused",
                    "gateway",
                    p["target_id"],
                    reason,
                    {
                        "proposal_id": p["id"],
                        "before": cap["context_revision"],
                        "after": d["context_revision"],
                    },
                )
                if reason.startswith("HOLD"):
                    self.record(c, p, d)
                return dict(result=reason)
            if d["result"] != "ALLOW":
                approved = any(
                    a["request_hash"] == digest(p)
                    and a["decision"] == "approve"
                    and a["expires_at"] > time.time()
                    for a in self.rows(c, "approvals")
                )
                if d["result"] != "REQUIRE_APPROVAL" or not approved:
                    cap["status"] = "revoked"
                    self.core.put(c, "capabilities", caps)
                    return self.record(c, p, d)
            before = self.core.snapshot(c)
            self.core.transition(c, "executing")
            self.core.apply(c, p["action_type"], p["target_id"], p["parameters"])
            cap["status"] = "consumed"
            self.core.put(c, "capabilities", caps)
            self.add(
                c,
                "executions",
                dict(
                    id=token(),
                    proposal_id=p["id"],
                    capability_id=ident,
                    action_type=p["action_type"],
                    target_id=p["target_id"],
                ),
            )
            self.core.event(
                c,
                "defense.executed",
                "containment-executor",
                p["target_id"],
                "EXECUTED",
                {"proposal_id": p["id"]},
            )
            self.core.transition(c, "verifying")
            check = verify(self.core, c, p, before)
            self.add(c, "verifications", check)
            self.core.event(
                c,
                "outcome.verified",
                "outcome-verifier",
                p["target_id"],
                check["result"],
                check,
            )
            self.core.transition(
                c,
                {
                    "VERIFIED": "contained",
                    "FAILED": "failed",
                    "INDETERMINATE": "indeterminate",
                }[check["result"]],
            )
            return check

    def manifest(self) -> Manifest:
        with self.core.tx() as c:
            s = self.core.snapshot(c)
            m = {k: self.rows(c, k) for k in COLLECTIONS}
            m.update(
                incident_id=s["incident_id"],
                context_revision=s["revision"],
                events=s["events"],
                policies=s["scenario"]["policies"],
                dependencies=s["dependencies"],
                final_state=s["state"],
                final_inventory={
                    k: s[k] for k in ("assets", "identities", "sessions", "tenants")
                },
                initial_evidence=[
                    e["id"]
                    for e in s["events"]
                    if e["id"] in {fixture["id"] for fixture in s["scenario"]["events"]}
                ],
                scenario_digest=digest(s["scenario"]),
                incident=s.get("incident", s["scenario"]["incident"]),
                limitations=[
                    "Local simulator evidence. An administrator can rewrite the database."
                ],
            )
            return m
