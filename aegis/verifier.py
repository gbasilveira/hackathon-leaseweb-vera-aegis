"""Observe persisted effects independently of the adapter's return value."""


def foreign_state(s, tenant):
    return {
        x["id"]: x
        for group in ("assets", "sessions", "identities")
        for x in s[group]
        if x.get("tenant_id") != tenant
    }


def verify(core, c, p, before):
    s = core.snapshot(c)
    target = p["target_id"]
    op = p["action_type"]
    checks = {
        "foreign_resources_preserved": foreign_state(s, p["tenant_id"])
        == foreign_state(before, p["tenant_id"])
    }
    row = next(
        (
            x
            for group in ("assets", "sessions", "identities")
            for x in s[group]
            if x["id"] == target
        ),
        {},
    )
    if op == "identity.suspend":
        sessions = [x for x in s["sessions"] if x["identity_id"] == target]
        probes = [(x["id"], g) for x in sessions for g in x.get("permissions", [])]
        checks.update(
            suspended=row.get("status") == "suspended",
            sessions_invalid=all(x["status"] != "active" for x in sessions),
            access_denied=all(
                not core.probe(c, i, g["action"], g["target"]) for i, g in probes
            )
            if probes
            else None,
        )
    elif op == "session.suspend":
        checks["suspended"] = row.get("status") in ("suspended", "revoked")
        grants = row.get("permissions", [])
        checks["access_denied"] = (
            all(not core.probe(c, target, g["action"], g["target"]) for g in grants)
            if grants
            else None
        )
    elif op == "identity.restore":
        checks["active"] = row.get("status") == "active"
    elif op in ("vm.start", "vm.stop"):
        checks["state"] = row.get("state") == (
            "running" if op == "vm.start" else "stopped"
        )
    else:
        old = next((x for x in before["assets"] if x["id"] == target), {})
        checks["snapshot"] = row.get("snapshots") == old.get("snapshots", 0) + 1
    result = (
        "FAILED"
        if False in checks.values()
        else "INDETERMINATE"
        if None in checks.values()
        else "VERIFIED"
    )
    return dict(proposal_id=p["id"], result=result, checks=checks)
