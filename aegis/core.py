"""Transactional state and deterministic replay for synthetic incident fixtures."""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCENARIOS = Path(__file__).resolve().parent.parent / "scenarios"
ACTIONS = {
    "inventory.list": ("assets", None, None),
    "asset.inspect": ("assets", None, None),
    "identity.inspect": ("identities", None, None),
    "session.inspect": ("sessions", None, None),
    "vm.start": ("assets", "state", "running"),
    "vm.stop": ("assets", "state", "stopped"),
    "vm.snapshot": ("assets", "snapshots", None),
    "session.suspend": ("sessions", "status", "suspended"),
    "identity.suspend": ("identities", "status", "suspended"),
    "identity.restore": ("identities", "status", "active"),
    "service.health": ("assets", None, None),
}
TARGETS = {action: definition[0] for action, definition in ACTIONS.items()}
TARGETS["host.stop"] = "assets"
COLLECTIONS = ("tenants", "assets", "identities", "sessions")
POLICY_FACTS = {
    "action", "unknown", "destructive", "shared", "cross_tenant", "critical_shared",
    "sensitive", "limited", "evidence_ok",
}
POLICY_RESULTS = {"ALLOW", "REQUIRE_APPROVAL", "DENY", "HOLD"}
READ_ACTIONS = {action for action, (_, field, _) in ACTIONS.items() if field is None}
REPLAY_WRITES = {"vm.start", "vm.stop", "vm.snapshot"}
REPLAY_ACTIONS = READ_ACTIONS | REPLAY_WRITES
TARGET_TYPES = {"host.stop": "host", "service.health": "service", **{action: "vm" for action in REPLAY_WRITES}}
SEVERITIES = ("unclassified", "low", "medium", "high", "critical")


def _index(items):
    return {item["id"]: item for item in items}


def _unique(items, label, field="id"):
    if not isinstance(items, list):
        raise ValueError(f"{label} must be a list")
    seen = set()
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get(field), str) or not item[field]:
            raise ValueError(f"{label} entries require a nonempty {field}")
        if item[field] in seen:
            raise ValueError(f"Duplicate {label} {field}: {item[field]}")
        seen.add(item[field])
    return seen


def _member(value, choices):
    return isinstance(value, str) and value in choices


def _resolve(action, target, records):
    collection = TARGETS.get(action)
    if collection is None:
        return None
    record = records(collection).get(target)
    required_type = TARGET_TYPES.get(action)
    return record if record and (required_type is None or record.get("type") == required_type) else None


def _graph(edges, entities):
    if not isinstance(edges, list):
        raise ValueError("Dependencies must be a list")
    seen = set()
    for edge in edges:
        if not isinstance(edge, dict):
            raise ValueError("Dependency must be an object")
        source, target = edge.get("source"), edge.get("target")
        if not _member(source, entities) or not _member(target, entities) or source == target:
            raise ValueError("Invalid dependency endpoints")
        if not isinstance(edge.get("type"), str) or not edge["type"]:
            raise ValueError("Dependency requires a type")
        if (source, target) in seen:
            raise ValueError("Duplicate dependency")
        seen.add((source, target))
    return seen


def _policy_expression(expr):
    if not isinstance(expr, dict) or len(expr) != 1:
        raise ValueError("Invalid policy expression")
    op, args = next(iter(expr.items()))
    if op in ("all", "any") and isinstance(args, list) and args:
        for child in args:
            _policy_expression(child)
    elif op == "not":
        _policy_expression(args)
    elif not (
        op in ("eq", "ne", "gt", "gte", "lt", "lte", "in", "contains")
        and isinstance(args, list) and len(args) == 2 and _member(args[0], POLICY_FACTS)
    ):
        raise ValueError("Invalid policy operator, arguments or fact")


def validate(scenario):
    """Reject invalid references and unsupported simulator actions at load time."""
    if not isinstance(scenario, dict):
        raise ValueError("Scenario must be an object")
    for key in ("id", "name", "description", "initial_state"):
        if not isinstance(scenario.get(key), str) or not scenario[key]:
            raise ValueError(f"Scenario requires a nonempty {key}")
    ids = {key: _unique(scenario.get(key), key) for key in COLLECTIONS}
    for collection in COLLECTIONS:
        if any(not isinstance(item.get("name"), str) or not item["name"] for item in scenario[collection]):
            raise ValueError(f"{collection} entries require a name")
    for asset in scenario["assets"]:
        if not _member(asset.get("tenant_id"), ids["tenants"]):
            raise ValueError("Unknown asset tenant")
        if (not isinstance(asset.get("shared"), bool) or asset.get("state") not in ("running", "stopped")
            or asset.get("criticality") not in ("normal", "critical")
            or asset.get("type") not in ("vm", "host", "service")):
            raise ValueError("Assets require shared, criticality, type and state")
    for identity in scenario["identities"]:
        if not _member(identity.get("tenant_id"), ids["tenants"]):
            raise ValueError("Unknown identity tenant")
        if identity.get("status") not in ("active", "suspended"):
            raise ValueError("Identity requires an active or suspended status")
    identities = _index(scenario["identities"])
    for session in scenario["sessions"]:
        if not _member(session.get("identity_id"), identities):
            raise ValueError("Unknown session identity")
        identity = identities[session["identity_id"]]
        if session.get("tenant_id") != identity["tenant_id"]:
            raise ValueError("Session tenant must match its identity")
        if session.get("status") not in ("active", "suspended"):
            raise ValueError("Session requires an active or suspended status")
        ttl = session.get("valid_for_seconds")
        if type(ttl) is not int or not 0 <= ttl <= 86_400:
            raise ValueError("Session requires a valid duration")
    entities = {key: _index(scenario[key]) for key in COLLECTIONS}
    for principal in (*scenario["identities"], *scenario["sessions"]):
        permissions = principal.get("permissions")
        if not isinstance(permissions, list):
            raise ValueError("Identity and session permissions must be a list")
        for grant in permissions:
            if (not isinstance(grant, dict) or set(grant) != {"action", "target"}
                or not _member(grant.get("action"), ACTIONS)
                or not _member(grant.get("target"), ids[TARGETS[grant["action"]]])
                or _resolve(grant["action"], grant["target"], entities.__getitem__) is None):
                raise ValueError("Invalid simulator grant")
    entity_ids = set().union(*ids.values())
    if sum(map(len, ids.values())) != len(entity_ids):
        raise ValueError("Entity IDs must be unique across collections")
    incident = scenario.get("incident")
    if (not isinstance(incident, dict) or not isinstance(incident.get("id"), str)
        or not incident["id"] or not _member(incident.get("tenant_id"), ids["tenants"])):
        raise ValueError("Incident requires a known tenant")
    if scenario.get("schema_version") != 1:
        raise ValueError("Unsupported scenario schema version")
    edges = _graph(scenario.get("dependencies"), entity_ids)
    change = scenario.get("change")
    if change is not None:
        injected = _graph([change], entity_ids)
        if injected & edges:
            raise ValueError("The injected dependency must be new")
    proposals = _unique(scenario.get("proposals"), "proposals")
    alternative = scenario.get("alternative_proposal_id")
    if alternative is not None and not _member(alternative, proposals):
        raise ValueError("Unknown alternative proposal")
    for proposal in scenario["proposals"]:
        action = proposal.get("action_type")
        if (not _member(action, TARGETS) or not _member(proposal.get("target_id"), ids[TARGETS[action]])
            or _resolve(action, proposal["target_id"], entities.__getitem__) is None):
            raise ValueError("Invalid proposal action or target")
        if proposal.get("parameters") != {}:
            raise ValueError("Proposal parameters must be an empty object")
        if proposal.get("phase") not in ("initial", "alternative"):
            raise ValueError("Invalid proposal phase")
        for key in ("rationale", "expected_effect"):
            if not isinstance(proposal.get(key), str):
                raise ValueError(f"Proposal requires {key}")
        assumptions = proposal.get("assumptions")
        if not isinstance(assumptions, list) or any(not isinstance(item, str) for item in assumptions):
            raise ValueError("Invalid proposal assumptions")
    event_ids = _unique(scenario.get("events"), "events")
    if any(event_id.startswith("event-") for event_id in event_ids):
        raise ValueError("Fixture event IDs cannot use the generated event prefix")
    for proposal in scenario["proposals"]:
        refs = proposal.get("evidence_refs")
        if not isinstance(refs, list) or any(not isinstance(ref, str) or ref not in event_ids for ref in refs):
            raise ValueError("Proposal evidence must reference replay fixture events")
    for item in scenario["events"]:
        for key in ("event_type", "actor_id", "target_id", "outcome"):
            if not isinstance(item.get(key), str) or not item[key]:
                raise ValueError(f"Replay event requires a nonempty {key}")
        if not isinstance(item.get("payload"), dict):
            raise ValueError("Replay event payload must be an object")
        if item.get("trust_level", "synthetic_fixture") not in ("synthetic_fixture", "untrusted"):
            raise ValueError("Invalid fixture trust level")
        if "source" in item and (not isinstance(item["source"], str) or not item["source"]):
            raise ValueError("Invalid fixture event source")
        check = item.get("permission_check")
        if check is not None and (
            not isinstance(check, dict) or not _member(check.get("session_id"), ids["sessions"])
            or not _member(check.get("action"), REPLAY_ACTIONS)
            or not _member(check.get("target_id"), ids[TARGETS[check["action"]]])
            or _resolve(check["action"], check["target_id"], entities.__getitem__) is None
            or type(check.get("mutate", False)) is not bool
            or (check.get("mutate") and (
                check["action"] not in REPLAY_WRITES or item.get("trust_level") == "untrusted"
            ))
        ):
            raise ValueError("Invalid fixed fixture permission check")
    classification = incident.get("classification")
    if (not isinstance(classification, dict) or classification.get("default") not in SEVERITIES
        or not isinstance(classification.get("rules"), list)):
        raise ValueError("Incident requires a severity classification policy")
    for rule in classification["rules"]:
        if (not isinstance(rule, dict) or not _member(rule.get("event_id"), event_ids)
            or rule.get("severity") not in SEVERITIES):
            raise ValueError("Invalid incident severity rule")
    role_ids = _unique(scenario.get("roles"), "roles")
    agent_role_ids = _unique(scenario.get("agent_roles"), "agent roles")
    if role_ids & agent_role_ids:
        raise ValueError("Agent roles must be distinct from human roles")
    for identity in scenario["identities"]:
        roles = identity.get("roles", [])
        if not isinstance(roles, list) or any(not _member(role, role_ids) for role in roles):
            raise ValueError("Invalid identity role")
    if not isinstance(scenario.get("metadata"), dict):
        raise ValueError("Scenario requires metadata")
    criteria = scenario.get("success_criteria")
    if not isinstance(criteria, list) or not criteria or any(not isinstance(item, str) or not item for item in criteria):
        raise ValueError("Scenario requires success criteria")
    _unique(scenario.get("actors"), "actors")
    for actor in scenario["actors"]:
        if any(not isinstance(actor.get(key), str) or not actor[key] for key in ("name", "role")):
            raise ValueError("Actors require a name and role")
    _unique(scenario.get("policies"), "policies")
    for policy in scenario["policies"]:
        if not isinstance(policy.get("version"), (str, int)) or not isinstance(policy.get("rules"), list):
            raise ValueError("Policy requires a version and rules")
        for rule in policy["rules"]:
            if (not isinstance(rule, dict) or type(rule.get("priority")) is not int
                or not _member(rule.get("result"), POLICY_RESULTS)
                or not isinstance(rule.get("reason"), str) or not rule["reason"]):
                raise ValueError("Invalid policy rule")
            _policy_expression(rule.get("when"))
    transitions = scenario.get("transitions")
    if not isinstance(transitions, dict) or scenario["initial_state"] not in transitions:
        raise ValueError("Transitions must include the initial state")
    for signals in transitions.values():
        if not isinstance(signals, dict) or any(not _member(target, transitions) for target in signals.values()):
            raise ValueError("Invalid state transition")
    _unique(scenario.get("processes"), "processes")
    process = next((item for item in scenario["processes"] if item["id"] == "incident-response"), {})
    if process.get("transitions") != transitions or process.get("initial_state") != scenario["initial_state"]:
        raise ValueError("Incident response process must match scenario transitions")
    return scenario


class Core:
    def __init__(self, path):
        self.path = path
        with self.tx() as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL)")

    @contextmanager
    def tx(self):
        connection = sqlite3.connect(self.path, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def get(connection, key, default=None):
        row = connection.execute("SELECT v FROM kv WHERE k = ?", (key,)).fetchone()
        return json.loads(row["v"]) if row is not None else default

    @staticmethod
    def put(connection, key, value):
        connection.execute(
            "INSERT INTO kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            (key, json.dumps(value, sort_keys=True, ensure_ascii=False)),
        )

    @staticmethod
    def scenarios():
        return sorted(
            (path.stem for path in SCENARIOS.glob("*.json") if path.name != "schema.json"),
            key=lambda scenario_id: (scenario_id != "control-plane-compromise", scenario_id),
        )

    def load(self, scenario_id):
        if scenario_id not in self.scenarios():
            raise ValueError("Unknown scenario")
        scenario = validate(json.loads((SCENARIOS / f"{scenario_id}.json").read_text(encoding="utf-8")))
        if scenario["id"] != scenario_id:
            raise ValueError("Scenario ID must match its filename")
        with self.tx() as connection:
            generation = self.get(connection, "generation", 0) + 1
            connection.execute("DELETE FROM kv")
            self.put(connection, "generation", generation)
            self.put(connection, "incident_id", f"{scenario_id}-{generation}")
            self.put(connection, "scenario", scenario)
            self.put(connection, "state", scenario["initial_state"])
            self.put(connection, "revision", 0)
            self.put(connection, "cursor", 0)
            self.put(connection, "events", [])
            for key in (*COLLECTIONS, "dependencies"):
                self.put(connection, key, scenario[key])
            now = datetime.now(timezone.utc)
            sessions = [
                {**session, "expires_at": (now + timedelta(seconds=session["valid_for_seconds"])).isoformat()}
                for session in scenario["sessions"]
            ]
            self.put(connection, "sessions", sessions)
            self.put(connection, "incident", {
                "id": self.get(connection, "incident_id"),
                "fixture_id": scenario["incident"]["id"],
                "tenant_id": scenario["incident"]["tenant_id"],
                "severity": scenario["incident"]["classification"]["default"],
                "created_at": now.isoformat(),
                "updated_at": now.isoformat(),
                "observed_at": None,
                "detected_at": None,
                "evidence_refs": [],
            })
            self.event(connection, "scenario_loaded", "system", scenario_id, "success", {})
            return self.snapshot(connection)

    def snapshot(self, connection=None):
        if connection is None:
            with self.tx() as connection:
                return self.snapshot(connection)
        snapshot = {key: self.get(connection, key, []) for key in (*COLLECTIONS, "dependencies", "events")}
        snapshot.update({key: self.get(connection, key) for key in ("scenario", "incident_id", "incident", "state")})
        snapshot["revision"] = self.get(connection, "revision", 0)
        snapshot["cursor"] = self.get(connection, "cursor", 0)
        return snapshot

    def event(self, connection, event_type, actor_id, target_id, outcome, payload, *, event_id=None, source=None, trust_level="simulator"):
        events = self.get(connection, "events", [])
        sequence = len(events) + 1
        scenario = self.get(connection, "scenario") or {}
        tenant_id = scenario.get("incident", {}).get("tenant_id")
        for collection in COLLECTIONS:
            target = _index(self.get(connection, collection, [])).get(target_id)
            if target:
                tenant_id = target_id if collection == "tenants" else target["tenant_id"]
                break
        entry = {
            "id": event_id or f"event-{sequence:04d}",
            "sequence": sequence,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tenant_id": tenant_id,
            "source": source or actor_id,
            "trust_level": trust_level,
            "incident_id": self.get(connection, "incident_id"),
            "event_type": event_type,
            "actor_id": actor_id,
            "target_id": target_id,
            "outcome": outcome,
            "payload": payload,
        }
        events.append(entry)
        self.put(connection, "events", events)
        incident = self.get(connection, "incident")
        if incident is not None:
            incident["updated_at"] = entry["timestamp"]
            if event_id is not None:
                incident["evidence_refs"].append(event_id)
                for rule in scenario["incident"]["classification"]["rules"]:
                    if rule["event_id"] == event_id:
                        incident["severity"] = max(incident["severity"], rule["severity"], key=SEVERITIES.index)
                if event_type == "observation_started" and incident["observed_at"] is None:
                    incident["observed_at"] = entry["timestamp"]
                if event_type == "alert_observed" and incident["detected_at"] is None:
                    incident["detected_at"] = entry["timestamp"]
            self.put(connection, "incident", incident)
        return entry

    def step(self):
        with self.tx() as connection:
            scenario = self.get(connection, "scenario")
            if scenario is None:
                raise ValueError("Load a scenario first")
            cursor = self.get(connection, "cursor")
            if cursor >= len(scenario["events"]):
                return None
            item = scenario["events"][cursor]
            payload = {**item["payload"], "fixture_id": item["id"]}
            outcome = item["outcome"]
            check = item.get("permission_check")
            if check is not None:
                outcome = "allowed" if self.probe(connection, check["session_id"], check["action"], check["target_id"]) else "denied"
                payload["permission_check"] = check
                if outcome == "allowed":
                    if check.get("mutate"):
                        payload["result"] = self.apply(connection, check["action"], check["target_id"], {})
                    elif check["action"] in READ_ACTIONS:
                        payload["result"] = self.apply(connection, check["action"], check["target_id"], {})
            event = self.event(
                connection, item["event_type"], item["actor_id"], item["target_id"], outcome,
                payload, event_id=item["id"], source=item.get("source"),
                trust_level=item.get("trust_level", "synthetic_fixture"),
            )
            self.put(connection, "cursor", cursor + 1)
            self.transition(connection, item["event_type"])
            return event

    def transition(self, connection, signal):
        scenario = self.get(connection, "scenario")
        state = self.get(connection, "state")
        destination = scenario["transitions"].get(state, {}).get(signal, state)
        if destination != state:
            self.put(connection, "state", destination)
            self.event(connection, "process_transition", "system", self.get(connection, "incident_id"), "success",
                       {"from": state, "to": destination, "signal": signal})
        return destination

    def impact(self, connection, action, target):
        if action not in TARGETS:
            raise ValueError("Unknown simulator action")
        entities = {key: _index(self.get(connection, key, [])) for key in COLLECTIONS}
        if _resolve(action, target, entities.__getitem__) is None:
            raise ValueError("Unknown or incompatible action target")
        assets, identities, sessions, tenant_ids = (entities[key] for key in ("assets", "identities", "sessions", "tenants"))
        affected = {target}
        frontier = [target]
        dependents = {}
        for edge in self.get(connection, "dependencies", []):
            dependents.setdefault(edge["target"], []).append(edge["source"])
        for session in sessions.values():
            dependents.setdefault(session["identity_id"], []).append(session["id"])
            dependents.setdefault(session["id"], []).extend(grant["target"] for grant in session["permissions"])
        direct = set(dependents.get(target, ())) - {target}
        while frontier:
            for dependent in dependents.get(frontier.pop(), ()):
                if dependent not in affected:
                    affected.add(dependent)
                    frontier.append(dependent)
        impacted_assets = affected & assets.keys()
        tenants = affected & tenant_ids.keys()
        tenants.update(assets[item]["tenant_id"] for item in impacted_assets)
        tenants.update(identities[item]["tenant_id"] for item in affected & identities.keys())
        tenants.update(identities[sessions[item]["identity_id"]]["tenant_id"] for item in affected & sessions.keys())
        critical = sorted(item for item in impacted_assets if assets[item]["criticality"] == "critical")
        critical_shared = any(assets[item]["shared"] for item in critical)
        incident = self.get(connection, "incident", {})
        foreign_tenants = sorted(tenants - {incident.get("tenant_id")})
        return {
            "tenants": sorted(tenants),
            "foreign_tenants": foreign_tenants,
            "critical_shared": critical_shared,
            "critical_services": [item for item in critical if assets[item]["type"] == "service"],
            "affected": sorted(affected),
            "direct": sorted(direct),
            "transitive": sorted(affected - direct - {target}),
            "invariants": {
                "tenant_boundary_preserved": not foreign_tenants,
                "critical_shared_resources_preserved": not critical_shared,
            },
        }

    def read(self, connection, action, record):
        if action == "inventory.list":
            return {"items": [
                {key: record[key] for key in ("id", "name", "type", "state")}
            ]}
        if action == "service.health":
            assets = _index(self.get(connection, "assets", []))
            dependencies = {}
            for edge in self.get(connection, "dependencies", []):
                dependencies.setdefault(edge["source"], []).append(edge["target"])
            checked = {record["id"]}
            frontier = [record["id"]]
            while frontier:
                for dependency in dependencies.get(frontier.pop(), ()):
                    if dependency not in checked:
                        checked.add(dependency)
                        frontier.append(dependency)
            unavailable = sorted(item for item in checked & assets.keys() if assets[item]["state"] != "running")
            return {"id": record["id"], "status": "degraded" if unavailable else "healthy", "unavailable": unavailable}
        fields = {
            "asset.inspect": ("id", "name", "tenant_id", "type", "state", "criticality", "shared", "snapshots"),
            "identity.inspect": ("id", "name", "tenant_id", "type", "status", "roles"),
            "session.inspect": ("id", "name", "tenant_id", "identity_id", "status", "expires_at"),
        }
        return {key: record[key] for key in fields[action] if key in record}

    def apply(self, connection, action, target, parameters):
        if action not in ACTIONS:
            raise ValueError("Unknown simulator action")
        if parameters != {}:
            raise ValueError("Unexpected simulator action parameters")
        collection, field, value = ACTIONS[action]
        records = self.get(connection, collection, [])
        record = _resolve(action, target, lambda _: _index(records))
        if record is None:
            raise ValueError("Unknown or incompatible action target")
        if action in READ_ACTIONS:
            return self.read(connection, action, record)
        if action == "vm.snapshot":
            value = record.get(field, 0) + 1
        changed = field is not None and record.get(field) != value
        if changed:
            record[field] = value
            self.put(connection, collection, records)
        if action == "identity.suspend":
            sessions = self.get(connection, "sessions", [])
            active = [item for item in sessions if item["identity_id"] == target and item["status"] == "active"]
            for session in active:
                session["status"] = "suspended"
            if active:
                self.put(connection, "sessions", sessions)
                changed = True
        if changed:
            self.put(connection, "revision", self.get(connection, "revision") + 1)
        return {"changed": changed, "revision": self.get(connection, "revision")}

    def probe(self, connection, session_id, action, target):
        session = _index(self.get(connection, "sessions", [])).get(session_id)
        if action not in ACTIONS or session is None or session["status"] != "active":
            return False
        if datetime.fromisoformat(session["expires_at"]) <= datetime.now(timezone.utc):
            return False
        record = _resolve(action, target, lambda collection: _index(self.get(connection, collection, [])))
        if record is None:
            return False
        identity = _index(self.get(connection, "identities", [])).get(session["identity_id"])
        if identity is None or identity["status"] != "active" or identity["tenant_id"] != record["tenant_id"]:
            return False
        required_grant = {"action": action, "target": target}
        return required_grant in session["permissions"] and required_grant in identity["permissions"]

    def change(self):
        with self.tx() as connection:
            scenario = self.get(connection, "scenario")
            if scenario is None or not scenario.get("change"):
                raise ValueError("The current scenario has no configured change")
            edge = scenario["change"]
            edges = self.get(connection, "dependencies")
            if edge in edges:
                return self.snapshot(connection)
            edges.append(edge)
            self.put(connection, "dependencies", edges)
            self.put(connection, "revision", self.get(connection, "revision") + 1)
            self.event(connection, "dependency_changed", "operator", edge["target"], "success", edge)
            return self.snapshot(connection)
