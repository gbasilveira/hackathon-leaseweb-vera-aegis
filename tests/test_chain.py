import asyncio
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from aegis.agent import investigate
from aegis.core import Core
from aegis.governance import Governance


class Chain(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.core = Core(Path(tmp.name) / "demo.sqlite")
        self.core.load("control-plane-compromise")
        while self.core.step() is not None:
            pass
        self.gov = Governance(self.core)
        self.fixture = next(
            p
            for p in self.core.snapshot()["scenario"]["proposals"]
            if p["action_type"] == "identity.suspend"
        )

    def propose(self, **changes):
        return self.gov.submit({**self.fixture, **changes})

    def cap(self):
        p = self.propose()
        self.assertEqual(self.gov.evaluate(p)["result"], "ALLOW")
        return self.gov.manifest()["capabilities"][-1]["id"]

    def test_full_offline_chain(self):
        asyncio.run(investigate(self.core, self.gov, "DETERMINISTIC_REPLAY"))
        proposals = self.gov.manifest()["proposals"]
        denied = next(p for p in proposals if p["action_type"] == "host.stop")
        safe = next(p for p in proposals if p["action_type"] == "identity.suspend")
        self.assertEqual(self.gov.evaluate(denied["id"])["result"], "DENY")
        self.assertEqual(self.gov.evaluate(safe["id"])["result"], "ALLOW")
        cap = self.gov.manifest()["capabilities"][-1]["id"]
        self.assertEqual(self.gov.execute(cap)["result"], "VERIFIED")
        before = len(self.gov.manifest()["executions"])
        cap = self.cap()
        self.core.change()
        self.assertEqual(self.gov.execute(cap)["result"], "HOLD_CONTEXT_CHANGED")
        m = self.gov.manifest()
        self.assertEqual(len(m["executions"]), before)
        self.assertNotEqual(m["decisions"][-1]["result"], "ALLOW")
        self.assertTrue(all(m["verifications"][0]["checks"].values()))

    def test_parallel_reuse(self):
        cap = self.cap()
        with ThreadPoolExecutor(2) as pool:
            results = list(pool.map(self.gov.execute, [cap, cap]))
        self.assertCountEqual(
            [r["result"] for r in results], ["VERIFIED", "DENY_CONSUMED"]
        )
        self.assertEqual(len(self.gov.manifest()["executions"]), 1)

    def test_expiration_and_policy_drift(self):
        cap = self.cap()
        with self.core.tx() as c:
            caps = self.core.get(c, "capabilities")
            caps[-1]["expires_at"] = 0
            self.core.put(c, "capabilities", caps)
        self.assertEqual(self.gov.execute(cap)["result"], "DENY_EXPIRED")
        cap = self.cap()
        with self.core.tx() as c:
            s = self.core.get(c, "scenario")
            s["policies"][0]["version"] = "changed"
            self.core.put(c, "scenario", s)
        self.assertEqual(self.gov.execute(cap)["result"], "HOLD_POLICY_CHANGED")
        self.assertEqual(self.gov.manifest()["executions"], [])

    def test_closed_catalog_and_evidence(self):
        for action in ("vm.delete", "unknown.action"):
            self.assertEqual(
                self.gov.evaluate(self.propose(action_type=action))["result"], "DENY"
            )
        self.assertEqual(
            self.gov.evaluate(self.propose(evidence_refs=[]))["result"], "HOLD"
        )
        with self.assertRaises(ValueError):
            self.gov.execute(self.propose())

    def test_sensitive_approval(self):
        s = self.core.snapshot()
        vm = next(
            a
            for a in s["assets"]
            if a["tenant_id"] == s["scenario"]["incident"]["tenant_id"]
            and a["type"] in ("virtual_machine", "vm")
        )
        human = next(
            i for i in s["identities"] if "incident_owner" in i.get("roles", [])
        )
        p = self.propose(action_type="vm.stop", target_id=vm["id"])
        self.assertEqual(self.gov.evaluate(p)["result"], "REQUIRE_APPROVAL")
        for actor in ("response-planner", "unknown"):
            with self.assertRaises(ValueError):
                self.gov.approve(p, actor)
        self.assertEqual(self.gov.approve(p, human["id"])["result"], "ALLOW")
        self.assertEqual(
            self.gov.execute(self.gov.manifest()["capabilities"][-1]["id"])["result"],
            "VERIFIED",
        )

    def test_hash_tamper_blocks_human_and_capability(self):
        s = self.core.snapshot()
        vm = next(
            x
            for x in s["assets"]
            if x["tenant_id"] == s["scenario"]["incident"]["tenant_id"]
            and x["type"] in ("virtual_machine", "vm")
        )
        actor = next(
            x["id"] for x in s["identities"] if "incident_owner" in x.get("roles", [])
        )
        p = self.propose(action_type="vm.stop", target_id=vm["id"])
        self.gov.evaluate(p)
        with self.core.tx() as c:
            rows = self.core.get(c, "proposals")
            rows[-1]["rationale"] = "Request content changed"
            self.core.put(c, "proposals", rows)
        with self.assertRaises(ValueError):
            self.gov.approve(p, actor)
        cap = self.cap()
        with self.core.tx() as c:
            rows = self.core.get(c, "proposals")
            rows[-1]["parameters"] = {"unexpected": True}
            self.core.put(c, "proposals", rows)
        self.assertEqual(self.gov.execute(cap)["result"], "DENY_REQUEST_CHANGED")
        self.assertEqual(self.gov.manifest()["executions"], [])

    def test_malformed_policy_fails_closed(self):
        with self.core.tx() as c:
            s = self.core.get(c, "scenario")
            s["policies"][0]["rules"][0]["when"] = {"unsupported": []}
            self.core.put(c, "scenario", s)
        d = self.gov.evaluate(self.propose())
        self.assertEqual(d["reason_codes"], ["DENY_POLICY_ERROR"])
        self.assertEqual(self.gov.manifest()["capabilities"], [])

    def test_denies_foreign_target(self):
        s = self.core.snapshot()
        foreign = next(
            x
            for x in s["assets"]
            if x["tenant_id"] != s["scenario"]["incident"]["tenant_id"]
            and not x["shared"]
        )
        decision = self.gov.evaluate(
            self.propose(action_type="vm.stop", target_id=foreign["id"])
        )
        self.assertEqual(decision["result"], "DENY")
        self.assertEqual(self.core.snapshot()["assets"], s["assets"])

    def test_verifier_reports_incomplete_observations(self):
        from aegis.verifier import verify

        with self.core.tx() as c:
            p = {
                **self.fixture,
                "id": "incomplete",
                "tenant_id": self.core.snapshot(c)["scenario"]["incident"]["tenant_id"],
            }
            self.core.apply(c, p["action_type"], p["target_id"], {})
            self.core.put(c, "sessions", [])
            state = self.core.snapshot(c)
            self.assertEqual(verify(self.core, c, p, state)["result"], "INDETERMINATE")

    def test_policy_defaults_and_operators(self):
        from aegis.governance import matches

        self.assertTrue(
            matches(
                {
                    "all": [
                        {"not": {"lt": ["count", 2]}},
                        {"any": [{"gte": ["count", 3]}, {"in": ["count", [2]]}]},
                    ]
                },
                {"count": 2},
            )
        )
        with self.core.tx() as c:
            s = self.core.get(c, "scenario")
            s["policies"][0]["rules"] = []
            self.core.put(c, "scenario", s)
        self.assertEqual(
            self.gov.evaluate(self.propose())["reason_codes"], ["DENY_DEFAULT"]
        )

    def test_drift_prevents_first_suspension(self):
        cap = self.cap()
        before = self.core.snapshot()
        self.core.change()
        self.assertEqual(self.gov.execute(cap)["result"], "HOLD_CONTEXT_CHANGED")
        after = self.core.snapshot()
        for key in ("assets", "sessions", "identities"):
            self.assertEqual(before[key], after[key])
        manifest = self.gov.manifest()
        self.assertEqual(manifest["executions"], [])
        self.assertEqual(manifest["capabilities"][-1]["status"], "revoked")
        self.assertEqual(manifest["decisions"][-1]["result"], "DENY")

    def test_later_fixture_attempts_observe_containment(self):
        self.core.load("control-plane-compromise")
        while not set(self.fixture["evidence_refs"]) <= {e["id"] for e in self.core.snapshot()["events"]}:
            self.assertIsNotNone(self.core.step())
        self.assertEqual(self.gov.execute(self.cap())["result"], "VERIFIED")
        attempts = []
        while (event := self.core.step()) is not None:
            if "permission_check" in event["payload"]:
                attempts.append(event["outcome"])
        self.assertTrue(attempts)
        self.assertEqual(set(attempts), {"denied"})
