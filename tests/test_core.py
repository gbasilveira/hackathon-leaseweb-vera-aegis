"""Tests for scenario replay and the transactional simulator."""

import copy
import json
import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timedelta

from aegis.core import ACTIONS, SCENARIOS, Core, validate


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        path = Path(self.directory.name) / "simulation.sqlite"
        self.core = Core(path)
        self.core.load("control-plane-compromise")

    def test_scenarios_validate(self):
        self.assertEqual(self.core.scenarios(), ["control-plane-compromise", "secondary-scenario"])
        for scenario in self.core.scenarios():
            report = self.core.load(scenario)
            self.assertEqual(report["scenario"]["id"], scenario)
            self.assertEqual(report["state"], "CREATED")
            self.assertEqual(report["revision"], 0)

    def test_replay_uses_permission_checks_and_simulated_state(self):
        observation = self.core.step()
        self.assertEqual(observation["id"], "observation-001")
        self.assertEqual(self.core.snapshot()["state"], "OBSERVING")
        alert = self.core.step()
        self.assertEqual(alert["trust_level"], "untrusted")
        self.assertEqual(alert["tenant_id"], "tenant-b")
        self.assertEqual(datetime.fromisoformat(alert["timestamp"]).utcoffset(), timedelta(0))
        self.assertEqual(self.core.snapshot()["state"], "DETECTED")
        allowed = self.core.step()
        self.assertEqual(allowed["id"], "evidence-002")
        self.assertEqual(allowed["outcome"], "allowed")
        self.assertEqual(self.core.snapshot()["state"], "INVESTIGATING")
        self.assertEqual(next(x for x in self.core.snapshot()["assets"] if x["id"] == "vm-a")["snapshots"], 1)
        denied = self.core.step()
        self.assertEqual(denied["outcome"], "denied")
        self.assertEqual(self.core.snapshot()["revision"], 1)
        self.assertEqual(self.core.step()["outcome"], "allowed")
        self.assertEqual(next(x for x in self.core.snapshot()["assets"] if x["id"] == "vm-sandbox-b")["state"], "stopped")
        self.assertEqual(self.core.step()["outcome"], "allowed")
        self.assertEqual(next(x for x in self.core.snapshot()["assets"] if x["id"] == "vm-sandbox-b")["state"], "running")
        inventory = self.core.step()
        self.assertEqual(inventory["outcome"], "allowed")
        self.assertEqual(inventory["payload"]["result"]["id"], "vm-a")
        self.assertEqual(self.core.step()["outcome"], "denied")
        expired = self.core.step()
        self.assertEqual(expired["outcome"], "denied")
        self.assertEqual(expired["actor_id"], "session-expired-b")
        self.assertIsNone(self.core.step())

    def test_drift_expands_identity_impact_only(self):
        with self.core.tx() as connection:
            before = self.core.impact(connection, "identity.suspend", "identity-a")
        self.assertEqual(before["tenants"], ["tenant-b"])
        self.assertFalse(before["critical_shared"])
        revision = self.core.change()["revision"]
        self.assertEqual(self.core.change()["revision"], revision)
        with self.core.tx() as connection:
            changed = self.core.impact(connection, "identity.suspend", "identity-a")
            alternative = self.core.impact(connection, "session.suspend", "session-a")
        self.assertEqual(changed["tenants"], ["tenant-b", "tenant-c"])
        self.assertTrue(changed["critical_shared"])
        self.assertEqual(alternative["tenants"], ["tenant-b"])
        self.assertFalse(alternative["critical_shared"])

    def test_session_check_is_independent_of_action_return(self):
        with self.core.tx() as connection:
            self.assertTrue(self.core.probe(connection, "session-a", "vm.stop", "vm-a"))
            self.assertFalse(self.core.probe(connection, "session-a", "vm.stop", "vm-c"))
            self.core.apply(connection, "identity.suspend", "identity-a", {})
            self.assertFalse(self.core.probe(connection, "session-a", "vm.stop", "vm-a"))
            self.assertEqual(self.core.snapshot(connection)["sessions"][0]["status"], "suspended")

    def test_failed_transaction_does_not_mutate_resource_or_revision(self):
        with self.assertRaisesRegex(RuntimeError, "cancel"):
            with self.core.tx() as connection:
                self.core.apply(connection, "session.suspend", "session-a", {})
                raise RuntimeError("cancel")
        snapshot = self.core.snapshot()
        self.assertEqual(snapshot["revision"], 0)
        self.assertEqual(snapshot["sessions"][0]["status"], "active")

    def test_invalid_fixture_references_fail_closed(self):
        scenario = json.loads((SCENARIOS / "control-plane-compromise.json").read_text())
        bad_edge = copy.deepcopy(scenario)
        bad_edge["dependencies"][0]["target"] = "does-not-exist"
        with self.assertRaisesRegex(ValueError, "dependency endpoints"):
            validate(bad_edge)
        scenario["proposals"][0]["evidence_refs"] = ["does-not-exist"]
        with self.assertRaisesRegex(ValueError, "reference replay fixture"):
            validate(scenario)

    def test_host_stop_is_outside_the_executable_catalog(self):
        self.assertNotIn("host.stop", ACTIONS)
        with self.core.tx() as connection, self.assertRaisesRegex(ValueError, "Unknown simulator action"):
            self.core.apply(connection, "host.stop", "host-a", {})


if __name__ == "__main__":
    unittest.main()
