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

    def test_primary_topology_connects_each_tenant_to_shared_compute(self):
        snapshot = self.core.snapshot()
        assets = {item["id"]: item for item in snapshot["assets"]}
        placements = [edge for edge in snapshot["dependencies"] if edge["type"] == "runs_on"]
        self.assertEqual(
            {assets[edge["source"]]["tenant_id"] for edge in placements},
            {"tenant-a", "tenant-b", "tenant-c"},
        )
        self.assertEqual({edge["target"] for edge in placements}, {"host-a", "host-b"})
        self.assertTrue(all(assets[edge["target"]]["type"] == "hypervisor_host" for edge in placements))
        self.assertTrue({"network", "management_plane"} <= {asset["type"] for asset in assets.values()})

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
        inventory_result = inventory["payload"]["result"]
        self.assertEqual(inventory_result["tenant_id"], "tenant-b")
        self.assertEqual(
            {item["id"] for item in inventory_result["items"]},
            {"vm-a", "vm-sandbox-b", "service-tenant-b"},
        )
        self.assertEqual(self.core.step()["outcome"], "denied")
        expired = self.core.step()
        self.assertEqual(expired["outcome"], "denied")
        self.assertEqual(expired["actor_id"], "session-expired-b")
        self.assertEqual(self.core.step()["payload"]["result"]["id"], "identity-a")
        self.assertEqual(self.core.step()["payload"]["result"]["id"], "session-a")
        self.assertEqual(self.core.step()["payload"]["result"]["status"], "healthy")
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
        self.assertIn("service-b", changed["direct"])
        self.assertIn("service-tenant-b", changed["transitive"])
        self.assertEqual(changed["critical_services"], ["service-b"])
        self.assertFalse(changed["invariants"]["tenant_boundary_preserved"])
        self.assertEqual(alternative["tenants"], ["tenant-b"])
        self.assertFalse(alternative["critical_shared"])

    def test_read_catalog_resolves_target_kind_and_computes_service_health(self):
        with self.core.tx() as connection:
            self.assertTrue(self.core.probe(connection, "session-a", "identity.inspect", "identity-a"))
            self.assertTrue(self.core.probe(connection, "session-a", "session.inspect", "session-a"))
            self.assertFalse(self.core.probe(connection, "session-a", "identity.inspect", "session-a"))
            self.assertFalse(self.core.probe(connection, "session-a", "inventory.list", "tenant-c"))
            self.core.apply(connection, "vm.stop", "vm-a", {})
            health = self.core.apply(connection, "service.health", "service-tenant-b", {})
            self.assertEqual(health, {"id": "service-tenant-b", "status": "degraded", "unavailable": ["vm-a"]})
            with self.assertRaisesRegex(ValueError, "incompatible action target"):
                self.core.apply(connection, "service.health", "vm-a", {})
            with self.assertRaisesRegex(ValueError, "Unexpected simulator action parameters"):
                self.core.apply(connection, "vm.start", "vm-a", {"arbitrary": True})

    def test_incident_classifier_uses_recorded_evidence(self):
        incident = self.core.snapshot()["incident"]
        self.assertEqual(incident["severity"], "unclassified")
        self.assertEqual(incident["evidence_refs"], [])
        observed, alert, check = self.core.step(), self.core.step(), self.core.step()
        incident = self.core.snapshot()["incident"]
        self.assertEqual(incident["severity"], "high")
        self.assertEqual(incident["observed_at"], observed["timestamp"])
        self.assertEqual(incident["detected_at"], alert["timestamp"])
        self.assertIn(check["id"], incident["evidence_refs"])

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
        bad_checkout = copy.deepcopy(scenario)
        bad_checkout["events"][2]["trust_level"] = "untrusted"
        with self.assertRaisesRegex(ValueError, "fixed fixture permission check"):
            validate(bad_checkout)
        bad_grant = copy.deepcopy(scenario)
        bad_grant["sessions"][0]["permissions"][0]["target"] = "host-a"
        with self.assertRaisesRegex(ValueError, "Invalid simulator grant"):
            validate(bad_grant)
        scenario["proposals"][0]["evidence_refs"] = ["does-not-exist"]
        with self.assertRaisesRegex(ValueError, "reference replay fixture"):
            validate(scenario)

    def test_host_stop_is_outside_the_executable_catalog(self):
        self.assertNotIn("host.stop", ACTIONS)
        with self.core.tx() as connection, self.assertRaisesRegex(ValueError, "Unknown simulator action"):
            self.core.apply(connection, "host.stop", "host-a", {})


if __name__ == "__main__":
    unittest.main()
