"""The live policy must decide from measured topology, not from action names."""

import unittest

from aegis.gateway import Gateway, MemoryStore
from aegis.live import LiveIncident, _suspect, decide, facts
from tests.test_gateway import FakePlane

#: Mirrors what discovery reports on a provisioned host: one network carrying
#: two tenants, which is what makes it shared and critical.
SHARED = {
    "nodes": {
        "tenant-b--app": {"id": "tenant-b--app", "kind": "domain", "tenant_id": "tenant-b",
                          "state": "running", "shared": False},
        "tenant-c--svc": {"id": "tenant-c--svc", "kind": "domain", "tenant_id": "tenant-c",
                          "state": "running", "shared": False},
        "net:aebr-shared": {"id": "net:aebr-shared", "kind": "net", "tenant_id": "infrastructure",
                            "shared": True, "criticality": "critical",
                            "observed_tenants": ["tenant-b", "tenant-c"]},
        "host:hv1": {"id": "host:hv1", "kind": "host", "tenant_id": "infrastructure",
                     "shared": True, "criticality": "critical"},
    },
    "edges": [
        {"source": "tenant-b--app", "target": "net:aebr-shared", "relation": "attached_to"},
        {"source": "tenant-c--svc", "target": "net:aebr-shared", "relation": "attached_to"},
        {"source": "tenant-b--app", "target": "host:hv1", "relation": "runs_on"},
        {"source": "tenant-c--svc", "target": "host:hv1", "relation": "runs_on"},
    ],
}
EVIDENCE = ["libvirt:tenant-b--app"]


class PolicyTest(unittest.TestCase):
    def verdict(self, action, target, evidence=EVIDENCE, topology=None):
        decision = decide(topology or SHARED, action, target, evidence)
        return decision["result"], decision["reason"]

    def test_shared_infrastructure_is_denied_because_it_was_measured(self):
        """Two tenants were observed on this bridge, so the denial is arithmetic
        rather than a fixture assertion."""
        node = SHARED["nodes"]["net:aebr-shared"]
        self.assertEqual(node["observed_tenants"], ["tenant-b", "tenant-c"])
        self.assertEqual(
            self.verdict("network.isolate", "net:aebr-shared"),
            ("DENY", "DENY_SHARED_RESOURCE"),
        )

    def test_unpublished_action_is_denied_before_any_policy_runs(self):
        self.assertEqual(
            self.verdict("host.stop", "host:hv1"), ("DENY", "DENY_UNPUBLISHED_ACTION")
        )

    def test_scoped_reversible_containment_is_allowed(self):
        self.assertEqual(
            self.verdict("network.isolate", "tenant-b--app"),
            ("ALLOW", "ALLOW_SCOPED_REVERSIBLE"),
        )

    def test_irreversible_action_requires_a_human(self):
        self.assertEqual(
            self.verdict("vm.snapshot", "tenant-b--app"),
            ("REQUIRE_APPROVAL", "REQUIRE_APPROVAL_IRREVERSIBLE"),
        )

    def test_proposal_without_evidence_is_held(self):
        self.assertEqual(
            self.verdict("network.isolate", "tenant-b--app", evidence=[]),
            ("HOLD", "HOLD_NO_EVIDENCE"),
        )

    def test_unknown_target_is_denied(self):
        self.assertEqual(
            self.verdict("network.isolate", "no-such-guest"),
            ("DENY", "DENY_UNKNOWN_TARGET"),
        )

    def test_blast_radius_growth_flips_an_allowed_action_to_denied(self):
        """The same proposal, before and after a catalogue entry appears."""
        self.assertEqual(
            self.verdict("network.isolate", "tenant-b--app")[0], "ALLOW"
        )
        grown = {
            "nodes": dict(
                SHARED["nodes"],
                **{"svc-billing": {"id": "svc-billing", "kind": "service",
                                   "tenant_id": "tenant-c", "criticality": "critical"}},
            ),
            "edges": SHARED["edges"]
            + [{"source": "svc-billing", "target": "tenant-b--app", "relation": "depends_on"}],
        }
        self.assertEqual(
            self.verdict("network.isolate", "tenant-b--app", topology=grown),
            ("DENY", "DENY_CROSS_TENANT_BLAST"),
        )

    def test_facts_are_all_derived_from_observation(self):
        derived = facts(SHARED, "network.isolate", "tenant-b--app", EVIDENCE)
        self.assertEqual(derived["closure"], ["tenant-b--app"])
        self.assertEqual(derived["blast_tenants"], ["tenant-b"])
        self.assertFalse(derived["target_shared"])
        self.assertTrue(derived["reversible"])


class EndToEndTest(unittest.TestCase):
    def setUp(self):
        self.plane = FakePlane()
        self.incident = LiveIncident(self.plane, MemoryStore())

    def test_propose_evaluate_issue_execute_verify(self):
        proposal = self.incident.propose(
            "network.isolate", "vm-a", "Contain the implicated guest.", ["obs-1"]
        )
        decision = self.incident.evaluate(proposal)
        self.assertEqual(decision["result"], "ALLOW")
        capability = self.incident.issue(proposal, decision)
        self.assertEqual(capability["status"], "issued")
        result = self.incident.execute(capability)
        self.assertEqual(result["result"], "VERIFIED")
        self.assertTrue(self.incident.evidence()["chain"]["ok"])

    def test_denied_proposal_issues_no_handle(self):
        proposal = self.incident.propose(
            "network.isolate", "net:br0", "Isolate the shared bridge.", ["obs-1"]
        )
        decision = self.incident.evaluate(proposal)
        self.assertEqual(decision["reason"], "DENY_SHARED_RESOURCE")
        self.assertIsNone(self.incident.issue(proposal, decision))
        self.assertEqual(self.plane.calls, [])

    def test_every_step_is_sealed_in_order(self):
        proposal = self.incident.propose("network.isolate", "vm-a", "Contain.", ["obs-1"])
        self.incident.execute(self.incident.issue(proposal, self.incident.evaluate(proposal)))
        self.assertEqual(
            [entry["event_type"] for entry in self.incident.store.entries],
            ["proposal.submitted", "governance.decision", "capability.issued", "outcome.verified"],
        )
        self.assertTrue(self.incident.evidence()["chain"]["ok"])


if __name__ == "__main__":
    unittest.main()


class PlannerWithoutAPlaneTest(unittest.TestCase):
    """The planner process holds no hypervisor, so it must work from what the
    sensor published and must be unable to act by itself."""

    def setUp(self):
        self.plane = FakePlane()
        self.published = self.plane.discover()
        self.incident = LiveIncident(
            plane=None, store=MemoryStore(), topology=self.published
        )

    def test_it_can_propose_evaluate_and_issue(self):
        proposal = self.incident.propose(
            "network.isolate", "vm-a", "Bulk capture observed.", ["libvirt:vm-a"]
        )
        decision = self.incident.evaluate(proposal)
        self.assertEqual(decision["result"], "ALLOW")
        self.assertIsNotNone(self.incident.issue(proposal, decision))

    def test_it_cannot_execute_anything_itself(self):
        self.assertIsNone(self.incident.gateway)
        proposal = self.incident.propose("network.isolate", "vm-a", "x", ["e"])
        capability = self.incident.issue(proposal, self.incident.evaluate(proposal))
        with self.assertRaises(RuntimeError):
            self.incident.execute(capability)
        self.assertEqual(self.plane.calls, [])

    def test_a_stale_view_cannot_widen_what_the_gateway_allows(self):
        """The planner decides from a snapshot. If the world has moved since,
        the gateway catches it, which is why a stale planner is tolerable."""
        proposal = self.incident.propose(
            "network.isolate", "vm-a", "Bulk capture observed.", ["libvirt:vm-a"]
        )
        capability = self.incident.issue(proposal, self.incident.evaluate(proposal))
        self.plane.edges.append(
            {"source": "service-b", "target": "vm-a", "relation": "depends_on"}
        )
        gateway = Gateway(
            self.plane, self.incident.store, enforce_privsep=False
        )
        refused = gateway.consume(capability["id"], capability["nonce"])
        self.assertEqual(refused["result"], "HOLD_CONTEXT_CHANGED")
        self.assertEqual(self.plane.calls, [])

    def test_no_topology_published_yet(self):
        with self.assertRaises(RuntimeError):
            LiveIncident(plane=None, store=MemoryStore()).topology()


class SuspectTest(unittest.TestCase):
    """Target selection reads hypervisor signal only, and is a placeholder for
    a model rather than a detector worth trusting."""

    def observations(self, counts):
        return [
            {
                "event_type": "hypervisor.observed",
                "target_id": target,
                "trust_level": "hypervisor",
                "snapshots": count,
            }
            for target, count in counts.items()
        ]

    def topology(self, links=None):
        return {
            "nodes": {
                name: {"id": name, "kind": "domain", "link": (links or {}).get(name, "up")}
                for name in ("vm-a", "vm-b")
            },
            "edges": [],
        }

    def test_the_busiest_snapshot_target_is_chosen(self):
        target, why = _suspect(
            self.observations({"vm-a": 1, "vm-b": 7}), self.topology()
        )
        self.assertEqual(target, "vm-b")
        self.assertIn("7 snapshots", why)

    def test_an_already_contained_guest_is_not_chosen_again(self):
        target, _ = _suspect(
            self.observations({"vm-a": 1, "vm-b": 7}),
            self.topology(links={"vm-b": "down"}),
        )
        self.assertEqual(target, "vm-a")

    def test_no_signal_means_no_proposal(self):
        self.assertEqual(
            _suspect(self.observations({"vm-a": 0, "vm-b": 0}), self.topology()),
            (None, ""),
        )

    def test_guest_reports_are_never_considered(self):
        """A guest could claim anything; only hypervisor entries are read."""
        forged = [
            {
                "event_type": "guest.reported",
                "target_id": "vm-a",
                "trust_level": "guest",
                "snapshots": 999,
            }
        ]
        self.assertEqual(_suspect(forged, self.topology()), (None, ""))
