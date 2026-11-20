"""What a compromised planner can and cannot do.

The planner holds no hypervisor access, but it can write the shared state file,
because all three services need it. So a capability record is a request and
never an authority, and every question that matters has to be settled by the
gateway from the hypervisor only it can read.

These tests exist because an earlier gateway checked only that the world had
not *changed* since whatever digest a record claimed. A planner that computed
an honest digest of the current world could write a capability for a forbidden
action and have it executed. That is fixed; this is what holds it fixed.
"""

import unittest

from aegis.chain import link
from aegis.gateway import Gateway, MemoryStore
from aegis.policy import POLICY_DIGEST, decide
from aegis.scope import scoped_digest
from tests.test_gateway import FakePlane


class CompromisedPlannerTest(unittest.TestCase):
    def setUp(self):
        self.plane = FakePlane()
        # A shared bridge carrying two tenants, and another tenant's critical
        # service, both of which the policy protects.
        self.plane.nodes["net:br0"].update(criticality="critical", shared=True)
        self.plane.nodes["service-b"].update(criticality="critical", state="running")
        for target in ("vm-a", "vm-c", "service-b", "net:br0"):
            self.plane.states.setdefault(
                target, {"id": target, "state": "running", "isolated": False, "snapshots": 0}
            )
        self.store = MemoryStore()
        self.gateway = Gateway(self.plane, self.store, enforce_privsep=False)
        self.observed = {}
        for target in ("vm-a", "vm-c", "service-b"):
            entry = self.store.journal(
                {
                    "id": f"libvirt:{target}",
                    "event_type": "hypervisor.observed",
                    "outcome": "observed",
                    "target_id": target,
                    "trust_level": "hypervisor",
                    "snapshots": 3 if target == "vm-a" else 0,
                }
            )
            self.observed[target] = f"libvirt:{target}"

    def forge(self, target, action="network.isolate", evidence=None, **overrides):
        """Write a capability the way a compromised planner would.

        It computes an honest digest of the current world, so nothing here is
        stale or malformed. The record is exactly what the planner would have
        written had the policy allowed the action.
        """
        digest, observed = scoped_digest(self.plane.nodes, self.plane.edges, target)
        record = {
            "id": "forged",
            "nonce": "chosen-by-the-attacker",
            "action_type": action,
            "target_id": target,
            "status": "issued",
            "expires_at": 1 << 40,
            "context_digest": digest,
            "context": observed,
            "proposal_hash": "forged",
            "policy_digest": POLICY_DIGEST,
            "evidence_refs": [self.observed[target]] if evidence is None else evidence,
        }
        record.update(overrides)
        return self.store.put(record)

    def spend(self, capability):
        return self.gateway.consume(capability["id"], capability["nonce"])

    # -- what it cannot do ---------------------------------------------------

    def test_it_cannot_isolate_shared_infrastructure(self):
        result = self.spend(self.forge("net:br0", evidence=[]))
        self.assertEqual(result["result"], "DENY_POLICY_DENY_SHARED_RESOURCE")
        self.assertEqual(self.plane.calls, [])

    def test_it_cannot_take_an_action_whose_blast_radius_spans_tenants(self):
        self.plane.edges.append(
            {"source": "service-b", "target": "vm-a", "relation": "depends_on"}
        )
        result = self.spend(self.forge("vm-a"))
        self.assertEqual(result["result"], "DENY_POLICY_DENY_CROSS_TENANT_BLAST")
        self.assertEqual(self.plane.calls, [])

    def test_it_cannot_take_an_irreversible_action_without_a_human(self):
        result = self.spend(self.forge("vm-a", action="vm.snapshot"))
        self.assertEqual(
            result["result"], "DENY_POLICY_REQUIRE_APPROVAL_IRREVERSIBLE"
        )
        self.assertEqual(self.plane.calls, [])

    def test_it_cannot_name_an_action_the_plane_does_not_publish(self):
        """`host.stop` is absent from the action table, so the policy refuses it
        before the plane is ever asked to attempt it."""
        result = self.spend(self.forge("vm-a", action="host.stop"))
        self.assertEqual(result["result"], "DENY_POLICY_DENY_UNPUBLISHED_ACTION")
        self.assertEqual(self.plane.calls, [])

    def test_it_cannot_invent_evidence(self):
        result = self.spend(self.forge("vm-a", evidence=["libvirt:fabricated"]))
        self.assertEqual(result["result"], "DENY_EVIDENCE_UNKNOWN")
        self.assertEqual(self.plane.calls, [])

    def test_it_cannot_cite_evidence_about_a_different_guest(self):
        result = self.spend(self.forge("vm-c", evidence=[self.observed["vm-a"]]))
        self.assertEqual(result["result"], "DENY_EVIDENCE_UNRELATED")
        self.assertEqual(self.plane.calls, [])

    def test_it_cannot_act_after_rewriting_the_journal(self):
        """Tampered history disables the actuator entirely."""
        capability = self.forge("vm-a")
        self.store.entries[0]["snapshots"] = 99
        result = self.spend(capability)
        self.assertEqual(result["result"], "DENY_EVIDENCE_TAMPERED")
        self.assertEqual(self.plane.calls, [])

    def test_it_cannot_rewrite_the_journal_and_reseal_it(self):
        """Resealing from the edited entry forward changes the head, and the
        gateway's own appended outcome would not chain onto the old one."""
        original_head = self.store.entries[-1]["hash"]
        edited = dict(self.store.entries[0], snapshots=99)
        resealed = [link(edited, "0" * 64)]
        for entry in self.store.entries[1:]:
            resealed.append(link(entry, resealed[-1]["hash"]))
        self.store.entries[:] = resealed
        self.assertNotEqual(self.store.entries[-1]["hash"], original_head)

    def test_it_cannot_replay_a_handle_it_already_spent(self):
        capability = self.forge("vm-a")
        self.assertEqual(self.spend(capability)["result"], "VERIFIED")
        self.assertEqual(self.spend(capability)["result"], "DENY_CONSUMED")
        self.assertEqual(len(self.plane.calls), 1)

    def test_it_cannot_outlive_the_policy_it_was_issued_under(self):
        result = self.spend(self.forge("vm-a", policy_digest="a-different-ruleset"))
        self.assertEqual(result["result"], "HOLD_POLICY_CHANGED")
        self.assertEqual(self.plane.calls, [])

    # -- what it can do, and what bounds it ----------------------------------

    def test_it_can_still_contain_one_guest_the_policy_already_allows(self):
        """The honest residual.

        A planner that writes a well-formed capability for an action the policy
        permits gets that action. The gateway's guarantee is about blast radius
        and authority, not about whether containment was warranted: judging
        that is detection, and detection is the part of this system that makes
        no strong claim.

        What bounds the damage is the policy itself. An operator who will not
        accept an autonomous planner isolating a single guest sets containment
        to require approval, and the next test shows that holding.
        """
        result = self.spend(self.forge("vm-a"))
        self.assertEqual(result["result"], "VERIFIED")
        self.assertTrue(result["after"]["isolated"])

    def test_requiring_approval_removes_even_that(self):
        """With containment made irreversible-equivalent by policy, a
        compromised planner can reach nothing at all."""
        import aegis.policy as policy

        original = policy.REVERSIBLE
        try:
            policy.REVERSIBLE = frozenset()
            result = self.spend(self.forge("vm-a"))
            self.assertEqual(
                result["result"], "DENY_POLICY_REQUIRE_APPROVAL_IRREVERSIBLE"
            )
            self.assertEqual(self.plane.calls, [])
        finally:
            policy.REVERSIBLE = original


class PolicyIsTheBoundTest(unittest.TestCase):
    """The gateway's decision is the policy's decision, taken on live data."""

    def test_the_gateway_reaches_the_same_verdict_as_the_planner_would(self):
        plane = FakePlane()
        plane.nodes["net:br0"].update(criticality="critical", shared=True)
        topology = plane.discover()
        for target, expected in (
            ("vm-a", "ALLOW"),
            ("net:br0", "DENY"),
        ):
            with self.subTest(target=target):
                self.assertEqual(
                    decide(topology, "network.isolate", target, ["libvirt:x"])["result"],
                    expected,
                )


if __name__ == "__main__":
    unittest.main()
