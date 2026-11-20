"""The gateway must spend a capability exactly once, revalidate against the
plane rather than stored state, and never assume an actuator succeeded."""

import os
import unittest
from unittest.mock import patch

from aegis.chain import verify_chain
from aegis.controlplane import PlaneError
from aegis.gateway import Gateway, MemoryStore
from aegis.privsep import PrivilegeError
from aegis.scope import scoped_digest

NODES = {
    "vm-a": {"id": "vm-a", "kind": "domain", "tenant_id": "tenant-b", "state": "running"},
    "vm-c": {"id": "vm-c", "kind": "domain", "tenant_id": "tenant-c", "state": "running"},
    "net:br0": {"id": "net:br0", "kind": "net", "tenant_id": "infrastructure", "shared": True},
    "service-b": {"id": "service-b", "kind": "service", "tenant_id": "tenant-c"},
}
EDGES = [
    {"source": "vm-a", "target": "net:br0", "relation": "attached_to"},
    {"source": "vm-c", "target": "net:br0", "relation": "attached_to"},
]


class FakePlane:
    """Stands in for libvirt so the gateway's logic is tested without a host."""

    uri = "qemu:///fake"
    read_only = False

    def __init__(self):
        self.nodes = {key: dict(value) for key, value in NODES.items()}
        self.edges = [dict(edge) for edge in EDGES]
        self.states = {
            "vm-a": {"id": "vm-a", "state": "running", "isolated": False, "snapshots": 0}
        }
        self.failure = None
        self.hide_after_actuation = False
        self.calls = []

    def discover(self):
        return {"nodes": self.nodes, "edges": self.edges}

    def read_state(self, target):
        if self.hide_after_actuation and self.calls:
            return {}
        return dict(self.states.get(target, {}))

    def actuate(self, action, target, parameters=None):
        self.calls.append((action, target))
        if self.failure:
            raise PlaneError(self.failure)
        state = self.states[target]
        if action == "network.isolate":
            state["isolated"] = True
        elif action == "vm.suspend":
            state["state"] = "paused"
        elif action == "vm.snapshot":
            state["snapshots"] += 1
        return {"ok": True, "action": action}


class GatewayTest(unittest.TestCase):
    def setUp(self):
        self.plane = FakePlane()
        self.store = MemoryStore()
        self.now = 1000.0
        self.gateway = Gateway(
            self.plane, self.store, clock=lambda: self.now, enforce_privsep=False
        )

    def mint(self, action="network.isolate", target="vm-a", ttl=300):
        digest, observed = scoped_digest(self.plane.nodes, self.plane.edges, target)
        return self.store.put(
            {
                "id": "cap-1",
                "nonce": "nonce-1",
                "action_type": action,
                "target_id": target,
                "status": "issued",
                "expires_at": self.now + ttl,
                "context_digest": digest,
                "context": observed,
            }
        )

    def test_authorised_capability_executes_and_is_verified(self):
        self.mint()
        result = self.gateway.consume("cap-1", "nonce-1")
        self.assertEqual(result["result"], "VERIFIED")
        self.assertTrue(result["after"]["isolated"])
        self.assertEqual(self.store.get("cap-1")["status"], "consumed")
        self.assertEqual(self.plane.calls, [("network.isolate", "vm-a")])

    def test_capability_cannot_be_spent_twice(self):
        self.mint()
        self.gateway.consume("cap-1", "nonce-1")
        again = self.gateway.consume("cap-1", "nonce-1")
        self.assertEqual(again["result"], "DENY_CONSUMED")
        self.assertEqual(len(self.plane.calls), 1)

    def test_wrong_nonce_is_refused_and_burns_the_handle(self):
        self.mint()
        self.assertEqual(
            self.gateway.consume("cap-1", "guessed")["result"], "DENY_BAD_NONCE"
        )
        self.assertEqual(self.plane.calls, [])
        self.assertEqual(self.gateway.consume("cap-1", "nonce-1")["result"], "DENY_REVOKED")

    def test_expired_capability_is_refused(self):
        self.mint(ttl=10)
        self.now += 11
        self.assertEqual(
            self.gateway.consume("cap-1", "nonce-1")["result"], "DENY_EXPIRED"
        )
        self.assertEqual(self.plane.calls, [])

    def test_unknown_capability_is_refused(self):
        self.assertEqual(
            self.gateway.consume("nope", "nonce-1")["result"], "DENY_UNKNOWN_CAPABILITY"
        )

    def test_unrelated_world_change_does_not_cost_authority(self):
        """A guest elsewhere changing state, and a new guest joining the shared
        bridge, must both leave a pending grant executable."""
        self.mint()
        self.plane.nodes["vm-c"]["state"] = "paused"
        self.plane.nodes["vm-new"] = {"id": "vm-new", "kind": "domain", "tenant_id": "tenant-c"}
        self.plane.edges.append(
            {"source": "vm-new", "target": "net:br0", "relation": "attached_to"}
        )
        self.assertEqual(self.gateway.consume("cap-1", "nonce-1")["result"], "VERIFIED")

    def test_new_dependant_revokes_authority_and_names_the_node(self):
        """The demonstration's central claim: authority lapses the moment the
        blast radius moves, and the refusal explains why."""
        self.mint()
        self.plane.edges.append(
            {"source": "service-b", "target": "vm-a", "relation": "depends_on"}
        )
        result = self.gateway.consume("cap-1", "nonce-1")
        self.assertEqual(result["result"], "HOLD_CONTEXT_CHANGED")
        self.assertEqual(self.plane.calls, [])
        self.assertIn("service-b (tenant-c) now depends on vm-a", result["reasons"])
        self.assertTrue(any("blast radius" in reason for reason in result["reasons"]))

    def test_actuator_failure_is_indeterminate_and_spends_the_handle(self):
        """A hypervisor call cannot be rolled back, so a failure must never
        leave a handle that can fire the same action again."""
        self.mint()
        self.plane.failure = "libvirt: device update failed"
        result = self.gateway.consume("cap-1", "nonce-1")
        self.assertEqual(result["result"], "INDETERMINATE")
        self.assertEqual(self.store.get("cap-1")["status"], "consumed")
        self.assertEqual(
            self.gateway.consume("cap-1", "nonce-1")["result"], "DENY_CONSUMED"
        )
        self.assertEqual(len(self.plane.calls), 1)

    def test_unreadable_target_after_action_is_indeterminate_not_failed(self):
        """We acted but cannot re-read the target, so the honest answer is that
        we do not know whether containment took effect."""
        self.mint(action="vm.suspend")
        self.plane.hide_after_actuation = True
        result = self.gateway.consume("cap-1", "nonce-1")
        self.assertEqual(result["result"], "INDETERMINATE")
        self.assertEqual(self.plane.calls, [("vm.suspend", "vm-a")])

    def test_every_gateway_decision_is_sealed_in_order(self):
        self.mint()
        self.gateway.consume("cap-1", "nonce-1")
        self.gateway.consume("cap-1", "nonce-1")
        report = verify_chain(self.store.entries)
        self.assertTrue(report["ok"], report)
        self.assertEqual(
            [entry["event_type"] for entry in self.store.entries],
            ["outcome.verified", "gateway.refused"],
        )

    def test_gateway_refuses_to_start_with_model_credentials(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-leaked"}, clear=False):
            with self.assertRaises(PrivilegeError):
                Gateway(self.plane, MemoryStore())


if __name__ == "__main__":
    unittest.main()
