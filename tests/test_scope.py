"""The scoped digest must be precise in both directions: it may not thrash on
unrelated change, and it must revoke on change that moves the blast radius."""

import unittest

from aegis.scope import dependents, explain, scope_of, scoped_digest

NODES = {
    "vm-a": {"id": "vm-a", "kind": "domain", "tenant_id": "tenant-b", "state": "running"},
    "vm-c": {"id": "vm-c", "kind": "domain", "tenant_id": "tenant-c", "state": "running"},
    "host-a": {"id": "host-a", "kind": "host", "tenant_id": "tenant-a",
               "criticality": "critical", "shared": True, "state": "running"},
    "bridge-0": {"id": "bridge-0", "kind": "network", "tenant_id": "tenant-a", "shared": True},
    "service-b": {"id": "service-b", "kind": "service", "tenant_id": "tenant-c",
                  "criticality": "critical", "state": "running"},
}
EDGES = [
    {"source": "vm-a", "target": "host-a", "relation": "runs_on"},
    {"source": "vm-a", "target": "bridge-0", "relation": "attached_to"},
    {"source": "vm-c", "target": "bridge-0", "relation": "attached_to"},
    {"source": "service-b", "target": "host-a", "relation": "depends_on"},
]


class ScopeTest(unittest.TestCase):
    def digest(self, nodes=None, edges=None, target="vm-a"):
        return scoped_digest(nodes or NODES, edges or EDGES, target)

    def test_closure_is_reverse_reachability(self):
        self.assertEqual(scope_of(NODES, EDGES, "vm-a"), {"vm-a"})
        self.assertEqual(
            scope_of(NODES, EDGES, "host-a"), {"host-a", "vm-a", "service-b"}
        )
        self.assertEqual(dependents(EDGES, ["bridge-0"]), {"bridge-0", "vm-a", "vm-c"})

    def test_unrelated_domain_change_preserves_authority(self):
        """A guest starting or stopping elsewhere must not revoke a grant."""
        before, _ = self.digest()
        moved = dict(NODES, **{"vm-c": dict(NODES["vm-c"], state="stopped")})
        after, _ = self.digest(nodes=moved)
        self.assertEqual(before, after)

    def test_new_peer_on_shared_bridge_preserves_authority(self):
        """A new guest attaching to the same bridge does not change who isolating
        vm-a harms, so the pending grant survives. This is the property the
        original global digest lacked."""
        before, _ = self.digest()
        grown = dict(
            NODES, **{"vm-new": {"id": "vm-new", "kind": "domain", "tenant_id": "tenant-c"}}
        )
        after, _ = self.digest(
            nodes=grown,
            edges=EDGES + [{"source": "vm-new", "target": "bridge-0", "relation": "attached_to"}],
        )
        self.assertEqual(before, after)

    def test_new_dependant_revokes_and_is_named(self):
        """A service in another tenant starting to depend on the target grows the
        blast radius, so authority must lapse and the reason must name the node."""
        before, observed_before = self.digest()
        after, observed_after = self.digest(
            edges=EDGES + [{"source": "service-b", "target": "vm-a", "relation": "depends_on"}]
        )
        self.assertNotEqual(before, after)
        self.assertEqual(observed_after["members"], ["service-b", "vm-a"])
        reasons = explain(observed_before, observed_after)
        self.assertIn("service-b (tenant-c) now depends on vm-a", reasons)
        self.assertTrue(any("blast radius moved from 1 to 2" in r for r in reasons))

    def test_migration_revokes_because_wiring_changed(self):
        """The host's own load is not authority relevant, but losing the
        attachment to that host is."""
        before, _ = self.digest()
        state_only = dict(NODES, **{"host-a": dict(NODES["host-a"], state="degraded")})
        self.assertEqual(before, self.digest(nodes=state_only)[0])
        migrated = [
            dict(edge, target="host-b") if edge == EDGES[0] else edge for edge in EDGES
        ]
        self.assertNotEqual(before, self.digest(edges=migrated)[0])

    def test_target_state_change_revokes(self):
        """Someone else acting on the target first must invalidate the grant."""
        before, _ = self.digest()
        acted = dict(NODES, **{"vm-a": dict(NODES["vm-a"], state="paused")})
        self.assertNotEqual(before, self.digest(nodes=acted)[0])


if __name__ == "__main__":
    unittest.main()
