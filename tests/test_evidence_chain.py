"""Evidence may still be rewritten by whoever owns the database, but not
silently: every downstream link must break."""

import unittest

from aegis.chain import GENESIS, head, seal, verify_chain

ENTRIES = [
    {"id": "e1", "event_type": "alert_observed", "target_id": "vm-a"},
    {"id": "e2", "event_type": "governance.decision", "outcome": "ALLOW"},
    {"id": "e3", "event_type": "defense.executed", "target_id": "vm-a"},
    {"id": "e4", "event_type": "outcome.verified", "outcome": "VERIFIED"},
]


class ChainTest(unittest.TestCase):
    def setUp(self):
        self.chain = seal(ENTRIES)

    def test_sealed_chain_verifies(self):
        report = verify_chain(self.chain)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["length"], 4)
        self.assertEqual(report["head"], head(self.chain))
        self.assertEqual(self.chain[0]["prev_hash"], GENESIS)

    def test_sealing_is_deterministic(self):
        self.assertEqual(self.chain, seal(ENTRIES))

    def test_edited_entry_breaks_at_that_index(self):
        tampered = [dict(entry) for entry in self.chain]
        tampered[1]["outcome"] = "DENY"
        report = verify_chain(tampered)
        self.assertFalse(report["ok"])
        self.assertEqual((report["broken_at"], report["entry_id"]), (1, "e2"))

    def test_removed_entry_breaks_the_chain(self):
        report = verify_chain(self.chain[:1] + self.chain[2:])
        self.assertFalse(report["ok"])
        self.assertEqual(report["broken_at"], 1)

    def test_reordered_entries_break_the_chain(self):
        shuffled = [self.chain[0], self.chain[2], self.chain[1], self.chain[3]]
        self.assertFalse(verify_chain(shuffled)["ok"])

    def test_append_extends_without_rewriting(self):
        extended = self.chain + seal(
            [{"id": "e5", "event_type": "gateway.refused"}], head(self.chain)
        )
        report = verify_chain(extended)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["length"], 5)
        self.assertEqual(extended[:4], self.chain)


if __name__ == "__main__":
    unittest.main()
