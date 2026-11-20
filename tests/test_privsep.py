"""Each role must detect a privilege it is not allowed to hold, by trying."""

import os
import unittest
from unittest.mock import patch

from aegis.privsep import PrivilegeError, assert_role, inspect, matrix

#: The test driver grants read-write access with no daemon, so it stands in for
#: a hypervisor socket that a process should not have been able to open.
REACHABLE = "test:///default"
UNREACHABLE = "qemu:///no-such-socket-for-tests"


class PrivsepTest(unittest.TestCase):
    def test_planner_holding_a_hypervisor_socket_is_a_violation(self):
        report = inspect("planner", REACHABLE)
        self.assertEqual(report["libvirt_observed"], "read-write")
        self.assertFalse(report["ok"])
        self.assertIn("may hold 'none' libvirt access", report["violations"][0])

    def test_sensor_holding_write_access_is_a_violation(self):
        report = inspect("sensor", REACHABLE)
        self.assertFalse(report["ok"])
        self.assertIn("read-only", report["violations"][0])

    def test_planner_without_a_hypervisor_is_clean(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test"}, clear=False):
            report = inspect("planner", UNREACHABLE)
        self.assertEqual(report["libvirt_observed"], "none")
        self.assertTrue(report["ok"], report["violations"])

    def test_gateway_must_not_see_model_credentials(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-leaked"}, clear=False):
            report = inspect("gateway", REACHABLE)
            self.assertFalse(report["ok"])
            self.assertIn("ANTHROPIC_API_KEY", report["violations"][0])
            with self.assertRaises(PrivilegeError):
                assert_role("gateway", REACHABLE)

    def test_gateway_with_the_right_privileges_starts(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertTrue(assert_role("gateway", REACHABLE)["ok"])

    def test_enforcement_can_be_observed_without_aborting(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-leaked"}, clear=False):
            self.assertFalse(assert_role("gateway", REACHABLE, enforce=False)["ok"])

    def test_matrix_covers_every_role(self):
        self.assertEqual(
            [row["role"] for row in matrix(UNREACHABLE)],
            ["sensor", "planner", "gateway"],
        )


if __name__ == "__main__":
    unittest.main()
