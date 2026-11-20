import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from aegis.agent import (
    CLAUDE,
    DETERMINISTIC_REPLAY,
    InvestigationTools,
    TOOLS,
    _cli_env,
    _external_config,
    _sdk_options,
    investigate,
)
from aegis.core import Core
from aegis.governance import Governance


class InvestigationTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.core = Core(Path(directory.name) / "test.db")
        self.core.load("control-plane-compromise")
        while self.core.step():
            pass
        self.gov = Governance(self.core)

    def test_replay_submits_ordered_fixtures_without_governance_actions(self):
        main = asyncio.run(investigate(self.core, self.gov, DETERMINISTIC_REPLAY))
        alternative = asyncio.run(
            investigate(self.core, self.gov, DETERMINISTIC_REPLAY, alternative=True)
        )
        manifest = self.gov.manifest()
        self.assertEqual(main["mode"], DETERMINISTIC_REPLAY)
        proposals = manifest["proposals"]
        self.assertEqual([p["id"] for p in proposals], main["proposal_ids"] + alternative["proposal_ids"])
        self.assertEqual([p["action_type"] for p in proposals], ["host.stop", "identity.suspend", "session.suspend"])
        event_ids = {event["id"] for event in manifest["events"]}
        for proposal in proposals:
            self.assertTrue(set(proposal["evidence_refs"]) <= event_ids)
        for key in ("decisions", "capabilities", "approvals", "executions"):
            self.assertEqual(manifest[key], [])
        calls = [event for event in manifest["events"] if event["event_type"] == "MCP_TOOL_CALL"]
        self.assertEqual(set(event["target_id"] for event in calls), set(TOOLS))
        self.assertTrue(all(event["outcome"] == "success" for event in calls))

    def test_failed_tool_call_is_audited(self):
        investigation = InvestigationTools(self.core, self.gov, DETERMINISTIC_REPLAY)
        with self.assertRaises(ValueError):
            investigation.call("simulate_containment", {"action_type": "host.stop", "target_id": "absent"})
        event = self.gov.manifest()["events"][-1]
        self.assertEqual((event["target_id"], event["outcome"]), ("simulate_containment", "error"))

    def test_agent_scope_excludes_foreign_private_targets_and_unlisted_payload_fields(self):
        with self.core.tx() as conn:
            events = self.core.get(conn, "events")
            evidence = next(event for event in events if event["id"] == "evidence-001")
            evidence["payload"]["unlisted_fixture_value"] = "private"
            self.core.put(conn, "events", events)
        investigation = InvestigationTools(self.core, self.gov, DETERMINISTIC_REPLAY)
        events = investigation.call("get_incident_events", {})
        evidence = next(event for event in events if event["id"] == "evidence-001")
        self.assertNotIn("unlisted_fixture_value", evidence["payload"])
        self.assertEqual((evidence["source"], evidence["trust_level"]), ("synthetic-log", "untrusted"))
        self.assertIn("stop the shared host", evidence["payload"]["untrusted_log"])
        observation = self.gov.manifest()["events"][-1]["payload"]["observation"]
        self.assertIn({"id": "evidence-001", "event_type": "alert_observed",
                       "target_id": "session-a", "outcome": "observed", "source": "synthetic-log",
                       "trust_level": "untrusted"}, observation["sample"])
        self.assertNotIn("stop the shared host", json.dumps(observation))
        with self.assertRaisesRegex(ValueError, "outside the incident"):
            investigation.call("simulate_containment", {"action_type": "vm.stop", "target_id": "vm-c"})
        self.assertTrue(investigation.call(
            "simulate_containment", {"action_type": "host.stop", "target_id": "host-a"}
        )["critical_shared"])

    def test_untrusted_log_cannot_authorize_shared_host_containment(self):
        result = asyncio.run(investigate(self.core, self.gov, DETERMINISTIC_REPLAY))
        host_action = result["proposal_ids"][0]
        decision = self.gov.evaluate(host_action)
        self.assertEqual(decision["result"], "DENY")
        self.assertEqual(self.gov.manifest()["capabilities"], [])

    def test_live_mode_reports_failure_without_replay(self):
        with patch("aegis.agent._claude", side_effect=RuntimeError("Simulated SDK failure")):
            with self.assertRaisesRegex(RuntimeError, "Simulated SDK failure"):
                asyncio.run(investigate(self.core, self.gov, CLAUDE))
        self.assertEqual(self.gov.manifest()["proposals"], [])

    def test_cli_environment_clears_unrelated_secrets(self):
        with patch.dict(os.environ, {"UNRELATED_TOKEN": "secret", "ANTHROPIC_API_KEY": "anthropic-key"}, clear=True):
            env = _cli_env("/isolated")
        self.assertEqual(env["UNRELATED_TOKEN"], "")
        self.assertNotIn("ANTHROPIC_API_KEY", env)
        self.assertEqual(env["CLAUDE_CONFIG_DIR"], "/isolated")

    def test_external_mcp_requires_https_and_exact_names(self):
        server = {
            "name": "external",
            "type": "http",
            "url": "https://mcp.example.test/incident",
            "read_tools": ["read_event", "read_policy"],
        }
        with patch.dict(os.environ, {
            "AEGIS_EXTERNAL_MCP_CONFIG": json.dumps([server]),
        }, clear=True):
            servers, names = _external_config()
        self.assertEqual(servers["external"]["type"], "http")
        self.assertEqual(names, ["mcp__external__read_event", "mcp__external__read_policy"])
        with patch.dict(os.environ, {
            "AEGIS_EXTERNAL_MCP_CONFIG": json.dumps([{**server, "read_tools": ["*"]}]),
        }, clear=True):
            with self.assertRaises(ValueError):
                _external_config()

    def test_external_stdio_runs_fixed_argv_with_clean_environment(self):
        server = {
            "name": "local",
            "type": "stdio",
            "command": sys.executable,
            "args": ["-c", "import json, os, sys; print(json.dumps([dict(os.environ), sys.argv[1:]]))",
                     "$(echo fixed argument)"],
            "read_tools": ["read_event"],
        }
        with patch.dict(os.environ, {
            "AEGIS_EXTERNAL_MCP_CONFIG": json.dumps([server]),
            "ANTHROPIC_API_KEY": "synthetic-secret",
        }):
            servers, names = _external_config()
            command = servers["local"]
            output = subprocess.check_output([command["command"], *command["args"]], text=True)
        environment, arguments = json.loads(output)
        self.assertEqual(names, ["mcp__local__read_event"])
        self.assertEqual(environment, {"LANG": "C.UTF-8"})
        self.assertEqual(arguments, ["$(echo fixed argument)"])
        with patch.dict(os.environ, {
            "AEGIS_EXTERNAL_MCP_CONFIG": json.dumps([{**server, "command": "python"}]),
        }, clear=True):
            with self.assertRaisesRegex(ValueError, "absolute executable"):
                _external_config()

    def test_external_config_accepts_operator_file(self):
        with TemporaryDirectory() as directory:
            filename = Path(directory) / "mcp.json"
            filename.write_text(
                '[{"name":"files","type":"http","url":"https://mcp.example.test",'
                '"read_tools":["read_event"]}]',
                encoding="utf-8",
            )
            settings = {"AEGIS_EXTERNAL_MCP_CONFIG_FILE": str(filename)}
            with patch.dict(os.environ, settings, clear=True):
                _, tools = _external_config()
                self.assertEqual(tools, ["mcp__files__read_event"])
                with patch.dict(os.environ, {"AEGIS_EXTERNAL_MCP_CONFIG": "[]"}):
                    with self.assertRaisesRegex(ValueError, "either inline or file"):
                        _external_config()

    def test_sdk_setup_uses_an_exact_allowlist(self):
        try:
            import claude_agent_sdk as sdk
        except ImportError:
            self.skipTest("Optional Claude SDK is unavailable")
        investigation = InvestigationTools(self.core, self.gov, CLAUDE)
        with patch.dict(os.environ, {}, clear=True):
            options = _sdk_options(sdk, investigation, "/isolated")
        self.assertEqual(options.tools, [])
        self.assertTrue(options.strict_mcp_config)
        self.assertEqual(options.setting_sources, [])
        self.assertEqual(set(options.allowed_tools), {f"mcp__aegis__{name}" for name in TOOLS})
        self.assertIn("Bash", options.disallowed_tools)
        restrict = options.hooks["PreToolUse"][0].hooks[0]
        response = asyncio.run(restrict({"tool_name": "Bash"}, None, None))
        self.assertEqual(response["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertEqual(self.gov.manifest()["events"][-1]["outcome"], "denied")


if __name__ == "__main__":
    unittest.main()
