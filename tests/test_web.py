"""Exercise the web interface with real local HTTP requests."""

import http.client
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis.api import Workspace, make_server


class WebTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "simulation.db"
        self.server = make_server(self.path, port=0)
        thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(thread.join, 2)
        self.addCleanup(self.server.shutdown)
        self.port = self.server.server_address[1]

    def request(self, path, method="GET", body=None, **headers):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            if body is not None and not isinstance(body, str):
                body = json.dumps(body)
                headers.setdefault("Content-Type", "application/json")
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read()
            if response.getheader("Content-Type", "").startswith("application/json"):
                raw = json.loads(raw)
            return response.status, raw, dict(response.getheaders())
        finally:
            connection.close()

    def action(self, name, data=None):
        status, body, _ = self.request("/api/v1/" + name, "POST", body=data or {})
        self.assertEqual(status, 200, body)
        return body

    def wait_for_job(self):
        for _ in range(160):
            status, body, _ = self.request("/api/v1/state")
            self.assertEqual(status, 200)
            if body["job"]["state"] != "running":
                return body
            time.sleep(0.025)
        self.fail("Job did not finish")

    def test_static_and_same_origin_policy(self):
        status, root, headers = self.request("/")
        self.assertEqual(status, 200)
        self.assertIn(b'Dependency graph', root)
        self.assertIn(b'/vendor/cytoscape.min.js', root)
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertEqual(self.request("/api/v1/health")[1], {"status": "ok"})
        self.assertEqual(self.request("/vendor/cytoscape.min.js")[0], 200)
        self.assertEqual(self.request("/vendor/CYTOSCAPE-LICENSE.txt")[0], 200)
        self.assertEqual(self.request("/%2e%2e/core.py")[0], 404)
        self.assertEqual(self.request("/api/v1/state", Host="evil.test")[0], 403)
        self.assertEqual(self.request("/api/v1/step", "POST", {}, Origin="https://evil.test")[0], 403)
        self.assertEqual(self.request("/api/v1/step", "POST", {}, Origin="null")[0], 403)
        self.assertEqual(self.request("/api/v1/step", "POST", {}, **{"Sec-Fetch-Site": "cross-site"})[0], 403)
        self.assertEqual(self.request("/api/v1/step", "POST", "{}", **{"Content-Type": "text/plain"})[0], 415)
        self.assertEqual(self.request("/api/v1/step", "POST", "[]", **{"Content-Type": "application/json"})[0], 400)
        self.assertEqual(self.request("/api/v1/step", "POST", {}, Origin=f"http://127.0.0.1:{self.port}")[0], 200)

    def test_replay_and_proposal(self):
        _, catalog, _ = self.request("/api/v1/scenarios")
        self.assertGreaterEqual(len(catalog), 2)
        initial = self.action("load", {"scenario_id": "control-plane-compromise"})
        self.assertEqual(initial["snapshot"]["cursor"], 0)
        started = self.action("replay")
        self.assertEqual(started["job"]["state"], "running")
        result = self.wait_for_job()
        snapshot = result["snapshot"]
        self.assertEqual(result["job"]["state"], "complete")
        self.assertEqual(snapshot["cursor"], len(snapshot["scenario"]["events"]))
        self.action("investigate", {"mode": "DETERMINISTIC_REPLAY"})
        investigated = self.wait_for_job()
        self.assertEqual(investigated["job"]["state"], "complete")
        proposal_id = investigated["job"]["result"]["proposal_ids"][0]
        self.assertEqual(investigated["manifest"]["decisions"], [])
        evaluated = self.action("evaluate", {"proposal_id": proposal_id})
        self.assertEqual(evaluated["manifest"]["decisions"][-1]["proposal_id"], proposal_id)
        self.assertEqual(evaluated["manifest"]["decisions"][-1]["result"], "DENY")
        restored = Workspace(self.path).status()
        self.assertEqual(restored["manifest"]["decisions"], evaluated["manifest"]["decisions"])
        _, exported, headers = self.request("/api/v1/manifest")
        self.assertEqual(exported, evaluated["manifest"])
        self.assertIn("incident-manifest.json", headers["Content-Disposition"])
        reset = self.action("reset")
        self.assertNotEqual(initial["snapshot"]["incident_id"], reset["snapshot"]["incident_id"])
        self.assertEqual(reset["manifest"]["proposals"], [])

    def test_replay_can_pause_and_step(self):
        self.action("replay")
        paused = self.action("pause")
        time.sleep(0.5)
        _, current, _ = self.request("/api/v1/state")
        self.assertEqual(current, paused)
        stepped = self.action("step")
        self.assertEqual(stepped["snapshot"]["cursor"], paused["snapshot"]["cursor"] + 1)

    def test_reset_cancels_replay(self):
        self.action("replay")
        reset = self.action("reset")
        time.sleep(0.5)
        _, current, _ = self.request("/api/v1/state")
        self.assertEqual(current, reset)

    def test_investigation_excludes_mutations_and_allows_polling(self):
        gate = threading.Event()
        self.addCleanup(gate.set)

        async def blocked(*args, **kwargs):
            gate.wait(timeout=5)
            return {"proposal_ids": []}

        with patch("aegis.api.investigate", blocked):
            started = self.action("investigate", {"mode": "CLAUDE"})
            self.assertEqual(started["job"]["state"], "running")
            for action in ("reset", "step", "change"):
                self.assertEqual(self.request(f"/api/v1/{action}", "POST", {})[0], 409)
            self.assertEqual(self.request("/api/v1/state")[1]["job"]["state"], "running")
            gate.set()
            self.assertEqual(self.wait_for_job()["job"]["state"], "complete")
