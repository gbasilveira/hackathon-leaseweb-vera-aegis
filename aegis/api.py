"""Local web interface for the simulated response governor."""

import asyncio
import ipaddress
import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .agent import investigate
from .core import Core, SCENARIOS
from .governance import Governance

LOG = logging.getLogger(__name__)
API_PREFIX = "/api/v1/"
WEB = Path(__file__).with_name("web")
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/vendor/cytoscape.min.js": ("vendor/cytoscape.min.js", "text/javascript; charset=utf-8"),
    "/vendor/CYTOSCAPE-LICENSE.txt": ("vendor/CYTOSCAPE-LICENSE.txt", "text/plain; charset=utf-8"),
}


class RequestError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def required_string(data, key):
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RequestError(f"{key} must be a nonempty string")
    return value


class Workspace:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.RLock()
        self.catalog = []
        for scenario_id in Core.scenarios():
            file = SCENARIOS / f"{scenario_id}.json"
            scenario = json.loads(file.read_text(encoding="utf-8"))
            self.catalog.append({
                "id": scenario.get("id", file.stem),
                "title": scenario.get("title", scenario.get("name", file.stem)),
                "description": scenario.get("description", ""),
            })
        if not self.catalog:
            raise ValueError("No scenarios found")
        self.core = Core(self.path)
        self.governance = Governance(self.core)
        self.job = None
        existing = self.core.snapshot()["scenario"]
        if existing:
            self.scenario_id = existing["id"]
            self._capture()
        else:
            self._load(self.catalog[0]["id"])

    def _load(self, scenario_id):
        if scenario_id not in {item["id"] for item in self.catalog}:
            raise RequestError("Unknown scenario", 404)
        self.core.load(scenario_id)
        self.scenario_id = scenario_id
        self.job = None
        self._capture()

    def _capture(self):
        manifest = self.governance.manifest()
        for capability in manifest.get("capabilities", []):
            capability.pop("nonce", None)
        snapshot = self.core.snapshot()
        snapshot["events"] = manifest["events"]
        self.current = {"snapshot": snapshot, "manifest": manifest}

    def status(self):
        with self.lock:
            if self.job and self.job["kind"] == "investigate" and self.job["state"] == "running":
                self._capture()
            return {**self.current, "job": dict(self.job) if self.job else None}

    def _start(self, operation, mode=None, alternative=False):
        self.job = {"kind": operation, "state": "running"}
        if mode:
            self.job["mode"] = mode
        threading.Thread(
            target=self._run,
            args=(self.job, self.core, self.governance, mode, alternative),
            daemon=True,
        ).start()

    def _run(self, job, core, governance, mode, alternative):
        try:
            if job["kind"] == "investigate":
                result = asyncio.run(investigate(core, governance, mode, alternative=alternative))
            else:
                result = self._replay(job, core)
            with self.lock:
                if self.job is job and job["state"] == "running":
                    self._capture()
                    job.update(state="complete", result=result)
        except Exception as error:
            LOG.warning("%s job failed (%s)", job["kind"], type(error).__name__)
            with self.lock:
                if self.job is job and job["state"] == "running":
                    self._capture()
                    job.update(state="failed", error=f"The {job['kind']} job failed.")

    def _replay(self, job, core):
        while True:
            with self.lock:
                if self.job is not job or job["state"] != "running":
                    return
                event = core.step()
                self._capture()
                if event is None:
                    return
            time.sleep(0.45)

    def action(self, action, data):
        with self.lock:
            running = self.job and self.job["state"] == "running"
            if action in {"load", "reset"}:
                if running and self.job["kind"] == "investigate":
                    raise RequestError("Wait for the investigation to finish before resetting", 409)
                scenario_id = required_string(data, "scenario_id") if action == "load" else self.scenario_id
                self._load(scenario_id)
                return self.status()
            if action == "pause":
                if not running or self.job["kind"] != "replay":
                    raise RequestError("No replay is running", 409)
                self.job["state"] = "paused"
                return self.status()
            if running:
                raise RequestError("A background job is running", 409)
            result = None
            if action == "step":
                self.core.step()
            elif action == "replay":
                self._start("replay")
            elif action == "change":
                self.core.change()
            elif action == "investigate":
                mode = required_string(data, "mode")
                alternative = data.get("alternative", False)
                if mode not in {"CLAUDE", "DETERMINISTIC_REPLAY"} or type(alternative) is not bool:
                    raise RequestError("Invalid investigation options")
                self._start("investigate", mode, alternative)
            elif action == "evaluate":
                self.governance.evaluate(required_string(data, "proposal_id"))
            elif action == "execute":
                result = self.governance.execute(required_string(data, "capability_id"))
            elif action == "approve":
                accept = data.get("accept")
                if type(accept) is not bool:
                    raise RequestError("accept must be a boolean")
                self.governance.approve(required_string(data, "proposal_id"),
                                        required_string(data, "actor"), accept)
            else:
                raise RequestError("Unknown endpoint", 404)
            if not self.job or self.job["state"] != "running":
                self._capture()
            return {**self.status(), "result": result}


class Handler(BaseHTTPRequestHandler):
    def _check_authority(self):
        hosts = self.headers.get_all("Host", [])
        if len(hosts) != 1 or hosts[0].lower() not in self.server.allowed_hosts:
            raise RequestError("Invalid Host", 403)
        origins = self.headers.get_all("Origin", [])
        if origins and origins != [f"http://{hosts[0].lower()}"]:
            raise RequestError("Invalid Origin", 403)
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            raise RequestError("Cross-site request rejected", 403)

    def _reply(self, body, content_type, status=200, attachment=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if attachment:
            self.send_header("Content-Disposition", f'attachment; filename="{attachment}"')
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; "
                         # This hash allows the fixed Cytoscape container positioning rule.
                         "style-src 'self' 'sha256-pgvDUBa4IjFA2yuSJ2cqcyxmNYJMborsd0ORcRv9vw8='; "
                         "img-src 'self' data:; connect-src 'self'; "
                         "object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, value, status=200):
        self._reply(json.dumps(value, allow_nan=False).encode(), "application/json; charset=utf-8", status)

    def _read_object(self):
        if self.headers.get("Transfer-Encoding"):
            raise RequestError("Unsupported transfer encoding")
        if self.headers.get_content_type() != "application/json":
            raise RequestError("Expected application/json", 415)
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdecimal():
            raise RequestError("Invalid Content-Length")
        if len(lengths[0]) > 5 or int(lengths[0]) > 8192:
            raise RequestError("Request is too large", 413)
        try:
            value = json.loads(self.rfile.read(int(lengths[0])))
        except (ValueError, RecursionError):
            raise RequestError("Malformed JSON") from None
        if not isinstance(value, dict):
            raise RequestError("Expected a JSON object")
        return value

    def _dispatch(self, post=False):
        try:
            self._check_authority()
            path = urlsplit(self.path).path
            # Accept unversioned aliases for local callers.
            if path.startswith("/api/") and not path.startswith(API_PREFIX):
                path = API_PREFIX + path.removeprefix("/api/")
            if not post:
                if path in STATIC:
                    filename, content_type = STATIC[path]
                    self._reply((WEB / filename).read_bytes(), content_type)
                elif path == API_PREFIX + "state":
                    self._json(self.server.workspace.status())
                elif path == API_PREFIX + "scenarios":
                    self._json(self.server.workspace.catalog)
                elif path == API_PREFIX + "manifest":
                    manifest = self.server.workspace.status()["manifest"]
                    payload = json.dumps(manifest, indent=2, allow_nan=False).encode() + b"\n"
                    self._reply(payload, "application/json; charset=utf-8", attachment="incident-manifest.json")
                elif path == API_PREFIX + "health":
                    self._json({"status": "ok"})
                else:
                    raise RequestError("Unknown endpoint", 404)
            elif path.startswith(API_PREFIX):
                action = path.removeprefix(API_PREFIX)
                self._json(self.server.workspace.action(action, self._read_object()))
            else:
                raise RequestError("Unknown endpoint", 404)
        except RequestError as error:
            self._json({"error": str(error)}, error.status)
        except (KeyError, ValueError) as error:
            self._json({"error": str(error)}, 400)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as error:
            LOG.warning("Request failed (%s)", type(error).__name__)
            self._json({"error": "Internal error"}, 500)

    def do_GET(self):
        self._dispatch()

    def do_POST(self):
        self._dispatch(post=True)

    def log_message(self, format, *args):
        pass


def make_server(path, host="127.0.0.1", port=8765):
    if host == "localhost":
        host = "127.0.0.1"
    address = ipaddress.ip_address(host)
    if address.version != 4 or not (address.is_loopback or address.is_unspecified):
        raise ValueError("Use an IPv4 loopback address or 0.0.0.0 for a container")
    workspace = Workspace(path)
    server = ThreadingHTTPServer((host, port), Handler)
    _, actual_port = server.server_address
    names = {"localhost", str(address) if address.is_loopback else "127.0.0.1"}
    server.allowed_hosts = {f"{name}:{actual_port}" for name in names}
    if actual_port == 80:
        server.allowed_hosts.update(names)
    server.workspace = workspace
    return server


def serve(path, host="127.0.0.1", port=8765):
    with make_server(path, host, port) as server:
        address, actual_port = server.server_address
        display_address = "127.0.0.1" if address == "0.0.0.0" else address
        print(f"VERA Aegis demo at http://{display_address}:{actual_port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
