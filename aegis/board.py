"""A console over the live path.

The browser interface that ships with the simulator reads the fixture engine:
its own digest, its own policy, its own state. Showing that during a
demonstration about real infrastructure would put a picture of one system next
to a hypervisor running another, which is worse than showing no picture at all.

This serves the live path instead, and only the live path. It reads the shared
store the three services write and opens libvirt read-only for topology. It has
no write path of any kind: there is no form, no action, no endpoint that
changes anything. An operator who wants to act uses the CLI, which goes through
the gateway.

Bound to loopback. Rendered server-side so the page needs no scripts and no
network of its own.
"""

import html
import json
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .chain import verify_chain

REFRESH = 4

#: Where a node sits, by kind. Guests on top because they are what gets acted
#: on; the infrastructure they share underneath, because that is what denies a
#: broad action.
ROWS = {"domain": 0, "service": 1, "net": 2, "pool": 2, "host": 3}

STYLE = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin: 0; background: #0d1117; color: #c9d1d9;
       font: 14px/1.55 ui-monospace, SFMono-Regular, Menlo, monospace; }
header { padding: 14px 20px; border-bottom: 1px solid #21262d;
         display: flex; gap: 24px; flex-wrap: wrap; align-items: baseline; }
h1 { margin: 0; font-size: 15px; letter-spacing: .08em; text-transform: uppercase; }
h2 { margin: 0 0 10px; font-size: 12px; letter-spacing: .1em;
     text-transform: uppercase; color: #8b949e; font-weight: 600; }
.meta { color: #8b949e; font-size: 12px; }
main { display: grid; gap: 1px; background: #21262d;
       grid-template-columns: repeat(auto-fit, minmax(380px, 1fr)); }
section { background: #0d1117; padding: 16px 20px; min-width: 0; }
section.wide { grid-column: 1 / -1; }
table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
th { text-align: left; color: #8b949e; font-weight: 600; padding: 3px 10px 6px 0;
     border-bottom: 1px solid #21262d; white-space: nowrap; }
td { padding: 3px 10px 3px 0; vertical-align: top; border-bottom: 1px solid #161b22; }
td.wrap { white-space: pre-wrap; word-break: break-word; }
.ok { color: #3fb950; } .bad { color: #f85149; } .warn { color: #d29922; }
.dim { color: #6e7681; }
.pill { display: inline-block; padding: 0 7px; border-radius: 10px; font-size: 11px;
        border: 1px solid currentColor; }
svg { width: 100%; height: auto; display: block; }
.empty { color: #6e7681; font-style: italic; }
code { color: #79c0ff; }
"""


def _now():
    return datetime.now(timezone.utc).strftime("%H:%M:%S UTC")


def _esc(value):
    return html.escape("" if value is None else str(value))


def _verdict_class(text):
    text = str(text or "")
    if text.startswith(("DENY", "FAILED")):
        return "bad"
    if text.startswith(("HOLD", "REQUIRE", "INDETERMINATE")):
        return "warn"
    if text in ("ALLOW", "VERIFIED", "ISSUED", "observed"):
        return "ok"
    return "dim"


def _graph(topology):
    """The measured topology, laid out by kind.

    Contained guests are marked, and so is every node the system computed to
    be shared and therefore critical, because that computation is what denies
    the broad action.
    """
    nodes = topology.get("nodes", {})
    if not nodes:
        return '<p class="empty">No topology published yet.</p>'
    lanes = {}
    for node in sorted(nodes.values(), key=lambda item: str(item.get("id"))):
        lanes.setdefault(ROWS.get(node.get("kind"), 1), []).append(node)
    width, gap_y, pad = 1000, 108, 46
    height = pad * 2 + gap_y * max(1, len(lanes) - 1)
    placed, parts = {}, []
    for row, members in sorted(lanes.items()):
        step = width / (len(members) + 1)
        for index, node in enumerate(members, start=1):
            placed[node["id"]] = (step * index, pad + gap_y * sorted(lanes).index(row))
    for edge in topology.get("edges", []):
        if edge["source"] not in placed or edge["target"] not in placed:
            continue
        x1, y1 = placed[edge["source"]]
        x2, y2 = placed[edge["target"]]
        catalogue = edge.get("source_of_truth") == "catalogue"
        parts.append(
            f'<line x1="{x1:.0f}" y1="{y1 + 16:.0f}" x2="{x2:.0f}" y2="{y2 - 20:.0f}" '
            f'stroke="{"#d29922" if catalogue else "#30363d"}" stroke-width="1.2"'
            + (' stroke-dasharray="4 3"' if catalogue else "")
            + "/>"
        )
    for node_id, (x, y) in placed.items():
        node = nodes[node_id]
        contained = node.get("link") == "down"
        shared = bool(node.get("shared"))
        fill = "#161b22"
        stroke = "#f85149" if contained else "#d29922" if shared else "#30363d"
        label = node_id if len(str(node_id)) <= 26 else str(node_id)[:24] + "…"
        tenants = node.get("observed_tenants")
        detail = (
            f"{len(tenants)} tenants" if tenants and len(tenants) > 1
            else _esc(node.get("tenant_id") or "")
        )
        parts.append(
            f'<g><rect x="{x - 96:.0f}" y="{y - 20:.0f}" width="192" height="40" rx="6" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="{2 if contained or shared else 1}"/>'
            f'<text x="{x:.0f}" y="{y - 3:.0f}" fill="#c9d1d9" font-size="12" '
            f'font-family="monospace" text-anchor="middle">{_esc(label)}</text>'
            f'<text x="{x:.0f}" y="{y + 12:.0f}" fill="{"#f85149" if contained else "#6e7681"}" '
            f'font-size="10" font-family="monospace" text-anchor="middle">'
            f'{"CONTAINED" if contained else _esc(detail)}</text></g>'
        )
    legend = (
        '<text x="8" y="16" fill="#6e7681" font-size="10" font-family="monospace">'
        "orange border: measured shared and critical · "
        "red: contained · dashed: declared in the service catalogue</text>"
    )
    return (
        f'<svg viewBox="0 0 {width} {height + 24}" '
        f'xmlns="http://www.w3.org/2000/svg">{legend}{"".join(parts)}</svg>'
    )


def _table(headers, rows, empty="Nothing yet."):
    if not rows:
        return f'<p class="empty">{_esc(empty)}</p>'
    head = "".join(f"<th>{_esc(name)}</th>" for name in headers)
    body = "".join(
        "<tr>" + "".join(f"<td{cell[1]}>{cell[0]}</td>" for cell in row) + "</tr>"
        for row in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _cell(value, cls=""):
    return (_esc(value), f' class="{cls}"' if cls else "")


def render(topology, state):
    entries = state.get("entries", [])
    capabilities = state.get("capabilities", {})
    chain = verify_chain(entries)
    nodes = topology.get("nodes", {})
    contained = [n["id"] for n in nodes.values() if n.get("link") == "down"]
    shared = [n["id"] for n in nodes.values() if n.get("shared")]

    governance = [
        row
        for row in entries
        if row.get("event_type")
        in ("governance.decision", "capability.issued", "gateway.refused",
            "outcome.verified", "defense.failed")
    ][-14:][::-1]
    observations = [
        row for row in entries if row.get("event_type") == "hypervisor.observed"
    ][-12:][::-1]
    excluded = [row for row in entries if row.get("event_type") == "guest.reported"]

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="refresh" content="{REFRESH}">
<title>VERA Aegis · live</title><style>{STYLE}</style></head><body>
<header>
  <h1>VERA Aegis</h1>
  <span class="meta">{_esc(topology.get('host') or 'no host')}</span>
  <span class="meta">{len(nodes)} nodes · {len(topology.get('edges', []))} edges</span>
  <span class="meta">chain <span class="{'ok' if chain['ok'] else 'bad'}">
    {'verified' if chain['ok'] else 'BROKEN at ' + str(chain['broken_at'])}</span>
    · {chain['length']} sealed · head <code>{_esc(chain['head'][:16])}…</code></span>
  <span class="meta">{_esc(_now())} · refreshes every {REFRESH}s</span>
</header>
<main>
<section class="wide"><h2>Measured topology</h2>{_graph(topology)}
  <p class="meta">{len(shared)} node(s) computed shared and critical from observed tenant
  counts{': ' + _esc(', '.join(sorted(shared))) if shared else ''}.
  {('<span class="bad">' + _esc(', '.join(sorted(contained))) + ' contained.</span>') if contained else 'Nothing contained.'}</p>
</section>

<section><h2>Governance</h2>{_table(
    ["event", "outcome", "target", "detail"],
    [[
        _cell(row.get("event_type", "").replace("governance.", "").replace("outcome.", "")),
        _cell(row.get("outcome") or row.get("result"), _verdict_class(row.get("outcome"))),
        _cell(row.get("target_id")),
        _cell(
            row.get("reason")
            or "; ".join(row.get("reasons", []))
            or (("blast " + ", ".join(row.get("blast_tenants", [])))
                if row.get("blast_tenants") else "")
            or ("scope " + ", ".join(row.get("scope", [])) if row.get("scope") else ""),
            "wrap dim",
        ),
    ] for row in governance],
    "No decision yet. Run the walkthrough or wait for the planner.",
)}</section>

<section><h2>Capabilities</h2>{_table(
    ["handle", "action", "target", "status"],
    [[
        _cell(str(key)[:14]),
        _cell(row.get("action_type")),
        _cell(row.get("target_id")),
        _cell(row.get("status"),
              "ok" if row.get("status") == "consumed"
              else "warn" if row.get("status") == "issued" else "bad"),
    ] for key, row in sorted(capabilities.items())][-12:][::-1],
    "No handle issued.",
)}</section>

<section><h2>Hypervisor observations</h2>{_table(
    ["target", "state", "links", "snapshots"],
    [[
        _cell(row.get("target_id")),
        _cell(row.get("state")),
        _cell(", ".join(f"{k}={v}" for k, v in (row.get("links") or {}).items()),
              "bad" if "down" in str(row.get("links")) else ""),
        _cell(row.get("snapshots")),
    ] for row in observations],
    "The sensor has sealed nothing yet.",
)}
  <p class="meta">{len(excluded)} guest report(s) journalled and
  <span class="warn">excluded from decision facts</span>: guest-supplied content
  is attacker-controlled and may never carry authority.</p>
</section>

<section class="wide"><h2>Sealed journal, most recent last</h2>{_table(
    ["#", "event", "outcome", "target"],
    [[
        _cell(row.get("sequence"), "dim"),
        _cell(row.get("event_type")),
        _cell(row.get("outcome"), _verdict_class(row.get("outcome"))),
        _cell(row.get("target_id")),
    ] for row in entries[-16:]],
    "Empty journal.",
)}
  <p class="meta">Read-only view of the live path. Every action goes through the
  gateway, which re-runs the policy against live libvirt before spending any
  handle.</p>
</section>
</main></body></html>"""


def serve(store_path, uri, host="127.0.0.1", port=8780, read_only=True):
    from .libvirt_plane import LibvirtControlPlane
    from .gateway import FileStore

    store = FileStore(store_path)

    def topology():
        published = store.topology()
        if published:
            return published
        try:
            return LibvirtControlPlane(uri, read_only=read_only).discover()
        except Exception:  # noqa: BLE001
            return {"nodes": {}, "edges": [], "host": None}

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def _send(self, body, kind="text/html; charset=utf-8", status=200):
            payload = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path == "/state.json":
                data = store._read()
                return self._send(
                    json.dumps({"topology": topology(), **data}, default=str, indent=2),
                    "application/json",
                )
            if path not in ("/", "/index.html"):
                return self._send("not found", "text/plain; charset=utf-8", 404)
            self._send(render(topology(), store._read()))

        def do_POST(self):
            # There is no write path. Acting goes through the gateway.
            self._send("read-only", "text/plain; charset=utf-8", 405)

    class Server(ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    return Server((host, port), Handler)
