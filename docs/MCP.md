# Incident investigation with Claude and MCP

AEGIS runs against synthetic incidents. `DETERMINISTIC_REPLAY` is the offline
mode. It evaluates the same investigation tool paths and submits the scenario's
ordered proposal fixtures for the selected phase. Populate the incident with
**Replay timeline** or **Step** before investigating so the proposal can cite
recorded evidence.

To enable `CLAUDE`, install the optional dependencies into the environment that
runs AEGIS and provide an Anthropic API key through `ANTHROPIC_API_KEY`.

```sh
python -m pip install -r requirements-claude.txt
```

The default model is the Anthropic `sonnet` alias. Set `AEGIS_CLAUDE_MODEL` to choose
another Claude model. Each run has an SDK budget of US$1 and accepts the following
operator limits.

| Environment variable | Default | Supported range |
| --- | ---: | ---: |
| `AEGIS_CLAUDE_MAX_TURNS` | 18 | 1–24 |
| `AEGIS_CLAUDE_MAX_TOKENS` | 30,000 | 20,000–50,000 |
| `AEGIS_CLAUDE_MAX_TOOL_CALLS` | 30 | 1–50 |
| `AEGIS_CLAUDE_TIMEOUT_SECONDS` | 180 | 1–300 |

A failed or unavailable Claude run is reported in its selected mode. Proposals
already submitted during a run remain queued for review even if the run ends
with an error.

The SDK uses a temporary working directory and temporary Claude configuration
directory, an empty built-in tool preset, disabled filesystem settings and
session persistence, a strict MCP configuration, exact tool names, and a
deny-by-default permission hook. The CLI environment clears unrelated inherited
values. The application sends synthetic evidence and context returned by tools
to Anthropic in live mode. Tool names and outcomes are recorded in the
incident's journal. Approval, capability issuance, execution and outcome
verification remain application-side operations.

From the repository root, this smoke check uses the bundled
`control-plane-compromise` fixture in a temporary database and confirms that
Claude submits a proposal without issuing an approval or executing containment.

```sh
python -m scripts.smoke_claude
```

| MCP tool | Scope |
| --- | --- |
| `get_incident_events` | Recorded events for the current synthetic incident |
| `get_identity_context` | The incident tenant and its identities |
| `get_asset_graph` | Incident tenant assets and connected topology, with basic ownership |
| `get_asset_dependencies` | Edges in the incident-connected graph |
| `get_applicable_policies` | Policy rules |
| `get_existing_sessions` | Simulated sessions and grants for the incident tenant |
| `simulate_containment` | Projected effects of an action against current state |
| `get_previous_decisions` | Proposal and decision summaries |
| `submit_response_proposal` | Queues a proposal for governance review |

An operator can set `AEGIS_EXTERNAL_MCP_CONFIG` to a JSON array of trusted MCP
servers. Each server declares exact names for its read-only tools in
`read_tools`. AEGIS restricts invocation to those names and records their
outcomes. External integrations are off by default and are unused by offline
replay.

```json
[
  {
    "name": "reference",
    "type": "http",
    "url": "https://mcp.example.test/incident",
    "read_tools": ["read_bulletin"]
  },
  {
    "name": "local_reference",
    "type": "stdio",
    "command": "/opt/mcp/bin/reference-server",
    "args": ["--fixture", "/opt/mcp/fixtures/reference.json"],
    "read_tools": ["read_bulletin"]
  }
]
```

HTTP servers use Streamable HTTP over HTTPS. Stdio servers require an absolute
trusted executable on the AEGIS host or in its container. The SDK runs the
fixed argument vector directly and starts the executable with a clean
environment. The executable still has the operating system privileges of the
AEGIS process, so operators should use servers and tools they trust. AEGIS
exposes incident records through explicit read tools.

SDK API and permission details are in the upstream documentation.
[Claude Agent SDK](https://github.com/anthropics/claude-agent-sdk-python)
