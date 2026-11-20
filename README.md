# VERA Aegis

**Context-bound authority for incident response in a simulated multi-tenant cloud.** Watch an investigator propose containment, inspect its blast radius, authorize a scoped action, then invalidate a pending authorization by changing a dependency. The independent verifier checks persisted effects.

## Run locally

On Linux with Python 3.11 or later:

```sh
git clone https://github.com/gbasilveira/hackathon-leaseweb-vera-aegis.git
cd hackathon-leaseweb-vera-aegis
./scripts/diagnose.sh
./scripts/test.sh
./scripts/dev.sh
```

Open **http://127.0.0.1:8765**. Choose deterministic replay for a completely offline investigation. Use the [five-minute runbook](docs/DEMO_RUNBOOK.md). Stop the process with Ctrl-C. Restarting preserves the incident in SQLite. Reset reconstructs the selected fixture and clears that demonstration's evidence.

## Run in Docker

```sh
docker compose up --build -d
docker compose ps
```

The default image runs the offline investigator. State lives in the named volume. On a remote VM, connect with `ssh -L 8765:127.0.0.1:8765 user@vm` and open the same local URL. The port is published on loopback. No privileged container, Docker socket or KVM device is required.

## Live investigation

```sh
WITH_CLAUDE=1 ./scripts/install.sh
source .venv/bin/activate
# Supply ANTHROPIC_API_KEY through your local secret manager.
./scripts/dev.sh
```

Select Claude in the console. For Docker, set `WITH_CLAUDE=1` when building with Compose and provide the API key through the environment. Account access, network and quota are required. The replay investigator is always available.

## Inspect a scenario

```sh
python -m aegis config-export control-plane-compromise > /tmp/scenario.json
python -m aegis graph control-plane-compromise
python -m aegis --db /tmp/aegis.sqlite reset secondary-scenario
```

To import, give the exported configuration a new scenario ID and run `python -m aegis config-import /path/to/config.json` from a writable checkout. Restart the UI to refresh the catalog.

## Documentation

- [Architecture and generated topology](docs/README_ARCHITECTURE.md)
- [Deployment](docs/DEPLOYMENT.md) and [tests](docs/TESTING.md)
- [Scenario configuration](docs/SCENARIO_SCHEMA.md) and [attack narrative](docs/ATTACK_CHAIN.md)
- [Governance](docs/GOVERNANCE.md) and [limitations](docs/LIMITATIONS.md)
- [Implementation contracts](docs/IMPLEMENTATION_CONTRACTS.md)
- [Threat model and limitations](docs/THREAT_MODEL.md)
- [Local HTTP API](docs/API.md)
- [Agent tools and live setup](docs/MCP.md)
- [Presentation guide](docs/DEMO_RUNBOOK.md)
- [Licensing](docs/LICENSING.md)

Original application code is Apache-2.0. Third-party components retain their own terms.

## Engineering handoff

See the [continuation checkpoint](docs/HANDOFF.md), [specification coverage](docs/SPEC_TRACKER.md) and [operation history](docs/OPERATIONS.md) for verified behavior, pending environment checks and the next operation.
