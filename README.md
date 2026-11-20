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

## Run against real QEMU guests

The sections above run the deterministic fixture replay, which needs no
hypervisor. To run the live system against real guests on a Linux host with
libvirt:

```sh
sudo ./deploy/provision.sh
python3 -m aegis.live --catalogue /var/lib/aegis/catalogue.json topology
python3 -m aegis.live --catalogue /var/lib/aegis/catalogue.json privileges
python3 -m aegis.live --catalogue /var/lib/aegis/catalogue.json demo --target tenant-b--app
```

Topology is discovered from libvirt rather than declared, containment drops
guest interface links, and authority is bound to the impact closure of the
action so that unrelated change does not revoke a pending grant. The adversary
runs as its own account through stock `virsh` and shares no code with the
defence. See [ADR 001](docs/ADR-001-live-architecture.md) for each decision and
what it does and does not prove, and the
[live walkthrough](docs/DEMO_RUNBOOK.md#live-hypervisor-walkthrough) to present
it.

## Documentation

- [How it works, end to end](docs/HOW_IT_WORKS.md)
- [Presentation specification](docs/DECK_SPEC.md), every slide with its diagrams
- [Live architecture decisions](docs/ADR-001-live-architecture.md) and [architecture with generated topology](docs/README_ARCHITECTURE.md)
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
