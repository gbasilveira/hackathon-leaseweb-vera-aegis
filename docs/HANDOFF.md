# Continuation checkpoint · 20 November 2026

**Live control plane.** Branch `live-control-plane` adds a real path over libvirt
and QEMU alongside the simulator, which is untouched and remains the offline
fallback. Topology is discovered from live domain XML rather than declared,
containment uses guest interface link state, and capability authority is bound
to the impact closure of the action instead of to all state, which the previous
global digest would have revoked within seconds on a live hypervisor. The
adversary runs as its own unix account through stock `virsh` and shares no code,
process, socket or store with the defence. Every decision, and what it does and
does not prove, is in [ADR 001](ADR-001-live-architecture.md); operations 015 to
025 in [OPERATIONS.md](OPERATIONS.md) record the work and its verification.

**Current outcome.** The public main branch contains a working simulator demo. The application checkpoint is `51f48ef`. The handoff documentation is committed on top of it. The public origin is [gbasilveira/hackathon-leaseweb-vera-aegis](https://github.com/gbasilveira/hackathon-leaseweb-vera-aegis). The operator supplied the SSH remote and publication authorization.

**What to run first.** For the live path on a Linux host with libvirt, run
`sudo ./deploy/provision.sh`, then `python3 -m aegis.live --catalogue
/var/lib/aegis/catalogue.json topology` and confirm the shared network is
reported critical naming two observed tenants; the walkthrough's first denial
follows from that measurement. Then `demo --target tenant-b--app`. The live
walkthrough is in [DEMO_RUNBOOK.md](DEMO_RUNBOOK.md#live-hypervisor-walkthrough).
For the simulator, run `./scripts/demo.sh` for three isolated governance paths. Run `./scripts/test.sh` for the offline suite. For an operator walkthrough use [DEMO_RUNBOOK.md](DEMO_RUNBOOK.md). The shared development machine has a Compose project named `vera-aegis` on loopback port 8765, built with the optional SDK. Check `docker compose ps` and `curl -fsS http://127.0.0.1:8765/api/v1/health`. The UI opens in deterministic mode. State resides in the named volume. The presentation VM has not been provided or accessed.

**Verified checkpoint, live path.** 41 new tests, 68 of 78 passing. The 10
errors are in tests/test_agent.py and are pre-existing SDK version drift,
`claude-agent-sdk` 0.2.172 present against the 0.2.185 pinned in
pyproject.toml; that work added only new files and modified no existing module.
Validated against a real libvirt connection: discovery, and `vm.suspend` and
`vm.resume` with the state transition confirmed by independent re-read. The
eight-act walkthrough ran end to end. `network.isolate`, the deploy scripts and
the systemd units are **unvalidated on a hypervisor**, because that session had
no QEMU and could not reach the target host.

**Verified checkpoint, simulator.** A fresh public clone passed the complete 37-test suite with the SDK installed. The plain Python environment passed 36 and skipped one SDK-specific test. Headless Chrome exercised the primary and secondary operator flows. A credentialed live Claude investigation submitted a synthetic proposal without issuing any authority. No further paid call is needed to reproduce the deterministic demonstration.

## Remaining work by priority

| Priority | Operation | Completion evidence |
|---|---|---|
| Done 20 Nov | Provisioning, discovery and the full eight-act walkthrough all ran on the hypervisor. `network.isolate` executed for the first time: `vnet0` moved `up` to `down` and `isolated: True` was confirmed by independent re-read. Discovery reported the shared network, pool and host as critical, each naming two observed tenants. | Operations 026 and 027 in OPERATIONS.md. |
| **Next action** | Install the three units from `deploy/systemd/`, create `/etc/aegis/planner.env` mode 0600, and confirm `aegis.live privileges` reports `ok` for all three roles when each runs under its own account. Run as a human operator it will correctly report the planner as a violation, because the read-only socket is world-readable; that is what `InaccessiblePaths` in the planner unit exists to fix, and confirming it is what validates the deployed split. | Three `ok` rows, obtained per role under its own service account. |
| Before presenting | Run `aegis.live demo --target tenant-b--app --action network.isolate`. This is the first execution of `network.isolate` anywhere: it needs `virDomainUpdateDeviceFlags`, which libvirt's test driver does not implement, so it has never run. | Act 5 reporting `isolated: True` from re-read, and act 6 naming the catalogue node that revoked the pending handle. |
| Before presenting | Install the three units from `deploy/systemd/`, create `/etc/aegis/planner.env` mode 0600, and confirm `aegis.live privileges` reports no violation for any role. | A privilege matrix with three clean rows. |
| If tenant enforcement is in the pitch | Run `sudo ./deploy/enable-acl.sh` and confirm libvirtd refuses the attacker account on a foreign tenant's domain. | A polkit denial in the journal; `--revert` tested. |
| Credential hygiene | Rotate the Anthropic API key supplied in the 20 November session: it existed in a chat transcript. It was written to no file. | New key in `/etc/aegis/planner.env` only. |
| Pending | The simulator path still uses the global context digest and the old hard-coded policy facts. Either port it to `aegis.scope` or document it as legacy. | Updated `governance.assess`, or a note in LIMITATIONS.md. |
| Pending | The browser console reads the simulator path only; the live path is CLI-only. | A live view, or a documented scope boundary. |
| Before presenting | Run diagnostics, Compose health, offline walkthrough and export on the organizer's VM. Confirm the SSH tunnel from the presentation laptop. | Record OS, Python/Docker versions, health result, exported verification result and elapsed pitch time. No VM access information was supplied in this session. |
| Before using live Claude on stage | Check that VM's egress, API key and available quota. Rehearse offline if external access fails. | One live synthetic smoke for the new environment. Never store a key in the repository. |
| If external intelligence is part of the pitch | Configure a real authorized read-only MCP provider and verify one allowed read. | Record server/tool names and sanitized outcome. Stdio handshake was verified with a synthetic server. No real third-party HTTPS provider or credentials were supplied. |
| If full domain parity is required | Review the field, process and provenance qualifications in rows 4, 8, 10 and 16 of the spec tracker. Add regression tests before expanding contracts. | Updated wire schema, fixtures, tests and matrix rows. |

## Ownership and boundaries

On the live path: `controlplane.py` is the adapter boundary and the closed
action enum, `libvirt_plane.py` owns discovery, observation and actuation,
`scope.py` owns the impact closure and the scoped digest, `chain.py` owns
sealed evidence, `privsep.py` owns the privilege assertions each process makes
about itself, `gateway.py` owns the only writable plane connection and the
single-operation socket, and `live.py` owns the derived policy and the operator
console. The planner holds egress and no hypervisor; the gateway holds the
hypervisor and no egress. Guest-side signal is partitioned out of decision
facts by `controlplane.authority_facts` and never sanitised.

On the simulator path: Core owns SQLite, scenario validation, fixture operations, graph impact, process state and incident classification. Agent code owns Claude and tool dispatch. Governance owns the evaluated request, approvals and capability lifecycle. The verifier rereads state independently. The HTTP server grants simulated operator access and manages background work. The browser never submits a command line or directly changes process state.

When resuming publication on this machine, Git HTTPS supports a public clone. SSH push worked through the user's existing agent socket under `/run/user/$(id -u)/ssh-agent.socket` after the default shell lacked an agent connection. No key material was copied. Verify remote HEAD with `git ls-remote origin HEAD`.

Use the [specification matrix](SPEC_TRACKER.md) for implementation coverage and the [operation history](OPERATIONS.md) for results and recovery details. Append the next operation to the history and update the corresponding row.
