# Continuation checkpoint · 20 November 2026

**Current outcome.** The public main branch contains a working simulator demo. The application checkpoint is `51f48ef`. The handoff documentation is committed on top of it. The public origin is [gbasilveira/hackathon-leaseweb-vera-aegis](https://github.com/gbasilveira/hackathon-leaseweb-vera-aegis). The operator supplied the SSH remote and publication authorization.

**What to run first.** From a clone, run `./scripts/demo.sh` for three isolated governance paths. Run `./scripts/test.sh` for the offline suite. For an operator walkthrough use [DEMO_RUNBOOK.md](DEMO_RUNBOOK.md). The shared development machine has a Compose project named `vera-aegis` on loopback port 8765, built with the optional SDK. Check `docker compose ps` and `curl -fsS http://127.0.0.1:8765/api/v1/health`. The UI opens in deterministic mode. State resides in the named volume. The presentation VM has not been provided or accessed.

**Verified checkpoint.** A fresh public clone passed the complete 37-test suite with the SDK installed. The plain Python environment passed 36 and skipped one SDK-specific test. Headless Chrome exercised the primary and secondary operator flows. A credentialed live Claude investigation submitted a synthetic proposal without issuing any authority. No further paid call is needed to reproduce the deterministic demonstration.

## Remaining work by priority

| Priority | Operation | Completion evidence |
|---|---|---|
| Before presenting | Run diagnostics, Compose health, offline walkthrough and export on the organizer's VM. Confirm the SSH tunnel from the presentation laptop. | Record OS, Python/Docker versions, health result, exported verification result and elapsed pitch time. No VM access information was supplied in this session. |
| Before using live Claude on stage | Check that VM's egress, API key and available quota. Rehearse offline if external access fails. | One live synthetic smoke for the new environment. Never store a key in the repository. |
| If external intelligence is part of the pitch | Configure a real authorized read-only MCP provider and verify one allowed read. | Record server/tool names and sanitized outcome. Stdio handshake was verified with a synthetic server. No real third-party HTTPS provider or credentials were supplied. |
| If full domain parity is required | Review the field, process and provenance qualifications in rows 4, 8, 10 and 16 of the spec tracker. Add regression tests before expanding contracts. | Updated wire schema, fixtures, tests and matrix rows. |

## Ownership and boundaries

Core owns SQLite, scenario validation, fixture operations, graph impact, process state and incident classification. Agent code owns Claude and tool dispatch. Governance owns the evaluated request, approvals and capability lifecycle. The verifier rereads state independently. The HTTP server grants simulated operator access and manages background work. The browser never submits a command line or directly changes process state.

When resuming publication on this machine, Git HTTPS supports a public clone. SSH push worked through the user's existing agent socket under `/run/user/$(id -u)/ssh-agent.socket` after the default shell lacked an agent connection. No key material was copied. Verify remote HEAD with `git ls-remote origin HEAD`.

Use the [specification matrix](SPEC_TRACKER.md) for implementation coverage and the [operation history](OPERATIONS.md) for results and recovery details. Append the next operation to the history and update the corresponding row.
