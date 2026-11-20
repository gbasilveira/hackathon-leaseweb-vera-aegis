# Five-minute demonstration

Before presenting, start the server, open the console and reset the primary scenario. Verify local health and test Claude connectivity separately. Pick deterministic replay if external service latency or quota is unsuitable. Its label identifies the source of proposals.

| Time | Operator action | What to show |
|---|---|---|
| 0:00–0:35 | Inspect topology and select the compromised identity. | Several tenants share compute and backup infrastructure. |
| 0:35–1:15 | Step through the suspicious session and the snapshot (evidence-002). Leave subsequent attempts queued. | A synthetic principal operates through its session. The control plane computes the outcome. |
| 1:15–2:00 | Start investigation. | Read the recorded tool invocations, observations and structured proposals. Live output varies. |
| 2:00–2:45 | Evaluate the host intervention in deterministic replay. | The dependency report identifies affected tenants. The denial produces no capability. |
| 2:45–3:30 | Evaluate identity suspension and execute the issued capability. | Inspect the verifier's checks, then resume replay. The queued requests now encounter a suspended identity. Let replay finish before issuing the next capability. |
| 3:30–4:15 | Evaluate the same identity proposal again. Inject the configured dependency, then attempt execution with the pending capability. | Compare graph revisions and inspect HOLD_CONTEXT_CHANGED and the fresh decision. |
| 4:15–5:00 | Export evidence. | Inspect proposal, policy, impact, decisions, executions and checks. The invalidated capability produced no execution. |

“Attackers operate at machine speed. VERA enables machine-speed defense without surrendering control.”

The default presentation uses **Control Plane Simulator** and **Deterministic replay** (no LLM inference). Select **Claude** for a live investigation. The high-impact proposal is a configured replay alternative. A live model may choose a narrower proposal immediately.

## Live hypervisor walkthrough

The table above drives the fixture replay, which needs no hypervisor and is the
safe fallback. This section drives real QEMU guests. See
[ADR 001](ADR-001-live-architecture.md) for why each act proves what it claims.

Provision once, as root:

```sh
sudo ./deploy/provision.sh
python3 -m aegis.live --catalogue /var/lib/aegis/catalogue.json topology
```

Confirm before presenting that the shared network is reported as critical and
names two observed tenants. That line is the demonstration's foundation: the
denial in act 2 follows from it arithmetically.

| Time | Operator action | What to show |
|---|---|---|
| before | `sudo ./deploy/reset-demo.sh`, then open the console in a browser tab | Links up, nothing contained, three services active. Leave the console visible for the whole pitch; it updates itself as each act runs. |
| 0:00–0:40 | `aegis.live topology` | Three guests, three tenants, two networks. One network carries two tenants and is therefore critical. Nothing here was declared; it was read from the hypervisor. |
| 0:40–1:10 | `aegis.live privileges` | The planner has egress and no hypervisor. The gateway has the hypervisor and no egress. Each process verified this by attempting the access it is denied. |
| 1:10–1:40 | In a second terminal: `sudo -u demo-attacker /opt/aegis/attacker.sh tenant-b--app` | A legitimate operator credential, stock `virsh`, no project code. Broad enumeration, then bulk snapshots, then probing another tenant. |
| 1:40–3:30 | `aegis.live demo --target tenant-b--app` | Acts 1 to 5. The broad action is refused. The scoped one earns a single-use handle. An unrelated service dependency appears and the handle survives — the mechanism is precise, not merely strict. Then it executes, and `isolated: True` is read back from the hypervisor, not reported by the actuator. |
| 3:30–4:30 | Same run, acts 6 and 7 | A critical tenant-c service starts depending on the target. The pending handle is refused, and the refusal names that service and says the blast radius moved from one tenant to two. Re-evaluated, the same proposal is now denied outright. |
| 4:15–4:40 | `aegis.live compare` | The counter and the model on identical evidence. The counter proposes containment on a snapshot count and the policy would allow it; the model declines and says why. This is the answer to "what stops it containing a legitimate workload". |
| 4:40–5:00 | Same run, act 8 | The sealed journal, its head, and an entry edited live so the chain breaks at a named index. |

### The three processes

The table above runs one process that both decides and actuates, which is the
right shape for a walkthrough and the wrong shape for a deployment. For the
deployed split, `sudo ./deploy/install-services.sh`, then:

```sh
sudo journalctl -u aegis-sensor -u aegis-planner -u aegis-gateway -f
```

The sensor publishes topology and sealed observations. The planner reads that
published view, because it holds no hypervisor access at all, proposes against
it, and asks the gateway over a socket that accepts one operation and carries
only an identifier and a nonce. The gateway recomputes the scoped digest from
live libvirt before spending anything.

The point worth making is that the planner's view is allowed to be wrong. It
can be stale, and a compromised planner can doctor it. Neither widens what the
gateway permits, because the gateway does not trust the snapshot the decision
was made against; it checks the world itself at the instant of use.

### Autonomous containment, end to end

With the three units running, nothing needs driving. Watch the journal in one
terminal and run the adversary in another, against a guest that is not already
contained:

```sh
sudo journalctl -u aegis-sensor -u aegis-planner -u aegis-gateway -f
sudo -u demo-attacker /opt/aegis/attacker.sh tenant-b--sandbox
```

The order of what appears is the whole argument. The sensor seals a change on
that guest's snapshot count, read from the hypervisor and not from anything the
guest said. The planner, which cannot open libvirt at all, reads that sealed
observation, proposes containment, evaluates it against the published topology
and mints a single-use handle. The gateway recomputes the scoped digest from
live libvirt, spends the handle once, drops the interface link and re-reads the
domain to confirm it.

Three processes, three privilege envelopes, one sealed chain. The adversary
shares nothing with any of them but the hypervisor.

If the journal shows nothing, the adversary produced no signal. Its last
line says so explicitly. The usual cause is running it from a path its own
account cannot read.

Release it the same way as the walkthrough:

```sh
sudo python3 -m aegis.live --catalogue /var/lib/aegis/catalogue.json \
    release --target tenant-b--sandbox
```

Two sentences worth saying out loud. The model never holds a credential: it
proposes, and the only thing that can act is a single-use handle bound to a hash
of the request and of the observed world, revalidated at the instant of use. We
do not claim the model's proposals are good; we claim a bad one cannot reach the
hypervisor.

Afterwards the target guest is left contained, because act 6 correctly refused
to release it. That is the right outcome, not a loose end, and it is worth
saying so before anyone asks whether the guest is now bricked. Then show that
the refusal was conditional:

```sh
sudo python3 -m aegis.live --catalogue /var/lib/aegis/catalogue.json \
    release --target tenant-b--app
```

`release` removes the walkthrough's own catalogue entries, nothing else, so the
dependency that revoked the pending handle is gone. The same proposal is then
evaluated again, allowed, issued a fresh handle and executed, and the link
comes back up. It goes through the whole governance path rather than around it;
reaching for `virsh` here would work and would prove nothing.

Run it before the pitch as well as after, so the host starts clean.

To remove the guests, networks and accounts entirely:

```sh
sudo ./deploy/provision.sh --destroy
```
