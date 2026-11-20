# How it works, end to end

This is the whole system in one place: the host, the accounts, the three
services, the data they share, the mechanism that decides, and the exact
sequence of a containment. [ADR 001](ADR-001-live-architecture.md) explains why
each decision was made; this explains what runs.

Everything described here was exercised on a real hypervisor. Where something
is unvalidated, it says so.

---

## 1 · The premise

A multi-tenant QEMU host. An operator credential has been compromised. Nothing
is exploited and no malware is involved: the adversary holds a legitimate
account and uses it legitimately, in an unusual pattern.

The question the system answers is not "can we detect this". It is: **can a
language model drive incident response on real infrastructure without ever
being trusted?**

The answer rests on one idea. The model only ever proposes. The only thing that
can change the world is a single-use handle, bound to a hash of the request and
of the observed world, revalidated against the hypervisor at the instant it is
spent.

---

## 2 · The host

`deploy/provision.sh` builds this. It is idempotent and `--destroy` removes it.

### Guests

| Domain | Tenant | Criticality | Network |
|---|---|---|---|
| `tenant-b--app` | tenant-b | normal | `aegis-shared` |
| `tenant-c--svc` | tenant-c | critical | `aegis-shared` |
| `tenant-b--sandbox` | tenant-b | normal | `aegis-private` |

Three guests, three tenants, two networks. The arrangement is the point:
`aegis-shared` carries two tenants and `aegis-private` carries one, so the
system can *measure* which infrastructure is shared instead of being told.

Guests are cirros on qcow2 overlays over one base image, 192 MiB each. Where
`/dev/kvm` is absent the domains run under TCG, which is slow to boot and
otherwise identical.

### Tenant attribution

Each domain carries libvirt metadata:

```xml
<metadata>
  <aegis:tenant xmlns:aegis='https://vera-aegis.local/tenant/1'
                id='tenant-b' criticality='normal'/>
</metadata>
```

Read with `virDomainGetMetadata`. If absent, the name prefix before `--` is
used, and failing that the domain is `unattributed`.

### Accounts

| Account | Group `aegis` | Group `libvirt` | Purpose |
|---|---|---|---|
| `aegis-sensor` | yes | **no** | observes |
| `aegis-planner` | yes | **no** | proposes |
| `aegis-gateway` | yes | yes | acts |
| `demo-attacker` | no | yes | the compromised operator credential |

The `aegis` group exists so three different accounts can share one state file
and one socket. It grants nothing else. libvirt access and network egress are
decided per unit.

`/var/lib/aegis` is `root:aegis` mode `2775`. The setgid bit matters: a file
one service creates stays writable by the others. The disk images inside are
deliberately **not** given that group, because libvirt applies its own dynamic
ownership to them when a domain starts.

---

## 3 · The three services

`deploy/install-services.sh` installs the package to `/opt/aegis`, the units to
`/etc/systemd/system`, and restarts all three.

### The sensor — `aegis.live observe`

Runs as `aegis-sensor`. Opens libvirt **read-only**. Every five seconds:

1. `plane.discover()` → publishes the topology into the shared store,
   overwriting the previous one.
2. `plane.observe()` → collects hypervisor-side signal per domain.
3. `controlplane.authority_facts()` partitions that signal by trust level and
   drops everything that is not hypervisor-trust from the decision facts.
4. Seals an observation into the journal **only when it changed**: the state,
   the interface link states or the snapshot count differ from the last seen
   for that target. Byte counters are excluded from that comparison because
   they always differ and carry no authority.

The unit gives it `PrivateNetwork=yes` and `IPAddressDeny=any`. Every signal it
collects is local and hypervisor-side, which is what makes that signal
unforgeable by a guest.

It cannot actuate. `privsep` makes it verify that at startup, and the
`LibvirtControlPlane` refuses to actuate on a read-only connection regardless.

### The planner — `aegis.live plan`

Runs as `aegis-planner`. **Holds no libvirt access at all.** Every fifteen
seconds:

1. Reads the published topology and the sealed journal from the store.
2. `_suspect()` picks a target: the guest with the highest snapshot count,
   skipping any whose link is already down. This is a placeholder for a model
   and reads no guest-supplied field.
3. `propose()` — builds the proposal and hashes it.
4. `evaluate()` — runs the policy against the **published** topology.
5. `issue()` — on ALLOW, mints a capability.
6. `execute_remote()` — connects to the gateway's socket and sends only an
   identifier and a nonce.

It is denied the hypervisor twice over. libvirt's read-only socket is
world-readable, so group membership alone would not be enough;
`InaccessiblePaths=/run/libvirt /var/run/libvirt /etc/libvirt` hides it. If
someone removes that line, `privsep` refuses to start the process. Two
independent mechanisms have to fail together.

**Its view of the world is allowed to be wrong.** It can be stale, and a
compromised planner can doctor it, because the gateway recomputes everything
from live libvirt before spending anything. `tests/test_live.py` asserts this:
a handle issued against a snapshot taken before a dependency appeared is
refused.

It has network egress, which is the privilege the gateway is denied. Its model
credential lives in `/etc/aegis/planner.env`, mode 0600, outside the
repository.

### The gateway — `aegis.live gateway`

Runs as `aegis-gateway`. Opens libvirt **read-write** and is the only component
in the system that does. Listens on `/run/aegis/gateway.sock`, mode 0660, group
`aegis`.

Its protocol has exactly one operation:

```json
{"op": "consume", "capability_id": "cap-1", "nonce": "…"}
```

There is no way to submit a proposal, change a policy or pass free text through
this socket, so a compromised planner can ask only for an action it was already
granted.

It is given **no network of any kind**: `PrivateNetwork=yes`,
`IPAddressDeny=any`, `RestrictAddressFamilies=AF_UNIX`. Even a leaked model
credential in its environment would reach nothing. `privsep` also refuses to
start it if such a credential is present at all.

### The privilege matrix

| Role | libvirt | Network | Model credential |
|---|---|---|---|
| sensor | read-only | denied | forbidden |
| planner | **none** | permitted | required |
| gateway | read-write | **denied** | forbidden |

The planner has egress and no hypervisor. The gateway has the hypervisor and no
egress. Neither can do the other's job, so neither compromise is sufficient.

`aegis/privsep.py` checks this by *attempting* the forbidden access. The checks
are negative on purpose: "I cannot reach libvirt, and I verified that by
trying" is the property worth having, because a misconfiguration usually grants
more access than intended, not less. Two outcomes are distinguished:

- **violations** — more access than the role allows. A security failure. Always
  fails closed.
- **shortfalls** — less access than the role needs. An operational failure. A
  gateway that cannot write cannot contain anything, and calling it healthy
  only moves the discovery to the first actuation, mid-incident.

`aegis.live privileges` prints the matrix. Run as a human operator it will
correctly report the planner as a violation, because that account can open the
world-readable read-only socket. That is exactly what `InaccessiblePaths`
exists to fix, and confirming it per account is what validates the deployment.

---

## 4 · What they share

### `/var/lib/aegis/state.json`

One JSON document, `root:aegis` 664, written under `flock` and landed with
`os.replace` so a reader never sees a half-written file.

- `topology` — the last picture the sensor published
- `capabilities` — every handle and its status
- `entries` — the hash-sealed journal

### `/var/lib/aegis/catalogue.json`

The service catalogue. A hypervisor knows that a guest sits on a bridge; it
cannot know that a billing service depends on that guest. In production that
lives in a CMDB. Here it is an operator-owned JSON file, re-read on every
discovery and merged into the observed graph.

A catalogue entry appearing mid-incident is the realistic way a blast radius
grows, and it is what costs a pending capability its authority during the
walkthrough.

### The trust boundary

| Trust | Source | Forgeable by |
|---|---|---|
| `hypervisor` | domain state, link state, tap counters, snapshot count | escaping the VM |
| `guest` | anything from inside a guest | the attacker, completely |

`authority_facts()` drops guest-trust signal from decision facts rather than
sanitising it, and journals it as `excluded_from_decisions` so a human can
still read it. There is no reliable way to tell a genuine guest log from one
the attacker wrote; filtering invites a bypass, excluding the channel does not.

This is what makes QEMU the right substrate: there is a real trust boundary to
point at, not a declared one.

---

## 5 · Discovery: measuring the blast radius

`LibvirtControlPlane.discover()` parses every domain's live XML and emits:

```
tenant-b--app  -runs_on->      host:instance-633091-6
tenant-b--app  -attached_to->  net:aebr-shared
tenant-b--app  -stored_on->    pool:/var/lib/aegis/images
```

Then, for each infrastructure node, it counts the distinct tenants observed
attached to it. More than one makes that node `shared` and `critical`.

That is the whole trick. The denial that protects other tenants is not an
assertion:

```
net:aebr-shared   net   infrastructure   True   critical   observed tenants: tenant-b, tenant-c
```

Two tenants were observed on that bridge, therefore a broad action there
crosses a tenant boundary, therefore it is denied. The audience can check the
arithmetic.

Edge direction follows one convention throughout: **source depends on target.**

---

## 6 · The scoped context digest

`aegis/scope.py`. This is the mechanism the whole system turns on.

A capability must commit to the part of the world that can change its meaning,
and to nothing else.

**The closure** of an action on a target is the target plus everything that
transitively depends on it — reverse reachability over the dependency graph.
That is the set of parties the action can harm.

The digest covers the closure's membership, the authority-relevant fields of
each member (an explicit `SCOPED_FIELDS` allowlist), the edges incident to the
closure, and the set of owning tenants.

What it deliberately **excludes**:

- What the target itself depends on. Isolating a guest does not harm the bridge
  beneath it, so bridge load must not revoke the grant.
- Volatile telemetry. Byte counters change on every observation and would
  reintroduce exactly the thrashing this design removes.

What it deliberately **includes**:

- The wiring attaching the target to its dependencies, so a migration does
  revoke, because the action's context genuinely changed.
- Closure membership itself, so a new dependant is caught twice: by membership
  and by wiring.

The original implementation digested all state, and the threat model recorded
the consequence as intentional. On a fixture that is conservative. On a
hypervisor where guests start, stop and migrate continuously, every capability
would be revoked within seconds of issue, before any operator could spend it,
and the mechanism would have had to be switched off in order to demonstrate it.

`scope.explain(before, after)` turns a digest mismatch into operator-readable
reasons:

```
svc-billing (tenant-c) now depends on tenant-b--app
new edge svc-billing -depends_on-> tenant-b--app
blast radius moved from 1 to 2 tenant(s): tenant-b, tenant-c
```

### Both directions matter

Revocation alone is easy and useless; precision is the hard part and the
stronger claim.

- A new guest joining the shared bridge, or a guest elsewhere changing state →
  the pending handle **survives**.
- A service in another tenant starting to depend on the target → the handle
  **lapses**, and the refusal names the service.

---

## 7 · The actions

A closed enum, in `aegis/controlplane.py`:

| Action | Reversible | Mechanism |
|---|---|---|
| `network.isolate` | yes | drop the link on every guest interface |
| `network.restore` | yes | raise them again |
| `vm.suspend` | yes | freeze vCPUs, memory preserved for forensics |
| `vm.resume` | yes | release them |
| `vm.snapshot` | **no** | capture guest state as evidence |

`host.stop` is **absent**. Stopping a shared host is the proposal the
demonstration must deny, and an action the plane cannot perform is a stronger
guarantee than a policy rule that says not to. It is refused before any policy
evaluates.

Isolation takes the `<interface>` element from the live domain XML, strips
`<link>` and `<alias>`, inserts `<link state='down'/>` and calls
`virDomainUpdateDeviceFlags` with `AFFECT_LIVE` — the mechanism behind
`virsh domif-setlink`. It is immediate, it survives a guest reboot, the guest
can neither see nor block it, and it is verifiable from the host by re-reading
the live XML. For a hypervisor it is the honest containment action, where
revoking a federated identity is not something this layer can do.

Note that libvirt omits the `<link>` element when a link is up, so absence
means up.

---

## 8 · The policy

`aegis/live.py`. Priority-ordered, first match wins, default denial.

| Priority | Reason | Result | Fires when |
|---|---|---|---|
| 100 | `DENY_UNPUBLISHED_ACTION` | DENY | the plane publishes no such action |
| 90 | `DENY_SHARED_RESOURCE` | DENY | the target was observed shared |
| 85 | `DENY_CRITICAL_SHARED_DEPENDENCY` | DENY | a critical shared node is in the closure |
| 80 | `DENY_CROSS_TENANT_BLAST` | DENY | the closure spans more than one tenant |
| 70 | `DENY_UNKNOWN_TARGET` | DENY | no such node |
| 60 | `HOLD_NO_EVIDENCE` | HOLD | the proposal cites no evidence |
| 50 | `REQUIRE_APPROVAL_IRREVERSIBLE` | REQUIRE_APPROVAL | the action cannot be undone |
| 40 | `ALLOW_SCOPED_REVERSIBLE` | ALLOW | reversible, single tenant |
| 0 | `DENY_DEFAULT` | DENY | always |

Every fact these read is derived from measurement: `target_shared`,
`tenant_count`, `critical_shared` and `closure` all come from the discovered
graph, and `reversible` from the action table. The previous implementation
hard-coded two action names and then overrode its own declarative rules with an
imperative block.

Adding a guest changes a decision without editing a rule.

---

## 9 · The capability

Minted only on ALLOW. It carries:

- `id` and a random `nonce`
- `action_type`, `target_id`
- `proposal_hash` — the request it authorises, and no other
- `policy_digest` — the rules it was judged under
- `context_digest` plus the full scoped observation
- `issued_at`, `expires_at` (300 seconds)
- `status`: `issued` → `consuming` → `consumed`, or `revoked` / `expired`

---

## 10 · Consumption: what the gateway checks

In order, in `Gateway.consume`:

1. The capability exists → else `DENY_UNKNOWN_CAPABILITY`.
2. The nonce matches → else `DENY_BAD_NONCE`, and the handle is burned.
3. Status is `issued` → else `DENY_CONSUMED` / `DENY_REVOKED`.
4. It has not expired → else `DENY_EXPIRED`.
5. **The scoped digest is recomputed from live libvirt.** Mismatch →
   `HOLD_CONTEXT_CHANGED`, with `explain()` naming the responsible node. Nothing
   is actuated.
6. Read the `before` state.
7. **Commit `status = consuming`, before touching the hypervisor.**
8. Actuate. A `PlaneError` → status `consumed`, result `INDETERMINATE`.
9. Commit `status = consumed`.
10. Read the `after` state independently.
11. Verify three-valued:
    - target unreadable → `INDETERMINATE`
    - effect check false → `FAILED`
    - effect check true → `VERIFIED`
12. Seal the outcome into the journal.

Step 7 is the one that is easy to miss. A SQLite transaction can be rolled
back; a `virsh` call cannot. The previous implementation actuated inside a
transaction, so a crash between spending the handle and completing the action
would have unwound the spend and left the same irreversible action able to fire
twice. The failure mode is now a refused retry, never a second execution.

Step 11 is three-valued on purpose. A target that cannot be re-read is not a
failed containment, it is an unknown one, and saying so is the entire point of
verifying independently of what the actuator returned.

---

## 11 · The evidence chain

`aegis/chain.py`. Every journal entry commits to the digest of the one before
it, starting from a genesis of 64 zeros. `verify_chain` walks it and reports the
index and identifier of the first broken link.

Editing, removing or reordering any entry breaks every link after it:

```
editing entry 1 breaks the chain at index 1 (entry content does not match its own hash)
```

Whoever owns the store can still rewrite the evidence — but no longer silently.
Publishing the chain head at handover is the one action that makes the journal
non-repudiable.

This is deliberately **not** a signature. Anchoring the head externally is an
operator decision, and the code does not pretend to do it.

The chain spans processes: the sensor, the planner and the gateway all append
to it, and it verifies as one.

---

## 12 · The adversary

`/opt/aegis/attacker.sh`, run as `demo-attacker`.

It imports no project code, links no project library, and shares no process,
socket or database with the defence. The only thing both touch is the
hypervisor. It uses nothing but the stock libvirt CLI.

Its pattern:

1. `id`, `virsh uri` — what does this credential reach
2. `virsh list --all` — enumerate every guest, including other tenants
3. `virsh dumpxml` — read the target's disks, networks and MACs
4. `virsh net-list --all` — enumerate networks
5. `virsh snapshot-create-as` ×3 — bulk capture, fast, cheap, exfiltration-shaped
6. `virsh dominfo` on other tenants' guests — probe laterally

Nothing here is an exploit. That is the premise: the credential is already
compromised, so no exploitation is needed, and the activity is ordinary
control-plane usage in an unusual pattern. That pattern is what a detector sees
in production.

The script ends by stating whether it actually produced the signal the defence
keys on. A silent failure there is indistinguishable from a defence that
noticed nothing, which is the worst possible way to learn about it.

It must be run from `/opt/aegis/`, not from a checkout: an operator's home
directory is typically mode 0750, which the adversary account cannot traverse.

---

## 13 · Autonomous containment, step by step

This is what happened on the host at 13:39:13, with nobody driving it.

1. **The adversary creates a snapshot** on `tenant-b--sandbox`.
2. **Within 5 seconds** the sensor polls. `discover()` publishes the topology.
   `observe()` reports `snapshots: 1` on that domain, read from the hypervisor
   and not from anything the guest said. The signature for that target changed,
   so an observation is sealed: `hypervisor.observed`.
3. **Within 15 seconds** the planner polls. It reads the published topology and
   the sealed entries from the store. It holds no libvirt access.
4. `_suspect()` selects `tenant-b--sandbox`: one snapshot, link up.
5. It proposes `network.isolate` → sealed as `proposal.submitted`.
6. It evaluates against the published topology. The closure is
   `['tenant-b--sandbox']`, the blast radius one tenant, the action reversible
   → `ALLOW / ALLOW_SCOPED_REVERSIBLE` → sealed as `governance.decision`.
7. It mints a capability bound to the scoped digest → sealed as
   `capability.issued`.
8. It sends `{"op":"consume", "capability_id", "nonce"}` over the unix socket.
   Nothing else crosses.
9. **The gateway recomputes the scoped digest from live libvirt.** It matches.
10. It commits the spend, calls `virDomainUpdateDeviceFlags`, and the link goes
    down.
11. It re-reads the domain. `isolated: True` → `VERIFIED` → sealed as
    `outcome.verified`.

In the journal:

```
13:38:58  no anomaly in the sealed hypervisor observations
13:39:13  suspect tenant-b--sandbox: 1 snapshots observed on this guest
13:39:13    -> ALLOW / ALLOW_SCOPED_REVERSIBLE
13:39:13    gateway: VERIFIED
13:39:28  no anomaly in the sealed hypervisor observations
```

And in the domain XML:

```xml
<target dev='vnet2'/>
<model type='virtio'/>
<link state='down'/>
```

The planner goes quiet afterwards because target selection skips a guest whose
link is already down.

Three processes, three privilege envelopes, one sealed chain. The adversary
shares nothing with any of them but the hypervisor.

---

## 14 · The operator walkthrough

`aegis.live demo --target tenant-b--app` runs the same mechanism in one
process, in eight acts, so each property can be shown deliberately. Full timing
is in [DEMO_RUNBOOK.md](DEMO_RUNBOOK.md#live-hypervisor-walkthrough).

| Act | What it shows |
|---|---|
| 1 | Measured topology. Shared nodes name the tenants observed on them. |
| 2 | `network.isolate` on the shared bridge → `DENY_SHARED_RESOURCE`, closure of three nodes, two-tenant blast radius. |
| 3 | The same action on one guest → `ALLOW`, and the handle it earns, bound to a closure of one. |
| 4 | An unrelated catalogue entry appears → the handle **survives**. Precision. |
| 5 | Execution, and `isolated: True` read back from the hypervisor. |
| 6 | A critical tenant-c service starts depending on the target → the pending handle is refused and the reason names it. |
| 7 | Re-evaluated under the new world → `DENY_CROSS_TENANT_BLAST`. |
| 8 | The sealed journal, its head, and an entry edited live so the chain breaks at a named index. |

It is idempotent: each run first removes only the catalogue entries a previous
run added.

### Releasing

Act 6 refuses to lift isolation and act 7 denies the proposal, which leaves the
obvious question of whether the guest is now unusable.

`aegis.live release --target <guest>` answers it. It drops the walkthrough's own
catalogue entries, nothing else, and the same proposal is re-evaluated, allowed,
issued a fresh handle and executed. The refusal was conditional on the world,
not permanent.

It is also the operator's cleanup, and it runs through the mechanism rather than
around it. Reaching for `virsh` here would work and would prove nothing.

---

## 15 · The module map

| File | Owns |
|---|---|
| `aegis/scope.py` | the impact closure and the scoped digest |
| `aegis/chain.py` | hash-sealed evidence |
| `aegis/controlplane.py` | the adapter boundary, the closed action enum, the trust partition |
| `aegis/libvirt_plane.py` | discovery, observation, actuation, independent re-read |
| `aegis/privsep.py` | the privilege assertions each process makes about itself |
| `aegis/gateway.py` | the only writable plane, the one-operation socket, the shared store |
| `aegis/live.py` | the derived policy, the planner, the operator console |
| `deploy/provision.sh` | the host: guests, networks, accounts, shared state |
| `deploy/install-services.sh` | the three units |
| `deploy/attacker.sh` | the adversary, sharing no code with any of the above |
| `deploy/enable-acl.sh` | libvirt's own authorisation, opt-in |

The simulator path — `aegis/core.py`, `governance.py`, `verifier.py` and
`scenarios/` — is untouched by this work and remains the offline fallback for a
machine with no hypervisor. It still uses the global context digest and the old
hard-coded policy facts. The browser console reads only that path.

---

## 16 · What this proves, and what it does not

**It proves** that a language model can drive incident response without ever
holding a credential; that stale authority is both dangerous and preventable
with a mechanism precise enough to leave unrelated change alone; that a blast
radius can be computed from discovered topology rather than declared; and that
verification can be independent of what the actuator reported.

**It does not prove that detection works.** `_suspect` is a snapshot-count
heuristic and is documented as a placeholder. A scripted walkthrough says
nothing about precision or recall on real traffic. This is the weakest part of
the system and the hardest to validate.

**It does not prove the model's proposals are good.** It proves bad proposals
are contained, which is a different and more defensible claim — and the one
worth making: *the mechanism does not require trusting the model.*

It remains a single host, with no federated identity and no cloud control
plane.

### Unvalidated

`deploy/enable-acl.sh`, which puts libvirt's polkit access driver in front of
tenant scoping so that cross-tenant denial is enforced by libvirtd rather than
asserted by us. It is opt-in, reversible, and grants root and the service
accounts full access first so a mistake cannot lock an operator out of their own
hypervisor. It has never been run.

---

## 17 · The engineering record

`docs/OPERATIONS.md` records every operation, including the nine defects
introduced and fixed during this work and one diagnosis that was simply wrong.
Seven of those were only visible on real hardware: a unit invoking a module
that was never written, state directory permissions, a recursive chown that
took libvirt's disk images from qemu, `systemctl enable --now` silently leaving
old processes serving new code, an adversary script unreachable inside a 0750
home directory, a privilege check blind to insufficient privilege, and a
journal that recorded heartbeats instead of changes.

That record is deliberate. A log that reads as though everything worked first
time is not evidence of care.
