# ADR 001 · From simulated incident to live control plane

**Date** 20 November 2026 · **Status** implemented, pending validation on the organiser VM

## Context

The committed demonstration was a deterministic replay. `Core.step` walked a
list of hand-written events from `scenarios/control-plane-compromise.json` and
applied them to SQLite JSON collections. The defence read the same collections
through the same `Core.apply` and `Core.probe` functions that the replay used,
in the same process, against the same database file.

That made three claims unavailable to us.

The attack and the defence were not independent, so nothing about the
mechanism's safety could be demonstrated: the fixture that described the attack
also supplied the evidence the policy consumed, and the function that replayed
an attacker action was the function that executed a containment.

The topology was declared. A fixture asserted that a host was critical and
shared. The policy then denied actions on it, which proved only that the
fixture and the policy agreed with each other.

Nothing executed. `identity.suspend` set a string field in a JSON blob. No
claim about containment survived contact with a system that can actually refuse
a packet.

The review that preceded this work also identified a defect that would have
made a live deployment unusable, and one that would have made it dangerous.
Both are addressed below as decisions 1 and 2.

## Decisions

### 1 · Authority is bound to the impact closure, not to global state

**Gap.** `Governance.assess` digested `revision`, `dependencies`, `assets`,
`sessions`, `identities` and `tenants` into one `context_digest`, and
`THREAT_MODEL.md` recorded the consequence as intentional: *"Global context
digests deliberately invalidate grants on unrelated state changes."* On a
fixture that is conservative. On a hypervisor where guests start, stop and
migrate continuously, every capability would be revoked within seconds of
issue, before any operator could spend it. The mechanism would have had to be
switched off to demo it, which would have removed the thing worth demoing.

**Decision.** `aegis/scope.py` computes the reverse-reachable set of the
target — everything that transitively depends on it — and digests only that
closure: the authority-relevant fields of each member, the edges incident to
the closure, and the set of owning tenants. Volatile telemetry is excluded by
construction, through an explicit `SCOPED_FIELDS` allowlist.

**Why reverse reachability.** The question a capability must answer is "has the
set of parties this action can harm changed". That set is the dependants of the
target. What the target itself depends on is excluded: isolating a guest does
not harm the bridge beneath it, so bridge load must not revoke the grant. The
*wiring* attaching the target to its dependencies is still committed to, so a
migration does revoke, because the action's context genuinely changed.

**Consequence.** The mechanism becomes precise instead of merely paranoid, and
precision is demonstrable in both directions, which is a stronger claim than
revocation alone. A refusal also names the responsible node, via
`scope.explain`, instead of reporting an opaque digest mismatch.

**Evidence.** `tests/test_scope.py` asserts both directions, including that a
new guest joining a shared bridge preserves authority while a new dependant
revokes it. `tests/test_gateway.py::test_unrelated_world_change_does_not_cost_authority`
and `::test_new_dependant_revokes_authority_and_names_the_node` assert the same
through the gateway.

### 2 · Consumption is committed before actuation

**Gap.** `Governance.execute` called `core.apply` and then `verify` inside one
`core.tx()`. A SQLite transaction can be rolled back. A `virsh` call cannot. If
the process died between spending a capability and completing the action, the
transaction would unwind and the handle would still be live, so the same
irreversible action could fire twice.

**Decision.** `Gateway.consume` moves the capability to `consuming` and commits
that before touching the plane. An actuator failure is caught, the handle is
marked `consumed`, and the result is `INDETERMINATE`.

**Consequence.** The failure mode is a refused retry, never a second execution.
A human decides what to do about an unknown outcome; the system does not guess.

**Evidence.** `tests/test_gateway.py::test_actuator_failure_is_indeterminate_and_spends_the_handle`.

### 3 · Topology is measured, not declared

**Decision.** `LibvirtControlPlane.discover` reads every domain's live XML and
emits guests, the host, the networks they attach to and the storage directories
they occupy. Shared criticality is then *computed*: an infrastructure node
carrying more than one observed tenant is marked shared and critical.

**Consequence.** The denial that protects other tenants stops being an
assertion. Two tenants were observed on that bridge, therefore a broad action
there crosses a tenant boundary, therefore it is denied. During the walkthrough
the node reports the tenants it observed, so the audience can check the
arithmetic.

**Evidence.** Validated against a live libvirt connection; see operation 013 in
`OPERATIONS.md`. `tests/test_live.py::test_shared_infrastructure_is_denied_because_it_was_measured`
asserts the policy consequence.

### 4 · Policy facts are derived from observation

**Gap.** The fixture policy hard-coded two action names:
`sensitive = action not in {"session.suspend", "identity.suspend"}` and
`limited` as its complement. The declarative rules in the JSON were then
overridden by an imperative `DENY_SCOPE` block. It was not a policy engine.

**Decision.** `live.facts` derives every fact from measured topology: whether
the target is shared, how many tenants are in the closure, whether a critical
shared node is implicated, whether the action is reversible, whether the
target exists at all. `live.POLICY` is seven priority-ordered rules over those
facts, defaulting to denial.

**Consequence.** Adding a guest changes the decision without editing a rule.
Reversibility becomes a first-class fact, so an irreversible action requires a
human even when its blast radius is small.

**Evidence.** `tests/test_live.py::PolicyTest`, including
`test_blast_radius_growth_flips_an_allowed_action_to_denied`.

### 5 · Containment uses primitives a hypervisor actually has

**Gap.** `identity.suspend` modelled revoking a federated identity, which this
layer cannot do: there is no IdP, and `LIMITATIONS.md` recorded the absence of
"provider-specific token revocation semantics".

**Decision.** The published actions are `network.isolate`, `network.restore`,
`vm.suspend`, `vm.resume` and `vm.snapshot`. Isolation drops the link on every
guest interface through `virDomainUpdateDeviceFlags` with `AFFECT_LIVE`, the
mechanism behind `virsh domif-setlink`.

**Why link state.** It is immediate, it survives a guest reboot, the guest can
neither see nor block it, it is reversible, and it is verifiable from the host
by re-reading the live domain XML. For a hypervisor it is the honest
containment action.

**Consequence.** `host.stop` is not merely denied by policy, it is absent from
`ACTIONS`, so the plane refuses it before any rule evaluates. An action a
component cannot perform is a stronger guarantee than one it is told not to.

**Evidence.** `vm.suspend` and `vm.resume` validated end to end against a live
connection, with state moving `running → paused → running` and verified by
independent re-read. `network.isolate` is correctly unsupported by libvirt's
test driver and raises `PlaneError`; it requires a QEMU domain.

### 6 · Guest-side signal may never carry authority

**Gap.** The injection string lived in a fixture field, and `core.py` blocked
untrusted events from holding write permissions. With real guests the planner
reads attacker-influenced text: hostnames, filenames, log lines.

**Decision.** Observations carry a trust level.
`controlplane.authority_facts` partitions them and drops everything that is
not `TRUST_HYPERVISOR`. Guest reports are still journalled, labelled
`excluded_from_decisions`, so a human can read them and the system cannot act
on them.

**Why partition rather than sanitise.** There is no reliable way to tell a
genuine guest log from one the attacker wrote. Filtering invites a bypass;
excluding the channel does not.

**Consequence.** This is the property that makes QEMU the right substrate:
domain state, device link state and tap counters cannot be forged without
escaping the virtual machine, so there is a real trust boundary to point at
rather than a declared one.

### 7 · The monolith is split, and each process proves its own limits

**Gap.** The single most dangerous design in the proposed architecture was one
binary holding both a model credential and the hypervisor socket. Compromising
it would equal owning every guest, and the authorisation gateway inside it
would be decorative.

**Decision.** Three processes with asymmetric privileges, and
`aegis/privsep.py` asserting the asymmetry at startup by *attempting* the
forbidden access and refusing to start if it succeeds. The checks are negative
on purpose: "I cannot reach libvirt, and I verified that by trying" is the
property worth having, because misconfiguration usually grants more access than
intended, not less.

| Process | Hypervisor | Network | Model credential |
|---|---|---|---|
| sensor | read-only socket | denied | forbidden |
| planner | denied by namespace | permitted | required |
| gateway | read-write socket | denied | forbidden |

**Why both halves matter.** The planner has egress and no hypervisor. The
gateway has the hypervisor and no egress, enforced by `PrivateNetwork=yes` and
`IPAddressDeny=any`: even a leaked key in its environment reaches nothing.
Neither process can do the other's job, so neither compromise is sufficient.

The planner is denied libvirt twice over. libvirt's read-only socket is
world-readable, so group membership alone would not be enough;
`InaccessiblePaths=/run/libvirt` hides it. If someone removes that line,
`privsep` refuses to start the process. Two independent mechanisms must fail
together.

The gateway's socket protocol has exactly one operation, consumption. There is
no way to submit a proposal, change a policy or pass free text through it, so a
compromised planner can ask only for an action it was already granted.

**Evidence.** `tests/test_privsep.py` uses libvirt's test driver as a socket a
process should not have been able to open, and asserts that each role detects
it. `tests/test_gateway.py::test_gateway_refuses_to_start_with_model_credentials`
asserts the gateway aborts.

### 8 · Evidence is sealed in a hash chain

**Gap.** `manifest()` returned a SQLite dump, and the document admitted that an
administrator could rewrite it.

**Decision.** `aegis/chain.py` seals every journal entry against the digest of
the one before it. `verify_chain` reports the index and identifier of the first
broken link.

**Consequence.** Whoever owns the database can still rewrite the evidence, but
no longer silently: every downstream link breaks. Publishing the chain head at
handover is the one action that makes the journal non-repudiable. This is
deliberately not a signature, and anchoring the head externally remains an
operator decision rather than something the code pretends to do.

**Evidence.** `tests/test_evidence_chain.py` covers edit, deletion, reordering
and append. The walkthrough tampers with an entry live and prints the broken
index.

### 9 · The attacker shares no code with the defence

**Decision.** `deploy/attacker.sh` runs as its own unix account and drives
stock `virsh`. It imports no project code, links no project library and shares
no process, socket or database with the defence. The only thing both touch is
the hypervisor.

Nothing in it is an exploit. The premise is a compromised operator credential,
so the activity is ordinary control-plane usage in an unusual pattern: broad
enumeration, then repeated snapshotting, then probing other tenants' guests.
That pattern is what a detector sees in production.

**Decision, service dependencies.** A hypervisor knows that a guest sits on a
bridge. It cannot know that a billing service depends on that guest. That lives
in a CMDB. `LibvirtControlPlane` therefore merges a service catalogue, re-read
on every discovery, with the infrastructure graph it observes. A catalogue entry
appearing mid-incident is the realistic way a blast radius grows, and it is what
costs a pending capability its authority during the walkthrough.

**Decision, tenant enforcement.** `deploy/enable-acl.sh` turns on libvirt's
polkit access driver and scopes the attacker credential to its own tenant's
domains, so cross-tenant denial is enforced by libvirtd rather than asserted by
us. It is opt-in and reversible, and it grants root and the service accounts
full access first so that a mistake cannot lock an operator out of their own
hypervisor. Untested on the target host; see the remaining work below.

## What this does and does not prove

It proves that a language model can drive incident response without ever
holding credentials, that stale authority is both dangerous and preventable
with a mechanism precise enough to leave unrelated change alone, that blast
radius can be computed from discovered topology, and that verification can be
independent of the actuator's return value.

It does not prove that detection works. The sensor is the weakest link and the
hardest to validate; a scripted walkthrough says nothing about precision or
recall on real traffic. It does not prove the model's proposals are good — it
proves bad proposals are contained, which is a different and more defensible
claim, and the one worth making: the mechanism does not require trusting the
model. It remains a single host, with no federated identity and no cloud
control plane.

## Remaining work

| Priority | Operation | Completion evidence |
|---|---|---|
| Before presenting | Run `deploy/provision.sh` on the organiser VM, confirm three guests boot and that discovery reports the shared network as critical with two observed tenants. | `virsh list --all`, `aegis.live topology` output, elapsed boot time under TCG if `/dev/kvm` is absent. |
| Before presenting | Run the walkthrough against a provisioned host with `--action network.isolate`. | Act 5 showing `isolated: True` and Act 6 naming the catalogue node. |
| Before presenting | Install the three units, confirm `aegis.live privileges` reports no violation per role. | Privilege matrix with three clean rows. |
| If tenant enforcement is part of the pitch | Run `deploy/enable-acl.sh` and verify libvirtd refuses the attacker on a foreign domain. | polkit denial in the journal. |
| Pending | The fixture path still uses the global digest and the old facts. It is the offline fallback and is untouched by this work. | Either port it to `aegis.scope` or document it as legacy. |
