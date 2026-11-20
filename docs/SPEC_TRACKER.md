# Specification coverage

Numbers match the original 27-section brief. **Verified** identifies exercised functionality. **Implemented** identifies an artifact or code path. **Qualified** identifies a concrete variation or remaining validation. **External** requires an environment or provider outside this repository.

| Spec | Status | Implementation, evidence and qualifications |
|---|---|---|
| 1 · Mission | Verified | Independent Python project and public repository. tests/test_chain.py exercises verified containment and stale-grant rejection end to end. |
| 2 · Operating environment, packaging and licenses | Verified / External | Python and Compose run on development Linux without KVM. Dockerfile, compose.yaml, scripts and both licensing documents cover installation, health, volume and runtime terms. Organizer VM remains untested. Optional workload containers and hypervisor adapter are outside this implementation. |
| 3 · Architecture | Implemented | docs/README_ARCHITECTURE.md and IMPLEMENTATION_CONTRACTS.md trace observation, proposal, decision, execution and verification. |
| 4 · Domain | Qualified | aegis/models.py, core.py and governance.py describe and persist tenants, assets, principals, sessions, dependencies, incidents, events, proposals, decisions, approvals, capabilities and manifests. Runtime records are validated dictionaries. TypedDict contracts describe the principal wire fields. Session creation time is inferred from the fixture load and TTL. Simulated identity selection has no enterprise authentication. |
| 5 · Scenario engine | Verified | Two independent JSON fixtures, Draft 2020-12 schema and cross-reference loader. Both fixtures validated against the schema. Runtime uses standard-library validation. See tests/test_core.py. |
| 6 · Infrastructure | Verified | SQLite state and eleven simulator operations. Fixture grants, session expiry, identity status and tenant checks precede replay operations. Tests inspect actual changes, post-containment denial and rollback. |
| 7 · Context graph | Verified | Core.impact uses directed traversal, configured dependencies and session grants. UI renders runtime edges. Whole-context digest conservatively invalidates unrelated changes. |
| 8 · Process | Qualified | Fixture process definitions drive transitions. Executors emit internal signals, with state and journal writes sharing transactions. One active incident per database. The engine supports state/event transitions with checks in the calling executor; there is no general BPMN expression interpreter. |
| 9 · Decisions | Verified | Highest-priority matching declarative rules and closed operators. Deny, hold, approve and allow paths, policy drift, tamper and default-deny tests in tests/test_chain.py. |
| 10 · Roles | Qualified | Scenarios declare human and agent roles. MCP binds calls to configured investigator/planner permissions. Governance, executor and verifier are deterministic components with authority enforced in their code paths. The role catalog is not a general-purpose runtime for installing new agent types. |
| 11 · Claude / MCP | Verified / External | Pinned ClaudeSDKClient and nine in-process tools. Credentialed model smoke succeeded. Internal resource URIs map to read tools. Operator-configured HTTPS and stdio transports, restricted tools, clean subprocess environment, budgets and injection regression in tests/test_agent.py. Third-party HTTPS read remains provider-dependent. |
| 12 · Impact | Verified | Direct/transitive dependencies, critical services, tenant impact and invariants computed from local state. See test_drift_expands_identity_impact_only. |
| 13 · Gateway | Verified | Canonical request hash, simulated role-checked human approval, expiring random capabilities, transactional revalidation and single consumption. Parallel reuse and approval tamper tests. |
| 14 · Context drift | Verified | Tests both before the first identity suspension and after containment. HOLD_CONTEXT_CHANGED revokes stale authority, records before/after revisions and evaluates again. Zero executions from the invalidated handle. |
| 15 · Outcome | Verified | Independent state read, original grant probes and foreign-tenant comparisons. Missing session observations yield INDETERMINATE. See aegis/verifier.py. |
| 16 · Evidence | Verified / Qualified | Journal and downloadable JSON manifest with decisions, approvals, issued handles, executions and checks. Tool results are bounded observation summaries. Local database is editable by its administrator. No externally anchored hash chain. |
| 17 · WebUI | Verified | Local Cytoscape, topology, process, split timelines, decision cards, inbox actions, replay controls, export and polling. tests/browser-smoke.cjs passed in headless Chrome. |
| 18 · HTTP | Verified | Versioned loopback API. Aggregated state and manifest endpoints replace several suggested per-entity routes. Same-origin checks and job exclusion tested. See docs/API.md. |
| 19 · Demo scenario | Verified | Tenant B incident, three tenants, two hosts, shared backup, cross-tenant denial, high-impact denial, scoped execution and drift. The Claude proposal sequence is nondeterministic. |
| 20 · Tests | Verified | Clean offline environment, SDK-enabled suite, separate paid smoke and optional browser smoke. Commands in TESTING.md, MCP.md and API.md. |
| 21 · Phases | Verified | Development, integration, failure recovery and deployment outcomes recorded in OPERATIONS.md. |
| 22 · Delegation | Implemented | Core/scenario, UI/API and Claude/MCP implemented in separate workstreams. Integration and authority checks reviewed centrally. |
| 23 · Repository | Implemented | Compact module structure, two fixtures, schema, Docker packaging, scripts, docs and tests. README links to entry points. |
| 24 · Documentation | Implemented | English install and demo documentation, Mermaid architecture, config-generated topology, API, security, licensing, operations, limitations and tests. |
| 25 · Acceptance A–N | Verified / External | A–E and G–L verified on development Linux, F verified with live Claude and internal MCP. M has a documented runbook and automated browser walkthrough; timed jury-VM rehearsal is outstanding. N is published on public main. |
| 26 · Five-minute pitch | Implemented / External | DEMO_RUNBOOK.md gives timed operator actions. Browser smoke verifies the underlying interactions. Human delivery timing on the presentation hardware remains to be measured. |
| 27 · Final delivery | Verified | Public clone, Python suites, browser, live SDK and Docker health validated. See HANDOFF.md for environment-specific remaining work. |

## Live path coverage

The matrix above describes the fixture replay, which is unchanged and remains
the offline fallback. These rows describe the live control plane added on
20 November 2026. **Validated** means exercised against a real libvirt
connection in this repository's test suite. **Host-pending** means implemented
and unit-tested but not yet run on a hypervisor with QEMU domains.

| Spec | Status | Live implementation and qualifications |
|---|---|---|
| 1 · Mission | Validated | aegis/live.py drives propose, evaluate, issue, consume and verify against a real plane. 41 new tests. |
| 3 · Architecture | Validated | aegis/controlplane.py is the adapter boundary. docs/ADR-001-live-architecture.md traces each decision. |
| 4 · Domain | Validated | Topology is discovered from live domain XML, not declared. Shared criticality is computed from the count of observed tenants. |
| 6 · Infrastructure | Validated / Host-pending | vm.suspend and vm.resume validated end to end with independent re-read. network.isolate and network.restore implemented through virDomainUpdateDeviceFlags and unvalidated: libvirt's test driver does not support device update, so they need a QEMU domain. vm.snapshot likewise needs qcow2 backing. |
| 7 · Context graph | Validated | aegis/scope.py binds authority to reverse reachability. Unrelated change no longer revokes, which the previous global digest did by design and which would have made a live deployment unusable. |
| 9 · Decisions | Validated | Seven priority-ordered rules over facts derived entirely from measurement, defaulting to denial. Reversibility is a first-class fact. |
| 10 · Roles | Validated / Host-pending | aegis/privsep.py enforces three asymmetric roles by attempting forbidden access. The systemd units that realise the split are written and not yet installed. |
| 12 · Impact | Validated | Closure, blast-radius tenant count and critical-shared implication all computed from the discovered graph. |
| 13 · Gateway | Validated | Single-use handle bound to request and scoped context hashes, revalidated against the plane at consumption, committed before actuation so an unrollbackable call cannot fire twice. |
| 14 · Context drift | Validated | A service-catalogue entry appearing mid-incident revokes a pending handle and the refusal names the node and the tenant growth. Both directions asserted. |
| 15 · Outcome | Validated | Three-valued verification by re-reading the plane. A target that cannot be re-read is INDETERMINATE rather than FAILED. |
| 16 · Evidence | Validated / Qualified | Hash-chained journal detecting edit, deletion and reordering. Still no external anchor: whoever owns the store can rewrite it, but not silently. |
| 11 · Claude / MCP | Validated | aegis/claude_planner.py runs the model on the live path with five in-process tools, four read-only and one recording a single proposal. Smoked against the real API three times: the model read the topology and sealed observations, declined to propose on a snapshot count alone and explained why, confirmed it had not acted on the excluded guest report, and escalated a tenant-attribution inconsistency it found in the seeded data. Policy, issuance and execution remain deterministic and run after the model stops. tests/test_agent.py still errors in some environments on SDK version drift, 0.2.172 against the 0.2.185 pinned. |
| 9 · Decisions | Validated / Hardened | The gateway re-runs the policy from live topology at consumption, so a capability record is a request and not an authority. See operation 041 and tests/test_sabotage.py. |
| 17 · WebUI | Not covered | The browser console still reads the fixture path only. The live path is CLI-only. |
| 19 · Demo scenario | Validated / Host-pending | The eight-act walkthrough runs end to end against a live connection. Act 2's shared-resource denial degrades to an unpublished-action denial on a single-tenant host, so the provisioned three-tenant fixture is required for the intended narrative. |
| 20 · Tests | Validated | 78 collected, 68 pass. The 10 errors are pre-existing SDK version drift in tests/test_agent.py, which this work did not touch. |
