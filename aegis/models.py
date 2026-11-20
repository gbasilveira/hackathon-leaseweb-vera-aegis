"""JSON wire types shared by the scenario, policy and evidence boundaries."""
from typing import Any, Literal, NotRequired, TypedDict

JsonObject = dict[str, Any]


class Tenant(TypedDict):
    id: str
    name: str
    policies: NotRequired[list[str]]
    criticality: NotRequired[str]
    owner: NotRequired[str]
    metadata: NotRequired[JsonObject]


class Asset(TypedDict):
    id: str
    type: str
    tenant_id: str
    name: str
    state: str
    criticality: str
    shared: bool
    metadata: NotRequired[JsonObject]


class Identity(TypedDict):
    id: str
    tenant_id: str
    type: str
    status: str
    permissions: list[JsonObject]
    roles: list[str]


class Session(TypedDict):
    id: str
    identity_id: str
    tenant_id: str
    status: Literal["active", "suspended", "revoked", "expired"]
    permissions: list[JsonObject]


class Dependency(TypedDict):
    source: str
    target: str
    relation: NotRequired[str]
    type: NotRequired[str]


class Proposal(TypedDict):
    action_type: str
    target_id: str
    evidence_refs: list[str]
    parameters: JsonObject
    rationale: str
    expected_effect: str
    assumptions: list[str]


class Decision(TypedDict):
    id: str
    proposal_id: str
    result: Literal["ALLOW", "DENY", "HOLD", "REQUIRE_APPROVAL"]
    reason_codes: list[str]
    context_digest: str
    context_revision: int
    policy_digest: str
    policy_id: str
    policy_version: str
    timestamp: float
    impact: JsonObject


class Approval(TypedDict):
    id: str
    proposal_id: str
    request_hash: str
    approver_id: str
    approver_role: str
    decision: str
    created_at: float
    expires_at: float


class Capability(TypedDict):
    id: str
    nonce: str
    status: Literal["issued", "consumed", "expired", "revoked"]
    issued_at: float
    expires_at: float
    tenant_id: str
    proposal_id: str
    proposal_hash: str
    action_type: str
    target_id: str
    policy_digest: str
    context_digest: str
    context_revision: int
    decision_id: str


class Event(TypedDict):
    id: str
    sequence: int
    timestamp: str
    actor_id: str
    tenant_id: str
    event_type: str
    target_id: str
    outcome: str
    payload: JsonObject
    trust_level: str
    source: str


class Incident(TypedDict):
    id: str
    scenario_id: str
    tenant_id: str
    severity: str
    state: str
    evidence_refs: list[str]
    context_revision: int


class Manifest(TypedDict):
    incident_id: str
    context_revision: int
    events: list[Event]
    proposals: list[Proposal]
    decisions: list[Decision]
    capabilities: list[Capability]
    approvals: list[Approval]
    executions: list[JsonObject]
    verifications: list[JsonObject]
    final_state: str
    limitations: list[str]
