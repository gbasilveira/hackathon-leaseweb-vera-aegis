# Implementation contracts

The single Python service owns one simulator database. Core.tx serializes writers with SQLite BEGIN IMMEDIATE. Fixture replay receives a configured operation and a simulated session. Defenders enter through Governance.submit, evaluate, approve and execute. The model receives the submission interface through the scoped tool dispatcher.

A proposal binds incident, tenant, planner, action, target, parameters, evidence IDs, rationale, expected effect and assumptions. SHA-256 covers the complete sorted JSON object. Evaluation records policy and context digests. Each capability contains a random server-side handle, a nonce, expiry, proposal hash and decision ID. The gateway checks the stored handle in the same transaction as mutation, consumption and observation. A new decision supersedes issued handles for that proposal.

The verifier rereads inventory and session grants. Its three-valued result distinguishes missing observations from observed failures. The graph digest includes all tenants and simulated infrastructure state. An unrelated change can therefore force reevaluation.

The browser is a trusted local demonstration operator. An MCP invocation cannot select an approver or invoke the gateway. JSON configuration is operator-controlled. Event text, external tool responses and model output are untrusted.
