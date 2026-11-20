# Authorization and execution

The investigator reads observations. The response planner submits typed operations with explicit evidence references and assumptions. The two logical roles can share a Claude session. Governance evaluates highest-priority matching policy rules and uses default deny. Equality, ordering, membership, containment and boolean combinations use closed Python operator mappings. Unknown operations, incompatible target kinds and tenant scope checks also have enforcement in the gateway service.

Approval is a separate operator gesture on the evaluated proposal. The active simulated human must hold the incident owner role in the same tenant. Before issuing a capability, the service recomputes the request hash, impact, context and policy digests. A negative decision produces no capability. An approval expires after five minutes.

The execution input is an opaque, random server-side handle. The gateway obtains an immediate SQLite write transaction, checks status, expiration, proposal content, policy and context, then consumes the handle with the mutation. Concurrent consumers serialize. A drift rejection journals both revisions and triggers a fresh decision. Only a newly issued capability can authorize another attempt. The verifier rereads state inside the same transaction. A rollback discards partial execution.

The simulator's effective access check combines session status, identity status and configured grants. A verifier probe tests access after suspension without changing a workload. Foreign tenants' assets, identities and sessions are compared before and after execution.
