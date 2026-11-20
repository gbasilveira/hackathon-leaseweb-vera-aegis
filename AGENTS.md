# Working on VERA Aegis

Read docs/HANDOFF.md, docs/SPEC_TRACKER.md and docs/OPERATIONS.md before changing behavior. Use Git history for exact diffs. Preserve the user's autonomous execution policy and the simulator, agent and gateway boundaries in docs/IMPLEMENTATION_CONTRACTS.md.

For each implementation, deployment or validation operation, append an entry to docs/OPERATIONS.md with its date, spec identifiers, files or commands, observed result and any follow-up. Include failed attempts that affect reproducibility or trust. Update the affected spec rows and the next actionable item in docs/HANDOFF.md. Record verification commands and outcomes. Keep credentials, model transcripts and private infrastructure details out of tracking. This engineering log is separate from the application's incident event journal.

Run the offline tests first. Run the paid live smoke only when the change or deployment needs live validation. The reproducible browser and CLI procedures are in docs/API.md and docs/TESTING.md.
