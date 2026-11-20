# Verification

Run `./scripts/test.sh` from a clean checkout. The tests create temporary databases and exercise replay, authority checks, operator requests and the offline chain. Run `./scripts/demo.sh` to exercise the deterministic governance demonstration in isolation. SDK-specific option tests can also run in the optional environment. See MCP.md for the credentialed smoke procedure.

Inspect `docker compose ps` and GET `/api/v1/health` after deployment. Reset the primary scenario for a clean presentation. Export the evidence first if you need to retain it.
