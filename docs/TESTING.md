# Verification

Run `./scripts/test.sh` from a clean checkout. The tests create temporary databases and exercise replay, authority checks, operator requests and the offline chain. Run `./scripts/demo.sh` to exercise the deterministic governance demonstration in isolation. SDK-specific option tests can also run in the optional environment. See MCP.md for the credentialed smoke procedure.

Inspect `docker compose ps` and GET `/api/v1/health` after deployment. Reset the primary scenario for a clean presentation. Export the evidence first if you need to retain it.

## Deployment validation

On 20 November 2026, the public checkout passed 37 Python tests with the pinned optional SDK installed. The clean standard-library environment passed 36 tests and skipped the SDK configuration test. The browser smoke passed against headless Chrome, including simulated human approval, export and context drift. The Docker service returned a healthy response on Linux without KVM. A separate credentialed Claude smoke submitted an evidence-backed proposal through MCP without producing any capability or execution record.
