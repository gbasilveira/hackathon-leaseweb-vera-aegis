# Local web API

The API and browser interface share an HTTP origin. The service binds to IPv4 loopback by default and accepts the local authority for its configured port. For containers, bind to `0.0.0.0` and publish the same port on host loopback. Requests with an `Origin` header must match the authority in `Host`. Local command-line clients can omit `Origin`. Request bodies use `Content-Type: application/json` and are limited to 8 KiB.

One SQLite file represents the current simulation. The server resumes an existing incident on startup. Load or reset starts a new incident generation and clears the current simulation's records.

| Method | Path | Request body and result |
| --- | --- | --- |
| GET | `/api/v1/health` | `{"status":"ok"}` |
| GET | `/api/v1/scenarios` | List of available scenario IDs, titles, and descriptions |
| GET | `/api/v1/manifest` | Download the current incident manifest as JSON |
| GET | `/api/v1/state` | Current simulator snapshot, governance manifest, and background job status |
| POST | `/api/v1/load` | `{"scenario_id":"control-plane-compromise"}` |
| POST | `/api/v1/reset` | `{}` |
| POST | `/api/v1/step` | `{}` advances one replay event |
| POST | `/api/v1/replay` | `{}` starts playback from the current cursor |
| POST | `/api/v1/speed` | `{"speed":2}` sets playback speed. Supported multipliers are 0.5, 1, 2, and 4. |
| POST | `/api/v1/pause` | `{}` pauses playback at the current cursor |
| POST | `/api/v1/investigate` | `{"mode":"DETERMINISTIC_REPLAY","alternative":false}` starts an investigation. The other mode is `CLAUDE`. |
| POST | `/api/v1/change` | `{}` applies the fixture's context change |
| POST | `/api/v1/evaluate` | `{"proposal_id":"…"}` evaluates a proposal under the current policy and context |
| POST | `/api/v1/approve` | `{"proposal_id":"…","actor":"…","accept":true}` records the named incident owner's decision |
| POST | `/api/v1/execute` | `{"capability_id":"…"}` attempts the narrowly scoped simulator action |

Successful POST responses contain the same state as `GET /api/v1/state`. Execution additionally exposes the gateway result in `result`. The state payload contains `snapshot`, `manifest`, `speed`, `policy_digest`, and `job`. After starting a background job, poll until `job.state` is `complete` or `failed`. Results from an investigation include the mode, proposal IDs, and summary. Polls also show tool-call events recorded while the investigation runs. Mutations conflict with an active job and return HTTP 409. Reset and load can stop playback between events.

HTTP errors contain an `error` string. A gateway decision can reject or hold execution while returning HTTP 200 because that decision is recorded as part of the simulation.

Cytoscape.js 3.35.0 is served locally under its MIT license. See [license](/vendor/CYTOSCAPE-LICENSE.txt) in the running console.

## Browser smoke test

The console, tests that exercise HTTP, and runtime work without Node. The optional browser test uses Node.js 18 or later and Playwright. It starts an isolated server on a random loopback port, creates a temporary SQLite database, and removes the test files when it finishes.

From the repository root on a POSIX shell, install the optional tools into a temporary directory and run the test.

```sh
test_tools="$(mktemp -d)"
npm install --prefix "$test_tools" playwright@1.56.1
"$test_tools/node_modules/.bin/playwright" install chromium
NODE_PATH="$test_tools/node_modules" node tests/browser-smoke.cjs
```

Set `CHROME_PATH` to use an existing Chromium or Google Chrome executable instead of installing Chromium. Set `PYTHON` to select Python 3.11 or later. Run `python -m unittest tests.test_web -v` for the dependency-free HTTP tests.
