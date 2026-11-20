#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
exec "${PYTHON:-python3}" -m unittest tests.test_chain.Chain.test_full_offline_chain tests.test_chain.Chain.test_drift_prevents_first_suspension tests.test_chain.Chain.test_later_fixture_attempts_observe_containment -v
