#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m venv .venv
if [[ "${WITH_CLAUDE:-0}" == 1 ]]; then .venv/bin/pip install -r requirements-claude.txt; fi
