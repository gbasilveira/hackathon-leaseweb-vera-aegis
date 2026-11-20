#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
uname -sm
python3 --version
command -v docker >/dev/null && docker --version
[[ -e /dev/kvm ]] && echo 'KVM present' || echo 'Simulator available without KVM'
[[ -n "${ANTHROPIC_API_KEY:-}" ]] && echo 'API key configured' || echo 'Offline replay available'
