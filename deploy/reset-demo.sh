#!/bin/sh
# Put the host back into a clean pre-pitch state.
#
# Several things accumulate across rehearsals and each one silently breaks a
# later run: snapshots the adversary already created, so a re-run produces no
# new signal; guests left contained from an earlier containment, which target
# selection correctly skips; demo entries in the service catalogue; and a state
# store full of observations from whichever code was running at the time.
#
# Run this before rehearsing and before presenting.
set -eu

BASE=/var/lib/aegis
STATE="$BASE/state.json"
CATALOGUE="$BASE/catalogue.json"
GUESTS="tenant-b--app tenant-c--svc tenant-b--sandbox"

[ "$(id -u)" = 0 ] || { echo "run this with sudo" >&2; exit 1; }

say() { printf '\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }

say "1 · Release every contained guest"
# Use the adapter, not virsh. virsh domif-setlink was failing here with its
# error discarded, so the script reported links up while the guests stayed
# contained and the walkthrough then started from the wrong state. The adapter
# path is the one the gateway uses and is known to work on this host.
cd "$(dirname "$0")/.." 2>/dev/null || true
python3 - "$GUESTS" <<'PYEOF' || echo "  WARNING: release failed; see the error above"
import sys
from aegis.libvirt_plane import LibvirtControlPlane
from aegis.controlplane import PlaneError

plane = LibvirtControlPlane("qemu:///system")
for guest in sys.argv[1].split():
    state = plane.read_state(guest)
    if not state:
        print(f"  {guest}: not defined")
        continue
    if state.get("isolated"):
        try:
            effect = plane.actuate("network.restore", guest)
            print(f"  {guest}: restored {effect.get('interfaces')}")
        except PlaneError as error:
            print(f"  {guest}: RESTORE FAILED: {error}")
    if state.get("state") == "paused":
        try:
            plane.actuate("vm.resume", guest)
            print(f"  {guest}: resumed")
        except PlaneError as error:
            print(f"  {guest}: RESUME FAILED: {error}")
    after = plane.read_state(guest)
    mark = "" if not after.get("isolated") else "  <-- STILL CONTAINED"
    print(f"  {guest}: links {after.get('links')} state {after.get('state')}{mark}")
PYEOF

say "2 · Remove rehearsal snapshots"
for guest in $GUESTS; do
  virsh dominfo "$guest" >/dev/null 2>&1 || continue
  removed=0
  for snap in $(virsh snapshot-list --domain "$guest" --name 2>/dev/null); do
    [ -n "$snap" ] || continue
    virsh snapshot-delete --domain "$guest" --snapshotname "$snap" >/dev/null 2>&1 && removed=$((removed + 1))
  done
  note "$guest: removed $removed snapshot(s)"
done

say "3 · Clear the walkthrough's catalogue entries"
python3 - "$CATALOGUE" <<'PY'
import json, sys
path = sys.argv[1]
demo = ("svc-unrelated", "svc-billing")
try:
    data = json.load(open(path))
except (OSError, ValueError):
    data = {}
data["nodes"] = {k: v for k, v in data.get("nodes", {}).items() if k not in demo}
data["edges"] = [e for e in data.get("edges", []) if e.get("source") not in demo]
json.dump(data, open(path, "w"), indent=2)
print(f"  catalogue holds {len(data['nodes'])} declared node(s)")
PY

say "4 · Archive the state store and start a fresh chain"
if [ -f "$STATE" ]; then
  stamp=$(date +%Y%m%d-%H%M%S)
  cp "$STATE" "$BASE/state-$stamp.json"
  note "previous journal kept at $BASE/state-$stamp.json"
fi
echo '{"capabilities": {}, "entries": [], "topology": null}' > "$STATE"
chown "root:aegis" "$STATE" 2>/dev/null || true
chmod 664 "$STATE"
note "fresh store; the chain starts from genesis"

say "5 · Optional SDK for the Claude planner"
PY=/opt/aegis/venv/bin/python3
[ -x "$PY" ] || PY=python3
if "$PY" -c 'import claude_agent_sdk' >/dev/null 2>&1; then
  note "claude-agent-sdk present for $PY"
else
  note "claude-agent-sdk missing: the model planner will report itself unavailable"
  note "install it without touching Debian's packages:"
  note "  sudo python3 -m venv --system-site-packages /opt/aegis/venv"
  note "  sudo /opt/aegis/venv/bin/pip install claude-agent-sdk==0.2.185"
fi
if [ -s /etc/aegis/planner.env ]; then
  note "/etc/aegis/planner.env is populated"
else
  note "/etc/aegis/planner.env is empty: add the key for the model planner"
fi

say "6 · Restart the services on current code"
for unit in aegis-sensor aegis-gateway aegis-planner; do
  systemctl list-unit-files "$unit.service" >/dev/null 2>&1 || continue
  systemctl reset-failed "$unit" 2>/dev/null || true
  systemctl restart "$unit" 2>/dev/null || note "$unit did not restart"
done
sleep 3
for unit in aegis-sensor aegis-gateway aegis-planner; do
  printf '  %-16s %s\n' "$unit" "$(systemctl is-active "$unit" 2>/dev/null || echo absent)"
done

say "Clean."
virsh list --all
echo
echo "Confirm, then present:"
echo "  python3 -m aegis.live --catalogue $CATALOGUE topology    # no guest marked (contained)"
