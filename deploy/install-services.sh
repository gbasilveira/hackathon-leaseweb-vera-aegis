#!/bin/sh
# Install the three-process deployment.
#
# Until this runs, the privilege split is code and tests rather than a running
# system: the walkthrough driver is one process that both decides and actuates.
# These units are what make the separation real.
#
#   sensor   reads the hypervisor read-only, publishes topology and observations
#   planner  reads what the sensor published, proposes, holds no hypervisor
#   gateway  holds the only writable hypervisor socket, holds no network
set -eu

SOURCE=$(cd "$(dirname "$0")/.." && pwd)
TARGET=/opt/aegis
UNITS=/etc/systemd/system

[ "$(id -u)" = 0 ] || { echo "run this with sudo" >&2; exit 1; }
[ -d /var/lib/aegis ] || { echo "run deploy/provision.sh first" >&2; exit 1; }

say() { printf '\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }

say "1 · Application"
mkdir -p "$TARGET"
cp -r "$SOURCE/aegis" "$TARGET/"
find "$TARGET" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
note "copied the package to $TARGET/aegis"

say "2 · Adversary script"
# A 0750 home directory makes this unreadable to the adversary account, which
# is where the runbook pointed people and why the script silently never ran.
install -m 755 "$SOURCE/deploy/attacker.sh" "$TARGET/attacker.sh"
note "installed to $TARGET/attacker.sh, reachable by the demo-attacker account"

say "3 · Planner credential"
mkdir -p /etc/aegis
if [ ! -f /etc/aegis/planner.env ]; then
  install -m 600 -o aegis-planner -g aegis-planner /dev/null /etc/aegis/planner.env
  note "created an empty /etc/aegis/planner.env mode 0600"
  note "add the key with:"
  note "  sudo sh -c 'printf \"ANTHROPIC_API_KEY=%s\\n\" \"\$KEY\" > /etc/aegis/planner.env'"
else
  note "/etc/aegis/planner.env already exists, left untouched"
fi

say "4 · Units"
cp "$SOURCE"/deploy/systemd/aegis-*.service "$UNITS/"
systemctl daemon-reload
note "installed sensor, planner and gateway"

say "5 · Start"
# `enable --now` does nothing to a unit that is already active, so on a second
# run it would copy the new code and leave the old processes serving it. Enable
# for boot, then restart unconditionally.
#
# Sensor first: it publishes the topology the planner reads. Gateway next, so
# its socket exists before the planner asks anything of it.
systemctl reset-failed aegis-sensor aegis-gateway aegis-planner 2>/dev/null || true
systemctl enable aegis-sensor aegis-gateway aegis-planner >/dev/null 2>&1 || true
systemctl restart aegis-sensor aegis-gateway
sleep 3
systemctl restart aegis-planner || note "planner did not start; see journalctl -u aegis-planner"
sleep 2
note "restarted all three, so they run the code just copied"

say "Status"
for unit in aegis-sensor aegis-gateway aegis-planner; do
  state=$(systemctl is-active "$unit" 2>/dev/null || true)
  printf '  %-16s %s\n' "$unit" "$state"
done
echo
echo "Verify the boundaries, each under its own account:"
echo "  sudo -u aegis-sensor  python3 -m aegis.live --uri qemu:///system privileges"
echo "  sudo systemd-run -p User=aegis-planner -p InaccessiblePaths=/run/libvirt \\"
echo "      --pty python3 -m aegis.live privileges"
echo
echo "Run the adversary from a path its account can actually read:"
echo "  sudo -u demo-attacker /opt/aegis/attacker.sh tenant-b--sandbox"
echo
echo "Watch the three processes work:"
echo "  sudo journalctl -u aegis-sensor -u aegis-planner -u aegis-gateway -f"
echo
echo "If a unit fails, the likely causes in order: a missing shared group or"
echo "state permission (re-run deploy/provision.sh), MemoryDenyWriteExecute"
echo "against a Python extension, or ProtectSystem=strict hiding a path."
