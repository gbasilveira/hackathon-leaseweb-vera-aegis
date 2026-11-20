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
VENV=/opt/aegis/venv
UNITS=/etc/systemd/system
SDK_VERSION=0.2.185

[ "$(id -u)" = 0 ] || { echo "run this with sudo" >&2; exit 1; }
[ -d /var/lib/aegis ] || { echo "run deploy/provision.sh first" >&2; exit 1; }

say() { printf '\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }

say "1 · Application"
mkdir -p "$TARGET"
cp -r "$SOURCE/aegis" "$TARGET/"
find "$TARGET" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
note "copied the package to $TARGET/aegis"

say "2 · Interpreter"
# One interpreter for all three services, in a virtual environment that can
# still see the distribution's libvirt binding. The optional SDK must not go
# into Debian's python: pip cannot uninstall the typing_extensions that ships
# with the distribution, because it has no RECORD file, so the install aborts
# halfway.
# Without python3-venv the venv module produces a tree with no working pip, so
# the environment looks present and every install into it fails. Check for a
# usable pip rather than for the directory.
if ! "$VENV/bin/python3" -m pip --version >/dev/null 2>&1; then
  [ -d "$VENV" ] && note "replacing $VENV: it has no usable pip"
  rm -rf "$VENV"
  python3 -m venv --system-site-packages "$VENV" 2>/dev/null \
    || { apt-get install -y -qq python3-venv >/dev/null 2>&1 \
         && python3 -m venv --system-site-packages "$VENV"; }
  if "$VENV/bin/python3" -m pip --version >/dev/null 2>&1; then
    note "created $VENV with a working pip"
  else
    note "WARNING: could not build a usable environment; install python3-venv"
  fi
else
  note "$VENV present with a working pip"
fi
if "$VENV/bin/python3" -c 'import libvirt' 2>/dev/null; then
  note "libvirt binding visible inside the environment"
else
  # Not fatal. The environment is only used by the planner, which is forbidden
  # libvirt anyway, so a missing binding there costs nothing. It is reported
  # because it usually means the environment was built against a different
  # interpreter than the one python3-libvirt was installed for.
  note "libvirt not visible in the environment; only the planner uses it, so this is fine"
fi
if "$VENV/bin/python3" -c 'import claude_agent_sdk' 2>/dev/null; then
  note "claude-agent-sdk present"
elif [ "${WITH_CLAUDE:-1}" = 1 ]; then
  # Show why, rather than swallowing it. A silent failure here is how the model
  # planner ends up reporting itself unavailable with no explanation.
  if "$VENV/bin/python3" -m pip install -q "claude-agent-sdk==$SDK_VERSION" 2>/tmp/aegis-sdk.log; then
    note "installed claude-agent-sdk==$SDK_VERSION"
  else
    note "could not install the SDK; the model planner will be unavailable:"
    tail -4 /tmp/aegis-sdk.log 2>/dev/null | sed 's/^/    /'
  fi
fi

say "3 · Adversary script"
# A 0750 home directory makes this unreadable to the adversary account, which
# is where the runbook pointed people and why the script silently never ran.
install -m 755 "$SOURCE/deploy/attacker.sh" "$TARGET/attacker.sh"
note "installed to $TARGET/attacker.sh, reachable by the demo-attacker account"

say "4 · Planner credential"
mkdir -p /etc/aegis
if [ ! -f /etc/aegis/planner.env ]; then
  install -m 600 -o aegis-planner -g aegis-planner /dev/null /etc/aegis/planner.env
  note "created an empty /etc/aegis/planner.env mode 0600"
  note "add the key with:"
  note "  sudo sh -c 'printf \"ANTHROPIC_API_KEY=%s\\n\" \"\$KEY\" > /etc/aegis/planner.env'"
else
  note "/etc/aegis/planner.env already exists, left untouched"
fi

say "5 · Units"
# Each service gets the interpreter that can do its job, which turns out to
# mirror the privilege split exactly. The sensor and the gateway need the
# libvirt binding and never a model; they use the distribution's python, where
# python3-libvirt is installed. The planner needs the SDK and must never reach
# libvirt; it uses the environment. Pointing all three at the environment broke
# the sensor and the gateway on a host where it could not see the binding.
for unit in "$SOURCE"/deploy/systemd/aegis-*.service; do
  name=$(basename "$unit")
  if [ "$name" = aegis-planner.service ] && [ -x "$VENV/bin/python3" ]; then
    sed "s#^ExecStart=/usr/bin/python3#ExecStart=$VENV/bin/python3#" "$unit" > "$UNITS/$name"
    note "$name runs $VENV/bin/python3"
  else
    cp "$unit" "$UNITS/$name"
    note "$name runs /usr/bin/python3"
  fi
done
systemctl daemon-reload

# A service pointed at an interpreter that cannot import what it needs fails on
# start, and Restart=on-failure makes that look briefly healthy.
/usr/bin/python3 -c 'import libvirt' 2>/dev/null \
  || note "WARNING: /usr/bin/python3 cannot import libvirt; sensor and gateway will fail"
note "installed sensor, planner and gateway"

say "6 · Start"
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
echo "Run anything that touches libvirt with the distribution interpreter:"
echo "  cd /opt/aegis && sudo python3 -m aegis.live --help"
echo "Run the model planner or compare with the environment:"
echo "  cd /opt/aegis && sudo sh -c 'export \$(cat /etc/aegis/planner.env) && \\"
echo "      $VENV/bin/python3 -m aegis.live --store /var/lib/aegis/state.json compare'"
echo
echo "The live console, read-only, on loopback:"
echo "  cd /opt/aegis && sudo python3 -m aegis.live \\"
echo "      --store /var/lib/aegis/state.json board"
echo "  then from your laptop: ssh -L 8780:127.0.0.1:8780 ubuntu@<host>"
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
