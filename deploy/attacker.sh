#!/bin/sh
# Adversary workload. Runs as demo-attacker with legitimate operator
# credentials, using nothing but the stock libvirt CLI.
#
# This script imports no project code, links against no project library and
# shares no process, socket or database with the defence. The only thing it has
# in common with VERA Aegis is the hypervisor it both act on, which is the
# point: the defence observes real consequences, not a replayed script.
#
# Nothing here is an exploit. The premise is that an operator credential is
# already compromised, so the activity is ordinary control-plane usage in an
# unusual pattern: broad enumeration followed by repeated snapshotting and
# probing of other tenants' guests. That pattern is what a detector sees.
set -u

TARGET="${1:-tenant-b--app}"
PAUSE="${PAUSE:-1}"

step() { printf '\033[1m[attacker]\033[0m %s\n' "$*"; sleep "$PAUSE"; }
try()  { printf '  $ %s\n' "$*"; sh -c "$*" 2>&1 | sed 's/^/    /' | head -8; }

step "whoami and what can this credential reach"
try "id"
try "virsh uri"

step "enumerate every guest on the host, including other tenants"
try "virsh list --all"

step "read the full definition of the target, including its disks and networks"
try "virsh dumpxml $TARGET | grep -E '<(name|source|target dev|mac)'"

step "enumerate the networks and who is attached"
try "virsh net-list --all"

step "repeatedly snapshot the target: fast, cheap, and exfiltration-shaped"
for index in 1 2 3; do
  try "virsh snapshot-create-as --domain $TARGET --name attacker-$index --description 'bulk capture'"
done
try "virsh snapshot-list --domain $TARGET"
# This is the signal the defence keys on, so say plainly whether it exists.
# A silent failure here looks exactly like a defence that noticed nothing.
captured=$(virsh snapshot-list --domain "$TARGET" --name 2>/dev/null | grep -c . || true)
if [ "${captured:-0}" -gt 0 ]; then
  printf '  \033[1m=> %s snapshot(s) now exist on %s. This is hypervisor state.\033[0m\n' "$captured" "$TARGET"
else
  printf '  \033[31m=> no snapshots were created, so there is nothing for the defence to see.\033[0m\n'
  printf '     Check disk ownership: ls -la /var/lib/aegis/images/\n'
  printf '     The qcow2 files must belong to libvirt-qemu. Repair with: sudo ./deploy/provision.sh\n'
fi

step "probe guests belonging to other tenants"
for guest in $(virsh list --all --name 2>/dev/null | grep -v "^$TARGET$" | grep -v '^$'); do
  try "virsh dominfo $guest | head -4"
done

step "done. The hypervisor recorded every one of these as a real operation."
echo
echo "Observe the same host from the defence side, in another terminal:"
echo "  python3 -m aegis.live --catalogue /var/lib/aegis/catalogue.json topology"
