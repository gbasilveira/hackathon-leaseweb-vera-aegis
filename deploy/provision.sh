#!/bin/sh
# Provision a real multi-tenant QEMU host for VERA Aegis.
#
# Creates three running guests across two libvirt networks, attributed to three
# tenants, so that shared criticality is *measured* rather than declared: the
# network carrying more than one tenant becomes critical because discovery
# observes two tenants attached to it.
#
# Also creates the four unix accounts the privilege split needs. Idempotent:
# re-running it converges rather than duplicating.
#
# Usage:  sudo ./deploy/provision.sh            provision
#         sudo ./deploy/provision.sh --destroy  remove everything it created
set -eu

BASE_DIR=/var/lib/aegis
IMAGES="$BASE_DIR/images"
CATALOGUE="$BASE_DIR/catalogue.json"
NS="https://vera-aegis.local/tenant/1"
CIRROS_URL="https://download.cirros-cloud.net/0.6.2/cirros-0.6.2-x86_64-disk.img"
SHARED_NET=aegis-shared
PRIVATE_NET=aegis-private
# tenant--name:network:tenant:criticality
GUESTS="tenant-b--app:$SHARED_NET:tenant-b:normal
tenant-c--svc:$SHARED_NET:tenant-c:critical
tenant-b--sandbox:$PRIVATE_NET:tenant-b:normal"
USERS="aegis-sensor aegis-planner aegis-gateway demo-attacker"

say() { printf '\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }

[ "$(id -u)" = 0 ] || { echo "run this with sudo" >&2; exit 1; }

if [ "${1:-}" = "--destroy" ]; then
  say "Removing provisioned guests, networks and accounts"
  echo "$GUESTS" | while IFS=: read -r name _ _ _; do
    virsh destroy "$name" >/dev/null 2>&1 || true
    virsh snapshot-list --domain "$name" --name 2>/dev/null | while read -r snap; do
      [ -n "$snap" ] && virsh snapshot-delete --domain "$name" --snapshotname "$snap" >/dev/null 2>&1 || true
    done
    virsh undefine "$name" --nvram >/dev/null 2>&1 || virsh undefine "$name" >/dev/null 2>&1 || true
    note "removed guest $name"
  done
  for net in "$SHARED_NET" "$PRIVATE_NET"; do
    virsh net-destroy "$net" >/dev/null 2>&1 || true
    virsh net-undefine "$net" >/dev/null 2>&1 || true
    note "removed network $net"
  done
  for user in $USERS; do userdel "$user" >/dev/null 2>&1 || true; done
  rm -rf "$BASE_DIR"
  say "Done."
  exit 0
fi

say "1 · Packages"
if ! command -v virsh >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq qemu-system-x86 qemu-utils libvirt-daemon-system \
    libvirt-clients python3-libvirt curl >/dev/null
  note "installed qemu, libvirt and python3-libvirt"
else
  note "libvirt already present"
fi
systemctl enable --now libvirtd >/dev/null 2>&1 || true

if [ -e /dev/kvm ]; then
  DOMAIN_TYPE=kvm
  note "/dev/kvm present: guests will use hardware virtualisation"
else
  DOMAIN_TYPE=qemu
  note "/dev/kvm absent: falling back to TCG emulation, guests boot slowly but boot"
fi

say "2 · Base image"
mkdir -p "$IMAGES"
if [ ! -f "$IMAGES/base.qcow2" ]; then
  curl -fsSL -o "$IMAGES/base.img" "$CIRROS_URL"
  qemu-img convert -f qcow2 -O qcow2 "$IMAGES/base.img" "$IMAGES/base.qcow2" 2>/dev/null \
    || mv "$IMAGES/base.img" "$IMAGES/base.qcow2"
  rm -f "$IMAGES/base.img"
  note "fetched cirros base image"
else
  note "base image already present"
fi

say "3 · Networks"
for net in "$SHARED_NET" "$PRIVATE_NET"; do
  if ! virsh net-info "$net" >/dev/null 2>&1; then
    bridge=$(echo "$net" | sed 's/aegis-/aebr-/')
    cat > "/tmp/$net.xml" <<XML
<network>
  <name>$net</name>
  <bridge name='$bridge' stp='on' delay='0'/>
  <forward mode='nat'/>
  <ip address='192.168.$( [ "$net" = "$SHARED_NET" ] && echo 90 || echo 91 ).1' netmask='255.255.255.0'>
    <dhcp><range start='192.168.$( [ "$net" = "$SHARED_NET" ] && echo 90 || echo 91 ).10'
                 end='192.168.$( [ "$net" = "$SHARED_NET" ] && echo 90 || echo 91 ).99'/></dhcp>
  </ip>
</network>
XML
    virsh net-define "/tmp/$net.xml" >/dev/null
    rm -f "/tmp/$net.xml"
    note "defined network $net"
  fi
  virsh net-autostart "$net" >/dev/null 2>&1 || true
  virsh net-start "$net" >/dev/null 2>&1 || true
done

say "4 · Guests"
echo "$GUESTS" | while IFS=: read -r name net tenant criticality; do
  [ -n "$name" ] || continue
  disk="$IMAGES/$name.qcow2"
  if [ ! -f "$disk" ]; then
    qemu-img create -f qcow2 -b "$IMAGES/base.qcow2" -F qcow2 "$disk" >/dev/null
  fi
  if ! virsh dominfo "$name" >/dev/null 2>&1; then
    cat > "/tmp/$name.xml" <<XML
<domain type='$DOMAIN_TYPE'>
  <name>$name</name>
  <memory unit='MiB'>192</memory>
  <vcpu>1</vcpu>
  <metadata>
    <aegis:tenant xmlns:aegis='$NS' id='$tenant' criticality='$criticality'/>
  </metadata>
  <os><type arch='x86_64' machine='q35'>hvm</type><boot dev='hd'/></os>
  <features><acpi/><apic/></features>
  <devices>
    <emulator>$(command -v qemu-system-x86_64)</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='$disk'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <interface type='network'>
      <source network='$net'/>
      <model type='virtio'/>
    </interface>
    <console type='pty'/>
    <serial type='pty'/>
  </devices>
</domain>
XML
    virsh define "/tmp/$name.xml" >/dev/null
    rm -f "/tmp/$name.xml"
    note "defined guest $name in $tenant on $net"
  fi
  virsh start "$name" >/dev/null 2>&1 || true
done

say "5 · Service catalogue"
mkdir -p "$BASE_DIR"
[ -f "$CATALOGUE" ] || echo '{"nodes": {}, "edges": []}' > "$CATALOGUE"
chmod 644 "$CATALOGUE"
note "catalogue at $CATALOGUE (the CMDB stand-in; the walkthrough writes here)"

say "6 · Accounts for the privilege split"
for user in $USERS; do
  id "$user" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$user"
done
# Only the gateway gets the writable hypervisor socket. The sensor is left out
# of the group on purpose: libvirt's read-only socket is world-readable, which
# is exactly the access the sensor is allowed to have. The planner is denied
# even that, by namespace, in its systemd unit.
usermod -aG libvirt aegis-gateway
# The attacker holds legitimate operator credentials. That is the premise of the
# scenario: nothing is exploited, a valid account is misused.
usermod -aG libvirt demo-attacker
usermod -s /bin/sh demo-attacker
note "aegis-gateway and demo-attacker are in the libvirt group"
note "aegis-sensor has read-only socket access only"
note "aegis-planner is denied libvirt by InaccessiblePaths in its unit"

say "Provisioned."
virsh list --all
echo
echo "Next:"
echo "  python3 -m aegis.live --catalogue $CATALOGUE topology"
echo "  python3 -m aegis.live --catalogue $CATALOGUE privileges"
echo "  python3 -m aegis.live --catalogue $CATALOGUE demo --target tenant-b--app"
echo "  sudo -u demo-attacker ./deploy/attacker.sh tenant-b--app"
