#!/bin/sh
# Turn libvirt's own authorisation on, so cross-tenant denial is enforced by
# the hypervisor rather than asserted by the defence.
#
# Without this, every member of the libvirt group can manage every domain, and
# "the attacker could not reach tenant-c" would be a claim with nothing behind
# it. With it, libvirtd consults polkit per API call with the domain's name
# attached, and the kernel-side answer is the authorisation decision.
#
# This changes host-wide authorisation. It is opt-in, it is reversible with
# --revert, and it grants root and the aegis accounts full access first so a
# mistake cannot lock you out of your own hypervisor.
set -eu

CONF=/etc/libvirt/libvirtd.conf
RULE=/etc/polkit-1/rules.d/60-aegis-tenant.rules
BACKUP="$CONF.aegis-backup"

[ "$(id -u)" = 0 ] || { echo "run this with sudo" >&2; exit 1; }

if [ "${1:-}" = "--revert" ]; then
  rm -f "$RULE"
  [ -f "$BACKUP" ] && mv "$BACKUP" "$CONF"
  systemctl restart libvirtd
  echo "libvirt authorisation reverted to group-based access."
  exit 0
fi

[ -f "$BACKUP" ] || cp "$CONF" "$BACKUP"
if ! grep -q '^access_drivers' "$CONF"; then
  printf '\n# Added by VERA Aegis deploy/enable-acl.sh\naccess_drivers = [ "polkit" ]\n' >> "$CONF"
fi

cat > "$RULE" <<'JS'
// VERA Aegis tenant scoping for libvirt.
//
// Order matters. Full access is granted to root and to the service accounts
// first, so that tightening the attacker's scope can never lock the operator
// or the gateway out of the hypervisor.
polkit.addRule(function(action, subject) {
    if (action.id.indexOf("org.libvirt.api.") !== 0 &&
        action.id.indexOf("org.libvirt.unix.") !== 0) {
        return null;
    }

    if (subject.user == "root" ||
        subject.user == "aegis-gateway" ||
        subject.user == "aegis-sensor") {
        return polkit.Result.YES;
    }

    // The compromised operator credential. It is a real account with real
    // access to its own tenant, and libvirtd itself refuses the rest: the
    // domain name arrives as action detail on every per-object API call.
    if (subject.user == "demo-attacker") {
        var domain = action.lookup("domain_name");
        if (domain === null) {
            // Connection-level checks carry no object. Allow the socket; the
            // per-object rules below are where scoping actually happens.
            return polkit.Result.YES;
        }
        if (domain.indexOf("tenant-b--") === 0) {
            return polkit.Result.YES;
        }
        polkit.log("aegis: denied " + subject.user + " on " + domain);
        return polkit.Result.NO;
    }

    return null;
});
JS

systemctl restart libvirtd
echo "libvirt authorisation is now polkit-backed."
echo
echo "Verify the boundary holds:"
echo "  sudo -u demo-attacker virsh dominfo tenant-b--app    # permitted"
echo "  sudo -u demo-attacker virsh dominfo tenant-c--svc    # refused by libvirtd"
echo "  sudo journalctl -u polkit --since '2 min ago' | grep aegis"
echo
echo "Revert with: sudo ./deploy/enable-acl.sh --revert"
