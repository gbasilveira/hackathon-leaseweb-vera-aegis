"""Real control plane over libvirt and QEMU.

Everything here is observed from the hypervisor, never from inside a guest. An
attacker who owns a guest completely cannot forge a domain state, a device link
state or a tap counter without escaping the virtual machine, so these are the
only signals allowed to carry authority.

Topology is discovered, not declared. Shared criticality in particular is
computed: a bridge or storage pool becomes critical because more than one
tenant was observed attached to it, not because a fixture said so. That is the
difference between "we told you this is shared" and "we measured that it is".

Containment uses reversible primitives. Dropping a guest's interface link is
immediate, survives a guest reboot, is invisible to and unblockable by the
guest, and is verifiable from the host by re-reading the live domain XML. It is
the honest containment action for a hypervisor, where revoking a federated
identity is not something this layer can do.
"""

import copy
import json
import os
import xml.etree.ElementTree as ET

from .controlplane import (
    ACTIONS,
    TRUST_HYPERVISOR,
    ControlPlane,
    PlaneError,
)

try:  # libvirt is absent on a plain checkout and on the offline test machine.
    import libvirt
except ImportError:  # pragma: no cover - exercised by absence, not by tests
    libvirt = None

if libvirt is not None:
    # The binding logs every error to stderr by default, including the expected
    # "no such metadata" probe on an unattributed domain. Errors still raise as
    # exceptions; only the console noise is suppressed.
    libvirt.registerErrorHandler(lambda _context, _error: None, None)

#: Metadata namespace carrying tenant attribution on each domain.
NS = "https://vera-aegis.local/tenant/1"

#: libvirt domain states, declared locally so the mapping is readable and does
#: not depend on the binding being importable.
STATES = {
    0: "nostate",
    1: "running",
    2: "blocked",
    3: "paused",
    4: "shutdown",
    5: "shutoff",
    6: "crashed",
    7: "pmsuspended",
}


def _require():
    if libvirt is None:
        raise PlaneError(
            "libvirt-python is not installed. Install python3-libvirt (or "
            "libvirt-python) on the hypervisor, or use the simulated plane."
        )
    return libvirt


def _tenant_of(domain, name):
    """Tenant attribution from domain metadata, falling back to a name prefix."""
    try:
        element = ET.fromstring(
            domain.metadata(libvirt.VIR_DOMAIN_METADATA_ELEMENT, NS, 0)
        )
        if (tenant := element.get("id")):
            return tenant, element.get("criticality", "normal")
    except (libvirt.libvirtError, ET.ParseError):
        pass
    return (name.split("--", 1)[0] if "--" in name else "unattributed"), "normal"


def _interfaces(root):
    """Each guest interface as (mac, target device, attachment id, link state).

    libvirt omits the `<link>` element when the link is up, so absence is up.
    """
    found = []
    for interface in root.findall("./devices/interface"):
        source = interface.find("source")
        attachment = None
        if source is not None:
            attachment = source.get("bridge") or source.get("network") or source.get("dev")
        mac = interface.find("mac")
        target = interface.find("target")
        link = interface.find("link")
        found.append(
            {
                "mac": mac.get("address") if mac is not None else None,
                "device": target.get("dev") if target is not None else None,
                "attachment": attachment,
                "link": link.get("state") if link is not None else "up",
                "element": interface,
            }
        )
    return found


def _disks(root):
    paths = []
    for disk in root.findall("./devices/disk"):
        source = disk.find("source")
        if source is None:
            continue
        if (path := source.get("file") or source.get("dev") or source.get("name")):
            paths.append(path)
    return paths


class LibvirtControlPlane(ControlPlane):
    """Adapter over a libvirt connection.

    The sensor opens this read-only and therefore cannot actuate even if its
    code were replaced. The gateway is the only component that opens it
    writable, and it is the only component that holds the socket permission to
    do so.
    """

    def __init__(
        self, uri="qemu:///system", read_only=False, grants=None, catalogue=None
    ):
        virt = _require()
        self.name = f"libvirt({uri}{',ro' if read_only else ''})"
        self.uri = uri
        self.read_only = read_only
        self._grants = grants or {}
        # The hypervisor knows the infrastructure graph: which guest sits on
        # which bridge, host and pool. It does not and cannot know that a
        # payments service depends on a particular guest. That lives in a
        # service catalogue, which in production is a CMDB and here is an
        # operator-owned JSON file re-read on every discovery. A catalogue
        # entry appearing is the realistic way a blast radius grows mid
        # incident, and it is what costs a pending capability its authority.
        self._catalogue = catalogue
        try:
            self.conn = virt.openReadOnly(uri) if read_only else virt.open(uri)
        except virt.libvirtError as error:
            hint = ""
            if "Permission denied" in str(error) and not read_only:
                hint = (
                    ". This account does not hold libvirt's writable socket, "
                    "which is the intended boundary: only the gateway's account "
                    "does. Add --read-only for a command that merely observes, "
                    "or run the operator walkthrough under sudo."
                )
            raise PlaneError(f"cannot reach libvirt at {uri}: {error}{hint}") from error

    # -- observation ---------------------------------------------------------

    def _domains(self):
        for domain in self.conn.listAllDomains():
            name = domain.name()
            root = ET.fromstring(domain.XMLDesc(0))
            tenant, criticality = _tenant_of(domain, name)
            yield domain, name, root, tenant, criticality

    def catalogue(self):
        """Declared service dependencies, re-read on every call."""
        if not self._catalogue:
            return {"nodes": {}, "edges": []}
        if isinstance(self._catalogue, dict):
            declared = self._catalogue
        else:
            try:
                declared = json.loads(open(self._catalogue).read())
            except (OSError, ValueError):
                return {"nodes": {}, "edges": []}
        return {
            "nodes": declared.get("nodes", {}),
            "edges": [
                edge
                for edge in declared.get("edges", [])
                if edge.get("source") and edge.get("target")
            ],
        }

    def discover(self):
        """Observed nodes and edges. Shared criticality is computed, not read."""
        nodes, edges = {}, []
        host = f"host:{self.conn.getHostname()}"
        attached = {}
        for domain, name, root, tenant, criticality in self._domains():
            nodes[name] = {
                "id": name,
                "kind": "domain",
                "type": "virtual_machine",
                "tenant_id": tenant,
                "criticality": criticality,
                "state": STATES.get(domain.state()[0], "unknown"),
                "shared": False,
                "link": ",".join(
                    sorted(i["link"] for i in _interfaces(root) if i["link"])
                ) or "none",
            }
            edges.append({"source": name, "target": host, "relation": "runs_on"})
            for interface in _interfaces(root):
                if interface["attachment"]:
                    node = f"net:{interface['attachment']}"
                    edges.append({"source": name, "target": node, "relation": "attached_to"})
                    attached.setdefault(node, set()).add(tenant)
            for path in _disks(root):
                node = f"pool:{os.path.dirname(path) or path}"
                edges.append({"source": name, "target": node, "relation": "stored_on"})
                attached.setdefault(node, set()).add(tenant)
        attached.setdefault(host, set()).update(
            node["tenant_id"] for node in nodes.values()
        )
        for node, tenants in attached.items():
            kind = node.split(":", 1)[0]
            nodes[node] = {
                "id": node,
                "kind": kind,
                "type": {"net": "network", "pool": "storage_pool", "host": "hypervisor_host"}[kind],
                "tenant_id": "infrastructure",
                # Measured: more than one observed tenant makes this shared and
                # therefore critical, which is what denies a broad action.
                "shared": len(tenants) > 1,
                "criticality": "critical" if len(tenants) > 1 else "standard",
                "state": "present",
                "observed_tenants": sorted(tenants),
            }
        declared = self.catalogue()
        for node_id, node in declared["nodes"].items():
            nodes.setdefault(node_id, dict(node, id=node_id, source="catalogue"))
        edges.extend(dict(edge, source_of_truth="catalogue") for edge in declared["edges"])
        return {"nodes": nodes, "edges": edges, "host": host}

    def observe(self):
        """Hypervisor-level signal only, with counters read from the host side."""
        observations = []
        for domain, name, root, tenant, _ in self._domains():
            interfaces = _interfaces(root)
            counters = {}
            for interface in interfaces:
                if not (device := interface["device"]):
                    continue
                try:
                    stats = domain.interfaceStats(device)
                    counters[device] = {"rx_bytes": stats[0], "tx_bytes": stats[4]}
                except Exception:  # noqa: BLE001 - inactive domain or no such tap
                    base = f"/sys/class/net/{device}/statistics"
                    try:
                        counters[device] = {
                            key: int(open(f"{base}/{key}").read())
                            for key in ("rx_bytes", "tx_bytes")
                        }
                    except OSError:
                        counters[device] = {}
            observations.append(
                {
                    "id": f"libvirt:{name}",
                    "source": "libvirt",
                    "trust_level": TRUST_HYPERVISOR,
                    "target_id": name,
                    "tenant_id": tenant,
                    "state": STATES.get(domain.state()[0], "unknown"),
                    "links": {i["device"] or i["mac"]: i["link"] for i in interfaces},
                    "counters": counters,
                    # Snapshot count is hypervisor-side and is the signal the
                    # bulk-capture pattern actually leaves behind.
                    "snapshots": domain.snapshotNum(),
                }
            )
        return observations

    def read_state(self, target):
        """Independent re-read for the verifier, from the live domain XML."""
        for domain, name, root, tenant, _ in self._domains():
            if name != target:
                continue
            interfaces = _interfaces(root)
            return {
                "id": name,
                "tenant_id": tenant,
                "state": STATES.get(domain.state()[0], "unknown"),
                "links": {i["device"] or i["mac"]: i["link"] for i in interfaces},
                "isolated": bool(interfaces)
                and all(i["link"] == "down" for i in interfaces),
                "snapshots": domain.snapshotNum(),
            }
        return {}

    # -- authorisation -------------------------------------------------------

    def authorize(self, credential, action, target):
        """Whether an operator credential may perform `action` on `target`.

        The grant table belongs to the plane, not to the defence, and is
        provisioned outside this process. Default is deny.
        """
        return [action, target] in [
            list(grant) for grant in self._grants.get(credential, ())
        ]

    # -- actuation -----------------------------------------------------------

    def _link(self, domain, root, state):
        changed = []
        for interface in _interfaces(root):
            if interface["link"] == state:
                continue
            element = copy.deepcopy(interface["element"])
            for stale in element.findall("link") + element.findall("alias"):
                element.remove(stale)
            ET.SubElement(element, "link", {"state": state})
            domain.updateDeviceFlags(
                ET.tostring(element, encoding="unicode"),
                libvirt.VIR_DOMAIN_AFFECT_LIVE,
            )
            changed.append(interface["device"] or interface["mac"])
        return changed

    def actuate(self, action, target, parameters=None):
        """Perform a published action. Never called by the planner."""
        self.check_writable()
        self.check_action(action)
        if parameters:
            raise PlaneError("this plane takes no actuation parameters")
        virt = _require()
        for domain, name, root, _, _ in self._domains():
            if name != target:
                continue
            try:
                if action == "network.isolate":
                    return {"ok": True, "action": action, "interfaces": self._link(domain, root, "down")}
                if action == "network.restore":
                    return {"ok": True, "action": action, "interfaces": self._link(domain, root, "up")}
                if action == "vm.suspend":
                    domain.suspend()
                    return {"ok": True, "action": action, "state": STATES.get(domain.state()[0])}
                if action == "vm.resume":
                    domain.resume()
                    return {"ok": True, "action": action, "state": STATES.get(domain.state()[0])}
                if action == "vm.snapshot":
                    label = f"aegis-{target}-{domain.snapshotNum()}"
                    domain.snapshotCreateXML(
                        f"<domainsnapshot><name>{label}</name>"
                        f"<description>VERA Aegis evidence</description></domainsnapshot>",
                        0,
                    )
                    return {"ok": True, "action": action, "snapshot": label}
            except virt.libvirtError as error:
                # An actuator failure is reported, never swallowed: the verifier
                # must be able to reach INDETERMINATE rather than assume success.
                raise PlaneError(f"{action} on {target} failed: {error}") from error
        raise PlaneError(f"no domain named {target!r} on {self.uri}")

    def close(self):
        try:
            self.conn.close()
        except Exception:  # noqa: BLE001
            pass


def describe():
    """Published actions, for the planner's tool schema."""
    return {name: detail for name, detail in sorted(ACTIONS.items())}
