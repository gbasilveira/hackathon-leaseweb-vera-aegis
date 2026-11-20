"""Control-plane adapters.

Governance must not know whether it is deciding about fixture records or real
QEMU domains. Before this module the defence read and wrote the same SQLite
JSON collections that the attack replay mutated, through the same
`Core.apply` and `Core.probe` functions, so no claim about independence could
be made. An adapter boundary makes the coupling explicit and replaceable: the
simulated plane keeps the fixture demonstration working, and the libvirt plane
drives real guests.

Two rules hold for every adapter.

Actions are a closed enum. A planner proposes a name from `ACTIONS` or its
proposal is rejected before any policy runs, so model output cannot name an
operation the plane did not publish.

Observations carry a trust level. `TRUST_HYPERVISOR` signal can only be forged
by escaping the virtual machine. `TRUST_GUEST` signal is whatever the workload
inside the guest chose to say, and an attacker who owns the guest owns it
completely. `authority_facts` refuses to derive a decision from guest signal.
"""

from .scope import scoped_digest

#: Operations a plane may be asked to perform. `host.*` is deliberately absent:
#: stopping a shared host is the proposal the demonstration must deny, and an
#: action the plane cannot perform is a stronger guarantee than a policy rule.
ACTIONS = {
    "network.isolate": "Drop the link on every guest interface",
    "network.restore": "Restore the link on every guest interface",
    "vm.suspend": "Freeze guest vCPUs, preserving memory for forensics",
    "vm.resume": "Release frozen guest vCPUs",
    "vm.snapshot": "Capture guest state as evidence",
}

#: Reversible actions can be undone by the plane. The policy may treat an
#: irreversible action as requiring human approval regardless of blast radius.
REVERSIBLE = {"network.isolate", "network.restore", "vm.suspend", "vm.resume"}

TRUST_HYPERVISOR = "hypervisor"
TRUST_GUEST = "guest"
TRUST_LEVELS = (TRUST_HYPERVISOR, TRUST_GUEST)


class PlaneError(RuntimeError):
    """The plane could not perform or observe what was asked."""


def authority_facts(observations):
    """Project observations that may inform an authority decision.

    Guest-trust signal is dropped rather than sanitised. There is no reliable
    way to tell a genuine guest log from one the attacker wrote, so it may
    appear in the journal as context for a human and never as a decision fact.
    """
    kept, dropped = [], []
    for observation in observations:
        level = observation.get("trust_level")
        if level == TRUST_HYPERVISOR:
            kept.append(observation)
        else:
            dropped.append(dict(observation, excluded_because=f"trust_level={level!r}"))
    return {"facts": kept, "excluded": dropped}


class ControlPlane:
    """The interface every adapter implements.

    `discover` returns observed topology, never declared topology, so the
    blast radius is measured rather than asserted. `read_state` exists so the
    verifier can re-read the world independently of whatever `actuate`
    returned.
    """

    name = "abstract"
    read_only = False

    def discover(self):
        raise NotImplementedError

    def observe(self):
        raise NotImplementedError

    def actuate(self, action, target, parameters=None):
        raise NotImplementedError

    def read_state(self, target):
        raise NotImplementedError

    def authorize(self, credential, action, target):
        raise NotImplementedError

    def context(self, target):
        """Scoped digest of the topology this plane can observe right now."""
        topology = self.discover()
        return scoped_digest(topology["nodes"], topology["edges"], target)

    def check_action(self, action):
        if action not in ACTIONS:
            raise PlaneError(f"{self.name} publishes no action named {action!r}")
        return action

    def check_writable(self):
        if self.read_only:
            raise PlaneError(f"{self.name} is attached read-only and cannot actuate")
