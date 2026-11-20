"""Privilege boundaries each process asserts about itself at startup.

A single binary that both reasons with a language model and holds the
hypervisor socket is the most dangerous component in the system: compromising
it is equivalent to owning every guest, and the authorisation gateway it
contains becomes decorative. Splitting the work into three processes is only
worth anything if the split is enforced, so each process refuses to start when
it discovers a privilege it is not supposed to have.

The checks are deliberately negative. Asserting "I can reach libvirt" proves
little, because a misconfiguration usually grants more access than intended,
not less. Asserting "I cannot reach libvirt, and I verified that by trying"
is the property worth having.

    sensor   reads the hypervisor, writes observations.  No model, no actuation.
    planner  reads observations, writes proposals.       No hypervisor at all.
    gateway  holds the only writable hypervisor socket.  No model credentials.
"""

import os

#: What each role must and must not be able to do. `libvirt` is the level of
#: access the role may hold; anything above it is a privilege bleed.
ROLES = {
    "sensor": {
        "libvirt": "read-only",
        "model_credentials": False,
        "summary": "observes the hypervisor and cannot change it",
    },
    "planner": {
        "libvirt": "none",
        "model_credentials": True,
        "summary": "reasons about observations and can only propose",
    },
    "gateway": {
        "libvirt": "read-write",
        "model_credentials": False,
        "summary": "performs authorised actions and cannot talk to a model",
    },
}

#: Environment variables that would let a process reach a model API.
CREDENTIAL_HINTS = ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "AWS_BEARER_TOKEN_BEDROCK")


class PrivilegeError(RuntimeError):
    """A process holds a privilege its role forbids."""


def _libvirt_access(uri):
    """Highest level of libvirt access this process actually has."""
    try:
        import libvirt
    except ImportError:
        return "none"
    libvirt.registerErrorHandler(lambda _context, _error: None, None)
    for level, opener in (("read-write", libvirt.open), ("read-only", libvirt.openReadOnly)):
        try:
            opener(uri).close()
            return level
        except Exception:  # noqa: BLE001 - any failure means no access at this level
            continue
    return "none"


def _credentials_present():
    return sorted(name for name in CREDENTIAL_HINTS if os.environ.get(name))


def inspect(role, uri="qemu:///system"):
    """Observed privileges for `role`, with every violation listed."""
    if role not in ROLES:
        raise PrivilegeError(f"unknown role {role!r}")
    expected = ROLES[role]
    ranks = {"none": 0, "read-only": 1, "read-write": 2}
    observed = _libvirt_access(uri)
    credentials = _credentials_present()
    violations = []
    if ranks[observed] > ranks[expected["libvirt"]]:
        violations.append(
            f"{role} may hold {expected['libvirt']!r} libvirt access but holds "
            f"{observed!r} on {uri}"
        )
    if credentials and not expected["model_credentials"]:
        violations.append(
            f"{role} must not see model credentials but found {', '.join(credentials)}"
        )
    return {
        "role": role,
        "summary": expected["summary"],
        "uri": uri,
        "libvirt_expected": expected["libvirt"],
        "libvirt_observed": observed,
        "model_credentials_allowed": expected["model_credentials"],
        "model_credentials_present": credentials,
        "uid": os.getuid(),
        "groups": sorted(os.getgroups()),
        "violations": violations,
        "ok": not violations,
    }


def assert_role(role, uri="qemu:///system", enforce=True):
    """Fail closed when the running process holds a forbidden privilege."""
    report = inspect(role, uri)
    if report["violations"] and enforce:
        raise PrivilegeError(
            f"refusing to start as {role}: " + "; ".join(report["violations"])
        )
    return report


def matrix(uri="qemu:///system"):
    """Privilege table for every role, for the operator console."""
    return [inspect(role, uri) for role in ROLES]
