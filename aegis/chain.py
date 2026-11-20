"""Append-only evidence sealed with a hash chain.

Each entry commits to the digest of the entry before it. Editing, removing or
reordering any entry breaks every link after it, so the chain head is the one
value an operator must publish to make the journal non-repudiable. This removes
the standing limitation that a database administrator could silently rewrite
the evidence: they can still rewrite it, but no longer silently.

The chain is deliberately not a signature. Anchoring the head externally (a
transparency log, a co-signer, a printed value read out at handover) is an
operator decision and is documented rather than assumed.
"""

from .scope import sha

GENESIS = "0" * 64


def _body(entry):
    return {key: value for key, value in entry.items() if key != "hash"}


def link(entry, prev_hash):
    """Seal one entry against `prev_hash`."""
    sealed = dict(_body(entry), prev_hash=prev_hash)
    sealed["hash"] = sha(sealed)
    return sealed


def seal(entries, prev_hash=GENESIS):
    """Seal a list of entries into a chain starting from `prev_hash`."""
    chain = []
    for entry in entries:
        prev_hash = (sealed := link(entry, prev_hash))["hash"]
        chain.append(sealed)
    return chain


def head(entries):
    return entries[-1]["hash"] if entries else GENESIS


def verify_chain(entries):
    """Walk the chain and report the first broken link, if any."""
    prev_hash = GENESIS
    for index, entry in enumerate(entries):
        body = _body(entry)
        if entry.get("prev_hash") != prev_hash:
            return {
                "ok": False,
                "broken_at": index,
                "entry_id": entry.get("id"),
                "detail": "prev_hash does not match the preceding entry",
                "length": len(entries),
                "head": prev_hash,
            }
        if sha(body) != entry.get("hash"):
            return {
                "ok": False,
                "broken_at": index,
                "entry_id": entry.get("id"),
                "detail": "entry content does not match its own hash",
                "length": len(entries),
                "head": prev_hash,
            }
        prev_hash = entry["hash"]
    return {
        "ok": True,
        "broken_at": None,
        "entry_id": None,
        "detail": "every link verified",
        "length": len(entries),
        "head": prev_hash,
    }
