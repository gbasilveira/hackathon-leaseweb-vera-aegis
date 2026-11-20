"""Check live Claude proposal submission using only the bundled synthetic fixture."""

import asyncio
from pathlib import Path
from tempfile import TemporaryDirectory

from aegis.agent import CLAUDE, investigate
from aegis.core import Core
from aegis.governance import Governance


def main():
    with TemporaryDirectory(prefix="aegis-smoke-") as directory:
        core = Core(Path(directory) / "incidents.db")
        core.load("control-plane-compromise")
        while core.step():
            pass
        governance = Governance(core)
        result = asyncio.run(investigate(core, governance, CLAUDE))
        manifest = governance.manifest()
        if not result["proposal_ids"] or any(
            manifest[key] for key in ("decisions", "approvals", "capabilities", "executions")
        ):
            raise RuntimeError("Expected proposals without governance or execution records.")
        print(f"Claude submitted {len(result['proposal_ids'])} synthetic proposal(s).")


if __name__ == "__main__":
    main()
