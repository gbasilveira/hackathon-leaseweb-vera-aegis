"""Local operator commands for the synthetic incident lab."""

import argparse
import json
import os
from pathlib import Path

from .core import Core, SCENARIOS, validate


def main():
    parser = argparse.ArgumentParser(prog="python -m aegis")
    parser.add_argument("--db", default=os.getenv("AEGIS_DB", "data/aegis.sqlite"))
    cmd = parser.add_subparsers(dest="command", required=True)
    server = cmd.add_parser("serve")
    server.add_argument("--host", default=os.getenv("AEGIS_HOST", "127.0.0.1"))
    server.add_argument(
        "--port", type=int, default=int(os.getenv("AEGIS_PORT", "8765"))
    )
    for name in ("reset", "config-export", "graph"):
        cmd.add_parser(name).add_argument(
            "scenario", choices=sorted(p.stem for p in SCENARIOS.glob("*.json"))
        )
    cmd.add_parser("config-import").add_argument("file", type=Path)
    args = parser.parse_args()
    Path(args.db).parent.mkdir(parents=True, exist_ok=True)
    if args.command == "serve":
        from .api import serve

        serve(args.db, args.host, args.port)
    elif args.command == "reset":
        Core(args.db).load(args.scenario)
    elif args.command == "config-import":
        import re

        config = json.loads(args.file.read_text())
        validate(config)
        if not re.fullmatch(r"[a-z0-9-]{1,80}", config["id"]):
            parser.error("Invalid scenario filename")
        with (SCENARIOS / (config["id"] + ".json")).open("x") as f:
            json.dump(config, f, indent=2)
    else:
        config = json.loads((SCENARIOS / (args.scenario + ".json")).read_text())
        if args.command == "config-export":
            print(json.dumps(config, indent=2))
        else:
            print("flowchart LR")
            nodes = {
                x["id"]: f"n{i}"
                for i, x in enumerate(
                    x
                    for k in ("tenants", "assets", "sessions", "identities")
                    for x in config[k]
                )
            }
            for label, key in nodes.items():
                print(f'    {key}["{label.replace(chr(34), "")}"]')
            for e in config["dependencies"]:
                print(
                    f"    {nodes[e['source']]} -->|{e.get('relation', e.get('type', 'depends_on'))}| {nodes[e['target']]}"
                )


if __name__ == "__main__":
    main()
