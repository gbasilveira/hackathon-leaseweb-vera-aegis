# Linux deployment

On the development machine, use the existing Python interpreter. Clone the repository, change into its root and run the commands in the README. The offline backend uses SQLite and the Python standard library. JavaScript and graph rendering assets are local. Network connectivity is required for the optional Claude installation and live inference.

On the demonstration VM, run scripts/diagnose.sh, confirm Docker Compose is available and run docker compose up --build -d. The image runs as UID 65532 with all Linux capabilities dropped. Compose publishes only on loopback. Use SSH forwarding to reach the dashboard. To migrate the demo, stop the process before copying the SQLite file. The named Compose volume persists between container replacements. Export evidence before resetting a scenario.

Set AEGIS_DB for a host database location, AEGIS_HOST for binding and AEGIS_PORT for the local listener. Use WITH_CLAUDE=1 to include the optional SDK in the container. Keep API credentials outside Git. Review agent-specific environment controls in MCP.md.

Compose forwards the agent model, budgets, timeout and inline external MCP configuration. A file-backed configuration or local stdio MCP executable must be provided inside the container with a read-only bind mount and its corresponding container path. Use a deployment-specific Compose override for these operator-controlled files.
