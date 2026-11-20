# Distribution inventory

| Component | Version | Terms and distribution |
|---|---|---|
| VERA Aegis | 0.1.0 | Original application source, Apache-2.0 |
| Cytoscape.js | 3.35.0 | Vendored MIT browser asset. Notice in aegis/web/vendor/CYTOSCAPE-LICENSE.txt |
| CPython and standard library | Host Python 3.14.10 during development, Docker Python 3.13 | PSF and notices for bundled modules. Host runtime installed separately |
| SQLite | Host and base-image runtime | Public domain core. Python sqlite3 uses the system runtime |
| Claude Agent SDK for Python | 0.2.185, optional installation | MIT wrapper, bundled Claude Code executable and hosted service subject to Anthropic terms |

See the [resolved optional package inventory](CLAUDE-LICENSES.md). The offline application needs no third-party Python packages. The Dockerfile builds on upstream Debian slim and CPython. The resulting operating system includes packages under other licenses, including GPL utilities. The repository distributes the application source and a build recipe. It does not relicense the resulting image, OS packages or Claude runtime. Use the source checkout with an existing Python interpreter for a minimal distribution.

For terms governing the hosted service and bundled CLI, see Anthropic's [legal and compliance documentation](https://code.claude.com/docs/en/legal-and-compliance).
