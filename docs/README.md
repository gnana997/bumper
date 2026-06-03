# bumper documentation

The full reference. New here? Start with the [README](../README.md) for install +
a 30-second quick start, then come back for depth.

| Page | What's in it |
| --- | --- |
| [cli.md](cli.md) | **Command reference** — `scan`, `list`, `search`, `explain`, `verify`, `guard`, `tui`, `init`, `mcp`; flags, exit codes, and output formats. |
| [rules.md](rules.md) | **Rules** — the YAML + CEL rule format, conventions learned the hard way, the full cross-cloud coverage map, the enforced-vs-advisory catalog, and how to write your own. |
| [ci.md](ci.md) | **CI / GitHub Action** — inputs, the permissions block, SARIF to the Security tab, the sticky PR comment, and the fork caveat. |
| [agents.md](agents.md) | **The agent enforcement model** — `verify` + `guard`, the MCP server and its tools, `bumper init`, and the supported agents. |
| [architecture.md](architecture.md) | **Internals** — package layout, tech stack, release supply-chain (cosign + SLSA) verification, and the roadmap. |

Project links: **[bumper.sh](https://bumper.sh)** ·
[GitHub Action](https://github.com/marketplace/actions/bumper-terraform-plan-safety-gate) ·
[Contributing](../CONTRIBUTING.md) · [Security policy](../SECURITY.md)
