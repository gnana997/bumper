# bumper documentation

The full reference. New here? Start with the [README](../README.md) for install +
a 30-second quick start, then come back for depth.

| Page | What's in it |
| --- | --- |
| [cli.md](cli.md) | **Command reference** — `scan`, `deps`, `list`, `search`, `explain`, `verify`, `guard`, `tui`, `init`; flags, exit codes, and output formats. |
| [rules.md](rules.md) | **Rules** — the YAML + CEL rule format, conventions learned the hard way, the full cross-cloud coverage map, the enforced-vs-advisory catalog, and how to write your own. |
| [ci.md](ci.md) | **CI / GitHub Actions** — the Terraform + dependency Actions, inputs, the permissions block, SARIF to the Security tab, the sticky PR comment, and the fork caveat. |
| [agents.md](agents.md) | **The agent guardrail** — the two tool-layer gates (Terraform apply + dependency install), `bumper init`, the supported agents, and how a hook signals a block. |
| [mcp.md](mcp.md) | **The Advisor MCP** — connect the hosted MCP to your agent; the six lookup tools (rules, CVEs, malware) and progressive disclosure. |
| [api.md](api.md) | **The Advisor API** — the same data over plain REST; every endpoint, the honest-status contract, limits, privacy, and self-hosting. |
| [self-hosting.md](self-hosting.md) | **Self-hosting the Advisor** — run the knowledge/CVE/malware service yourself; compose quick start, exposing it, keeping it fresh, sizing & tuning. |
| [comparison.md](comparison.md) | **How bumper compares** — vs Checkov/Trivy (IaC) and Dependabot/Snyk/Socket (deps); where it's different, and what it deliberately doesn't do. |
| [architecture.md](architecture.md) | **Internals** — package layout, the two scan paths, the hosted Advisor, tech stack, release supply-chain (cosign + SLSA), and the roadmap. |

Project links: **[bumper.sh](https://bumper.sh)** ·
[GitHub Action](https://github.com/marketplace/actions/bumper-terraform-plan-safety-gate) ·
[Contributing](../CONTRIBUTING.md) · [Security policy](../SECURITY.md)
