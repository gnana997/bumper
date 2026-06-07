# bumper

**Catch the `apply` that destroys your infrastructure — before it runs.**

[![CI](https://github.com/gnana997/bumper/actions/workflows/ci.yml/badge.svg)](https://github.com/gnana997/bumper/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/gnana997/bumper?sort=semver)](https://github.com/gnana997/bumper/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/gnana997/bumper)](https://goreportcard.com/report/github.com/gnana997/bumper)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Marketplace](https://img.shields.io/badge/GitHub%20Action-Marketplace-orange?logo=github)](https://github.com/marketplace/actions/bumper-terraform-plan-safety-gate)

**[bumper.sh](https://bumper.sh)** · **[Docs](docs/)** · **[GitHub Action](https://github.com/marketplace/actions/bumper-terraform-plan-safety-gate)**

bumper reads a `terraform show -json` plan and flags the changes that would
**expose** or **destroy** your **AWS**, **GCP**, or **Azure** account — *before*
`terraform apply` runs. The verdict is **100% deterministic**, so it's safe to
block a merge — or an apply — on it. A single static Go binary; no API key, no
account.

It runs three ways:

- a **CLI / CI gate** — text · JSON · SARIF (Security tab) · a sticky PR comment;
- **agent guard hooks** — block an unverified Terraform apply *and* a known-malicious
  package install before it runs, and scan dependencies after install;
- the hosted **[Advisor MCP](docs/mcp.md)** your agent queries for best-practice, CVE,
  and malware data (lookup-only — your code never leaves the machine).

An AI CLI you already have (`claude`, `gemini`, `codex`, `opencode`, `auggie`)
optionally explains each finding in plain English — zero setup, zero cost. The
deterministic core stands alone if it's absent.

## See it

```console
$ terraform show -json plan.tfplan > plan.json
$ bumper plan.json

bumper found 2 issue(s) in this plan:

CRITICAL  aws_db_instance.main     This apply will DESTROY and recreate a database with no final snapshot
  rule  AWS_DB_DESTRUCTIVE_REPLACE_NO_SNAPSHOT
  fix   Set skip_final_snapshot = false, or find what forces replacement before applying.

CRITICAL  aws_security_group.web   Public internet ingress (0.0.0.0/0) to a sensitive port range
  rule  AWS_SG_PUBLIC_INGRESS
  fix   Restrict cidr_blocks/ipv6_cidr_blocks to known ranges and narrow the port range.

2 finding(s)   2 critical
$ echo $?
1
```

On a terminal, severities are colored (critical red, high amber); piping or CI
output stays plain. Add `--explain` for an AI plain-English walkthrough.

## Install

```sh
# Homebrew (macOS)
brew install gnana997/tap/bumper

# install script (macOS / Linux) — downloads the latest release, checksum-verified
curl -fsSL https://get.bumper.sh | sh

# Go
go install github.com/gnana997/bumper/cmd/bumper@latest
```

Then wire it into your coding agent (guardrail hooks + the hosted Advisor MCP):

```sh
bumper init
```

Every release is checksummed, **cosign-signed** (keyless), and carries a **SLSA
build-provenance attestation** — see [docs/architecture.md → Releases and
provenance](docs/architecture.md#releases-and-provenance) to verify the binary came
from this repo's CI.

## Quick start

```sh
# produce plan JSON
terraform plan -out plan.tfplan
terraform show -json plan.tfplan > plan.json

# scan it
bumper plan.json
bumper --explain plan.json          # add plain-English enrichment
cat plan.json | bumper -            # or pipe via stdin
```

Exit codes: `0` = clean, `1` = findings present (CI-friendly), `2` = usage/parse
error. Output formats: `--format text` (default) · `json` · `sarif` · `markdown`.

## What you can do

| | | |
| --- | --- | --- |
| **Scan & explain** | flag exposure/destruction in a plan, optional AI enrichment | [docs/cli.md](docs/cli.md) |
| **Enforce the apply** | `verify` binds a passing scan to a plan by sha256; `guard` blocks an unverified `apply` | [docs/agents.md](docs/agents.md) |
| **Agent guardrail** | `bumper init` wires the guard hooks + the hosted Advisor MCP into Claude Code, Codex, opencode, … | [docs/agents.md](docs/agents.md) |
| **Dependency guardrail** | block malicious installs, scan deps for CVEs — in the agent loop and in CI | [docs/agents.md](docs/agents.md#dependency-guardrail) |
| **CI / GitHub Action** | SARIF to the Security tab, a sticky PR comment, fail on `high+` | [docs/ci.md](docs/ci.md) |
| **Search the catalog** | `bumper search` ranks enforced rules + an advisory best-practice catalog | [docs/cli.md](docs/cli.md#search) |
| **Interactive console** | `bumper tui` — the "hazard console" for the scary local apply | [docs/cli.md](docs/cli.md#tui) |

## The rule set

**112 curated rules** — 20 critical · 57 high · 32 medium · 3 low — across
**AWS** (60), **GCP** (35), and **Azure** (17): a consistent cross-cloud baseline
(public storage/databases, open admin ports, public k8s control planes,
wildcard/over-privileged IAM, TLS, encryption, public snapshots, destruction)
plus deep per-cloud coverage. Every rule is hand-ported with a passing **and** a
negative fixture, and carries its **provenance** (`source: trivy` with the
upstream `AVD-*` id, or `source: custom`).

`bumper search` also spans an embedded **advisory catalog** — ~2,600
knowledge-only entries normalized from Trivy, Checkov, KICS, and Prowler — so an
agent can ask "what should I bake in before writing Terraform for X?" fully
offline. Full coverage map, rule format, and how to write your own:
**[docs/rules.md](docs/rules.md)**.

## Why bumper is different

- **Reads the plan diff, not just the end state.** Most scanners check the
  resulting config. bumper also checks the *transition* (`create` / `delete` /
  `replace`) — the only way to catch "this `apply` will destroy your database."
  That **destruction** class is the differentiator.
- **It enforces, it doesn't just warn.** `verify` binds a passing scan to the
  exact plan by sha256; the `guard` hook then *blocks* an unverified
  `apply`/`destroy`. A linter you can ignore becomes a gate you can't.
- **Built for the agent era.** Tool-layer guard hooks (Terraform apply + package
  installs) plus the hosted Advisor MCP mean your AI agent can no longer silently
  apply infra it didn't verify or install a known-malicious package.
- **Deterministic core stands alone.** The AI layer is garnish; if it's absent or
  fails, the deterministic findings are still complete and blocking.

## Documentation

| | |
| --- | --- |
| [docs/cli.md](docs/cli.md) | command reference — scan, deps, list, search, explain, verify, guard, tui, init |
| [docs/rules.md](docs/rules.md) | rule format (YAML + CEL), coverage, the advisory catalog, writing your own |
| [docs/ci.md](docs/ci.md) | the GitHub Action — inputs, permissions, SARIF, sticky comment |
| [docs/agents.md](docs/agents.md) | the agent enforcement model — MCP, `bumper init`, verify + guard |
| [docs/architecture.md](docs/architecture.md) | internals, tech stack, supply-chain provenance, roadmap |

## Contributing & security

New **rules** and real-world **plan fixtures** are the most valuable
contributions — see [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability,
use private disclosure per [SECURITY.md](SECURITY.md) (not a public issue).

## License

[Apache-2.0](LICENSE). Built-in rules adapted from Apache-2.0 sources (Trivy,
Checkov) retain attribution in [NOTICE](NOTICE); CIS Benchmark content is not
redistributed.
