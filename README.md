# bumper

**One deterministic gate for your two riskiest moments: the `terraform apply`
that reshapes your cloud, and the dependency you're about to install.**

[![CI](https://github.com/gnana997/bumper/actions/workflows/ci.yml/badge.svg)](https://github.com/gnana997/bumper/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/gnana997/bumper?sort=semver)](https://github.com/gnana997/bumper/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/gnana997/bumper)](https://goreportcard.com/report/github.com/gnana997/bumper)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Marketplace](https://img.shields.io/badge/GitHub%20Action-Marketplace-orange?logo=github)](https://github.com/marketplace/actions/bumper-terraform-plan-safety-gate)

**[bumper.sh](https://bumper.sh)** · **[Docs](docs/)** · **[Examples](examples/)** · **[GitHub Action](https://github.com/marketplace/actions/bumper-terraform-plan-safety-gate)**

bumper blocks two classes of change **before they happen**:

- a **`terraform apply`** that would **destroy** or **expose** your **AWS**,
  **GCP**, or **Azure** account — read from a `terraform show -json` plan;
- an **install** that pulls in a **known-vulnerable** or **known-malicious**
  dependency — read from your lockfile.

Both verdicts are **100% deterministic**, so it's safe to block a merge, an
apply, or an AI agent on them. A single static Go binary; no API key, no account.

## See it

**Catch a destructive apply** — reads the plan *diff*, not just the end state:

```console
$ terraform show -json plan.tfplan > plan.json
$ bumper plan.json

CRITICAL  aws_db_instance.orders   This apply will DESTROY and recreate a database with no final snapshot
  rule  AWS_DB_DESTRUCTIVE_REPLACE_NO_SNAPSHOT
  fix   Set skip_final_snapshot = false, or find what forces replacement before applying.

CRITICAL  aws_security_group.api   Public internet ingress (0.0.0.0/0) to a sensitive port range
  rule  AWS_SG_PUBLIC_INGRESS
  fix   Restrict cidr_blocks/ipv6_cidr_blocks to known ranges and narrow the port range.

3 finding(s)   2 critical · 1 high
$ echo $?
1
```

**Catch a poisoned dependency** — known CVEs *and* known-malicious packages:

```console
$ bumper deps package-lock.json

  MALICIOUS  flatmap-stream@0.1.1 (npm) — MAL-2025-20690: Malicious code in flatmap-stream (npm)
  CRITICAL   event-stream@3.3.6 (npm)  GHSA-mh6f-8j2x-4483  fix → 4.0.0
  CRITICAL   lodash@4.17.4 (npm)       CVE-2019-10744       fix → 4.17.12
  CRITICAL   minimist@1.2.0 (npm)      CVE-2021-44906       fix → 1.2.6

4 vulnerable, 1 malicious package(s).
$ echo $?
1
```

Both examples are runnable from this repo — see [examples/](examples/). On a
terminal, severities are colored (critical red, high amber); piped/CI output
stays plain. Add `--explain` (plan scan) for an AI plain-English walkthrough.

## Install

```sh
# Homebrew (macOS)
brew install gnana997/tap/bumper

# install script (macOS / Linux) — downloads the latest release, checksum-verified
curl -fsSL https://get.bumper.sh | sh

# Go
go install github.com/gnana997/bumper/cmd/bumper@latest
```

Every release is checksummed, **cosign-signed** (keyless), and carries a **SLSA
build-provenance attestation** — see [docs/architecture.md → Releases and
provenance](docs/architecture.md#releases-and-provenance) to verify the binary
came from this repo's CI.

## Quick start

```sh
# Terraform: scan a plan
terraform plan -out plan.tfplan
terraform show -json plan.tfplan > plan.json
bumper plan.json
bumper --explain plan.json          # add plain-English enrichment

# Dependencies: scan a lockfile (npm / pip / uv / go.sum / …; auto-detected)
bumper deps package-lock.json
bumper deps                          # auto-detect a lockfile in the current dir
```

Exit codes: `0` = clean, `1` = findings present (CI-friendly), `2` = usage/parse
error. Output formats (both scans): `--format text` (default) · `json` · `sarif`
· `markdown`. Only package coordinates leave your machine for a deps scan —
**never your code**.

## Four ways to run it

- **CLI / CI gate** — text · JSON · SARIF (Security tab) · a sticky PR comment,
  for both plan and dependency scans.
- **Agent guard hooks** — block an unverified `terraform apply` *and* a
  known-malicious package install before they run, and scan dependencies after
  install. Wire them in with `bumper init`.
- **Hosted [Advisor MCP](docs/mcp.md)** — your agent queries it for
  best-practice, CVE, and malware data (lookup-only — your code never leaves the
  machine).
- **[Agent skills](docs/agents.md#agent-skills)** — `SKILL.md` playbooks that
  teach the agent to drive all of the above. `bumper init` installs them, or
  `npx skills add gnana997/bumper` for any agent.

An AI CLI you already have (`claude`, `gemini`, `codex`, `opencode`, `auggie`)
optionally explains each finding in plain English — zero setup, zero cost. The
deterministic core stands alone if it's absent.

```sh
bumper init                    # Claude Code (auto-detected)
bumper init --agent augment    # or Augment
bumper init --agent gemini     # or Gemini CLI
```

## What you can do

| | | |
| --- | --- | --- |
| **Scan a plan** | flag exposure/destruction in a Terraform plan, optional AI enrichment | [docs/cli.md](docs/cli.md) |
| **Scan dependencies** | flag vulnerable + malicious packages from a lockfile | [docs/cli.md](docs/cli.md) |
| **Enforce the apply** | `verify` binds a passing scan to a plan by sha256; `guard` blocks an unverified `apply` | [docs/agents.md](docs/agents.md) |
| **Agent guardrail** | `bumper init` wires the guard hooks + the hosted Advisor MCP into Claude Code, Augment, and Gemini CLI (`--agent`) | [docs/agents.md](docs/agents.md) |
| **Dependency guardrail** | block malicious installs, scan deps for CVEs — in the agent loop and in CI | [docs/agents.md](docs/agents.md#dependency-guardrail) |
| **Agent skills** | `bumper skills install` adds `SKILL.md` playbooks that teach the agent to drive bumper | [docs/agents.md](docs/agents.md#agent-skills) |
| **CI / GitHub Action** | SARIF to the Security tab, a sticky PR comment, fail on `high+` | [docs/ci.md](docs/ci.md) |
| **Search the catalog** | `bumper search` ranks enforced rules + an advisory best-practice catalog | [docs/cli.md](docs/cli.md#search) |
| **Interactive console** | `bumper tui` — the "hazard console" for the scary local apply | [docs/cli.md](docs/cli.md#tui) |

## Coverage

**Terraform rules — 112 curated, 100% deterministic:** 20 critical · 57 high ·
32 medium · 3 low, across **AWS** (60), **GCP** (35), and **Azure** (17): a
consistent cross-cloud baseline (public storage/databases, open admin ports,
public k8s control planes, wildcard/over-privileged IAM, TLS, encryption, public
snapshots, destruction) plus deep per-cloud coverage. Every rule is hand-ported
with a passing **and** a negative fixture, and carries its **provenance**
(`source: trivy` with the upstream `AVD-*` id, or `source: custom`). Coverage
map, rule format, and how to write your own: **[docs/rules.md](docs/rules.md)**.

**Dependency data — hosted [Advisor](docs/mcp.md):** CVE/OSV advisories across
npm, PyPI, Maven, Go, crates, RubyGems, and NuGet, plus known-malicious package
intel (`MAL-*`) — refreshed daily, with AI-written remediation insights on
critical/high CVEs. `bumper deps` and the agent malware-gate query it by package
coordinate only.

**Offline advisory catalog:** `bumper search` also spans ~2,600 knowledge-only
best-practice entries normalized from Trivy, Checkov, KICS, and Prowler — so an
agent can ask "what should I bake in before writing Terraform for X?" fully
offline.

## Why bumper is different

- **Reads the plan diff, not just the end state.** Most scanners check the
  resulting config. bumper also checks the *transition* (`create` / `delete` /
  `replace`) — the only way to catch "this `apply` will destroy your database."
  That **destruction** class is the differentiator.
- **Catches malice, not just bugs.** Dependency scanning flags known-vulnerable
  versions *and* known-malicious packages — the supply-chain attack, not only
  the stale CVE.
- **It enforces, it doesn't just warn.** `verify` binds a passing scan to the
  exact plan by sha256; the `guard` hook then *blocks* an unverified
  `apply`/`destroy`. A linter you can ignore becomes a gate you can't.
- **Built for the agent era.** Tool-layer guard hooks (Terraform apply + package
  installs) plus the hosted Advisor MCP mean your AI agent can no longer silently
  apply infra it didn't verify or install a known-malicious package.
- **Deterministic core stands alone.** The AI layer is garnish; if it's absent or
  fails, the deterministic findings are still complete and blocking.

How it stacks up against Checkov/Trivy (IaC) and Dependabot/Snyk/Socket (deps) —
including what it deliberately *doesn't* do — is in [docs/comparison.md](docs/comparison.md).

## CI / GitHub Action

Two composite actions, same signed release binary:

```yaml
# Terraform plan safety gate — SARIF + sticky PR comment, fail on high+
- uses: gnana997/bumper@v1
  with:
    plan-json: plan.json
    fail-severity: high

# Dependency scan — auto-detects lockfiles; malware always fails the job
- uses: gnana997/bumper/deps@v1
  with:
    fail-severity: high
```

Inputs, permissions, SARIF, and the sticky-comment behavior are documented in
[docs/ci.md](docs/ci.md). (The Marketplace listing is the Terraform action; the
dependency scan is the same repo at the `deps` subpath.)

## Documentation

| | |
| --- | --- |
| [docs/cli.md](docs/cli.md) | command reference — scan, deps, list, search, explain, verify, guard, tui, init |
| [docs/rules.md](docs/rules.md) | rule format (YAML + CEL), coverage, the advisory catalog, writing your own |
| [docs/ci.md](docs/ci.md) | the GitHub Actions — inputs, permissions, SARIF, sticky comment |
| [docs/agents.md](docs/agents.md) | the agent guardrail — the two tool-layer gates (Terraform apply + dependency install), agent skills, `bumper init`, supported agents |
| [docs/mcp.md](docs/mcp.md) | the hosted Advisor MCP — tools, what leaves the machine |
| [docs/architecture.md](docs/architecture.md) | internals, tech stack, supply-chain provenance, roadmap |
| [examples/](examples/) | runnable, hermetic examples for both gates |
| [e2e/](e2e/) | run the guardrail against a real Claude Code *or* Gemini CLI agent yourself (manual, local) |

## Contributing & security

New **rules** and real-world **plan fixtures** are the most valuable
contributions — see [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability,
use private disclosure per [SECURITY.md](SECURITY.md) (not a public issue).

## License

[Apache-2.0](LICENSE). Built-in rules adapted from Apache-2.0 sources (Trivy,
Checkov) retain attribution in [NOTICE](NOTICE); CIS Benchmark content is not
redistributed.
