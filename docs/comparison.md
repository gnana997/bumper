# How bumper compares

bumper isn't trying to replace your scanner suite. It occupies a specific niche: **the moment
of change** — a `terraform apply`, a package install — and especially **inside the agent
loop**, where code is generated and run without a human in the path. This page is an honest
map of where it overlaps existing tools, where it's genuinely different, and where it
deliberately does less.

- [Terraform plan safety](#terraform-plan-safety)
- [Dependency safety](#dependency-safety)
- [The agent guardrail](#the-agent-guardrail)
- [What bumper is *not*](#what-bumper-is-not)
- [When to reach for bumper](#when-to-reach-for-bumper)

## Terraform plan safety

vs **Checkov, Trivy/tfsec, Terrascan, KICS, Snyk IaC.**

Those are excellent, mature config scanners with huge rule sets across many frameworks. They
overwhelmingly check the **end state** — "is this configuration misconfigured?" bumper's wedge
is different: it reads the **plan diff** — the `create` / `update` / `delete` / `replace`
transition — so it can catch the class of problem an end-state scanner structurally can't:
*"this apply will destroy your database."*

| | bumper | Checkov / Trivy / Terrascan / Snyk IaC |
| --- | --- | --- |
| Reads the **plan diff** (create/delete/replace) | ✅ the core idea | ◑ mostly end-state config |
| Catches **destruction** (DB replace w/o snapshot, deletion-protection removed) | ✅ | ✗ (not a config-state property) |
| **Enforces** — binds a pass to the plan by sha256 and *blocks* the apply | ✅ `verify` + `guard` | ◑ warns / can fail CI; no apply-time bind |
| **Agent tool-layer hook** (blocks an unverified apply mid-session) | ✅ | ✗ |
| Deterministic, single static binary, fully offline | ✅ | ◑ varies |
| Raw rule count / frameworks | 112 enforced TF rules (+ ~2,600 advisory) | **far more** (thousands of rules; k8s, CFN, ARM, Helm, Dockerfile…) |
| Policy-as-code (Rego/OPA, custom graph policies) | ✗ (YAML+CEL rules) | ✅ (Checkov, others) |

**The honest summary:** for breadth — more clouds, more frameworks, thousands of rules,
custom policy languages — the incumbents win, and bumper happily federates their catalogs for
its advisory search. bumper wins on the **transition** (destruction/exposure as a *change*)
and on **enforcement in the agent loop**. They're complementary: run Checkov/Trivy for broad
config coverage, bumper as the apply-time safety gate.

## Dependency safety

vs **Dependabot, Snyk, Socket, osv-scanner, Trivy.**

| | bumper | Dependabot | Snyk | Socket | osv-scanner |
| --- | --- | --- | --- | --- | --- |
| Known-**vulnerable** scan (OSV/CVE) | ✅ | ✅ | ✅ | ◑ | ✅ |
| Known-**malicious** package block (OSV `MAL-`) | ✅ | ✗ | ◑ | ✅ | ◑ |
| **Behavioral / zero-day** malware detection | ✗ | ✗ | ◑ | ✅ (its specialty) | ✗ |
| **Pre-execution block in the agent loop** (deny the install *before* it runs) | ✅ | ✗ | ✗ | ◑ | ✗ |
| Auto-remediation **version-bump PRs** | ✗ | ✅ (its specialty) | ✅ | ◑ | ✗ |
| **Lookup-not-upload** (only coordinates leave; self-hostable) | ✅ | n/a (GitHub) | ✗ (SaaS) | ✗ (SaaS) | ✅ (local) |
| Same engine gates **infra + deps** | ✅ | ✗ | ◑ | ✗ | ✗ |

**The honest summary:** bumper's edge is the **pre-execution malware block at the agent's tool
layer** — it denies an install of a known-malicious package *before* the install runs, in the
loop where an AI agent would otherwise just run it. For *known-malicious* detection it relies
on OSV `MAL-` advisories; it does **not** do Socket-style behavioral analysis of novel
packages — Socket is more sophisticated there. For vulnerable-dependency *remediation*,
Dependabot's auto-PRs are the strength bumper doesn't have. Reach for bumper to **stop the bad
install in the agent loop and in CI** with one unified gate across infra and dependencies; keep
Dependabot/Snyk/Socket for what they each do best.

## The agent guardrail

This is the part with the fewest direct comparables. bumper installs **blocking pre-tool
hooks** into Claude Code, Augment, and Gemini CLI so the agent **cannot** run an unverified `terraform
apply` or install a known-malicious package — enforced at the tool layer, not as advice the
model can ignore. Most security tooling assumes a human runs the command and reads the report
later; bumper assumes an **agent** runs it, autonomously, and gates that. The hosted Advisor
MCP is the proactive half — the agent can ask "is this package safe?" / "what's the rule for
this resource?" *before* it writes the code. See [agents.md](agents.md).

## What bumper is *not*

Being explicit, because a security tool that overclaims is worse than useless:

- **Not a behavioral malware scanner.** It blocks *known*-malicious packages (OSV `MAL-`), not
  novel/zero-day payloads via static or behavioral analysis.
- **Not a dependency auto-updater.** No version-bump PRs — pair it with Dependabot/Renovate.
- **Not a full SCA platform.** No license compliance, SBOM management, or reachability for
  dependencies (yet).
- **Terraform only** for IaC — no CloudFormation, Pulumi, Kubernetes manifests, or Helm today.
- **Not a runtime or account-posture scanner.** It's a *change* gate (plan / install), not a
  continuous scanner of deployed infrastructure or live cloud accounts. (A read-only
  account-posture watcher is on the [roadmap](architecture.md#roadmap).)
- **Fewer raw IaC rules** than Checkov/Trivy — depth on the transition + enforcement, not
  breadth of config checks.

## When to reach for bumper

- You run an **AI coding agent** (Claude Code, Augment, Gemini CLI) and want it gated from destroying
  infra or installing malware — the case nothing else covers well.
- You want a **deterministic apply gate** that *blocks* on destruction/exposure, not just a
  linter that warns.
- You want **one gate across infra + dependencies**, in CI and in the agent loop, as a single
  static binary with no account.
- You care that dependency checks are **lookup-not-upload** and can be **self-hosted**
  ([self-hosting.md](self-hosting.md)).

It sits *alongside* Checkov/Trivy (broad config coverage), Dependabot (remediation PRs), and
Socket (behavioral supply-chain) — not in place of them.
