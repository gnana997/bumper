# The agent enforcement model

Scanning tells you what's dangerous; **the hooks make it unavoidable** — and the hosted
Advisor MCP lets an agent consult bumper *while* it works. Together they close the loop:

**advise (Advisor MCP) → generate → scan (CLI) → gate (hooks).**

- [Enforce the apply with verify and guard](#enforce-the-apply-with-verify-and-guard)
- [The verdict store](#the-verdict-store)
- [The guard hook](#the-guard-hook)
- [One-command setup: bumper init](#one-command-setup-bumper-init)
- [Scanning, not MCP tools](#scanning-not-mcp-tools)
- [Supported agents](#supported-agents)
- [Dependency guardrail](#dependency-guardrail)
- [Hosted Advisor](#hosted-advisor)

## Enforce the apply with verify and guard

The binding is by **sha256 of the saved plan**, so you can't verify one plan and
apply another:

```sh
terraform plan -out tfplan
bumper verify tfplan        # scans; exits 1 (and writes no verdict) on high/critical findings
terraform apply tfplan      # allowed only because verify recorded a verdict for this exact plan
```

- **`bumper verify <plan>`** runs `terraform show -json` itself, evaluates the
  rules, and on a pass writes a verdict bound to the plan's sha256. Blocking
  findings (≥ `high` by default) exit non-zero and write **nothing**; record an
  explicit override with `bumper verify --accept <plan>`.
- **`bumper guard`** is a **PreToolUse hook** that **denies** an unverified
  `terraform apply <plan>`, a bare `terraform apply` (which re-plans and applies in
  one unreviewable step), or a `terraform destroy`.

Because the guard lives in the agent's **tool layer**, it constrains the *agent* —
when you plan and apply by hand in your own terminal, you're never gated.
**Critical / destructive findings are a hard stop**; the agent must return to you
for an explicit decision. Lower severities are surfaced but overridable, so the
gate stays useful instead of becoming noise.

## The verdict store

A passing `verify` writes `.bumper/verified/<sha256>` — a small JSON verdict keyed
by the plan's content hash. It's **machine-specific and gitignored** (`bumper init`
adds `.bumper/` to `.gitignore`). A verdict expires after `guard --max-age` (12h by
default; `0` = never), so a stale approval can't unblock a much later apply.

Because the key is the plan's sha256, editing the plan, re-planning, or swapping in
a different `tfplan` invalidates the verdict — the guard will block until you
`verify` the new plan.

## The guard hook

`bumper guard` reads a tool-call payload on stdin and emits a Claude Code
PreToolUse decision on stdout. It **always exits 0** — the block is conveyed by the
JSON, not the exit code (so it can never wedge the agent's shell):

```console
$ echo '{"tool_name":"Bash","tool_input":{"command":"terraform apply tfplan"}}' | bumper guard
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",
 "permissionDecisionReason":"bumper: cannot verify \"tfplan\" — plan file not found at tfplan.
 Generate and verify a saved plan:\n  terraform plan -out tfplan\n  bumper verify tfplan\n  terraform apply tfplan"}}
```

Any command that isn't an unverified apply/destroy passes through untouched — the
guard never blanket-approves, so it's safe to install at user scope globally.

## One-command setup: bumper init

```console
$ bumper init --print
bumper init — would wire bumper into Claude Code:

  • install terraform guard · project   .claude/settings.json
  • install dependency hooks · project   .claude/settings.json
  • register advisor MCP · project       .mcp.json
  • ignore .bumper/ verdict store        .gitignore
  • note terraform workflow in CLAUDE.md CLAUDE.md
  • note deps workflow in CLAUDE.md      CLAUDE.md
```

`bumper init` is a hazard-console wizard; everything it writes is **merge-safe and
idempotent**. `--hook` scopes the hooks (`project|user|none`); `--terraform` / `--deps`
pick which hooks; `--advisor` scopes the MCP (`project|user|none`); `--print` previews;
`--yes` runs non-interactively. Hooks self-filter, so the defaults wire everything — a
repo that adds Terraform later is already covered. It writes:

**`.claude/settings.json`** — the guardrail hooks on `Bash` (terraform apply-guard,
dependency install-block, post-install scan):

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [{ "type": "command", "command": "bumper guard" }] },
      { "matcher": "Bash", "hooks": [{ "type": "command", "command": "bumper deps guard" }] }
    ],
    "PostToolUse": [
      { "matcher": "Bash", "hooks": [{ "type": "command", "command": "bumper deps watch" }] }
    ]
  }
}
```

**`.mcp.json`** — registers the hosted [Advisor MCP](mcp.md) (the single MCP — knowledge +
CVE/malware lookups; only package coordinates leave the machine):

```json
{
  "mcpServers": {
    "bumper-advisor": { "type": "http", "url": "https://advisor.bumper.sh/mcp" }
  }
}
```

## Scanning, not MCP tools

bumper has **one MCP** — the hosted [Advisor](mcp.md), for proactive knowledge/CVE/malware
lookups. *Scanning* is the CLI, enforced by the hooks:
- **Terraform:** `bumper verify <plan>` / `bumper <plan.json>` (the apply-guard requires it).
- **Dependencies:** `bumper deps` (the post-install hook runs it; see the
  [dependency guardrail](#dependency-guardrail)).

For offline rule lookups without the Advisor, the CLI has `bumper search` / `bumper list` /
`bumper explain` over the bundled catalog ([rules.md](rules.md#enforced-vs-advisory-two-corpora)).

## Supported agents

`bumper init` wires the hooks + advisor MCP into **Claude Code**, **Codex**,
**opencode**, **auggie**, and **gemini**. The `--explain` enrichment (for
`scan`/TUI) shells out to whichever of `claude` / `gemini` / `codex` / `opencode` /
`auggie` you already have installed and authenticated — no API key, no vendor
account. The deterministic verdict never depends on any of them.

## Dependency guardrail

The same enforcement idea, applied to **package installs** — a different action class, so
it's a separate pair of hooks (wired by `bumper init` alongside the terraform guard). It
uses the hosted [Advisor](api.md); only package coordinates leave the machine, never code.

A dependency carries two different risks, handled at two different moments:

- **Malicious package** (typosquat / backdoor; runs at install time) → **pre-install, hard
  block.** The `bumper deps guard` PreToolUse hook checks the named packages and **denies**
  the install if any is known-malicious — with a reason that names the package + advisory so
  the agent fixes the install (a typo, or an alternative) instead of just stopping.
- **Vulnerable dependency** (a legit package with a known CVE) → **post-install, non-blocking.**
  The `bumper deps watch` PostToolUse hook runs the scan after an install; when the tree is
  clean it's silent, and on findings it nudges the agent to **spawn a subagent** that runs
  `bumper deps`, pulls full detail via the Advisor MCP (`get_vuln`), and applies fixes —
  keeping the triage out of the main thread.

Run [`bumper deps`](cli.md#deps--the-dependency-guardrail) yourself any time to scan a
project. Detection is deterministic across all severities; the AI insight is the explain
layer, fetched on demand.

## Hosted Advisor

The scanner is offline and deterministic — that never changes. The hosted **Advisor**
is the optional other half: a knowledge-only server your agent can query for semantic
best-practice guidance across the full federated catalog, plus CVE lookups and a
known-malicious-package check (lookup-not-upload — it never sees your plan or state).
It's live at `advisor.bumper.sh`.

- **[Advisor MCP](mcp.md)** — connect the remote MCP to your agent (one line, no install).
- **[Advisor API](api.md)** — the same data over plain REST.
