# The agent enforcement model

Scanning tells you what's dangerous; **verify + guard make it unavoidable** — and
the MCP server lets an agent consult bumper *while* it writes Terraform. Together
they close the loop:

**`search_rules` (advise) → generate → `scan_plan` (verify) → `guard` (gate).**

- [Enforce the apply with verify and guard](#enforce-the-apply-with-verify-and-guard)
- [The verdict store](#the-verdict-store)
- [The guard hook](#the-guard-hook)
- [One-command setup: bumper init](#one-command-setup-bumper-init)
- [MCP tools](#mcp-tools)
- [Supported agents](#supported-agents)
- [Hosted Advisor (coming soon)](#hosted-advisor-coming-soon)

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

  • register MCP server · project      .mcp.json
  • install guard hook · project       .claude/settings.json
  • ignore .bumper/ verdict store      .gitignore
  • note verify workflow in CLAUDE.md  CLAUDE.md
```

`bumper init` is a hazard-console wizard; everything it writes is **merge-safe and
idempotent**. `--mcp` / `--hook` choose `project|user|none`; `--print` previews;
`--yes` runs non-interactively. It writes:

**`.mcp.json`** — registers the stdio MCP server:

```json
{
  "mcpServers": {
    "bumper": { "command": "bumper", "args": ["mcp"] }
  }
}
```

**`.claude/settings.json`** — installs the guard as a PreToolUse hook on `Bash`:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [{ "type": "command", "command": "bumper guard" }] }
    ]
  }
}
```

## MCP tools

`bumper mcp` runs the server directly (stdio) — what `init` wires up. It exposes
four tools to the agent:

| Tool | Does |
| --- | --- |
| `scan_plan` | scan a plan (inline JSON or a `.tfplan` path) → structured findings + a `blocking` verdict |
| `search_rules` | **before** writing Terraform for a resource, get what to bake in — bumper's **enforced** rules (must-fix) plus the **advisory** best-practice catalog, ranked |
| `list_rules` | browse the rule set (filter by severity / source / service) |
| `explain_rule` | one rule in full: the CEL check, fix, and provenance |

`search_rules` spans both corpora (enforced + the ~2,600-entry advisory catalog)
and runs fully offline — see
[rules.md → Enforced vs advisory](rules.md#enforced-vs-advisory-two-corpora).

## Supported agents

`bumper init` wires the MCP server + guard hook into **Claude Code**, **Codex**,
**opencode**, **auggie**, and **gemini**. The `--explain` enrichment (for
`scan`/TUI) shells out to whichever of `claude` / `gemini` / `codex` / `opencode` /
`auggie` you already have installed and authenticated — no API key, no vendor
account. The deterministic verdict never depends on any of them.

## Hosted Advisor (coming soon)

The scanner is offline and deterministic — that never changes. A hosted **Advisor**
MCP is planned as the optional other half: a knowledge-only server your agent can
query for semantic best-practice guidance across the full federated catalog
(lookup-not-upload — it never sees your plan or state). Track it at
[bumper.sh](https://bumper.sh).
