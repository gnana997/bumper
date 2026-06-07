# The agent guardrail

A coding agent doesn't just *suggest* changes — it **runs** them. bumper gates the two
riskiest actions an agent can take, **at the tool layer**, so it can't take them without
bumper's say-so:

1. a **`terraform apply`** that wasn't verified safe, and
2. an **install** of a known-malicious package.

And the hosted **Advisor MCP** lets the agent consult bumper *while it works* — before it
pins a dependency or writes Terraform for a resource. Together they close the loop:

**advise (Advisor MCP) → generate → scan (CLI) → gate (hooks).**

## The two guardrails

|  | Terraform apply gate | Dependency install gate |
| --- | --- | --- |
| **Catches** | a destructive / exposing `apply` | a vulnerable or known-malicious package |
| **Hook(s)** | `bumper guard` (PreToolUse) | `bumper deps guard` (PreToolUse) + `bumper deps watch` (PostToolUse) |
| **Fires** | before `apply` / `destroy` runs | before install (malware) **and** after install (CVEs) |
| **Decision** | deny an *unverified* apply | hard-deny a known-malicious install; nudge on CVEs |
| **Backing** | local deterministic rules + a sha256 verdict | the hosted Advisor (only coordinates leave the box) |

Both are wired in one step by [`bumper init`](#one-command-setup-bumper-init), for **Claude
Code**, **Augment**, and **Gemini CLI**. The hooks **self-filter**, so installing both is safe everywhere — a
Terraform guard in a Node repo simply never fires, and vice-versa.

- [The Terraform apply gate](#the-terraform-apply-gate)
- [Dependency guardrail](#dependency-guardrail)
- [How the hooks signal a block](#how-the-hooks-signal-a-block)
- [One-command setup: bumper init](#one-command-setup-bumper-init)
- [Scanning is the CLI, not an MCP tool](#scanning-is-the-cli-not-an-mcp-tool)
- [Supported agents](#supported-agents)
- [Hosted Advisor](#hosted-advisor)

---

## The Terraform apply gate

Scanning tells you a plan is dangerous; the gate makes acting on it **unavoidable**. The
binding is by **sha256 of the saved plan**, so you can't verify one plan and apply another:

```sh
terraform plan -out tfplan
bumper verify tfplan        # scans; exits 1 (and writes no verdict) on high/critical findings
terraform apply tfplan      # allowed only because verify recorded a verdict for this exact plan
```

- **`bumper verify <plan>`** runs `terraform show -json` itself, evaluates the rules, and on
  a pass writes a verdict bound to the plan's sha256. Blocking findings (≥ `high` by default)
  exit non-zero and write **nothing**; record an explicit override with
  `bumper verify --accept <plan>`.
- **`bumper guard`** is a **PreToolUse hook** that **denies** an unverified
  `terraform apply <plan>`, a bare `terraform apply` (which re-plans and applies in one
  unreviewable step), or a `terraform destroy`.

Because the guard lives in the agent's **tool layer**, it constrains the *agent* — when you
plan and apply by hand in your own terminal, you're never gated. **Critical / destructive
findings are a hard stop**; the agent must return to you for an explicit decision. Lower
severities are surfaced but overridable, so the gate stays useful instead of becoming noise.

### The verdict store

A passing `verify` writes `.bumper/verified/<sha256>` — a small JSON verdict keyed by the
plan's content hash. It's **machine-specific and gitignored** (`bumper init` adds `.bumper/`
to `.gitignore`). A verdict expires after `guard --max-age` (12h by default; `0` = never), so
a stale approval can't unblock a much later apply. Editing the plan, re-planning, or swapping
in a different `tfplan` changes the hash and invalidates the verdict — the guard blocks until
you `verify` the new plan.

Any command that isn't an unverified apply/destroy passes through untouched — the guard never
blanket-approves, so it's safe to install at user scope globally.

---

## Dependency guardrail

The same enforcement idea, applied to **package installs** — a different action class, so
it's a separate pair of hooks (wired by `bumper init` alongside the Terraform guard). It uses
the hosted [Advisor](api.md); only package coordinates leave the machine, never code.

A dependency carries two different risks, handled at two different moments:

- **Malicious package** (typosquat / backdoor; runs at install time) → **pre-install, hard
  block.** The `bumper deps guard` PreToolUse hook checks the named packages and **denies**
  the install if any is known-malicious — with a reason that names the package + advisory so
  the agent fixes the install (a typo, or an alternative) instead of just stopping.
- **Vulnerable dependency** (a legit package with a known CVE) → **post-install,
  non-blocking.** The `bumper deps watch` PostToolUse hook runs the scan after an install;
  when the tree is clean it's silent, and on findings it nudges the agent to run `bumper deps`,
  pull full detail via the Advisor MCP (`get_vuln`), and apply fixes — **spawning a subagent**
  to keep triage off the main thread if the agent supports one (e.g. Claude Code's `Task`).

Why the asymmetry: a malicious package is hostile *the moment it installs*, so it must be
stopped **before** it runs. A vulnerable-but-legitimate package is usually fine to install and
then upgrade, so blocking it would be noise — a nudge is enough.

Run [`bumper deps`](cli.md#deps--the-dependency-guardrail) yourself any time to scan a
project. Detection is deterministic across all severities; the AI insight is the explain
layer, fetched on demand.

---

## How the hooks signal a block

Every hook (`guard`, `deps guard`, `deps watch`) reads a tool-call payload on **stdin** and
responds two ways at once, so it works whether or not an agent understands bumper's JSON:

1. **A JSON decision on stdout** — what Claude Code / Augment parse and act on:

   ```console
   $ echo '{"tool_name":"Bash","tool_input":{"command":"terraform apply tfplan"}}' | bumper guard
   {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",
    "permissionDecisionReason":"bumper: cannot verify \"tfplan\" — plan file not found at tfplan.
    Generate and verify a saved plan:\n  terraform plan -out tfplan\n  bumper verify tfplan\n  terraform apply tfplan"}}
   ```

2. **Exit 2 + the reason on stderr** on a deny — a **universal block signal** for any agent
   that honors exit codes/stderr but ignores the JSON envelope (this is what lets new agents
   be supported with little or no code).

A passthrough (anything that isn't a blocked action) exits `0` and stays silent. A
**`watch`** hook is post-install and advisory, so it **never denies** — it only injects a
nudge and always exits `0`. And if a hook hits an internal error it **fails open**: it logs to
stderr and exits `0` rather than wedge the agent's shell.

### Debugging a hook

Because the hooks fail open, a payload mismatch (wrong tool name, command in an unexpected
field) looks like "nothing happened." To see exactly what an agent sends and what bumper
decided, add `--log <file>` (or set `$BUMPER_HOOK_LOG`) to any hook command:

```sh
bumper deps guard --client=augment --log /tmp/bumper-hooks.log
# or, without touching config:
export BUMPER_HOOK_LOG=/tmp/bumper-hooks.log
```

Each invocation appends one JSON line — timestamp, hook name, the raw stdin payload, and the
emitted decision (`""` = silent allow):

```json
{"hook":"guard","in":{"tool_name":"launch-process","tool_input":{"command":"terraform destroy"}},"out":{"hookSpecificOutput":{"permissionDecision":"deny","...":"..."}},"ts":"2026-06-07T13:05:33+05:30"}
```

This is the fastest way to confirm a new agent's shell-tool name and command field before
trusting the gate (logging is best-effort and never affects the hook's behavior).

---

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
idempotent**. `--agent claude|augment|gemini` picks the target agent (auto-detected by default);
`--hook` scopes the hooks (`project|user|none`); `--terraform` / `--deps` pick which hooks;
`--advisor` scopes the MCP (`project|user|none`); `--print` previews; `--yes` runs
non-interactively. Defaults wire **everything** — a repo that adds Terraform (or a lockfile)
later is already covered.

### Claude Code

**`.claude/settings.json`** — the guardrail hooks on `Bash` (Terraform apply-guard,
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

### Augment

`bumper init --agent augment` wires the same guardrail into Augment. The shapes are identical;
only the location and the shell-tool name differ. Augment **co-locates hooks and MCP in one
file** — `.augment/settings.json` — matches its shell tool **`launch-process`** (not `Bash`),
and the baked commands carry `--client=augment` so the hook knows which tool to expect.
Workflow notes go to `AGENTS.md` instead of `CLAUDE.md`:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "launch-process", "hooks": [{ "type": "command", "command": "bumper guard --client=augment" }] },
      { "matcher": "launch-process", "hooks": [{ "type": "command", "command": "bumper deps guard --client=augment" }] }
    ],
    "PostToolUse": [
      { "matcher": "launch-process", "hooks": [{ "type": "command", "command": "bumper deps watch --client=augment" }] }
    ]
  },
  "mcpServers": {
    "bumper-advisor": { "type": "http", "url": "https://advisor.bumper.sh/mcp" }
  }
}
```

### Gemini CLI

`bumper init --agent gemini` wires the same guardrail into **Gemini CLI**. Like Augment, it
**co-locates hooks and MCP in one file** — `.gemini/settings.json` — but Gemini differs in two
ways: it names its shell tool **`run_shell_command`**, and it uses **`BeforeTool`/`AfterTool`**
event keys (not `PreToolUse`/`PostToolUse`). Its MCP entry uses **`httpUrl`** for a
streamable-HTTP server, and workflow notes go to `GEMINI.md`. The baked commands carry
`--client=gemini`. A deny is delivered via the [exit-2 + stderr backstop](#how-the-hooks-signal-a-block),
which Gemini honors as a hard block:

```json
{
  "hooks": {
    "BeforeTool": [
      { "matcher": "run_shell_command", "hooks": [{ "type": "command", "command": "bumper guard --client=gemini" }] },
      { "matcher": "run_shell_command", "hooks": [{ "type": "command", "command": "bumper deps guard --client=gemini" }] }
    ],
    "AfterTool": [
      { "matcher": "run_shell_command", "hooks": [{ "type": "command", "command": "bumper deps watch --client=gemini" }] }
    ]
  },
  "mcpServers": {
    "bumper-advisor": { "httpUrl": "https://advisor.bumper.sh/mcp" }
  }
}
```

> **Gemini folder trust (CI / headless).** Gemini treats project hooks as
> **untrusted by default**. Interactively, the first time you open the project it
> shows a one-time trust prompt and then runs them — so the guardrail just works for
> day-to-day use. But in **headless mode** (`gemini -p …`, CI) it can't show that
> prompt and **silently skips the hook**. For any automated/headless run, trust the
> workspace with **`GEMINI_CLI_TRUST_WORKSPACE=true`** (or trust the folder once
> interactively). Note: **`--skip-trust` does *not* enable hooks** — it proceeds *as
> untrusted*; only the env var (or interactive trust) turns project hooks on.
> See [Gemini's trusted-folders docs](https://geminicli.com/docs/cli/trusted-folders/#headless-and-automated-environments).

---

## Scanning is the CLI, not an MCP tool

bumper has **one MCP** — the hosted [Advisor](mcp.md), for proactive knowledge/CVE/malware
*lookups*. *Scanning your own code* is the CLI, enforced by the hooks:

- **Terraform:** `bumper verify <plan>` / `bumper <plan.json>` (the apply-guard requires it).
- **Dependencies:** `bumper deps` (the post-install hook runs it).

This split is deliberate — the agent uses the MCP to *look things up* (best practice, "is this
package safe?") and the CLI to *act on your code* (your plan and lockfiles never leave the
machine). For offline rule lookups without the Advisor, the CLI also has `bumper search` /
`bumper list` / `bumper explain` over the bundled catalog
([rules.md](rules.md#enforced-vs-advisory-two-corpora)).

## Supported agents

`bumper init` wires both guardrails + the Advisor MCP into **Claude Code** (`--agent claude`,
the default), **Augment** (`--agent augment`), and **Gemini CLI** (`--agent gemini`) — three
agents with a pluggable blocking pre-tool hook the binary speaks today. **Codex** is on the
roadmap; hook contracts differ only in the deny envelope / event names, and the
[exit-2 + stderr backstop](#how-the-hooks-signal-a-block) already covers any agent that honors
exit codes.

Separately, the `--explain` enrichment (for `scan`/TUI) shells out to whichever of `claude` /
`gemini` / `codex` / `opencode` / `auggie` you already have installed and authenticated — no
API key, no vendor account. The deterministic verdict never depends on any of them.

## Hosted Advisor

The scanner is offline and deterministic — that never changes. The hosted **Advisor** is the
optional other half: a knowledge-only server your agent can query for semantic best-practice
guidance across the full federated catalog, plus CVE lookups and a known-malicious-package
check (lookup-not-upload — it never sees your plan or state). It's live at `advisor.bumper.sh`.

- **[Advisor MCP](mcp.md)** — connect the remote MCP to your agent (one line, no install).
- **[Advisor API](api.md)** — the same data over plain REST.
