# bumper × Claude Code — real end-to-end hook test

Drives the **actual** `claude` agent (headless `-p`) against bumper's guardrail
hooks, wired by `bumper init`, in throwaway repos. This proves the gate fires
inside a real agent loop — not just via piped payloads.

> [!WARNING]
> **Manual, local test — not for CI.** It runs ~3 real `claude -p` calls that
> **spend tokens on your own Claude account**, and it needs network (the live
> advisor at `advisor.bumper.sh` + the npm registry). Everything runs in throwaway
> temp dirs and npm is shimmed during the malware case, so nothing dangerous
> executes — but it is **not** hermetic and is intentionally **excluded from the
> automated test suite** (`go test ./...` does not run it).

## Run

```sh
cd e2e
./run-e2e.sh
```

Requires on PATH: `claude` (logged in), `bumper` (≥ 1.2.0), `terraform`, `npm`,
`jq`. Override via env: `BUMPER=`, `CLAUDE=`, `MAL_PKG=`, `VULN_PKG=`
(e.g. `MAL_PKG=some-other-mal-pkg ./run-e2e.sh`).

Tested against `claude` 2.1.150 — the CLI's flags can change between versions, so
if a scenario fails unexpectedly, first check the flags in `claude --help`
(`--permission-mode`, `--output-format`) and the captured `log-*.jsonl`.

### Gemini CLI variant (`run-e2e-gemini.sh`)

The same three scenarios against the **actual `gemini` agent**, wired by
`bumper init --agent gemini`:

```sh
cd e2e
./run-e2e-gemini.sh
```

Requires `gemini` (logged in, **a build with hooks support** — `BeforeTool`/
`AfterTool`) plus the same `bumper`/`terraform`/`npm`/`jq`. Override via
`GEMINI=`, `BUMPER=`, `MAL_PKG=`, `VULN_PKG=`.

What's different from the Claude run (all handled by bumper, transparent to you):

| | Claude Code | Gemini CLI |
|---|---|---|
| shell tool | `Bash` | `run_shell_command` |
| hook events | `PreToolUse` / `PostToolUse` | `BeforeTool` / `AfterTool` |
| config file | `.claude/settings.json` | `.gemini/settings.json` |
| headless flags | `-p --permission-mode bypassPermissions` | `-p --yolo` + `GEMINI_CLI_TRUST_WORKSPACE=true` |
| **how a deny lands** | JSON deny on stdout | **exit-2 + stderr backstop** (Gemini ignores stdout on a block) |

> [!IMPORTANT]
> **Folder trust (the headless gotcha).** Gemini treats project hooks in
> `.gemini/settings.json` as **untrusted by default**: interactively it shows a
> one-time trust prompt and then runs them, but in **headless `-p` mode it can't
> prompt, so it silently skips the hook** (no warning, no execution — the gate just
> never fires). The script exports **`GEMINI_CLI_TRUST_WORKSPACE=true`** to genuinely
> trust the workspace so the hooks run.
> **`--skip-trust` is NOT enough** — it proceeds *as untrusted* and hooks stay off;
> only the env var (or interactive trust) turns them on.
> **Real users don't hit this** — they trust their own project once (interactively)
> and the guardrail fires normally thereafter. See
> [Gemini's trusted-folders docs](https://geminicli.com/docs/cli/trusted-folders/#headless-and-automated-environments).

The assertions are **identical** because they read bumper's own
`$BUMPER_HOOK_LOG`, which is client-independent: bumper writes the same
`hookSpecificOutput` JSON for every agent (Gemini just blocks via exit 2 instead of
reading it), so `permissionDecision == "deny"` and the `additionalContext` nudge
both still appear in the log. `--yolo` makes Gemini actually *attempt* the shell
command (so the `BeforeTool` hook fires); the exit-2 deny stops it before it runs.

> The subagent-capture script (`capture-subagent.sh`) is **Claude-specific** (it
> parses Claude's `stream-json` event shape) and isn't ported to Gemini.

### Agent-skills variant (`run-e2e-skills.sh`)

A **different** proof from the hook tests above. It verifies bumper's
[Agent Skills](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview)
(`SKILL.md` playbooks) work in a real agent loop: the agent **discovers** the
right skill from its description, **reads** the `SKILL.md` body, and **resolves**
the hybrid pointer by running `bumper skills get <name>` (the stub → CLI
indirection that lets the playbook track the installed binary).

```sh
cd e2e
./run-e2e-skills.sh              # Claude Code (default)
AGENT=gemini ./run-e2e-skills.sh # Gemini CLI
```

Requires `claude` **or** `gemini` (logged in), `bumper` (with the `skills`
subcommand), and `jq`. Override via `BUMPER=`, `CLAUDE=`, `GEMINI=`, `AGENT=`.

**Isolation = clean proof.** Each repo is set up with **`bumper skills install`
only** — no `bumper init`, so there are *no hooks* and *no* `CLAUDE.md`/`GEMINI.md`
workflow notes. The only thing that can make the agent bumper-aware is the
installed skill, so a `bumper skills get` call is unambiguous evidence the skill
drove the agent.

**Ground truth = a logging wrapper.** A tiny `bumper` shim is placed first on
`PATH`; it appends every argv the agent invokes to `bumper-calls.log`, then
forwards to the build under test (so real output is still served). Each scenario
resets the log, names a *situation* (never the skill or its command), tells the
agent to **act**, and passes if the right skill **engaged** — by **either** signal:

- **named** — the agent's reply names the right skill. Claude Code reads `SKILL.md`
  natively, and because the **hybrid** body is self-sufficient it often follows the
  playbook *without* the `bumper skills get` call — so naming it is proof of
  discovery + load.
- **ran** — the agent invoked `bumper` at all. In a skills-**only** repo bumper is
  knowable *only* via a loaded skill, so any bumper call (whether `skills get` or a
  direct `bumper deps`/scan) proves the skill drove it.

Both are valid load paths for a working skill, so passing on either avoids
penalising the graceful-degradation the hybrid design is built for.

| # | Prompt names | Expected skill |
|---|---|---|
| **A** | "apply this Terraform (plan.json present)" | `gating-terraform-plans` (`plan-gate`) — scans the seeded plan |
| **B** | "add `lodash@4.17.4`" | `triaging-vulnerable-dependencies` (`deps-triage`) |
| **C** | "is `event-stream` safe?" | `querying-the-bumper-advisor` (`advisor`) |

Scenario A is seeded with `examples/terraform-safety/{main.tf,plan.json}` (a real
plan with destructive changes) so the agent can actually scan it. A preflight
asserts the build under test serves a playbook offline (a stale binary without
`skills get` is a hard fail, not a false negative). The harness mechanics are
validatable token-free by pointing `CLAUDE=`/`GEMINI=` at a fake agent.

## What it checks

| # | Prompt to Claude | Expected | Safety |
|---|---|---|---|
| **A** | "run `terraform apply`" | terraform guard **denies** (PreToolUse); nothing is applied | `terraform_data` only — no provider, no cloud |
| **B** | "`npm install npm-security-testing`" | deps guard **denies**; npm never runs | **npm is shimmed** to an inert no-op, so a missed block still can't execute the package |
| **C** | "`npm install lodash@4.17.4`" | install succeeds; deps **watch** injects a remediation nudge | lodash is legit, just old (CVE-2019-10744) — safe to install |

## Capturing the triage subagent (`capture-subagent.sh`)

When the `deps watch` nudge fires, Claude spawns a **Task subagent** to remediate.
`--output-format json` only returns the *main* agent's final text — the subagent's
work lives in the event stream. `capture-subagent.sh` runs the watch scenario with
`--output-format stream-json --verbose --include-partial-messages` and prints the
subagent's full transcript: its spawn prompt, every tool call + output (incl.
`bumper deps` and advisor-MCP `get_vuln` lookups), and its final report.

```sh
./capture-subagent.sh                 # fresh capture (one claude call)
./capture-subagent.sh path/stream.jsonl   # re-render a SAVED stream (no claude call)
```

How it pulls subagent events: each stream line carries `parent_tool_use_id` —
**non-null = subagent**. Subagent steps arrive as complete `assistant` (tool_use)
and `user` (tool_result) messages tagged with that id; the Task spawn is a
top-level `assistant` tool_use named `Agent` carrying `input.prompt`. (Observed on
claude 2.1.150: the subagent autonomously ran `bumper deps` → consulted
`mcp__bumper-advisor__get_vuln` → applied the fix → re-scanned → reported back. The
advisor MCP loaded and worked in headless.)

## How it observes (ground truth)

It exports **`BUMPER_HOOK_LOG`** before each `claude -p` run, so every hook
invocation appends one JSON line:

```json
{"hook":"deps guard","in":{"tool_name":"Bash","tool_input":{"command":"npm install npm-security-testing"}},"out":{"hookSpecificOutput":{"permissionDecision":"deny", ...}},"ts":"..."}
```

Assertions run against that log (deterministic — independent of Claude's output
format), and Claude's final text is printed for context. Pass/fail per scenario,
then a summary. Artifacts (repos + `log-*.jsonl`) are left in a temp dir, printed
at the end, for inspection.

## Why these flags

- `--permission-mode bypassPermissions` — makes headless Claude **attempt** the
  Bash call (otherwise it won't, and the hook never fires — a silent false pass).
  PreToolUse hooks **still run** in this mode; an exit-2 deny stops the tool
  before permission rules are even evaluated.
- **Never `--bare`** — it explicitly *skips hooks*.
- The harness validates `.claude/settings.json` is valid JSON after `init`,
  because `claude -p` **silently ignores invalid settings files** (which would
  make hooks no-op without any error).

## Gotchas / notes

- **MCP:** `bumper init` also wires the advisor MCP into `.mcp.json`. In headless
  mode a project MCP server may sit "pending approval" and simply be unavailable
  — that does **not** affect the hook blocking (hooks call the advisor over REST
  directly). Scenario C's nudge tells Claude to use the `bumper-advisor` MCP for
  detail; if it's unapproved, Claude just won't have that tool — the watch still
  fires, which is what we assert.
- The exit-2 backstop means a deny exits the hook with code 2 **and** emits the
  JSON deny on stdout — so the block lands on every agent (including ones that
  ignore the JSON). On `claude` 2.1.150 the reason surfaces **once** (verified, no
  double-display).
- **Scenario B depends on the package staying in the OSV `MAL-` feed.** If
  `npm-security-testing` is ever delisted, point `MAL_PKG` at any current
  known-malicious name. Scenario C depends on `lodash@4.17.4` still carrying CVEs
  (it does — it's a textbook example).
- Re-running is safe; each run uses a fresh temp dir. Artifacts (repos, hook logs,
  streams) are left under `$TMPDIR` and printed at the end for inspection.
