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
