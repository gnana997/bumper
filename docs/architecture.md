# Architecture & internals

bumper is **one static Go binary** with three jobs: scan a Terraform plan, scan a
dependency lockfile, and gate both at an agent's tool layer. A separate hosted service —
the [Advisor](api.md) — supplies the knowledge/CVE/malware data over HTTP. Everything below
is the binary unless noted.

- [Package layout](#package-layout)
- [Data flow](#data-flow)
- [Reading the plan JSON](#reading-the-plan-json)
- [The hosted Advisor](#the-hosted-advisor)
- [Tech stack](#tech-stack)
- [Releases and provenance](#releases-and-provenance)
- [Roadmap](#roadmap)

## Package layout

```
cmd/bumper/            CLI: subcommand dispatch, flags, exit codes, the hook runners
internal/plan/         terraform-json -> normalized {address, type, actions, before, after}
internal/rules/        YAML loader + CEL compile (go:embed builtins by provider + --rules dir)
internal/engine/       evaluate changes × rules -> ranked findings
internal/safety/       verify + guard — the sha256-bound apply gate
internal/deps/         dependency guardrail: lockfile parsers + Advisor REST client + hooks
internal/catalog/      embedded advisory catalog (federated Trivy/Checkov/KICS/Prowler)
internal/search/       cross-corpus BM25 search over enforced + advisory
internal/report/       text / json / sarif / markdown reporters (plan + deps)
internal/enrich/       AI-CLI adapters (claude/gemini/…) — optional --explain enrichment
internal/style/        terminal color palette (truecolor + 16-color fallback, TTY/NO_COLOR aware)
internal/setup/        `bumper init` — merge-safe hook + advisor-MCP wiring (Claude + Augment + Gemini)
internal/tui/          the hazard-console TUI and the init wizard
```

The **deterministic core** (`plan`, `rules`, `engine`, `safety`) never imports the
presentation or AI layers (`report`, `enrich`, `tui`, `style`) — the verdict can never depend
on a model or on rendering. That boundary is the whole trust story: the same plan always
yields the same findings. The dependency path (`deps`) is deterministic too — the Advisor
returns facts (advisory IDs, fixed versions); the AI insight is fetched separately, on demand,
and is never part of the pass/fail decision.

## Data flow

Two independent scan paths feed a shared set of reporters and the same hook layer:

```
TERRAFORM
terraform show -json → internal/plan    normalize each change to {address, type, actions, before, after}
                       internal/rules    load + CEL-compile builtins (+ --rules)
                       internal/engine   for each change × matching rule, eval when(…) → Finding; rank
                       internal/safety   verify → verdict (sha256) ; guard → allow/deny

DEPENDENCIES
lockfile             → internal/deps     parse locally → POST coordinates to the Advisor /scan
                       internal/deps     deps guard (pre-install malware block) / deps watch (post-install)

BOTH  →  internal/report   text / json / sarif / markdown      (+ internal/style colorization)
```

`internal/search` + `internal/catalog` sit alongside the engine: they power `bumper search`
and the `search_rules` MCP tool, spanning the enforced rules **and** the embedded advisory
corpus. They have no part in either scan's pass/fail verdict.

The hooks (`guard`, `deps guard`, `deps watch`) are thin runners in `cmd/bumper` over
`internal/safety` and `internal/deps`: read a tool-call payload on stdin, emit a JSON
decision on stdout, and exit `2` + stderr on a block (the universal backstop — see
[agents.md](agents.md#how-the-hooks-signal-a-block)).

## Reading the plan JSON

The single highest-leverage thing to understand when writing rules — the shape of
`terraform show -json` output:

- **HCL nested blocks become arrays of objects.** A single `ingress { … }` block arrives as
  `after.ingress` = `[{…}]`. Traverse with CEL's `.exists(r, …)` / `.all(r, …)`, **not**
  `after.ingress[0]` or `size(...)` assumptions.
- **Unset optional fields render `null`, not absent.** Always `has(...)`-guard, and prefer
  `x != true` over `x == false` for optional booleans (a `null` is neither).
- **Computed / "known after apply" fields render `null`.** A rule keyed on a value Terraform
  can't know yet simply won't fire — don't depend on it.
- **`before` is `null` on create; `after` is `null` on delete.** Destruction rules
  (`on: [delete, replace]`) read `before` and the `actions`, never `after`.

`internal/plan` flattens all of this into the five variables a rule sees (`address`, `type`,
`actions`, `before`, `after`); see [rules.md](rules.md) for the authoring side. A rule that
errors on a resource is treated as "no match", so these guards are about correctness, not
just style.

## The hosted Advisor

The dependency scan and the agent's knowledge lookups are backed by the **Advisor** — a
separate **open-core service** (the `bumper-advisor` repo, Apache-2.0), live at
`advisor.bumper.sh`. It serves the federated IaC catalog + a CVE/malware mirror built from
[OSV](https://osv.dev), over both REST ([api.md](api.md)) and MCP ([mcp.md](mcp.md)). It is
**lookup-not-upload**: the binary sends a query or package coordinates, never your code, plan,
or state. You can [self-host](self-hosting.md) it and point `--advisor-url` (or
`$BUMPER_ADVISOR_URL`) at your own instance. The AI insights are the hosted instance's
value-add and aren't part of the open distribution — a self-host serves the complete
deterministic data without them. The binary degrades gracefully if the Advisor is unreachable —
Terraform scanning is fully offline and never needs it.

## Tech stack

Built with **Go 1.26**, [cel-go](https://github.com/google/cel-go) for predicates,
[terraform-json](https://github.com/hashicorp/terraform-json) for plan parsing, the official
[MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk), and
[Bubble Tea](https://github.com/charmbracelet/bubbletea) for the TUI. **Single static binary,
`CGO_ENABLED=0`** — clean cross-compile, fully offline for Terraform scanning, air-gap
friendly. (The Advisor is a separate open-core service — Python + Postgres/pgvector — in the
`bumper-advisor` repo.)

## Releases and provenance

bumper takes its own supply chain seriously. Every release is **checksummed**, the checksum
file is **cosign-signed** (keyless, via GitHub OIDC), and each artifact carries a **SLSA
build-provenance attestation** — so you can prove the binary you're about to trust with your
infra came from this repo's CI:

```sh
# verify the signed checksums, then the artifact against them
cosign verify-blob \
  --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/gnana997/bumper/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  checksums.txt
sha256sum -c checksums.txt --ignore-missing

# or verify the build provenance directly
gh attestation verify bumper_*_linux_amd64.tar.gz --repo gnana997/bumper
```

The `install.sh` / `get.bumper.sh` installer verifies the sha256 against `checksums.txt`
before installing. Dependencies are watched by Dependabot + `govulncheck` (bumper also scans
its own `go.sum` in CI), and the code by CodeQL. Report vulnerabilities via private disclosure
— see [SECURITY.md](../SECURITY.md).

## Roadmap

Shipped and live: the Terraform apply gate, the dependency guardrail (vulnerable + malicious),
the hosted Advisor (MCP + REST), and agent wiring for Claude Code, Augment, and Gemini CLI. Next:

- **More agents** — Codex next. Hook contracts differ only in the deny envelope / event names
  (Gemini's `BeforeTool`/`AfterTool` vs Claude's `PreToolUse`/`PostToolUse`); the
  [exit-2 + stderr backstop](agents.md#how-the-hooks-signal-a-block) already covers basic
  blocking for any agent that honors exit codes.
- **Grow the multi-cloud rule set** from the embedded advisory catalog
  ([internal/catalog/](../internal/catalog/), rebuilt with `make catalog`) — port high-value
  intents into enforced CEL rules.
- **Reachability** beyond a single security group (SG → ENI → public subnet → IGW), to rank
  "actually reachable from the internet" above config-only exposure.
- A continuous, read-only **account-posture watcher** (the stateful tier) — distinct from this
  single-shot plan gate.
