# Architecture & internals

- [Package layout](#package-layout)
- [Data flow](#data-flow)
- [Reading the plan JSON](#reading-the-plan-json)
- [Tech stack](#tech-stack)
- [Releases and provenance](#releases-and-provenance)
- [Roadmap](#roadmap)

## Package layout

```
cmd/bumper/            CLI: subcommand dispatch, flags, exit codes
internal/plan/         terraform-json -> normalized {address, type, actions, before, after}
internal/rules/        YAML loader + CEL compile (go:embed builtins by provider + --rules dir)
internal/engine/       evaluate changes x rules -> ranked findings
internal/report/       text / json / sarif / markdown output
internal/style/        terminal color palette (truecolor + 16-color fallback, TTY/NO_COLOR aware)
internal/enrich/       AI-CLI adapters (claude/gemini/...) — optional enrichment
internal/safety/       verify + guard — the sha256-bound apply gate
internal/mcpserver/    MCP server: scan_plan / search_rules / list_rules / explain_rule
internal/catalog/      embedded advisory catalog (federated Trivy/Checkov/KICS/Prowler)
internal/search/       cross-corpus BM25 search over enforced + advisory
internal/setup/        `bumper init` — merge-safe MCP + hook wiring
internal/tui/          the hazard-console TUI and the init wizard
```

The **deterministic core** (`plan`, `rules`, `engine`, `safety`) never imports the
presentation or AI layers (`report`, `enrich`, `tui`, `style`) — the verdict can
never depend on a model or on rendering. That boundary is the whole trust story:
the same plan always yields the same findings.

## Data flow

```
terraform show -json   →  internal/plan      normalize each resource change to
                                              {address, type, actions, before, after}
                          internal/rules      load + CEL-compile builtins (+ --rules)
                          internal/engine     for each change × each matching rule,
                                              evaluate when(...) → Finding; rank by severity
   ┌────────────────────────────┴───────────────────────────────┐
   ▼                            ▼                                 ▼
internal/report           internal/safety                  internal/mcpserver
text/json/sarif/md        verify → verdict (sha256)        scan_plan / search_rules /
(+ internal/style         guard → allow/deny JSON          list_rules / explain_rule
 colorization)                                             (over stdio)
```

`internal/search` + `internal/catalog` sit alongside the engine: they power
`bumper search` and the `search_rules` MCP tool, spanning the enforced rules **and**
the embedded advisory corpus. They have no part in the deterministic plan verdict.

## Reading the plan JSON

The single highest-leverage thing to understand when writing rules — the shape of
`terraform show -json` output:

- **HCL nested blocks become arrays of objects.** A single `ingress { … }` block
  arrives as `after.ingress` = `[{…}]`. Traverse with CEL's `.exists(r, …)` /
  `.all(r, …)`, **not** `after.ingress[0]` or `size(...)` assumptions.
- **Unset optional fields render `null`, not absent.** Always `has(...)`-guard, and
  prefer `x != true` over `x == false` for optional booleans (a `null` is neither).
- **Computed / "known after apply" fields render `null`.** A rule keyed on a value
  Terraform can't know yet simply won't fire — don't depend on it.
- **`before` is `null` on create; `after` is `null` on delete.** Destruction rules
  (`on: [delete, replace]`) read `before` and the `actions`, never `after`.

`internal/plan` flattens all of this into the five variables a rule sees
(`address`, `type`, `actions`, `before`, `after`); see [rules.md](rules.md) for the
authoring side. A rule that errors on a resource is treated as "no match", so these
guards are about correctness, not just style.

## Tech stack

Built with **Go 1.26**, [cel-go](https://github.com/google/cel-go) for predicates,
[terraform-json](https://github.com/hashicorp/terraform-json) for plan parsing, the
official [MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk), and
[Bubble Tea](https://github.com/charmbracelet/bubbletea) for the TUI. **Single
static binary, `CGO_ENABLED=0`** — clean cross-compile, fully offline, air-gap
friendly.

## Releases and provenance

bumper takes its own supply chain seriously. Every release is **checksummed**, the
checksum file is **cosign-signed** (keyless, via GitHub OIDC), and each artifact
carries a **SLSA build-provenance attestation** — so you can prove the binary you're
about to trust with your infra came from this repo's CI:

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

The `install.sh` / `get.bumper.sh` installer verifies the sha256 against
`checksums.txt` before installing. Dependencies are watched by Dependabot +
`govulncheck`, and the code by CodeQL. Report vulnerabilities via private
disclosure — see [SECURITY.md](../SECURITY.md).

## Roadmap

- Grow the multi-cloud rule set from the embedded advisory catalog
  ([internal/catalog/](../internal/catalog/), rebuilt with `make catalog`) — port
  high-value intents into enforced CEL rules.
- **Reachability** beyond a single security group (SG → ENI → public subnet →
  IGW), to rank "actually reachable from the internet" above config-only exposure.
- A continuous, read-only **account-posture watcher** (the stateful tier) —
  distinct from this single-shot plan gate.
- The **hosted Advisor** MCP — semantic best-practice search over the full
  federated catalog (see [agents.md](agents.md#hosted-advisor-coming-soon)).
