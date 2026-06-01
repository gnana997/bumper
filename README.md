# bumper

**Catch dangerous Terraform changes before you `apply` — and block the ones nobody reviewed.**

bumper reads a `terraform show -json` plan and flags changes that would **expose**
or **destroy** your cloud infrastructure (AWS, GCP, Azure). The verdict is 100%
deterministic, so it's safe to block a merge — or an `apply` — on it. It runs three
ways: a **CLI/CI gate**, an **MCP server** your coding agent calls, and a **guard
hook** that stops an agent from applying a plan it never verified. A locally
installed AI CLI optionally explains each finding in plain English.

> **v1.0.0.** Ships **95 curated rules** (17 critical / 49 high / 27 medium / 2 low) across
> **AWS** (57), **GCP** (35), and **Azure** (3): network exposure (security groups,
> NACLs, GCP firewalls — both legacy `google_compute_firewall` and the modern
> network/regional/hierarchical firewall **policy** rules — Azure NSGs; IPv4/IPv6,
> port-range aware), VPC hygiene (auto-mode networks, public-zone DNSSEC, subnet
> flow logs), least-privilege IAM (primitive owner/editor grants, user-managed
> service-account keys, SA impersonation roles, default-SA grants), GKE & Compute
> hardening (legacy metadata endpoints, metadata concealment, node/default service
> accounts, Shielded VM secure boot, OS Login, serial port, project-wide SSH keys),
> public
> endpoints (RDS/EKS/MQ, AKS, Cloud SQL public IP & authorized networks, BigQuery
> & Cloud Storage public access, GKE public control plane), IAM & resource
> policies (wildcard admin, open trust/ECR/SQS principals, `allUsers` bindings,
> GCP default service account / cloud-platform scope, lambda confused-deputy), TLS
> hygiene (incl. GCP SSL policies, Cloud SQL SSL enforcement), encryption at rest,
> EC2/ECR/EKS/CloudTrail and GKE hardening (legacy ABAC, Shielded Nodes, network
> policy), ECS plaintext-secret detection, KMS key rotation, and
> **destruction/recovery** checks (stateful-resource destroy across AWS & GCP,
> no-final-snapshot, deletion-protection off, PITR, versioning, backup retention). Rules are seeded from the Apache-2.0 Trivy +
> Checkov catalogs (see [docs/rule-catalog/](docs/rule-catalog/)) and hand-ported
> with tests. Account-posture checks (root MFA, credential rotation) are
> intentionally out of scope — they belong to a continuous account scanner, not a
> plan gate.

## Install

**Homebrew (macOS)** — recommended; puts `bumper` on your `PATH`:

```sh
brew install gnana997/tap/bumper
```

**Install script** (macOS / Linux) — downloads the latest release binary and verifies its checksum:

```sh
curl -sSfL https://raw.githubusercontent.com/gnana997/bumper/main/install.sh | sh
```

**Pre-built binaries** — download a tarball from the [releases page](https://github.com/gnana997/bumper/releases). Every release is checksummed, the checksum file is signed with [cosign](https://docs.sigstore.dev/) (keyless), and each artifact carries a SLSA build-provenance attestation — so you can prove the binary you're about to trust with your infra came from this repo's CI:

```sh
cosign verify-blob \
  --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/gnana997/bumper/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  checksums.txt
sha256sum -c checksums.txt --ignore-missing
# or verify the build provenance:
gh attestation verify bumper_*_linux_amd64.tar.gz --repo gnana997/bumper
```

**Go developers**:

```sh
go install github.com/gnana997/bumper/cmd/bumper@latest
```

Then wire it into Claude Code (MCP server + apply-guard hook):

```sh
bumper init
```

## Why bumper is different

- **Reads the plan diff, not just the end state.** Most scanners check the
  resulting config. bumper also checks the *transition* (`create`/`delete`/
  `replace`), which is the only way to catch "this `apply` will destroy your
  database." That class of **destruction** rule is bumper's differentiator.
- **It enforces, it doesn't just warn.** `bumper verify` binds a passing scan to
  the exact plan by sha256; the `guard` hook then **blocks** a `terraform
  apply`/`destroy` an agent tries to run against an unverified plan. A linter you
  can ignore becomes a gate you can't.
- **Built for the agent era.** A native MCP server exposes `scan_plan` /
  `list_rules` / `explain_rule`, and `bumper init` wires both the server and the
  guard into Claude Code in one command.
- **AI enrichment with zero setup, zero cost.** If you already have `claude`,
  `gemini`, `codex`, `opencode`, or `auggie` installed and authenticated,
  `--explain` shells out to it. No API key to paste, no vendor account for us.
- **Deterministic core stands alone.** The AI layer is pure garnish; if it's
  absent or fails, the deterministic findings are still complete and blocking.

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

Exit codes: `0` = clean, `1` = findings present (CI-friendly), `2` = usage/parse error.

Output formats: `--format text` (default), `json`, `sarif` (GitHub code scanning),
`markdown` (a PR-comment body).

## Enforce the apply (verify + guard)

Scanning tells you what's dangerous; **verify + guard make it unavoidable**. The
binding is by sha256 of the saved plan, so you can't verify one plan and apply
another:

```sh
terraform plan -out tfplan
bumper verify tfplan        # scans; exits 1 (and writes no verdict) on high/critical findings
terraform apply tfplan      # allowed only because verify recorded a verdict for this exact plan
```

- `bumper verify <plan>` runs `terraform show -json` itself, evaluates the rules,
  and on a pass writes a verdict to `.bumper/verified/<sha256>` (gitignored).
  Blocking findings (≥ `high` by default) exit non-zero and write nothing; record
  an explicit override with `bumper verify --accept <plan>`.
- `bumper guard` is a Claude Code **PreToolUse hook**. It reads each Bash tool
  call and **denies** an unverified `terraform apply <plan>`, a bare
  `terraform apply` (which re-plans and applies in one unreviewable step), or a
  `terraform destroy`. Every other command passes through untouched — it never
  blanket-approves, so it's safe to install globally.

Because the guard lives in the agent's tool layer, it constrains the *agent* —
when you plan and apply by hand in your own terminal, you're never gated.

## Claude Code: MCP + one-command setup

```sh
bumper init     # interactive wizard: choose project/user scope for the MCP server + guard hook
bumper mcp      # run the MCP server directly (stdio) — what init wires up
```

`bumper init` is a hazard-console wizard that registers the MCP server in
`.mcp.json`, installs the guard in `.claude/settings.json`, ignores `.bumper/`,
and drops the verify→apply workflow into `CLAUDE.md` — all merge-safe and
idempotent. `--mcp`/`--hook` choose `project|user|none`; `--print` previews;
`--yes` runs non-interactively.

The MCP server exposes three tools to the agent:

| Tool | Does |
| --- | --- |
| `scan_plan` | scan a plan (inline JSON or a `.tfplan` path) → structured findings + a `blocking` verdict |
| `list_rules` | browse the rule set (filter by severity / source / service) |
| `explain_rule` | one rule in full: the CEL check, fix, and provenance |

## Interactive console (TUI)

For the local "scary `apply`" moment, browse findings interactively:

```sh
bumper tui plan.json     # the "hazard console" — findings board with a severity spine
bumper list --tui        # browse the whole rule set interactively
```

A two-pane board: a BLAST RADIUS severity histogram, findings down the left with
a color-coded severity spine, full detail (fix, provenance, the CEL check) on the
right, and `e` to pull a plain-English explanation from a local AI CLI. Keys:
`↑↓` move · `→` detail · `f` filter · `/` search · `e` explain · `?` help · `q` quit.

The TUI is **opt-in** and refuses to run when piped — the default `text`/`json`/
`sarif` output is what CI uses. Built on Bubble Tea (pure Go, still one binary).

## Inspecting the rule set

Every rule is inspectable — part of the trust story (you can see exactly what
fires and where it came from):

```sh
bumper list                          # all rules: severity · source · id · resource · title
bumper list --source custom          # only bumper's own (non-Trivy) rules
bumper list --severity critical      # filter by severity
bumper list --service rds            # filter by service/resource substring
bumper list --format json            # machine-readable catalog
bumper explain AWS_RDS_PUBLICLY_ACCESSIBLE   # one rule: provenance, fix, and the CEL check
```

Each rule carries its **provenance** — `source: trivy` (with the original
`AVD-AWS-NNNN` / `AVD-GCP-NNNN` / `AVD-AZU-NNNN` id) or `source: custom` for
bumper's own checks (the destruction/plan-diff rules and a few others).

## CI / GitHub Action

bumper ships a composite action that uploads SARIF to the **Security** tab and
posts a **sticky** PR comment (updated in place on every push — never spammed):

```yaml
permissions:
  contents: read
  security-events: write   # SARIF upload
  pull-requests: write     # sticky comment

steps:
  - uses: hashicorp/setup-terraform@v3
  - run: |
      terraform init -input=false
      terraform plan -input=false -out=plan.tfplan
      terraform show -json plan.tfplan > plan.json
  - uses: gnana997/bumper@v1
    with:
      plan-json: plan.json
      fail-severity: high        # fail the check on any high+ finding
```

See [.github/workflows/example-pr-gate.yml](.github/workflows/example-pr-gate.yml)
for the full template. The comment uses a hidden marker (`<!-- bumper -->`) to
find and replace its previous comment, so a PR only ever has one bumper comment.

## Rule format

Rules are declarative YAML with a [CEL](https://github.com/google/cel-go)
predicate. Built-ins are embedded in the binary
(`internal/rules/builtin/<provider>/`); add your own with `--rules ./my-rules/`.
The differentiator — a **destruction** rule that reads the change *actions*, not
the end state:

```yaml
- id: AWS_STATEFUL_RESOURCE_DESTROY
  source: custom
  severity: high
  on: [delete, replace]          # change actions ("" = any)
  when: |                        # CEL predicate; true => finding
    type in [
      "aws_db_instance", "aws_rds_cluster", "aws_dynamodb_table",
      "aws_s3_bucket", "aws_efs_file_system", "aws_redshift_cluster"
    ]
  title: "This apply will DELETE or REPLACE a stateful data resource (potential data loss)"
  fix: "Confirm the destruction is intended. Check prevent_destroy, final snapshots, and backups before applying."
```

Variables available to `when`: `address` (string), `type` (string),
`actions` (list<string>), `before` (dyn), `after` (dyn). Guard dynamic field
access with `has(...)` so a rule that doesn't apply simply doesn't match.

Custom CEL functions (see [internal/rules/celfuncs.go](internal/rules/celfuncs.go)):

- `parse_json(s)` — parse a JSON string (e.g. an IAM `policy`) into a value;
  returns `{}` on error so callers can `has(...)`-guard.
- `as_list(x)` — normalize the "string or array" idiom (`Action`, `Resource`,
  `Principal.AWS`, GCP IAM `members`); scalar → `[scalar]`, null → `[]`.
- `hits_sensitive_port(from, to)` — true if an inclusive port range covers any
  sensitive admin/db/cache port.
- `ports_hit_sensitive(ports)` — same, for the string/range port lists used by
  GCP firewalls and Azure NSGs (`"22"`, `"8080-8090"`).

## Architecture

```
cmd/bumper/            CLI: subcommand dispatch, flags, exit codes
internal/plan/         terraform-json -> normalized {address,type,actions,before,after}
internal/rules/        YAML loader + CEL compile (go:embed builtins by provider + --rules dir)
internal/engine/       evaluate changes x rules -> ranked findings
internal/report/       text / json / sarif / markdown output
internal/enrich/       AI-CLI adapters (claude/gemini/...) — optional enrichment
internal/safety/       verify + guard — the sha256-bound apply gate
internal/mcpserver/    MCP server: scan_plan / list_rules / explain_rule
internal/setup/        `bumper init` — merge-safe MCP + hook wiring
internal/tui/          the hazard-console TUI and the init wizard
```

Built with Go 1.26, [cel-go](https://github.com/google/cel-go) for predicates,
[terraform-json](https://github.com/hashicorp/terraform-json) for plan parsing,
the official [MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk), and
[Bubble Tea](https://github.com/charmbracelet/bubbletea) for the TUI. Single
static binary, no CGO.

## Roadmap

- Grow the multi-cloud rule set from the merged Trivy + Checkov worklist in
  [docs/rule-catalog/](docs/rule-catalog/) (GKE, Azure storage/keyvault next).
- Reachability beyond a single security group (SG → ENI → public subnet → IGW),
  to rank "actually reachable from the internet" above config-only exposure.
- A continuous, read-only account-posture watcher (the stateful tier) — distinct
  from this single-shot plan gate.

## Security

bumper takes its own supply chain seriously: releases are checksummed, signed
with cosign (keyless), and carry SLSA build-provenance attestations (see
[Install](#install) to verify). Dependencies are watched by Dependabot +
`govulncheck`, and the code by CodeQL. To report a vulnerability, see
[SECURITY.md](SECURITY.md) — please use private disclosure, not a public issue.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow. In short:

```sh
make build   # go build -o bumper ./cmd/bumper
make test    # go test ./...
make hooks   # install lefthook + gitleaks and wire up the git hooks
```

Git hooks (via [lefthook](https://github.com/evilmartians/lefthook), a single Go
binary — no Node): **pre-commit** runs a
[gitleaks](https://github.com/gitleaks/gitleaks) secret scan on staged changes +
a `gofmt` check; **pre-push** runs `go vet ./...` and `go test ./...`.

## License

[Apache-2.0](LICENSE). Built-in rules adapted from Apache-2.0 sources (Trivy,
Checkov) retain attribution in [NOTICE](NOTICE); CIS Benchmark content is not
redistributed.
