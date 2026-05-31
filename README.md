# bumper

**Catch dangerous Terraform changes before you `apply` — and have them explained in plain English.**

bumper is a single static Go binary that reads a `terraform show -json` plan and
flags changes that would **expose** or **destroy** your AWS infrastructure. The
verdict is 100% deterministic (so it's safe to block a merge on); a locally
installed AI CLI optionally translates each finding into plain English.

> Status: early but real. Ships with 57 curated rules (11 critical / 34 high /
> 12 medium) spanning network exposure (security groups across 3 shapes + NACLs,
> IPv4/IPv6, port-range aware), IAM & resource policies (wildcard admin, open
> trust/ECR/SQS principals, lambda confused-deputy), TLS hygiene (CloudFront /
> API Gateway / OpenSearch), encryption at rest across the data services,
> EC2/ECR/EKS/CloudTrail hardening, ECS plaintext-secret detection, and
> destruction/recovery checks (stateful-resource destroy, no-final-snapshot,
> PITR, versioning, backup retention, deletion protection). Rules are seeded
> from the Trivy catalog (see [docs/rule-catalog/](docs/rule-catalog/)) and
> hand-ported with tests. Account-posture checks (root MFA, password policy,
> credential rotation) are intentionally out of scope — they belong to a
> continuous account scanner, not a plan gate.

## Why bumper is different

- **Reads the plan diff, not just the end state.** Most scanners check the
  resulting config. bumper also checks the *transition* (`create`/`delete`/
  `replace`), which is the only way to catch "this `apply` will destroy your
  database." That class of **destruction** rule is bumper's differentiator.
- **AI enrichment with zero setup, zero cost.** If you already have `claude`,
  `gemini`, `codex`, `opencode`, or `auggie` installed and authenticated,
  `--explain` shells out to it. No API key to paste, no vendor account for us.
- **Deterministic core stands alone.** The AI layer is pure garnish; if it's
  absent or fails, the deterministic findings are still complete.

## Quick start

```sh
go build -o bumper ./cmd/bumper

# produce plan JSON
terraform plan -out plan.tfplan
terraform show -json plan.tfplan > plan.json

# scan it
./bumper plan.json
./bumper --explain plan.json        # add plain-English enrichment
cat plan.json | ./bumper -          # or pipe via stdin
```

Exit codes: `0` = clean, `1` = findings present (CI-friendly), `2` = usage/parse error.

Output formats: `--format text` (default), `json`, `sarif` (GitHub code scanning),
`markdown` (a PR-comment body).

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
`AVD-AWS-NNNN` id) or `source: custom` for bumper's own checks (the
destruction/plan-diff rules and a few others).

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
  - uses: gnana097/bumper@v1
    with:
      plan-json: plan.json
      fail-severity: high        # fail the check on any high+ finding
```

See [.github/workflows/example-pr-gate.yml](.github/workflows/example-pr-gate.yml)
for the full template. The comment uses a hidden marker (`<!-- bumper -->`) to
find and replace its previous comment, so a PR only ever has one bumper comment.

## Rule format

Rules are declarative YAML with a [CEL](https://github.com/google/cel-go)
predicate. Built-ins are embedded in the binary (`internal/rules/builtin/`);
add your own with `--rules ./my-rules/`.

```yaml
- id: AWS_SG_PUBLIC_INGRESS_SENSITIVE
  severity: critical
  resource: aws_security_group   # resource-type filter ("" = any)
  on: [create, update]           # change actions ("" = any); use [replace] for destruction rules
  when: |                        # CEL predicate; true => finding
    has(after.ingress) && after.ingress.exists(r,
      has(r.cidr_blocks) && ("0.0.0.0/0" in r.cidr_blocks) &&
      has(r.from_port) && (r.from_port in [22.0, 3389.0, 5432.0, 3306.0, 6379.0, 27017.0]))
  title: "Security group exposes a sensitive port to the entire internet (0.0.0.0/0)"
  fix: "Restrict cidr_blocks to your VPC CIDR or a known admin range."
  refs: ["https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html"]
```

Variables available to `when`: `address` (string), `type` (string),
`actions` (list<string>), `before` (dyn), `after` (dyn). Guard dynamic field
access with `has(...)` so a rule that doesn't apply simply doesn't match.

Custom CEL functions (see [internal/rules/celfuncs.go](internal/rules/celfuncs.go)):

- `parse_json(s)` — parse a JSON string (e.g. an IAM `policy`) into a value;
  returns `{}` on error so callers can `has(...)`-guard.
- `as_list(x)` — normalize the IAM "string or array" idiom (`Action`,
  `Resource`, `Principal.AWS`); scalar → `[scalar]`, null → `[]`.
- `hits_sensitive_port(from, to)` — true if the inclusive port range covers any
  sensitive admin/db/cache port.

## Architecture

```
cmd/bumper/            CLI: flags, exit codes
internal/plan/         terraform-json -> normalized {address,type,actions,before,after}
internal/rules/        YAML loader + CEL compile (go:embed built-ins + --rules dir)
internal/engine/       evaluate changes x rules -> ranked findings
internal/enrich/       AI-CLI adapters (claude/gemini/...) — optional enrichment
internal/report/       text / json output
```

Built with Go 1.26, [cel-go](https://github.com/google/cel-go) for predicates,
and [terraform-json](https://github.com/hashicorp/terraform-json) for plan
parsing.

## Roadmap

- Grow the curated rule set (exposure + destruction first), seeded against the
  Apache-2.0 corpora (Checkov / Trivy / Prowler) as a coverage oracle.
- SARIF output and a PR-comment surface.
- Reachability beyond single security groups (SG → ENI → public subnet → IGW).

## Development

Git hooks are managed by [lefthook](https://github.com/evilmartians/lefthook)
(a single Go binary — no Node). After cloning:

```sh
make hooks   # installs lefthook + gitleaks, then wires up the hooks
```

- **pre-commit** — [gitleaks](https://github.com/gitleaks/gitleaks) secret scan on
  staged changes + `gofmt` check. Blocks the commit on a leak or unformatted Go.
- **pre-push** — `go vet ./...` and `go test ./...`.

`gitleaks` must be on `PATH` (`brew install gitleaks`, or
`go install github.com/zricethezav/gitleaks/v8@latest`). Config lives in
[lefthook.yml](lefthook.yml). To bypass in an emergency: `git commit --no-verify`.

## License

TODO. Built-in rules that derive from Apache-2.0 sources will retain attribution
in `NOTICE`.
