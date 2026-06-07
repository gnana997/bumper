# Command reference

Every command and flag. `bumper help` prints the summary; `bumper <cmd> -h` shows
a command's flags.

```
bumper [flags] plan.json        scan a plan (use "-" for stdin)
bumper tui plan.json            scan + open the interactive hazard console
bumper list [flags] [--tui]     list the rule set (or browse it interactively)
bumper search [flags] <query>   find rules by keyword/resource
bumper explain <RULE_ID>        show one rule in detail
bumper verify <plan.tfplan>     scan a saved plan and record a verdict that unblocks its apply
bumper guard                    PreToolUse hook: block unverified apply/destroy (reads stdin)
bumper deps [path]              scan a lockfile for vulnerable + malicious dependencies
bumper deps guard / watch       dependency install hooks (read stdin)
bumper init [flags]             wire bumper into your agent (guardrail hooks + advisor MCP)
bumper version
```

**Exit codes:** `0` = clean · `1` = findings present (CI-friendly) · `2` =
usage/parse error.

> **Flag ordering for `scan`.** The bare scan command uses Go's flag parser, which
> stops at the first positional — so **flags must come before the plan path**:
> `bumper --format json plan.json` ✅, not `bumper plan.json --format json` ❌.
> (`list`, `search`, etc. accept flags in any position.)

---

## `scan` (default command)

```sh
terraform plan -out plan.tfplan
terraform show -json plan.tfplan > plan.json
bumper plan.json
bumper --explain plan.json          # AI plain-English enrichment
cat plan.json | bumper -            # read the plan from stdin
```

```console
$ bumper plan.json
bumper found 3 issue(s) in this plan:

CRITICAL  aws_db_instance.main     This apply will DESTROY and recreate a database with no final snapshot
  rule  AWS_DB_DESTRUCTIVE_REPLACE_NO_SNAPSHOT
  fix   Set skip_final_snapshot = false, or find what forces replacement before applying.
  ref   https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance#skip_final_snapshot

CRITICAL  aws_security_group.web   Public internet ingress (0.0.0.0/0 or ::/0) to a sensitive port range
  rule  AWS_SG_PUBLIC_INGRESS
  fix   Restrict cidr_blocks/ipv6_cidr_blocks to known ranges and narrow the port range.

HIGH      aws_db_instance.main     This apply will DELETE or REPLACE a stateful data resource (potential data loss)
  rule  AWS_STATEFUL_RESOURCE_DESTROY
  fix   Confirm the destruction is intended. Check prevent_destroy, final snapshots, and backups.

3 finding(s)   2 critical · 1 high
```

| Flag | Default | Description |
| --- | --- | --- |
| `--format` | `text` | `text` · `json` · `sarif` (GitHub code scanning) · `markdown` (a PR-comment body) |
| `--min-severity` | `low` | report findings at or above: `info`\|`low`\|`medium`\|`high`\|`critical` |
| `--rules` | – | directory of additional `.yaml` rules to load alongside the built-ins |
| `--explain` | off | enrich findings via a locally-installed AI CLI |
| `--llm` | `auto` | which AI CLI for `--explain`: `auto`\|`claude`\|`gemini`\|`codex`\|`opencode`\|`auggie` |
| `--no-fail` | off | always exit `0`, even when findings are present (report-only) |

On a terminal, output is colored (critical red, high amber, fixes green) with a
severity tally; piped/redirected/CI output and `NO_COLOR` stay plain.

### Output formats

**`--format json`** — a flat array; `rule_id`, `severity`, `title`, `address`,
`fix`, `refs`, `provider`, `source` per finding:

```json
[
  {
    "rule_id": "AWS_DB_DESTRUCTIVE_REPLACE_NO_SNAPSHOT",
    "severity": "critical",
    "title": "This apply will DESTROY and recreate a database with no final snapshot",
    "address": "aws_db_instance.main",
    "fix": "Set skip_final_snapshot = false, ...",
    "refs": ["https://registry.terraform.io/.../db_instance#skip_final_snapshot"],
    "provider": "aws",
    "source": "custom"
  }
]
```

**`--format sarif`** — SARIF 2.1.0 for GitHub code scanning; `critical`/`high` map
to `error`, `medium` to `warning`, lower to `note`, with a `security-severity`
property so findings bucket correctly in the Security tab.

**`--format markdown`** — a PR-comment body (emoji severity tally, the critical/high
findings inline, the full set in a collapsible table) prefixed with a hidden
`<!-- bumper -->` marker so the [GitHub Action](ci.md) can update one sticky
comment in place. See [ci.md](ci.md).

---

## `verify` / `guard`

The apply gate. Full model in [agents.md](agents.md).

```sh
bumper verify tfplan                 # scans; exits 1 (writes no verdict) on high/critical
bumper verify --accept tfplan        # record an explicit override
bumper guard                         # PreToolUse hook; reads a tool-call payload on stdin
```

| Command | Flag | Default | Description |
| --- | --- | --- | --- |
| `verify` | `--min-severity` | `high` | block (exit 1, write no verdict) at or above this severity |
| `verify` | `--accept` | off | record a verdict even when blocking findings are present |
| `verify` | `--rules` | – | extra rules directory |
| `guard` | `--max-age` | `12h` | how long a verdict stays valid (`0` = no expiry) |

`verify` runs `terraform show -json` on the `.tfplan` itself and, on a pass, writes
`.bumper/verified/<sha256>` (gitignored). `guard` always exits `0` — a block is
conveyed via the hook's JSON output, not the exit code.

---

## `deps` — the dependency guardrail

Scan a lockfile for **known-vulnerable** and **known-malicious** dependencies, checked
against the hosted [Advisor](api.md). Lockfiles are parsed locally — only package
coordinates (`ecosystem/name/version`) leave the machine, never your source.

```sh
bumper deps                          # auto-detect lockfile(s) in the current directory
bumper deps package-lock.json        # scan a specific lockfile
bumper deps --json requirements.txt  # machine-readable findings (for an agent)
```

Supports `package-lock.json`, `requirements.txt`, `poetry.lock`, `uv.lock`,
`Pipfile.lock`, `go.sum` / `go.mod`, `Cargo.lock`, and `Gemfile.lock`. Exits `1` when
findings are present (so CI gates), `0` when clean.

| Command | Flag | Default | Description |
| --- | --- | --- | --- |
| `deps` | `--format` | `text` | output: `text` \| `json` \| `sarif` \| `markdown` (`--json` is shorthand for `--format json`) |
| `deps` | `--min-severity` | `low` | report findings at or above `low\|medium\|high\|critical` (malware always counts) |
| `deps` | `--advisor-url` | `https://advisor.bumper.sh` | Advisor base URL (self-host); also `$BUMPER_ADVISOR_URL` |
| `deps` | `--no-fail` | off | always exit `0`, even with findings |

The `sarif` / `markdown` formats feed CI — SARIF to the GitHub Security tab, markdown to a
sticky PR comment. See the [dependency-scan Action](ci.md#dependency-scanning-in-ci).

### The hooks

Two PreToolUse/PostToolUse hooks (wired by [`bumper init`](#init--mcp)) make the
guardrail automatic for a coding agent — each reads a tool-call payload on stdin and
always exits `0`:

```sh
bumper deps guard    # PreToolUse: BLOCK an install of a known-malicious package
bumper deps watch    # PostToolUse: after an install, scan + nudge on findings
```

- **`deps guard`** inspects `install <pkg>` commands; if a named package is known-malicious
  it returns a `deny` decision whose reason names the package, the advisory, and what to do —
  so the agent corrects the install rather than just hitting a wall. Bare/manifest installs
  pass through to the post-install scan.
- **`deps watch`** runs the scan itself after any install; it stays **silent when the tree is
  clean** and, on findings, injects context nudging the agent to spawn a subagent to run
  `bumper deps` and remediate. Non-blocking. Full model in [agents.md](agents.md).

---

## `list`

Every rule is inspectable — part of the trust story.

```console
$ bumper list
SEVERITY  SOURCE  ID                                      RESOURCE                    TITLE
critical  custom  AWS_AMI_PUBLIC                          aws_ami_launch_permission   AMI is shared publicly (launch permission group = 'all')
critical  trivy   AWS_CLOUDFRONT_NO_HTTPS                 aws_cloudfront_distribution CloudFront distribution allows unencrypted HTTP …
critical  custom  AWS_DB_DESTRUCTIVE_REPLACE_NO_SNAPSHOT  aws_db_instance             This apply will DESTROY and recreate a database …
...
```

| Flag | Description |
| --- | --- |
| `--severity` | filter by `critical`\|`high`\|`medium`\|`low` |
| `--source` | filter by `trivy`\|`custom` |
| `--service` | filter by service/resource substring (e.g. `rds`, `s3`) |
| `--format` | `text` (default) or `json` |
| `--tui` | open the interactive rule browser |

<a id="search"></a>

## `search`

Ranks rules by relevance — "what should I bake in before writing Terraform for
X?" Spans **enforced** rules (must-fix) **and** the **advisory catalog**
(knowledge-only best practice). Same data the `search_rules` MCP tool returns.

```console
$ bumper search "public storage" --limit 4
8 matches    4 enforced · 4 advisory

● enforced  4   fires on your plan

  high     AZURE_STORAGE_CONTAINER_PUBLIC            Storage container allows anonymous public access …
  high     GCP_STORAGE_BUCKET_PUBLIC_ACL             Cloud Storage ACL grants public access (allUsers …
  medium   AZURE_STORAGE_ACCOUNT_ALLOWS_PUBLIC_BLOB  Storage account permits public blob access …
  high     AWS_S3_BUCKET_PUBLIC_ACL                  S3 bucket uses a public canned ACL

○ advisory  4   knowledge, not enforced — Trivy · Checkov · KICS · Prowler

  high     prowler  Storage account has 'Allow Blob Anonymous Access' disabled
  high     trivy    Storage containers in blob storage mode should not have public access
  critical kics     Cloud Storage Anonymous or Publicly Accessible
  -        checkov  Ensure storage account is configured without blob anonymous access
```

```sh
bumper search "public storage"                      # by keyword
bumper search --resource aws_s3_bucket              # everything for a resource type
bumper search --provider azure --severity critical  # narrow by cloud + severity
bumper search --enforced-only "open ssh"            # skip the advisory catalog
bumper search "open ssh" --format json              # machine-readable (same shape as search_rules)
```

| Flag | Description |
| --- | --- |
| `--provider` | `aws`\|`gcp`\|`azure` |
| `--severity` | `critical`\|`high`\|`medium`\|`low` |
| `--resource` | resource type, e.g. `aws_s3_bucket` |
| `--limit` | max results (default 30) |
| `--enforced-only` | skip the advisory catalog |
| `--format` | `text` (default) or `json` |

The advisory section is round-robined across Trivy / Checkov / KICS / Prowler so
no single source dominates the top.

## `explain`

```console
$ bumper explain AWS_SG_PUBLIC_INGRESS
AWS_SG_PUBLIC_INGRESS  [critical]
Security group allows public internet ingress (0.0.0.0/0 or ::/0) to a sensitive or wide port range

  source:  trivy · AVD-AWS-0107
  applies: aws_security_group  on [create, update]
  fix:     Restrict cidr_blocks/ipv6_cidr_blocks to known ranges and narrow the port range.
  ref:     https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html
  check (CEL):
    has(after.ingress) && after.ingress.exists(r, ... hits_sensitive_port(r.from_port, r.to_port) ...)
```

The `check (CEL)` block is the exact predicate that fires — nothing is hidden.

<a id="tui"></a>

## `tui` — the hazard console

For the local "scary `apply`" moment, browse findings interactively:

```sh
bumper tui plan.json     # findings board with a BLAST RADIUS severity spine
bumper list --tui        # browse the whole rule set interactively
```

A two-pane board: a severity histogram, findings down the left with a color-coded
spine, full detail (fix, provenance, CEL check) on the right, and `e` to pull a
plain-English explanation from a local AI CLI.

Keys: `↑↓` move · `→` detail · `f` filter · `/` search · `e` explain · `?` help ·
`q` quit. Flags: `--rules`, `--llm`. The TUI is **opt-in** and refuses to run when
piped — CI always gets plain `text`/`json`/`sarif`. Built on Bubble Tea (pure Go,
still one binary).

---

## `init`

Wire bumper into your coding agent — the guardrail hooks + the hosted [Advisor MCP](mcp.md).
See [agents.md](agents.md) for details.

```sh
bumper init           # interactive wizard
bumper init --yes     # non-interactive: wire everything (hooks + advisor MCP)
bumper init --print   # preview, write nothing
```

| Flag | Default | Description |
| --- | --- | --- |
| `--hook` | `project` | hook scope: `project`\|`user`\|`none` |
| `--terraform` | `true` | install the terraform apply-guard hook |
| `--deps` | `true` | install the dependency hooks (install-block + post-install scan) |
| `--advisor` | `project` | advisor MCP scope: `project`\|`user`\|`none` (`none` = skip) |
| `--advisor-url` | – | self-hosted Advisor base URL (also `$BUMPER_ADVISOR_URL`) |
| `--print` | off | show what would change and exit without writing |
| `--yes` | off | apply non-interactively (no wizard) |
| `--no-tui` | off | skip the wizard even on a TTY |

Defaults wire everything; hooks self-filter, so a Terraform guard in a Node repo simply
never fires. The dependency guardrail needs the Advisor for CVE/malware data — selecting
`--deps` keeps the advisor on (host it yourself with `--advisor-url`).
