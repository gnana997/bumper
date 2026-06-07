# CI / GitHub Action

bumper ships a composite action ([action.yml](../action.yml)) — published to the
[GitHub Marketplace](https://github.com/marketplace/actions/bumper-terraform-plan-safety-gate)
— that installs the checksum-verified release binary, uploads **SARIF** to the
**Security** tab, posts a **sticky** PR comment, and fails the check on `high+`.

- [Usage](#usage)
- [Inputs](#inputs)
- [What it does](#what-it-does)
- [Permissions and the fork caveat](#permissions-and-the-fork-caveat)
- [Monorepos and matrices](#monorepos-and-matrices)
- [Without the Action (any CI)](#without-the-action-any-ci)

## Usage

```yaml
name: terraform-safety
on:
  pull_request:
    paths: ["**.tf"]

permissions:
  contents: read
  security-events: write   # SARIF upload
  pull-requests: write     # sticky comment

jobs:
  bumper:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3

      # Your real workflow authenticates to your cloud/backend before this.
      - name: Terraform plan -> JSON
        run: |
          terraform init -input=false
          terraform plan -input=false -out=plan.tfplan
          terraform show -json plan.tfplan > plan.json

      - uses: gnana997/bumper@v1
        with:
          plan-json: plan.json
          fail-severity: high        # fail the check on any high+ finding
```

A ready-to-copy template lives at
[.github/workflows/example-pr-gate.yml](../.github/workflows/example-pr-gate.yml).

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `plan-json` | *(required)* | Path to a `terraform show -json` plan file (relative to `working-directory`). |
| `fail-severity` | `high` | Fail the job at or above this severity (`critical`\|`high`\|`medium`\|`low`), or `none` to never fail. |
| `min-severity` | `low` | Lowest severity included in the SARIF upload and PR comment. |
| `upload-sarif` | `true` | Upload SARIF to GitHub code scanning. |
| `comment` | `true` | Post/update the sticky PR comment. |
| `bumper-version` | `latest` | Release tag to install (e.g. `v1.1.0`), or `latest`. **Pin for reproducible CI.** |
| `working-directory` | `.` | Directory the `plan-json` path is relative to. |

`fail-severity` and `min-severity` are independent on purpose: surface everything
in the SARIF/comment (`min-severity: low`) while only **failing** on what matters
(`fail-severity: high`).

## What it does

- **SARIF → Security tab.** Findings upload via `github/codeql-action/upload-sarif`,
  so they appear inline in GitHub's Security tab. `critical`/`high` map to `error`,
  `medium` to `warning`, with a `security-severity` score so they bucket correctly.
- **One sticky comment.** A hidden marker (`<!-- bumper -->`) lets the action find
  and replace its previous comment, so a PR only ever has **one** bumper comment —
  updated in place on every push, never spammed. It renders like:

  > ## 🛡️ bumper — Terraform plan safety
  > **3 issue(s)** — 🔴 2 critical · 🟠 1 high · 🟡 0 medium
  > - 🔴 **This apply will DESTROY and recreate a database…** — `aws_db_instance.main`
  > - 🔴 **Public internet ingress (0.0.0.0/0)…** — `aws_security_group.web`
  > <details><summary>All findings</summary> … table … </details>

- **Fails on `high+`.** Exits non-zero when a finding at or above `fail-severity`
  is present, so the check blocks the merge — configurable per repo.

## Permissions and the fork caveat

- `security-events: write` is required for the SARIF upload; `pull-requests: write`
  for the comment. Both are in the snippet above. `contents: read` is enough
  otherwise (the action installs the binary from this repo's public releases).
- **Forked PRs:** GitHub restricts the `GITHUB_TOKEN` on `pull_request` runs from
  forks, so SARIF upload and PR comments won't work there. Options: run the gate on
  `push` to your own branches, or use `pull_request_target` with the usual caution
  (it runs with your repo's token — never check out and execute untrusted code).

## Monorepos and matrices

Scan several stacks in parallel with a matrix — each leg uploads SARIF under its
own `category` so the Security tab keeps them separate:

```yaml
strategy:
  matrix:
    stack: [network, data, app]
steps:
  - uses: actions/checkout@v4
  - uses: hashicorp/setup-terraform@v3
  - run: |
      cd ${{ matrix.stack }}
      terraform init -input=false
      terraform plan -input=false -out=plan.tfplan
      terraform show -json plan.tfplan > plan.json
  - uses: gnana997/bumper@v1
    with:
      working-directory: ${{ matrix.stack }}
      plan-json: plan.json
      fail-severity: high
```

## Dependency scanning in CI

Most value from bumper's dependency guardrail is at **agent/install time** (the
[hooks](agents.md#dependency-guardrail) block malicious installs and surface vulnerable
ones before anything reaches CI). The CI Action is the **backstop** for installs the hooks
didn't mediate — human commits, other tools — and a **hard fail-gate on malicious packages**
(not just an alert).

```yaml
permissions:
  contents: read
  security-events: write   # SARIF upload
  pull-requests: write     # sticky comment
steps:
  - uses: actions/checkout@v4
  - uses: gnana997/bumper/deps@v1
    with:
      lockfile: package-lock.json   # optional; auto-detects if omitted
      fail-severity: high           # malicious always fails
```

It uploads SARIF to the Security tab, posts a sticky PR comment, and fails the job on
findings at or above `fail-severity`. Lockfiles are scanned **lookup-not-upload** — only
package coordinates leave the runner. Inputs: `lockfile`, `fail-severity` (default `high`),
`min-severity`, `upload-sarif`, `comment`, `advisor-url` (self-host), `bumper-version`,
`working-directory`.

> Note: for GitHub repos this overlaps Dependabot/dependency-review for *vulnerable* deps —
> bumper's edge is the **pre-execution malware block in the agent loop** and a **hard malware
> fail-gate** here. Reach for the Action when you want a non-GitHub CI, a hard gate, or one
> unified bumper gate across infra + deps.

## Without the Action (any CI)

bumper is a single static binary — drop it into GitLab CI, CircleCI, Jenkins, or a
plain shell. Install it and gate on the exit code:

```sh
curl -fsSL https://get.bumper.sh | sh
bumper --format sarif plan.json > bumper.sarif || true   # plan: don't fail on the SARIF step
bumper --min-severity high plan.json                     # plan: exit 1 on high+ → fails the job

bumper deps --format sarif --no-fail > bumper-deps.sarif # deps: SARIF for any code-scanning upload
bumper deps --min-severity high                          # deps: exit 1 on high+ (auto-detects lockfiles)
```

Exit codes are CI-native: `0` clean, `1` findings present, `2` usage error. Upload the
SARIF with whatever mechanism your platform provides.
