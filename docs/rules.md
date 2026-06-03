# Rules

bumper's rules are declarative YAML with a [CEL](https://github.com/google/cel-go)
predicate, embedded in the binary (`internal/rules/builtin/<provider>/`). Add your
own with `--rules ./my-rules/`.

- [The rule format](#the-rule-format)
- [Worked examples](#worked-examples)
- [CEL variables and custom functions](#cel-variables-and-custom-functions)
- [Conventions (learned the hard way)](#conventions-learned-the-hard-way)
- [Coverage](#coverage)
- [Enforced vs advisory: two corpora](#enforced-vs-advisory-two-corpora)
- [Adding a rule](#adding-a-rule)

## The rule format

```yaml
- id: AWS_SNS_UNENCRYPTED          # unique, SCREAMING_SNAKE_CASE
  source: trivy                    # "trivy" (needs an avd:) or "custom"
  avd: AVD-AWS-0095                # upstream id — required when source: trivy
  severity: high                   # critical | high | medium | low
  resource: aws_sns_topic          # resource-type filter ("" = any; then guard on `type`)
  on: [create, update]             # change actions ("" = any)
  when: |                          # CEL predicate; true => finding
    !has(after.kms_master_key_id) || after.kms_master_key_id == ""
  title: "SNS topic is not encrypted at rest (no KMS key)"
  fix: "Set kms_master_key_id (e.g. alias/aws/sns or a customer-managed key)."
  refs:                            # optional
    - "https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html"
```

| Field | Required | Notes |
| --- | --- | --- |
| `id` | yes | unique across the whole set; the loader rejects duplicates |
| `source` | yes | `trivy` (carries provenance) or `custom` (bumper's own) |
| `avd` | iff `source: trivy` | the upstream `AVD-AWS/GCP/AZU-NNNN` id; **must** be absent for `custom` |
| `severity` | yes | `critical` \| `high` \| `medium` \| `low` |
| `resource` | no | resource-type filter; `""` (omit) = evaluate against every change, then guard on `type` |
| `on` | no | change actions: `create` \| `update` \| `delete` \| `replace`; `[]`/omit = any action |
| `when` | yes | CEL; `true` ⇒ a finding |
| `title` | yes | the one-line message shown to the user |
| `fix` | recommended | the one-line remediation |
| `refs` | no | doc links |

The `on:` filter is bumper's wedge: `on: [delete, replace]` lets a rule fire on the
*transition*, which is how it catches "this apply will destroy your database" —
something an end-state scanner can't see.

## Worked examples

**Destruction** — reads the change *actions*, not the end state:

```yaml
- id: AWS_STATEFUL_RESOURCE_DESTROY
  source: custom
  severity: high
  on: [delete, replace]
  when: |
    type in [
      "aws_db_instance", "aws_rds_cluster", "aws_dynamodb_table",
      "aws_s3_bucket", "aws_efs_file_system", "aws_redshift_cluster"
    ]
  title: "This apply will DELETE or REPLACE a stateful data resource (potential data loss)"
  fix: "Confirm the destruction is intended. Check prevent_destroy, final snapshots, and backups before applying."
```

**Encryption at rest** — the null-vs-absent idiom for an optional field (a compound
check; the queue is unencrypted only if *both* keys are off):

```yaml
- id: AWS_SQS_UNENCRYPTED
  source: trivy
  avd: AVD-AWS-0096
  severity: high
  resource: aws_sqs_queue
  on: [create, update]
  when: |
    (!has(after.kms_master_key_id) || after.kms_master_key_id == "") &&
    (!has(after.sqs_managed_sse_enabled) || after.sqs_managed_sse_enabled == false)
  title: "SQS queue is not encrypted at rest (no KMS key and SSE-SQS disabled)"
  fix: "Set sqs_managed_sse_enabled = true, or provide kms_master_key_id."
```

**IAM / JSON policies** — `parse_json` + `as_list` unlock the whole IAM family,
where `Action` / `Resource` / `Principal` may each be a string *or* an array:

```yaml
- id: AWS_IAM_WILDCARD_ADMIN
  source: trivy
  avd: AVD-AWS-0057
  severity: critical
  on: [create, update]
  when: |
    type in ["aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"] &&
    has(after.policy) &&
    as_list(parse_json(after.policy).Statement).exists(s,
      has(s.Effect) && s.Effect == "Allow" &&
      has(s.Action) && as_list(s.Action).exists(a, a == "*" || a == "iam:*" || a == "*:*") &&
      has(s.Resource) && as_list(s.Resource).exists(r, r == "*")
    )
  title: "IAM policy grants wildcard admin access (Action '*'/'iam:*' on Resource '*')"
  fix: "Scope Action and Resource to the minimum required; never combine '*' Action with '*' Resource."
```

## CEL variables and custom functions

Variables available to `when`:

| Variable | Type | What |
| --- | --- | --- |
| `address` | `string` | the resource address, e.g. `aws_db_instance.main` |
| `type` | `string` | the resource type, e.g. `aws_db_instance` |
| `actions` | `list<string>` | the change actions for this resource |
| `before` | `dyn` | the prior state (`null` on create) |
| `after` | `dyn` | the planned state (`null` on delete) |

Custom functions (see [internal/rules/celfuncs.go](../internal/rules/celfuncs.go)):

- **`parse_json(s)`** — parse a JSON string (e.g. an inline IAM `policy`) into a
  value; returns `{}` on error so callers can `has(...)`-guard.
- **`as_list(x)`** — normalize the "string or array" idiom (`Action`, `Resource`,
  `Principal.AWS`, GCP IAM `members`); scalar → `[scalar]`, null → `[]`.
- **`hits_sensitive_port(from, to)`** — true if an inclusive port range covers any
  sensitive admin/db/cache port (22, 3389, 5432, 3306, 6379, …).
- **`ports_hit_sensitive(ports)`** — same, for the string/range port lists used by
  GCP firewalls and Azure NSGs (`"22"`, `"8080-8090"`).

## Conventions (learned the hard way)

- **Null vs absent.** A real plan renders an *unset* optional field as `null`, not
  absent — so `(!has(x) || x == false)` silently fails to fire when `x` is `null`.
  Prefer `(!has(x) || x != true)` for optional booleans.
- **Guard with `has(...)`** before reading any `before`/`after` field. A rule that
  errors on a resource is treated as "no match", so a missing guard hides the bug
  rather than surfacing it.
- **Computed values render `null`.** A field that's "known after apply" comes
  through as `null`; a rule keyed on it can't fire — don't rely on it.
- **`before` is `null` on create, `after` is `null` on delete.** Guard accordingly
  for `on: [delete]` rules (read `before`, not `after`).
- Every rule ships with a **passing and a negative fixture** in
  `internal/engine/testdata/`.

## Coverage

**112 enforced rules** — 20 critical · 57 high · 32 medium · 3 low — across
**AWS** (60), **GCP** (35), **Azure** (17). A consistent cross-cloud baseline plus
deep per-cloud coverage:

- **Network exposure** — security groups, NACLs, GCP firewalls (legacy
  `google_compute_firewall` **and** the modern network/regional/hierarchical
  firewall **policy** rules), Azure NSGs; IPv4/IPv6, port-range aware.
- **VPC hygiene** — auto-mode networks, public-zone DNSSEC, subnet flow logs.
- **Least-privilege IAM** — primitive owner/editor grants, user-managed
  service-account keys, SA impersonation roles, Azure privileged role assignments,
  wildcard admin, open trust/ECR/SQS principals, `allUsers` bindings, GCP default
  service account / cloud-platform scope, lambda confused-deputy.
- **Public endpoints** — RDS/EKS/MQ, AKS, Cloud SQL public IP & authorized
  networks, BigQuery & Cloud Storage public access, GKE public control plane.
- **GKE & Compute hardening** — legacy metadata endpoints, metadata concealment,
  node/default service accounts, Shielded VM secure boot, OS Login, serial port,
  project-wide SSH keys, legacy ABAC, Shielded Nodes, network policy.
- **Azure service exposure** — storage/SQL/Redis/ACR public network, AKS public
  API, Key Vault purge protection, App Service TLS.
- **TLS in transit** — incl. GCP SSL policies, Cloud SQL SSL enforcement.
- **Encryption at rest**, **EC2/ECR/EKS/CloudTrail** hardening, **ECS**
  plaintext-secret detection, **KMS** key rotation.
- **Destruction / recovery** — stateful-resource destroy across AWS & GCP,
  no-final-snapshot, deletion-protection off, PITR, versioning, backup retention.

Rules are seeded from the Apache-2.0 Trivy + Checkov catalogs and hand-ported with
tests. **Account-posture** checks (root MFA, credential rotation) are intentionally
out of scope — they belong to a continuous account scanner, not a plan gate.

Browse the live set: `bumper list` (filter with `--severity` / `--source` /
`--service`), or `bumper explain <ID>` for any rule's full CEL.

## Enforced vs advisory: two corpora

`bumper search` (and the `search_rules` MCP tool) span **two** corpora:

- **Enforced** — the 112 rules above that actually fire on a plan. Executable,
  must-fix, can block a merge or an apply.
- **Advisory** — an embedded **~2,600-entry** best-practice catalog normalized
  from **Trivy, Checkov, KICS, and Prowler** (Apache-2.0, attributed in
  [NOTICE](../NOTICE)). Knowledge-only — clearly labeled, never executed.

The advisory catalog is **federated** (one map per source, no dedup), searched in
parallel, and round-robined on output so no one source dominates. It ships in the
binary, so search works fully offline. It's rebuilt from upstream with
`make catalog` (see [internal/catalog/](../internal/catalog/)) and acts as a
porting worklist: surface a high-value intent with `bumper search`, then port it
into an enforced CEL rule.

## Adding a rule

1. Drop a rule into `internal/rules/builtin/<provider>/<provider>_<service>.yaml`
   (or your own `--rules ./dir/`).
2. Add a **passing** and a **negative** fixture in `internal/engine/testdata/`.
3. `make test` — the loader validates unique ids and provenance.

Full workflow, including the `make corpus` real-world anti-pattern scan, is in
[CONTRIBUTING.md](../CONTRIBUTING.md).
