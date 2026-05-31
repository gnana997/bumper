# bumper anti-pattern corpus

A small multi-cloud set of intentionally-insecure Terraform that `bumper` is run
against as an integration test. Run it with:

```sh
make corpus            # build bumper, then scan every target below
# or directly:
tools/corpus_scan.sh   # uses bumper + terraform from PATH
```

## What's here

| Target | Kind | Exercises |
|---|---|---|
| `aws/` | live `.tf` | `AWS_SG_PUBLIC_INGRESS`, `AWS_EBS_VOLUME_UNENCRYPTED` |
| `gcp/` | live `.tf` | `GCP_FIREWALL_PUBLIC_INGRESS_SENSITIVE`, `GCP_IAM_PUBLIC_MEMBER` |
| `azure.json` | pre-rendered plan | `AZURE_NSG_PUBLIC_INGRESS_SENSITIVE`, `AZURE_DB_FIREWALL_PUBLIC`, `AZURE_STATEFUL_RESOURCE_DESTROY` |

## How offline planning works (and its limits)

bumper consumes `terraform show -json` output, so the harness must produce a
plan. It does so **without cloud credentials**:

- A **create-only** plan with **no data sources** makes no cloud API calls — the
  provider is only invoked locally for schema validation and diff computation.
  The harness supplies fake credentials + skip flags so the provider configures
  but never reaches out (`-refresh=false` avoids touching any existing state).

Two consequences shape the corpus:

1. **Destruction rules need prior state.** A fresh plan from an empty state is
   all creates, so `on: [delete, replace]` rules can't be exercised by a live
   `.tf` fixture. Those scenarios live in the pre-rendered `*.json` plans.
2. **Azure can't plan offline.** The `azurerm` provider authenticates to Azure
   AD on *configure* (even with `-refresh=false`), so fake creds fail. Azure
   coverage is therefore a committed `azure.json` plan, scanned directly. (It
   also carries the Azure destruction case, per point 1.)

AWS and GCP both plan fully offline, so they're live `.tf` and prove the whole
`terraform → show -json → bumper` pipeline end to end.

## Pointing the harness at external repos (TerraGoat, etc.)

`tools/corpus_scan.sh path/to/dir ...` accepts any Terraform directory. Be aware
that the popular "vulnerable by design" repos are **dated**:

- **TerraGoat** (`bridgecrewio/terragoat`) uses pre-0.12 syntax (`type =
  "string"`) and its resources target old provider schemas, so a modern
  `terraform` rejects it until you (a) unquote type constraints, (b) strip the
  remote `backend` block, and (c) pin old provider versions matching its
  vintage. Even then its few data sources (`aws_caller_identity`, `aws_ami`,
  `azurerm_client_config`, `google_compute_zones`) need real creds. Workable in
  a sandbox cloud account; not a clean offline gate.
- **AWSGoat / AzureGoat / GCPGoat** (`ine-labs/*`) are deployable apps with
  remote backends and data sources — they require real credentials.

The harness **skips** (rather than fails) any target whose `init`/`plan` errors,
and reports why, so a partial corpus still yields results.
