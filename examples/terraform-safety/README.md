# Terraform plan safety — example

A self-contained, **hermetic** example for the [bumper Terraform plan safety
gate](https://github.com/marketplace/actions/bumper-terraform-plan-safety-gate).
No cloud account or credentials needed — [plan.json](plan.json) is a captured
`terraform show -json` plan, and [main.tf](main.tf) is the source it came from.

## What it contains

`plan.json` describes a deliberately dangerous apply:

- **Replaces a production database** with `skip_final_snapshot = true` and
  `deletion_protection = false` — irreversible data loss.
- **Opens SSH (port 22) to `0.0.0.0/0`** — public internet ingress to a
  sensitive port.

## Run it

```sh
bumper examples/terraform-safety/plan.json
```

Expected output: **3 findings (2 critical · 1 high)**, exit code `1`.

```
CRITICAL  aws_db_instance.orders   This apply will DESTROY and recreate a database with no final snapshot
CRITICAL  aws_security_group.api   Security group allows public internet ingress (0.0.0.0/0 or ::/0) to a sensitive or wide port range
HIGH      aws_db_instance.orders   This apply will DELETE or REPLACE a stateful data resource (potential data loss)
```

In your own repo you produce the plan JSON from a real plan:

```sh
terraform plan -out plan.tfplan
terraform show -json plan.tfplan > plan.json
bumper plan.json
```

See [docs/ci.md](../../docs/ci.md) to wire this into a GitHub Action that uploads
SARIF and posts a sticky PR comment.
