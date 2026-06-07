# Sample Terraform that produces the dangerous plan in plan.json.
#
# This file is illustrative — you don't need to apply it. plan.json was captured
# with `terraform show -json` and is what bumper actually scans. Each resource
# below corresponds to a finding bumper flags; the comments call out the hazard.

# 1) A change that forces REPLACE of a stateful database, with the final snapshot
#    turned off and deletion protection removed — an irreversible data-loss apply.
#    -> AWS_DB_DESTRUCTIVE_REPLACE_NO_SNAPSHOT (critical) + AWS_STATEFUL_RESOURCE_DESTROY (high)
resource "aws_db_instance" "orders" {
  identifier          = "orders-prod"
  engine              = "postgres"
  skip_final_snapshot = true  # was false — no snapshot will be taken before destroy
  deletion_protection = false # was true — the guardrail is being removed
}

# 2) Opening SSH (22) to the entire internet — public ingress to a sensitive port.
#    -> AWS_SG_PUBLIC_INGRESS (critical)
resource "aws_security_group" "api" {
  name = "api-sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # was 10.0.0.0/8 — now world-reachable
  }
}

resource "aws_s3_bucket" "assets" {
  bucket = "acme-public-assets"
}
