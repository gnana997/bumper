# AWS anti-pattern fixture — plans fully offline (create-only, no data sources,
# fake creds via the provider skip flags). Exercises bumper's create-time
# exposure/encryption rules. Destruction rules need prior state, so those live in
# the pre-rendered plan fixtures (see tools/corpus/README.md).
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

# Public SSH/RDP to the world → AWS_SG_PUBLIC_INGRESS
resource "aws_security_group" "public_admin" {
  name        = "public-admin"
  description = "intentionally open"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Unencrypted EBS volume → AWS_EBS_ENCRYPTION_DISABLED
resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-east-1a"
  size              = 8
  encrypted         = false
}
