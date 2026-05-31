# GCP anti-pattern fixture — plans fully offline (create-only, no data sources;
# the google provider configures with a dummy OAuth token and makes no API calls
# for a create-only plan).
terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = "bumper-corpus"
  region  = "us-central1"
}

# Sensitive port open to the whole internet → GCP_FIREWALL_PUBLIC_INGRESS_SENSITIVE
resource "google_compute_firewall" "public_ssh" {
  name          = "public-ssh"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["22", "3389"]
  }
}

# Bucket granted to the entire internet → GCP_IAM_PUBLIC_MEMBER
resource "google_storage_bucket_iam_member" "public" {
  bucket = "example-bucket"
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
