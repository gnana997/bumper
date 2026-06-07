# Examples

Self-contained, runnable examples of bumper's two safety gates. Both are
**hermetic** — no cloud account, no credentials, no real installs — and produce
**real findings** (the dependency samples are verified against the hosted
Advisor).

| Example | Gate | Run |
| --- | --- | --- |
| [terraform-safety/](terraform-safety/) | catch a destructive / exposing `terraform apply` | `bumper examples/terraform-safety/plan.json` |
| [dependency-scan/](dependency-scan/) | catch vulnerable + malicious dependencies (crafted, incl. malware) | `bumper deps examples/dependency-scan/package-lock.json` |
| [dependency-scan/real-world/](dependency-scan/real-world/) | scan anonymized real lockfiles from large OSS projects (npm · Python · Rust) | `bumper deps examples/dependency-scan/real-world/rust/Cargo.lock` |

Each directory has its own README with the expected output and how to wire the
same check into CI via the [GitHub Action](../docs/ci.md).
