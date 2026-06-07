# Security Policy

bumper is a security tool, so we hold its own supply chain and code to a high
bar. Thank you for helping keep it trustworthy.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub's
[**Private vulnerability reporting**](https://github.com/gnana997/bumper/security/advisories/new)
(Security → Advisories → *Report a vulnerability*). If you can't use that, email
**gnana997@gmail.com** with the details.

Please include:

- a description of the issue and its impact,
- steps to reproduce (a minimal Terraform plan / config or command is ideal),
- the bumper version (`bumper version`) and your OS/arch,
- any suggested remediation.

### What to expect

- **Acknowledgement** within 3 business days.
- An initial assessment and severity within 7 days.
- We'll keep you updated on progress and coordinate a disclosure timeline; we aim
  to ship a fix within 90 days and will credit you (unless you prefer otherwise).

## Supported versions

bumper is pre-1.0 / early. Security fixes land on the latest release; please
upgrade to the newest version before reporting.

| Version | Supported |
| ------- | --------- |
| latest release | ✅ |
| older | ❌ |

## Scope

In scope:

- the `bumper` binary and all subcommands (`scan`, `deps`, `verify`, `guard`,
  `init`, `tui`),
- the release artifacts and their signatures/attestations,
- the deterministic rule engine and the `guard` enforcement logic (e.g. a way to
  make `guard` allow an unverified `terraform apply`/`destroy`),
- the `install.sh` script.

Out of scope:

- vulnerabilities in third-party dependencies without a demonstrated impact on
  bumper (report those upstream; we track them via Dependabot + govulncheck),
- findings that require a compromised local machine or already-malicious AI CLI,
- the optional AI-enrichment output (it is non-authoritative garnish; the
  deterministic finding is the source of truth).

## Verifying a release

Every release is checksummed, the checksum file is signed with cosign (keyless),
and each artifact carries a SLSA build-provenance attestation. See the
[Install section of the README](README.md#install) for verification commands.
