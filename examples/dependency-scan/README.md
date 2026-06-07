# Dependency scan — example

A self-contained example for the [bumper dependency
scan](../../docs/ci.md). The sample lockfiles pin **real, known-vulnerable and
known-malicious** packages, verified against the hosted Advisor — so the scan
produces genuine findings, not a mock.

## What it contains

[package-lock.json](package-lock.json) (npm):

- **`flatmap-stream@0.1.1`** — *malicious* (`MAL-2025-20690`, the package behind
  the 2018 `event-stream` supply-chain attack).
- `event-stream@3.3.6`, `lodash@4.17.4`, `minimist@1.2.0` — known-vulnerable
  (criticals incl. `CVE-2019-10744`, `CVE-2021-44906`).

[requirements.txt](requirements.txt) (Python): `django@2.2.0`, `pyyaml@5.1`,
`requests@2.19.0`, `urllib3@1.24.1` — all with known CVEs.

## Run it

```sh
bumper deps examples/dependency-scan/package-lock.json
bumper deps examples/dependency-scan/requirements.txt
```

Expected (npm), exit code `1`:

```
  MALICIOUS  flatmap-stream@0.1.1 (npm) — MAL-2025-20690: Malicious code in flatmap-stream (npm)
  CRITICAL  flatmap-stream@0.1.1 (npm)  GHSA-9x64-5r7x-2q53  no fix yet
  CRITICAL  event-stream@3.3.6 (npm)  GHSA-mh6f-8j2x-4483  fix → 4.0.0
  CRITICAL  lodash@4.17.4 (npm)  CVE-2019-10744  fix → 4.17.12
  CRITICAL  minimist@1.2.0 (npm)  CVE-2021-44906  fix → 1.2.6
```

Only package coordinates (ecosystem · name · version) are sent to the Advisor —
never your code. Add `--min-severity high` to focus, or `--format markdown` for
the report rendered in PR comments.

## Real-world lockfiles

The crafted fixtures above are deterministic and include the malware catch. For
authentic, full-size dependency trees across npm, Python (uv), and Rust, see
[real-world/](real-world/) — anonymized lockfiles from large OSS projects that
each surface dozens of genuine vulnerabilities.
