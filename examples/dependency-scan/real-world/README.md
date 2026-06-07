# Real-world dependency lockfiles (anonymized)

These are **real lockfiles from large open-source projects**, used to exercise
`bumper deps` against authentic, full-size dependency trees across ecosystems.
They are committed here (not fetched at scan time) so the examples are
deterministic and no external repository is referenced.

**Anonymized.** Each file has been de-identified: the project's own
package/workspace names are renamed to `sample-*`, any git/path source URLs are
removed, and npm download URLs are stripped. Only the third-party dependency
*facts* (package name + version) remain — those are public, and they're what make
the findings real. We don't name the source projects.

| File | Ecosystem | Finds (approx.) |
| --- | --- | --- |
| [npm/package-lock.json](npm/package-lock.json) | npm | ~45 vulnerable packages |
| [python/uv.lock](python/uv.lock) | Python (uv) | ~8 vulnerable packages |
| [rust/Cargo.lock](rust/Cargo.lock) | Rust (crates.io) | ~4 vulnerable (incl. a HIGH) |

Counts are **approximate** — they track the hosted Advisor, which refreshes
daily, so a scan today may report more or fewer than when this was written.

## Run them

```sh
bumper deps examples/dependency-scan/real-world/npm/package-lock.json
bumper deps examples/dependency-scan/real-world/python/uv.lock
bumper deps examples/dependency-scan/real-world/rust/Cargo.lock
```

Each exits `1` (findings present). Only package coordinates leave your machine —
never your code.

> These contain no malicious packages — maintained projects don't ship malware.
> For the malware-detection demo see the crafted
> [../package-lock.json](../package-lock.json) (`flatmap-stream` → `MAL-2025-20690`).
