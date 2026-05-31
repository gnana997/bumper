#!/usr/bin/env python3
"""Harvest the METADATA headers from Trivy's AWS Rego checks into a catalog.

This does NOT copy rule logic (that's hand-ported against our plan-JSON model).
It extracts the structured metadata (id, severity, title, service, fix, CIS
mappings) so we have a complete, curated worklist of what's worth porting.

Source: github.com/aquasecurity/trivy-checks (Apache-2.0). Usage:
    python3 tools/extract_trivy_catalog.py <trivy-checks-dir> <out-dir>
"""
import json
import os
import re
import sys
from collections import Counter


def metadata_block(text: str) -> str:
    """Return the leading commented METADATA block of a .rego file."""
    lines = []
    started = False
    for line in text.splitlines():
        if line.startswith("#"):
            started = True
            lines.append(re.sub(r"^#\s?", "", line))
        elif started:
            break
    return "\n".join(lines)


def field(block: str, key: str) -> str:
    m = re.search(rf"^\s*{re.escape(key)}:\s*(.+?)\s*$", block, re.MULTILINE)
    return m.group(1).strip().strip('"') if m else ""


def cis_frameworks(block: str) -> list:
    return sorted(set(re.findall(r"(cis-aws-[0-9.]+)", block)))


def main() -> int:
    src, out = sys.argv[1], sys.argv[2]
    aws_root = os.path.join(src, "checks", "cloud", "aws")
    rows = []
    for dirpath, _, files in os.walk(aws_root):
        for f in files:
            if not f.endswith(".rego") or f.endswith("_test.rego"):
                continue
            path = os.path.join(dirpath, f)
            with open(path, encoding="utf-8") as fh:
                block = metadata_block(fh.read())
            if "title:" not in block:
                continue
            rows.append({
                "id": field(block, "id"),
                "long_id": field(block, "long_id"),
                "service": field(block, "service") or os.path.basename(dirpath),
                "severity": field(block, "severity").lower(),
                "title": field(block, "title"),
                "fix": field(block, "recommended_action"),
                "cis": cis_frameworks(block),
                "source_file": os.path.relpath(path, src),
            })

    rows.sort(key=lambda r: (r["service"], r["id"]))
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "trivy-aws.json"), "w") as fh:
        json.dump(rows, fh, indent=2)

    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}
    with open(os.path.join(out, "trivy-aws.md"), "w") as fh:
        fh.write("# Trivy AWS check catalog (porting worklist)\n\n")
        fh.write(f"{len(rows)} checks harvested from trivy-checks (Apache-2.0). "
                 "Logic is hand-ported to bumper's plan-JSON + CEL model.\n\n")
        fh.write("| id | service | severity | cis | title |\n|---|---|---|---|---|\n")
        for r in sorted(rows, key=lambda r: (sev_rank.get(r["severity"], 4), r["service"])):
            cis = ",".join(c.replace("cis-aws-", "") for c in r["cis"]) or "-"
            fh.write(f"| {r['id']} | {r['service']} | {r['severity'] or '?'} | {cis} | {r['title'][:80]} |\n")

    # console summary
    by_service = Counter(r["service"] for r in rows)
    by_sev = Counter(r["severity"] or "?" for r in rows)
    print(f"harvested {len(rows)} AWS checks")
    print("by severity:", dict(sorted(by_sev.items())))
    print("with a CIS mapping:", sum(1 for r in rows if r["cis"]))
    print("top services:", dict(by_service.most_common(12)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
