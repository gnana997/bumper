#!/usr/bin/env python3
"""Harvest the METADATA headers from Trivy's cloud Rego checks into a catalog.

This does NOT copy rule logic (that's hand-ported against our plan-JSON model).
It extracts the structured metadata (id, severity, title, service, fix, CIS
mappings) so we have a complete, curated worklist of what's worth porting.

Source: github.com/aquasecurity/trivy-checks (Apache-2.0). Usage:
    python3 tools/extract_trivy_catalog.py <trivy-checks-dir> <out-dir> [provider]

provider defaults to "aws" (backward compatible). Supported: aws, gcp, azure.
Note: "gcp" maps to Trivy's on-disk directory name "google".
"""
import json
import os
import re
import sys
from collections import Counter

# Friendly provider name -> (Trivy on-disk dir under checks/cloud/, output label).
# Trivy names GCP "google" on disk; we keep "gcp" in our output filenames/ids
# to match the rest of bumper. Trivy has NO digitalocean provider.
PROVIDERS = {
    "aws":   ("aws",    "aws"),
    "gcp":   ("google", "gcp"),
    "google": ("google", "gcp"),
    "azure": ("azure",  "azure"),
}


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
    # CIS framework ids are provider-tagged (cis-aws-1.4, cis-gcp-1.3, ...).
    return sorted(set(re.findall(r"(cis-[a-z]+-[0-9.]+)", block)))


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__.strip())
        return 2
    src, out = sys.argv[1], sys.argv[2]
    friendly = sys.argv[3].lower() if len(sys.argv) > 3 else "aws"

    if friendly not in PROVIDERS:
        print(f"error: unknown provider {friendly!r}; supported: {', '.join(sorted(PROVIDERS))}")
        print("note: Trivy has no DigitalOcean provider — those rules must be authored from scratch.")
        return 2
    disk_dir, label = PROVIDERS[friendly]

    root = os.path.join(src, "checks", "cloud", disk_dir)
    if not os.path.isdir(root):
        # Fail loudly rather than writing an empty catalog (the silent-empty trap).
        cloud = os.path.join(src, "checks", "cloud")
        available = sorted(os.listdir(cloud)) if os.path.isdir(cloud) else []
        print(f"error: {root} does not exist.")
        print(f"available providers under {cloud}: {available or '(checks/cloud not found)'}")
        print("hint: pass the path to a trivy-checks clone; GCP lives under 'google'.")
        return 2

    rows = []
    for dirpath, _, files in os.walk(root):
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

    if not rows:
        print(f"warning: walked {root} but found 0 checks with a 'title:' METADATA block.")
        print("the rego metadata format may differ — inspect one file:")
        print(f"  head -40 $(find {root} -name '*.rego' ! -name '*_test.rego' | head -1)")
        return 1

    rows.sort(key=lambda r: (r["service"], r["id"]))
    os.makedirs(out, exist_ok=True)
    json_path = os.path.join(out, f"trivy-{label}.json")
    md_path = os.path.join(out, f"trivy-{label}.md")
    with open(json_path, "w") as fh:
        json.dump(rows, fh, indent=2)

    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}
    with open(md_path, "w") as fh:
        fh.write(f"# Trivy {label.upper()} check catalog (porting worklist)\n\n")
        fh.write(f"{len(rows)} checks harvested from trivy-checks (Apache-2.0). "
                 "Logic is hand-ported to bumper's plan-JSON + CEL model.\n\n")
        fh.write("| id | service | severity | cis | title |\n|---|---|---|---|---|\n")
        for r in sorted(rows, key=lambda r: (sev_rank.get(r["severity"], 4), r["service"])):
            cis = ",".join(re.sub(r"cis-[a-z]+-", "", c) for c in r["cis"]) or "-"
            fh.write(f"| {r['id']} | {r['service']} | {r['severity'] or '?'} | {cis} | {r['title'][:80]} |\n")

    # console summary
    by_service = Counter(r["service"] for r in rows)
    by_sev = Counter(r["severity"] or "?" for r in rows)
    print(f"harvested {len(rows)} {label} checks -> {json_path}")
    print("by severity:", dict(sorted(by_sev.items())))
    print("with a CIS mapping:", sum(1 for r in rows if r["cis"]))
    print("top services:", dict(by_service.most_common(12)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())