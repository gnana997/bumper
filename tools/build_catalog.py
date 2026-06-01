#!/usr/bin/env python3
"""Build bumper's embeddable advisory catalog from four Apache-2.0 upstreams.

ONE self-contained pipeline: clone the four source repos, harvest STRUCTURED
METADATA only (id, severity, title, resource type, remediation), normalize to a
common envelope, and write one file per (source, provider) under
internal/catalog/data/<source>/<provider>.json. It does NOT copy rule logic.

  Trivy/tfsec (aquasecurity/trivy-checks) : checks/cloud/<p>/**.rego METADATA
  Checkov     (bridgecrewio/checkov)      : checkov/terraform/checks/**.py (AST) + graph_checks/*.yaml
  KICS        (Checkmarx/kics)            : assets/queries/terraform/<p>/*/metadata.json
  Prowler     (prowler-cloud/prowler)     : prowler/providers/<p>/services/**/*.metadata.json

FEDERATED, not merged: deliberately NO dedup across sources. Each source is its
own corpus; the binary loads four maps and merges ranked results at query time.
A source change touches only its own adapter.

Usage: python3 tools/build_catalog.py [--work DIR] [--no-clone]
  --work    : clone dir (default ./.catalog-src)
  --no-clone: reuse existing clones instead of cloning
"""
import argparse
import ast
import glob
import json
import os
import re
import subprocess
import sys

try:
    import yaml
    HAVE_YAML = True
except ImportError:  # Checkov graph checks (CKV2_*) need PyYAML; degrade gracefully.
    HAVE_YAML = False

CLOUDS = ["aws", "gcp", "azure"]
PREF = {"aws": "aws_", "gcp": "google_", "azure": "azurerm_"}
OUT = "internal/catalog/data"

REPOS = {
    "trivy": "https://github.com/aquasecurity/trivy-checks",
    "checkov": "https://github.com/bridgecrewio/checkov",
    "kics": "https://github.com/Checkmarx/kics",
    "prowler": "https://github.com/prowler-cloud/prowler",
}
SPARSE = {
    "trivy": ["checks/cloud"],
    "checkov": ["checkov/terraform/checks"],
    "kics": ["assets/queries/terraform"],
    "prowler": [f"prowler/providers/{c}/services" for c in CLOUDS],
}
# canonical provider -> tool subdir (Trivy calls GCP "google").
TRIVY_DIR = {"aws": "aws", "gcp": "google", "azure": "azure"}


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def sev(s):
    s = (s or "").strip().lower()
    return s if s in ("critical", "high", "medium", "low") else ""


def res(rt):
    return rt.strip().lower().rstrip("_") if rt else ""


def keep_resources(resources, provider):
    return sorted({res(x) for x in (resources or []) if res(x) and res(x).startswith(PREF[provider])})


def write(source, provider, entries):
    d = os.path.join(OUT, source)
    os.makedirs(d, exist_ok=True)
    entries.sort(key=lambda e: e["source_id"])
    with open(os.path.join(d, provider + ".json"), "w") as f:
        json.dump(entries, f, indent=1, sort_keys=True)
    return len(entries)


def clone(name, dest, no_clone):
    if os.path.isdir(os.path.join(dest, ".git")):
        return dest
    if no_clone:
        sys.exit(f"error: --no-clone set but {dest} is not a git clone")
    print(f"  cloning {REPOS[name]} -> {dest}")
    subprocess.run(["git", "clone", "--filter=blob:none", "--sparse", "--depth", "1",
                    REPOS[name], dest], check=True)
    subprocess.run(["git", "-C", dest, "sparse-checkout", "set"] + SPARSE[name], check=True)
    return dest


# --------------------------------------------------------------------------- #
# Trivy: Rego METADATA block (harvest logic preserved from the prior extractor)
# --------------------------------------------------------------------------- #
def trivy_metadata(text):
    lines, started = [], False
    for line in text.splitlines():
        if line.startswith("#"):
            started = True
            lines.append(re.sub(r"^#\s?", "", line))
        elif started:
            break
    return "\n".join(lines)


def trivy_field(block, key):
    m = re.search(rf"^\s*{re.escape(key)}:\s*(.+?)\s*$", block, re.MULTILINE)
    return m.group(1).strip().strip('"') if m else ""


def harvest_trivy(repo_dir, provider):
    root = os.path.join(repo_dir, "checks", "cloud", TRIVY_DIR[provider])
    out = []
    for dp, _, files in os.walk(root):
        for f in files:
            if not f.endswith(".rego") or f.endswith("_test.rego"):
                continue
            block = trivy_metadata(open(os.path.join(dp, f), encoding="utf-8", errors="ignore").read())
            if "title:" not in block:
                continue
            out.append({
                "source": "trivy", "source_id": trivy_field(block, "id"), "provider": provider,
                "resources": [],  # Trivy METADATA has no TF resource type
                "severity": sev(trivy_field(block, "severity")),
                "title": trivy_field(block, "title").strip(),
                "remediation": trivy_field(block, "recommended_action").strip(),
                "refs": [], "cwe": "", "category": "",
            })
    return out


# --------------------------------------------------------------------------- #
# Checkov: Python check class (AST) + YAML graph checks
# --------------------------------------------------------------------------- #
def _literal(node):
    try:
        return ast.literal_eval(node)
    except Exception:
        return None


def _collect_init_values(init):
    locals_ = {}
    for stmt in init.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            tgt = stmt.targets[0]
            if isinstance(tgt, ast.Name):
                key = tgt.id
            elif isinstance(tgt, ast.Attribute) and isinstance(tgt.value, ast.Name) and tgt.value.id == "self":
                key = tgt.attr
            else:
                continue
            v = _literal(stmt.value)
            if v is not None:
                locals_[key] = v
    vals = dict(locals_)
    for node in ast.walk(init):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "__init__":
            for kw in node.keywords:
                if not kw.arg:
                    continue
                v = _literal(kw.value)
                if v is None and isinstance(kw.value, ast.Name):
                    v = locals_.get(kw.value.id)
                if v is not None:
                    vals[kw.arg] = v
    return vals


def _extract_categories(init):
    names = []

    def walk_for_members(node):
        for n in ast.walk(node):
            if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "CheckCategories":
                names.append(n.attr)

    for stmt in init.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 \
                and isinstance(stmt.targets[0], ast.Name) and stmt.targets[0].id == "categories":
            walk_for_members(stmt.value)
    for node in ast.walk(init):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "__init__":
            for kw in node.keywords:
                if kw.arg == "categories":
                    walk_for_members(kw.value)
    return ",".join(sorted(set(names)))


def _collect_resource_types(node, out=None):
    if out is None:
        out = []
    if isinstance(node, dict):
        rt = node.get("resource_types")
        if isinstance(rt, list):
            out.extend(x for x in rt if isinstance(x, str) and x != "*")
        elif isinstance(rt, str) and rt != "*":
            out.append(rt)
        for v in node.values():
            _collect_resource_types(v, out)
    elif isinstance(node, list):
        for v in node:
            _collect_resource_types(v, out)
    return out


def harvest_checkov(repo_dir, provider):
    base = os.path.join(repo_dir, "checkov", "terraform", "checks")
    roots = [os.path.join(base, kind, provider) for kind in ("resource", "data", "provider")]
    out = []
    for root in (r for r in roots if os.path.isdir(r)):
        for dp, _, files in os.walk(root):
            for f in files:
                if not f.endswith(".py") or f == "__init__.py":
                    continue
                try:
                    tree = ast.parse(open(os.path.join(dp, f), encoding="utf-8", errors="ignore").read())
                except SyntaxError:
                    continue
                for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
                    init = next((n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "__init__"), None)
                    if not init:
                        continue
                    vals = _collect_init_values(init)
                    cid = vals.get("id")
                    if not isinstance(cid, str) or not cid.startswith("CKV"):
                        continue
                    rt = vals.get("supported_resources") or vals.get("supported_data") or []
                    if isinstance(rt, (tuple, set)):
                        rt = list(rt)
                    if isinstance(rt, str):
                        rt = [rt]
                    out.append({
                        "source": "checkov", "source_id": cid, "provider": provider,
                        "resources": keep_resources([r for r in rt if isinstance(r, str)], provider),
                        "severity": "",  # OSS Python checks carry no severity (graph checks do)
                        "title": (vals.get("name") or "").strip(),
                        "remediation": (vals.get("guideline") or "").strip(),
                        "refs": [], "cwe": "", "category": _extract_categories(init),
                    })
    return out


def harvest_checkov_graph(repo_dir, provider):
    if not HAVE_YAML:
        return []
    root = os.path.join(repo_dir, "checkov", "terraform", "checks", "graph_checks", provider)
    out = []
    for dp, _, files in os.walk(root):
        for f in files:
            if not f.endswith((".yaml", ".yml")):
                continue
            try:
                doc = yaml.safe_load(open(os.path.join(dp, f), encoding="utf-8", errors="ignore"))
            except Exception:
                continue
            if not isinstance(doc, dict):
                continue
            meta = doc.get("metadata") or {}
            cid = meta.get("id")
            if not isinstance(cid, str) or not cid.startswith("CKV"):
                continue
            out.append({
                "source": "checkov", "source_id": cid, "provider": provider,
                "resources": keep_resources(_collect_resource_types(doc.get("definition")), provider),
                "severity": sev(meta.get("severity")),
                "title": (meta.get("name") or "").strip(),
                "remediation": (doc.get("guideline") or "").strip(),
                "refs": [], "cwe": "", "category": (meta.get("category") or "").strip(),
            })
    return out


# --------------------------------------------------------------------------- #
# KICS: TF resource recovered from the registry descriptionUrl
# --------------------------------------------------------------------------- #
def harvest_kics(repo_dir, provider):
    out = []
    for f in glob.glob(f"{repo_dir}/assets/queries/terraform/{provider}/*/metadata.json"):
        d = json.load(open(f))
        m = re.search(r"/resources/([a-z0-9_]+)", d.get("descriptionUrl", ""))
        out.append({
            "source": "kics", "source_id": d["id"], "provider": provider,
            "resources": [res(PREF[provider] + m.group(1))] if m else [],
            "severity": sev(d.get("severity")),
            "title": (d.get("queryName") or "").strip(),
            "remediation": (d.get("descriptionText") or "").strip(),
            "refs": [d["descriptionUrl"]] if d.get("descriptionUrl") else [],
            "cwe": str(d.get("cwe", "")), "category": (d.get("category") or "").strip(),
        })
    return out


# --------------------------------------------------------------------------- #
# Prowler: keep checks with Terraform remediation; TF resource from the HCL
# --------------------------------------------------------------------------- #
def harvest_prowler(repo_dir, provider):
    out = []
    for f in glob.glob(f"{repo_dir}/prowler/providers/{provider}/services/**/*.metadata.json", recursive=True):
        try:
            d = json.load(open(f))
        except Exception:
            continue
        tf = d.get("Remediation", {}).get("Code", {}).get("Terraform", "") or ""
        resources = sorted({res(x) for x in re.findall(r'resource\s+"([a-z0-9_]+)"', tf)})
        if not resources:
            continue
        rec = d.get("Remediation", {}).get("Recommendation", {})
        out.append({
            "source": "prowler", "source_id": d["CheckID"], "provider": provider,
            "resources": resources, "severity": sev(d.get("Severity")),
            "title": (d.get("CheckTitle") or "").strip(),
            "remediation": (rec.get("Text") or "").strip(),
            "fix_terraform": tf.strip(),
            "refs": [rec["Url"]] if rec.get("Url") else [],
            "cwe": "", "category": ",".join(d.get("Categories", [])),
        })
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", default="./.catalog-src")
    ap.add_argument("--no-clone", action="store_true")
    a = ap.parse_args()

    os.makedirs(a.work, exist_ok=True)
    print("sources:")
    dirs = {name: clone(name, os.path.join(a.work, name), a.no_clone) for name in REPOS}
    if not HAVE_YAML:
        print("  warning: PyYAML not installed — Checkov CKV2 graph checks skipped")

    print("building catalog ->", OUT)
    by_source, total = {}, 0
    for c in CLOUDS:
        per = {
            "trivy": harvest_trivy(dirs["trivy"], c),
            "checkov": harvest_checkov(dirs["checkov"], c) + harvest_checkov_graph(dirs["checkov"], c),
            "kics": harvest_kics(dirs["kics"], c),
            "prowler": harvest_prowler(dirs["prowler"], c),
        }
        for src, entries in per.items():
            n = write(src, c, entries)
            by_source[src] = by_source.get(src, 0) + n
            total += n
            print(f"  {src}/{c}.json: {n}")
    print("by source:", by_source)
    print("total records:", total)


if __name__ == "__main__":
    main()
