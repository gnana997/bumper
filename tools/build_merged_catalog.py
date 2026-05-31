#!/usr/bin/env python3
"""Build merged IaC check catalogs from Trivy + Checkov, for one provider or all.

Both projects are Apache-2.0. This harvests STRUCTURED METADATA only (id,
severity, title, resource types, fix) into a curated porting worklist for
bumper's plan-JSON + CEL rules. It does NOT copy rule logic — that's hand-ported.

  Trivy   (aquasecurity/trivy-checks)  : checks/cloud/<dir>/**.rego  (METADATA block)
  Checkov (bridgecrewio/checkov)       : checkov/terraform/checks/{resource,data,provider}/<dir>/**.py

Providers are DISCOVERED from each clone at runtime (not hardcoded), then mapped
to a canonical name via a small alias table — so a wrong guess can't silently
harvest nothing, and providers present in only one tool still produce output.

Known cross-tool name mismatches:
    GCP    : Trivy "google"  vs Checkov "gcp"
    Oracle : Trivy "oracle"  vs Checkov "oci"
DigitalOcean is "digitalocean" in both.

Usage:
    python3 tools/build_merged_catalog.py [provider|all] [--out DIR] [--work DIR] [--no-clone]

    provider : a canonical name (aws, gcp, azure, digitalocean, oracle, ...) or "all"
               (default: all)
    --out    : output dir       (default: ./docs/rule-catalog)
    --work   : clone dir        (default: ./.catalog-src)
    --no-clone: reuse existing clones instead of git cloning

Outputs per provider:  <out>/merged-<provider>.json  and  merged-<provider>.md
Plus in "all" mode:    <out>/merged-index.md  (coverage summary across providers)
"""
import argparse
import ast
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict

try:
    import yaml
    HAVE_YAML = True
except ImportError:  # graph checks (CKV2_*) need PyYAML; degrade gracefully without it.
    HAVE_YAML = False

TRIVY_REPO = "https://github.com/aquasecurity/trivy-checks"
CHECKOV_REPO = "https://github.com/bridgecrewio/checkov"

# tool-dir -> canonical name. Anything not listed maps to itself.
TRIVY_TO_CANON = {"google": "gcp"}
CHECKOV_TO_CANON = {"oci": "oracle"}

# Trivy dirs under checks/cloud/ that are NOT real TF cloud providers — skip in "all".
TRIVY_SKIP = set()  # checks/cloud only contains cloud providers; k8s/docker live elsewhere

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}

# Terraform resource-type prefixes, stripped before deriving a service.
PROVIDER_PREFIXES = (
    "aws_", "azurerm_", "azuread_", "azapi_", "google_", "google-beta_",
    "alicloud_", "oci_", "digitalocean_", "linode_", "nifcloud_", "openstack_",
    "yandex_", "tencentcloud_", "ncloud_", "panos_", "github_", "gitlab_",
    "okta_", "cloudstack_",
)

# Map a Checkov resource stem (after prefix strip) to Trivy's coarser SERVICE
# vocabulary, so both tools group together. Provider-scoped to avoid stem
# collisions (e.g. AWS "lb" -> elb vs Azure "lb" -> network). Longest matching
# prefix of {3,2,1} tokens wins; unknown stems fall back to the first token.
SERVICE_ALIASES = {
    "aws": {
        "db": "rds", "rds": "rds", "neptune": "neptune", "docdb": "docdb",
        "instance": "ec2", "ebs": "ec2", "ami": "ec2", "eip": "ec2",
        "key_pair": "ec2", "security_group": "ec2", "default_security_group": "ec2",
        "vpc": "ec2", "default_vpc": "ec2", "subnet": "ec2", "network_acl": "ec2",
        "network_interface": "ec2", "route": "ec2", "route_table": "ec2",
        "internet_gateway": "ec2", "flow_log": "ec2", "launch_template": "ec2",
        "launch_configuration": "ec2", "autoscaling": "ec2", "ebs_encryption": "ec2",
        "s3": "s3", "s3_bucket": "s3", "iam": "iam", "elasticache": "elasticache",
        "lambda": "lambda", "kms": "kms", "cloudfront": "cloudfront",
        "cloudtrail": "cloudtrail", "cloudwatch": "cloudwatch", "sns": "sns",
        "sqs": "sqs", "dynamodb": "dynamodb", "ecr": "ecr", "ecs": "ecs",
        "eks": "eks", "elasticsearch": "elasticsearch", "opensearch": "elasticsearch",
        "redshift": "redshift", "athena": "athena", "api_gateway": "apigateway",
        "apigatewayv2": "apigateway", "elb": "elb", "lb": "elb", "alb": "elb",
        "efs": "efs", "mq": "mq", "msk": "msk", "config": "config",
        "codebuild": "codebuild", "secretsmanager": "ssm", "ssm": "ssm",
        "workspaces": "workspaces", "dax": "dax", "glue": "glue",
        "sagemaker": "sagemaker", "kinesis": "kinesis",
    },
    "azure": {
        "mssql": "database", "sql": "database", "postgresql": "database",
        "mysql": "database", "mariadb": "database", "cosmosdb": "database",
        "storage": "storage", "storage_account": "storage",
        "network_security_rule": "network", "network_security_group": "network",
        "virtual_network": "network", "network_watcher": "network",
        "application_gateway": "network", "subnet": "network", "lb": "network",
        "key_vault": "keyvault", "kubernetes": "container", "container": "container",
        "app_service": "appservice", "function_app": "appservice",
        "linux_web_app": "appservice", "windows_web_app": "appservice",
        "linux_function_app": "appservice", "windows_function_app": "appservice",
        "virtual_machine": "compute", "linux_virtual_machine": "compute",
        "windows_virtual_machine": "compute", "managed_disk": "compute",
        "monitor": "monitor", "role": "authorization", "data_factory": "datafactory",
    },
    "gcp": {
        "compute": "compute", "storage_bucket": "storage", "storage": "storage",
        "container_cluster": "gke", "container_node_pool": "gke",
        "sql_database_instance": "sql", "sql": "sql", "project_iam": "iam",
        "organization_iam": "iam", "folder_iam": "iam", "service_account": "iam",
        "iam": "iam", "bigquery": "bigquery", "dns": "dns", "kms": "kms",
    },
}


def resource_to_service(restype: str, canon: str) -> str:
    """Derive a Trivy-aligned service name from a Checkov resource type."""
    s = restype
    for p in PROVIDER_PREFIXES:
        if s.startswith(p):
            s = s[len(p):]
            break
    submap = SERVICE_ALIASES.get(canon, {})
    toks = s.split("_")
    for n in (3, 2, 1):
        key = "_".join(toks[:n])
        if key in submap:
            return submap[key]
    return toks[0] if toks and toks[0] else "?"


def canonical_service(row: dict, canon: str) -> str:
    """The grouping key shared by both tools."""
    if row["tool"] == "trivy":
        return (row["service"] or "?").lower().replace("-", "_")
    if row["resources"]:
        return resource_to_service(row["resources"][0], canon)
    return "(unmapped)"


# ---------------------------------------------------------------------------
# cloning
# ---------------------------------------------------------------------------
def shallow_clone(repo: str, dest: str, no_clone: bool) -> str:
    if os.path.isdir(os.path.join(dest, ".git")):
        if not no_clone:
            print(f"  {dest} exists; pulling")
            subprocess.run(["git", "-C", dest, "pull", "--ff-only"], check=False)
        return dest
    if no_clone:
        sys.exit(f"error: --no-clone set but {dest} is not a git clone")
    print(f"  cloning {repo} -> {dest}")
    subprocess.run(["git", "clone", "--depth", "1", repo, dest], check=True)
    return dest


def list_subdirs(path: str) -> list:
    if not os.path.isdir(path):
        return []
    return sorted(d for d in os.listdir(path)
                  if os.path.isdir(os.path.join(path, d)) and not d.startswith("."))


# ---------------------------------------------------------------------------
# provider discovery -> canonical maps {canon: tool_dir}
# ---------------------------------------------------------------------------
def discover_trivy(repo_dir: str) -> dict:
    cloud = os.path.join(repo_dir, "checks", "cloud")
    out = {}
    for d in list_subdirs(cloud):
        if d in TRIVY_SKIP:
            continue
        out[TRIVY_TO_CANON.get(d, d)] = d
    return out


def discover_checkov(repo_dir: str) -> dict:
    # resource/ is the canonical home; data/ and provider/ share the same leaves.
    res = os.path.join(repo_dir, "checkov", "terraform", "checks", "resource")
    out = {}
    for d in list_subdirs(res):
        out[CHECKOV_TO_CANON.get(d, d)] = d
    return out


# ---------------------------------------------------------------------------
# Trivy: Rego METADATA block
# ---------------------------------------------------------------------------
def trivy_metadata(text: str) -> str:
    lines, started = [], False
    for line in text.splitlines():
        if line.startswith("#"):
            started = True
            lines.append(re.sub(r"^#\s?", "", line))
        elif started:
            break
    return "\n".join(lines)


def trivy_field(block: str, key: str) -> str:
    m = re.search(rf"^\s*{re.escape(key)}:\s*(.+?)\s*$", block, re.MULTILINE)
    return m.group(1).strip().strip('"') if m else ""


def harvest_trivy(repo_dir: str, tool_dir: str) -> list:
    root = os.path.join(repo_dir, "checks", "cloud", tool_dir)
    rows = []
    for dp, _, files in os.walk(root):
        for f in files:
            if not f.endswith(".rego") or f.endswith("_test.rego"):
                continue
            path = os.path.join(dp, f)
            block = trivy_metadata(open(path, encoding="utf-8", errors="ignore").read())
            if "title:" not in block:
                continue
            rows.append({
                "tool": "trivy",
                "id": trivy_field(block, "id"),
                "severity": trivy_field(block, "severity").lower(),
                "title": trivy_field(block, "title"),
                "service": trivy_field(block, "service") or os.path.basename(dp),
                "category": "",
                "resources": [],
                "fix": trivy_field(block, "recommended_action"),
                "source_file": os.path.relpath(path, repo_dir),
            })
    return rows


# ---------------------------------------------------------------------------
# Checkov: Python check class (AST)
# ---------------------------------------------------------------------------
def _literal(node):
    try:
        return ast.literal_eval(node)
    except Exception:
        return None


def _collect_init_values(init) -> dict:
    """Pull id/name/supported_resources from a Checkov check's __init__, covering
    every common pattern: inline literals in super().__init__(...), local
    variables assigned then passed (e.g. `name=description`), and self.X = ...
    The super() keyword *name* is canonical, but its value is resolved through the
    local literals when it is a bare variable reference."""
    locals_ = {}
    for stmt in init.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            tgt = stmt.targets[0]
            if isinstance(tgt, ast.Name):
                key = tgt.id
            elif isinstance(tgt, ast.Attribute) and isinstance(tgt.value, ast.Name) \
                    and tgt.value.id == "self":
                key = tgt.attr
            else:
                continue
            v = _literal(stmt.value)
            if v is not None:
                locals_[key] = v

    vals = dict(locals_)
    for node in ast.walk(init):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr == "__init__":
            for kw in node.keywords:
                if not kw.arg:
                    continue
                v = _literal(kw.value)
                if v is None and isinstance(kw.value, ast.Name):
                    v = locals_.get(kw.value.id)  # name=description → resolve `description`
                if v is not None:
                    vals[kw.arg] = v
    return vals


def _extract_categories(init) -> str:
    """Pull CheckCategories.X member names from a Python check's __init__, whether
    `categories` is a local or a super() kwarg. These are enum refs, not literals."""
    names = []

    def walk_for_members(node):
        for n in ast.walk(node):
            if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) \
                    and n.value.id == "CheckCategories":
                names.append(n.attr)

    for stmt in init.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 \
                and isinstance(stmt.targets[0], ast.Name) and stmt.targets[0].id == "categories":
            walk_for_members(stmt.value)
    for node in ast.walk(init):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr == "__init__":
            for kw in node.keywords:
                if kw.arg == "categories":
                    walk_for_members(kw.value)
    return ",".join(sorted(set(names)))


def _collect_resource_types(node, out=None) -> list:
    """Recursively gather every `resource_types` entry from a graph-check
    definition (they can be nested under and/or blocks)."""
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


def harvest_checkov_graph(repo_dir: str, tool_dir: str) -> list:
    """Harvest Checkov's YAML graph checks (CKV2_*). Unlike the Python checks,
    these carry severity and category in their metadata."""
    if not HAVE_YAML:
        return []
    root = os.path.join(repo_dir, "checkov", "terraform", "checks", "graph_checks", tool_dir)
    rows = []
    for dp, _, files in os.walk(root):
        for f in files:
            if not f.endswith((".yaml", ".yml")):
                continue
            path = os.path.join(dp, f)
            try:
                doc = yaml.safe_load(open(path, encoding="utf-8", errors="ignore"))
            except Exception:
                continue
            if not isinstance(doc, dict):
                continue
            meta = doc.get("metadata") or {}
            cid = meta.get("id")
            if not isinstance(cid, str) or not cid.startswith("CKV"):
                continue
            resources = sorted(set(_collect_resource_types(doc.get("definition"))))
            rows.append({
                "tool": "checkov",
                "id": cid,
                "severity": (meta.get("severity") or "").lower(),
                "title": meta.get("name") or "",
                "service": "",
                "category": meta.get("category") or "",
                "resources": resources,
                "fix": doc.get("guideline") or "",
                "source_file": os.path.relpath(path, repo_dir),
            })
    return rows


def harvest_checkov(repo_dir: str, tool_dir: str) -> list:
    base = os.path.join(repo_dir, "checkov", "terraform", "checks")
    roots = [os.path.join(base, kind, tool_dir) for kind in ("resource", "data", "provider")]
    roots = [r for r in roots if os.path.isdir(r)]
    rows = []
    for root in roots:
        for dp, _, files in os.walk(root):
            for f in files:
                if not f.endswith(".py") or f == "__init__.py":
                    continue
                path = os.path.join(dp, f)
                try:
                    tree = ast.parse(open(path, encoding="utf-8", errors="ignore").read())
                except SyntaxError:
                    continue
                for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
                    init = next((n for n in cls.body
                                 if isinstance(n, ast.FunctionDef) and n.name == "__init__"), None)
                    if not init:
                        continue
                    vals = _collect_init_values(init)
                    cid = vals.get("id")
                    if not isinstance(cid, str) or not cid.startswith("CKV"):
                        continue
                    res = vals.get("supported_resources") or vals.get("supported_data") or []
                    if isinstance(res, (tuple, set)):
                        res = list(res)
                    if isinstance(res, str):
                        res = [res]
                    rows.append({
                        "tool": "checkov",
                        "id": cid,
                        # Python OSS check classes have no severity field (it lives
                        # on the Prisma platform); graph checks do — see
                        # harvest_checkov_graph.
                        "severity": "",
                        "title": vals.get("name") or "",
                        "service": "",
                        "category": _extract_categories(init),
                        "resources": [r for r in res if isinstance(r, str)],
                        "fix": vals.get("guideline") or "",  # remediation URL, when set
                        "source_file": os.path.relpath(path, repo_dir),
                    })
    return rows


# ---------------------------------------------------------------------------
# emit one provider
# ---------------------------------------------------------------------------
def write_provider(rows: list, out_dir: str, canon: str):
    os.makedirs(out_dir, exist_ok=True)
    for r in rows:
        r["service_group"] = canonical_service(r, canon)
        if r["tool"] == "checkov" and not r.get("service"):
            r["service"] = r["service_group"]  # surface the derived service in JSON
    rows.sort(key=lambda r: (r["service_group"], r["tool"], r["id"]))
    json.dump(rows, open(os.path.join(out_dir, f"merged-{canon}.json"), "w"), indent=2)

    by_svc = defaultdict(list)
    for r in rows:
        by_svc[r["service_group"]].append(r)

    with open(os.path.join(out_dir, f"merged-{canon}.md"), "w") as fh:
        fh.write(f"# Merged {canon.upper()} catalog — Trivy + Checkov (porting worklist)\n\n")
        fh.write(f"{len(rows)} checks grouped by **service**, so a Trivy check and the "
                 "Checkov check(s) for the same intent sit together — port ONE bumper rule "
                 "per intent, citing both ids in provenance. Trivy supplies severity; "
                 "Checkov (OSS) does not (assign at port time). The `resource` column is the "
                 "Terraform type to write the rule against.\n\n")
        for svc in sorted(by_svc):
            bucket = by_svc[svc]
            nt = sum(1 for r in bucket if r["tool"] == "trivy")
            fh.write(f"### {svc} — {nt} trivy + {len(bucket) - nt} checkov\n\n")
            fh.write("| tool | id | sev | category | resource | title |\n"
                     "|---|---|---|---|---|---|\n")
            for r in sorted(bucket, key=lambda r: (SEV_RANK.get(r["severity"], 4), r["tool"], r["id"])):
                res = ", ".join(r["resources"]) if r["resources"] else "—"
                cat = (r.get("category") or "—").lower().replace("_", " ")
                fh.write(f"| {r['tool']} | {r['id']} | {r['severity'] or '—'} | {cat} | "
                         f"{res[:40]} | {r['title'][:64]} |\n")
            fh.write("\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("provider", nargs="?", default="all")
    ap.add_argument("--out", default="./docs/rule-catalog")
    ap.add_argument("--work", default="./.catalog-src")
    ap.add_argument("--no-clone", action="store_true")
    a = ap.parse_args()

    os.makedirs(a.work, exist_ok=True)
    print("sources:")
    trivy = shallow_clone(TRIVY_REPO, os.path.join(a.work, "trivy-checks"), a.no_clone)
    checkov = shallow_clone(CHECKOV_REPO, os.path.join(a.work, "checkov"), a.no_clone)

    trivy_map = discover_trivy(trivy)
    checkov_map = discover_checkov(checkov)
    print(f"  trivy providers:   {sorted(trivy_map)}")
    print(f"  checkov providers: {sorted(checkov_map)}")

    want = a.provider.lower()
    if want == "all":
        canon_list = sorted(set(trivy_map) | set(checkov_map))
    else:
        canon_list = [want]
        if want not in trivy_map and want not in checkov_map:
            sys.exit(f"error: {want!r} not found in either tool. "
                     f"available: {sorted(set(trivy_map) | set(checkov_map))}")

    summary = []
    for canon in canon_list:
        tr = harvest_trivy(trivy, trivy_map[canon]) if canon in trivy_map else []
        cv, cg = [], []
        if canon in checkov_map:
            cv = harvest_checkov(checkov, checkov_map[canon])
            cg = harvest_checkov_graph(checkov, checkov_map[canon])
        rows = tr + cv + cg
        if not rows:
            print(f"  {canon}: 0 checks — skipping")
            continue
        write_provider(rows, a.out, canon)
        summary.append((canon, len(tr), len(cv) + len(cg)))
        print(f"  {canon}: trivy={len(tr)} checkov={len(cv)}+{len(cg)}graph "
              f"-> merged-{canon}.(json|md)")

    if want == "all" and summary:
        with open(os.path.join(a.out, "merged-index.md"), "w") as fh:
            fh.write("# Merged catalog coverage (Trivy + Checkov)\n\n")
            fh.write("| provider | trivy | checkov | total |\n|---|---|---|---|\n")
            for c, t, k in sorted(summary, key=lambda x: -(x[1] + x[2])):
                fh.write(f"| {c} | {t} | {k} | {t + k} |\n")
        print(f"\nwrote {os.path.join(a.out, 'merged-index.md')}")

    if not summary:
        sys.exit("error: produced nothing — check clones / provider name")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())