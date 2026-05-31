#!/usr/bin/env bash
# corpus_scan.sh — run bumper across a multi-cloud "anti-pattern" corpus.
#
# For each target it produces a terraform plan and scans it with bumper:
#   - a DIRECTORY of *.tf  → init (offline) + plan (fake creds, -refresh=false)
#                            + `terraform show -json` | bumper
#   - a *.json FILE        → scanned directly (pre-rendered plan; used for Azure,
#                            whose provider authenticates on configure and cannot
#                            plan offline)
#
# Offline planning works because a CREATE-ONLY plan with no data sources makes no
# cloud API calls — the provider is only invoked locally for schema + diff. We
# feed fake credentials and skip flags so the provider never tries to reach out.
#
# Usage:
#   tools/corpus_scan.sh [targets...]        # defaults to tools/corpus/*
#   BUMPER=/path/to/bumper tools/corpus_scan.sh aws/ gcp/ azure/plan.json
#
# External repos (e.g. TerraGoat) can be passed too, but note many are pinned to
# old provider schemas — see tools/corpus/README.md.
set -uo pipefail

BUMPER="${BUMPER:-bumper}"
TERRAFORM="${TERRAFORM:-terraform}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Fake credentials so providers configure without real cloud access. For
# create-only plans these are never used to call an API.
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
export AWS_REGION="${AWS_REGION:-us-east-1}"
export GOOGLE_OAUTH_ACCESS_TOKEN="${GOOGLE_OAUTH_ACCESS_TOKEN:-fake-token}"
export CLOUDSDK_CORE_PROJECT="${CLOUDSDK_CORE_PROJECT:-bumper-corpus}"

total_findings=0
total_targets=0
failed_targets=0

# summarize NAME JSON — print a one-line severity breakdown of a bumper findings
# array. The JSON is piped on stdin; the script comes from -c.
summarize() {
	local name="$1" json="$2"
	printf '%s' "$json" | python3 -c '
import json, sys
from collections import Counter
name = sys.argv[1]
data = sys.stdin.read().strip()
try:
    findings = json.loads(data) if data else []
except Exception:
    findings = []
c = Counter(f.get("severity", "?") for f in findings)
order = ["critical", "high", "medium", "low"]
parts = [f"{c[s]} {s}" for s in order if c.get(s)]
brk = " (" + ", ".join(parts) + ")" if parts else ""
print(f"  {name:<28} {len(findings)} finding(s){brk}")
' "$name"
}

scan_json_file() {
	local target="$1" name="$2"
	local out
	out="$("$BUMPER" --format json "$target" 2>/dev/null)"
	local n
	n="$(python3 -c 'import json,sys; print(len(json.loads(sys.stdin.read() or "[]")))' <<<"$out")"
	summarize "$name (pre-rendered)" "$out"
	total_findings=$((total_findings + n))
}

scan_tf_dir() {
	local dir="$1" name="$2"
	echo "  $name: terraform init + plan (offline)…"
	if ! ( cd "$dir" && "$TERRAFORM" init -upgrade -backend=false -input=false -no-color ) >/dev/null 2>&1; then
		echo "  $name: SKIP (terraform init failed — provider/schema mismatch?)"
		failed_targets=$((failed_targets + 1))
		return
	fi
	if ! ( cd "$dir" && "$TERRAFORM" plan -refresh=false -input=false -no-color -out=.corpus.tfplan ) >/dev/null 2>&1; then
		echo "  $name: SKIP (terraform plan failed — likely a data source needing live creds)"
		failed_targets=$((failed_targets + 1))
		return
	fi
	local out
	out="$( cd "$dir" && "$TERRAFORM" show -json .corpus.tfplan 2>/dev/null | "$BUMPER" --format json - 2>/dev/null )"
	local n
	n="$(python3 -c 'import json,sys; print(len(json.loads(sys.stdin.read() or "[]")))' <<<"$out")"
	summarize "$name" "$out"
	total_findings=$((total_findings + n))
	rm -f "$dir/.corpus.tfplan"
}

main() {
	local targets=("$@")
	if [ ${#targets[@]} -eq 0 ]; then
		for d in "$ROOT"/tools/corpus/*/; do targets+=("$d"); done
		for j in "$ROOT"/tools/corpus/*.json; do [ -e "$j" ] && targets+=("$j"); done
	fi

	echo "== bumper corpus scan =="
	echo "bumper: $("$BUMPER" version 2>/dev/null || echo "$BUMPER")"
	echo

	for t in "${targets[@]}"; do
		total_targets=$((total_targets + 1))
		local name
		name="$(basename "${t%/}")"
		if [ -f "$t" ] && [[ "$t" == *.json ]]; then
			scan_json_file "$t" "$name"
		elif [ -d "$t" ]; then
			scan_tf_dir "$t" "$name"
		else
			echo "  $name: SKIP (not a .tf dir or .json file)"
			failed_targets=$((failed_targets + 1))
		fi
	done

	echo
	echo "-- $total_findings finding(s) across $total_targets target(s); $failed_targets skipped --"
}

main "$@"
