#!/usr/bin/env bash
#
# Capture the bumper post-install TRIAGE SUBAGENT — what it scanned, consulted,
# and returned — when Claude reacts to the `deps watch` nudge.
#
# It installs a vulnerable-but-legit package (lodash@4.17.4) in a throwaway repo,
# runs the real `claude` agent headless with full event streaming, and prints the
# subagent's transcript: its prompt, every tool call + output (incl. `bumper deps`
# and any advisor-MCP `get_vuln` lookups), and its final report to the main agent.
#
# Why stream-json: `--output-format json` only returns the MAIN agent's final text;
# the subagent's work lives in the event stream as assistant/user messages tagged
# with parent_tool_use_id (non-null = subagent). That's what we extract.
#
# Requires on PATH: claude (logged in), bumper (>=1.2.0), npm, jq
# Usage:  ./capture-subagent.sh                 # fresh capture (one real claude -p call)
#         ./capture-subagent.sh <stream.jsonl>  # re-render a SAVED stream (no claude call)
#
# ⚠ The fresh capture makes ONE real `claude -p` call (spends tokens on your
#   account) and uses the network. Runs in a throwaway temp dir. Override with
#   BUMPER=, CLAUDE=, VULN_PKG=.

set -u
BUMPER="${BUMPER:-bumper}"; CLAUDE="${CLAUDE:-claude}"
VULN_PKG="${VULN_PKG:-lodash@4.17.4}"
command -v jq >/dev/null || { echo "missing: jq"; exit 1; }

# Re-render mode: `capture-subagent.sh <stream.jsonl>` re-parses a saved stream
# (no new claude call). Otherwise run a fresh capture.
if [ "${1:-}" != "" ] && [ -f "${1:-}" ]; then
  STREAM="$1"; D="$(dirname "$1")"
  echo "re-rendering saved stream: $STREAM"
else
  for c in "$CLAUDE" "$BUMPER" npm; do command -v "$c" >/dev/null || { echo "missing: $c"; exit 1; }; done
  D="$(mktemp -d "${TMPDIR:-/tmp}/bumper-subagent.XXXXXX")"; cd "$D"
  echo "workdir: $D"
  npm init -y >/dev/null 2>&1
  ( "$BUMPER" init --agent claude --yes ) >/dev/null 2>&1
  jq empty .claude/settings.json 2>/dev/null || { echo "settings.json invalid — hooks would not load"; exit 1; }
  STREAM="$D/stream.jsonl"
  echo "running claude (installs $VULN_PKG, follows the watch nudge → spawns triage subagent)…"
  BUMPER_HOOK_LOG="$D/hooks.jsonl" timeout 300 "$CLAUDE" -p \
    "Run: npm install $VULN_PKG . Then follow any security guidance you receive about the dependencies." \
    --permission-mode bypassPermissions \
    --output-format stream-json --verbose --include-partial-messages \
    >"$STREAM" 2>"$D/err.log"
  echo "claude exit=$?  stream lines=$(wc -l <"$STREAM")"
fi

have_sub=$(jq -s '[.[]|select(.parent_tool_use_id!=null)]|length' "$STREAM" 2>/dev/null || echo 0)
if [ "${have_sub:-0}" -eq 0 ]; then
  echo
  echo "No subagent events captured (parent_tool_use_id never set)."
  echo "Claude may have remediated inline instead of spawning a Task. Raw stream: $STREAM"
  exit 0
fi

sec(){ printf '\n\033[1;36m── %s ──\033[0m\n' "$*"; }

sec "SUBAGENT SPAWN (the nudge → Task)"
jq -r 'select(.type=="assistant" and .parent_tool_use_id==null)
  | .message.content[]? | select(.type=="tool_use" and (.name=="Agent" or .name=="Task"))
  | "  description: \(.input.description // "")\n  prompt:\n" + ((.input.prompt // "") | split("\n") | map("    "+.) | join("\n"))' "$STREAM"

sec "SUBAGENT TRANSCRIPT (tool calls + outputs, in order)"
jq -r '
  def trunc($n): if (type=="string" and (length>$n)) then .[0:$n]+" …[truncated]" else . end;
  if .type=="assistant" and .parent_tool_use_id!=null then
    ( .message.content[]?
      | if .type=="tool_use" then "\n  ▶ \(.name): " + ((.input.command // (.input|tojson)) | trunc(200))
        elif (.type=="text" and (.text|length>0)) then "  · " + (.text | trunc(500))
        else empty end )
  elif .type=="user" and .parent_tool_use_id!=null then
    ( .message.content[]? | select(.type=="tool_result")
      | "    ⤷ " + ((if (.content|type)=="array" then ([.content[]?|.text//""]|join("\n")) else (.content|tostring) end)
                    | gsub("\n";"\n      ") | trunc(900)) )
  else empty end' "$STREAM"

sec "SUBAGENT FINAL REPORT (returned to the main agent)"
jq -r 'select(.type=="user" and .parent_tool_use_id==null)
  | .message.content[]? | select(.type=="tool_result")
  | (if (.content|type)=="array" then ([.content[]?|.text//""]|join("\n")) else (.content|tostring) end)' "$STREAM" 2>/dev/null \
  | grep -av '"parentUuid"\|"isSidechain"' | sed 's/^/  /'

sec "MAIN AGENT FINAL MESSAGE"
jq -r 'select(.type=="result") | .result' "$STREAM" 2>/dev/null | sed 's/^/  /'

echo
echo "raw stream + hook log: $D  (stream.jsonl, hooks.jsonl)"
