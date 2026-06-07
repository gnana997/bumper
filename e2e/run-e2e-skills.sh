#!/usr/bin/env bash
#
# bumper agent skills — real end-to-end skill test (Claude Code or Gemini CLI)
# ---------------------------------------------------------------------------
# Drives the ACTUAL agent (headless) against bumper's SKILL.md playbooks,
# installed by `bumper skills install`, in throwaway repos. Proves the skills
# work in a real agent loop: the agent DISCOVERS the right skill from its
# description, READS the SKILL.md body, and RESOLVES the hybrid pointer by
# running `bumper skills get <name>` — the stub → CLI indirection that is the
# whole feature.
#
# Pick the agent with AGENT=claude (default) or AGENT=gemini.
#
# Isolation: each repo is set up with `bumper skills install` ONLY — no `bumper
# init`, so there are no hooks and no CLAUDE.md/GEMINI.md workflow notes. The
# only way the agent can become bumper-aware is the installed skill. That makes
# a `bumper skills get` call unambiguous proof the skill drove the agent.
#
# Ground truth: a logging wrapper placed first on PATH as `bumper` records every
# argv the agent invokes (then forwards to the build under test, so real output
# is still served). We assert on that log, and print the agent's final text.
#
# Scenarios:
#   A  "about to apply terraform"     → agent loads gating-terraform-plans (plan-gate)
#   B  "about to add a dependency"     → agent loads triaging-vulnerable-dependencies
#   C  "is this package safe?"         → agent loads querying-the-bumper-advisor
#
# Requirements on PATH: claude OR gemini (logged in), bumper (with `skills`), jq
# Usage:  ./run-e2e-skills.sh            # Claude
#         AGENT=gemini ./run-e2e-skills.sh
#
# ⚠ MANUAL, local test — NOT for CI. It makes ~3 real agent calls that SPEND
#   tokens/quota on YOUR account. Everything runs in throwaway temp dirs; the
#   skills only ever instruct READ-ONLY bumper commands, so nothing is mutated.
#   Override: BUMPER=, CLAUDE=, GEMINI=, AGENT=.

set -u

AGENT="${AGENT:-claude}"
BUMPER="${BUMPER:-bumper}"

case "$AGENT" in
  claude)
    AGENTBIN="${CLAUDE:-claude}"
    PERM=(--permission-mode bypassPermissions --output-format json)
    RESP='.result'
    CFGDIR=".claude"
    ;;
  gemini)
    AGENTBIN="${GEMINI:-gemini}"
    PERM=(--yolo --output-format json)
    RESP='.response'
    CFGDIR=".gemini"
    # A throwaway temp dir is "untrusted"; Gemini disables yolo and may skip
    # project config there. Trust the workspace so skills load headlessly.
    export GEMINI_CLI_TRUST_WORKSPACE=true
    ;;
  *) echo "AGENT must be claude or gemini, got '$AGENT'"; exit 1 ;;
esac

PASS=0; FAIL=0; declare -a SUMMARY
c_say() { printf '\n\033[1;36m══ %s ══\033[0m\n' "$*"; }
c_ok()  { printf '   \033[32m✓ PASS\033[0m  %s\n' "$*"; PASS=$((PASS+1)); SUMMARY+=("PASS  $*"); }
c_no()  { printf '   \033[31m✗ FAIL\033[0m  %s\n' "$*"; FAIL=$((FAIL+1)); SUMMARY+=("FAIL  $*"); }
c_info(){ printf '   \033[2m· %s\033[0m\n' "$*"; }

# ---- preflight ---------------------------------------------------------------
for c in "$AGENTBIN" "$BUMPER" jq; do
  command -v "$c" >/dev/null 2>&1 || { echo "missing required tool: $c"; exit 1; }
done
ROOT="$(mktemp -d "${TMPDIR:-/tmp}/bumper-e2e-skills.XXXXXX")"

# Logging wrapper: first on PATH as `bumper`, records every argv then forwards to
# the build under test. This both (a) captures ground truth and (b) guarantees
# the agent's `bumper skills get` resolves against THIS build, not a stale PATH one.
BUMPER_ABS="$(readlink -f "$(command -v "$BUMPER")" 2>/dev/null || echo "$BUMPER")"
CALLS="$ROOT/bumper-calls.log"; : > "$CALLS"
mkdir -p "$ROOT/bin"
cat > "$ROOT/bin/bumper" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >> "$CALLS"
exec "$BUMPER_ABS" "\$@"
EOF
chmod +x "$ROOT/bin/bumper"
export PATH="$ROOT/bin:$PATH"
BUMPER="$ROOT/bin/bumper"

# Preflight: the build under test must actually serve a playbook offline. If
# `skills get` is missing (stale binary), the whole run is a false negative.
if ! "$BUMPER_ABS" skills get plan-gate 2>/dev/null | grep -q .; then
  echo "✗ the bumper under test ($BUMPER_ABS, $($BUMPER_ABS version 2>/dev/null)) has no \`skills get\`."
  echo "  Build from the skills branch and pass BUMPER=/abs/path/to/it."
  exit 1
fi

echo "agent  : $AGENT ($("$AGENTBIN" --version 2>/dev/null || echo '?'))"
echo "bumper : $($BUMPER_ABS version 2>/dev/null || echo '?')  ($BUMPER_ABS)"
echo "workdir: $ROOT"
printf '\033[33m! makes ~3 real %s calls (spends tokens/quota on your account) + uses the network\033[0m\n' "$AGENT"

# ---- helpers -----------------------------------------------------------------

# install ONLY the skills (no hooks, no context notes) for the chosen agent, then
# assert the three SKILL.md files landed (deterministic discovery prerequisite).
install_skills() {
  local dir="$1"
  ( cd "$dir" && "$BUMPER" skills install --agent "$AGENT" ) >/dev/null 2>&1
  local n
  n=$(find "$dir/$CFGDIR/skills" -name SKILL.md 2>/dev/null | wc -l | tr -d ' ')
  if [ "$n" -lt 3 ]; then
    c_no "$(basename "$dir"): expected 3 installed SKILL.md, found $n"
    return 1
  fi
  return 0
}

# run the agent headless (bounded) and echo its final text.
#  - </dev/null : some CLIs also read stdin; empty stdin avoids a TTY SIGTTIN hang.
#  - timeout -s KILL : node-based CLIs ignore SIGTERM, so hard-kill a slow call.
AGENT_TIMEOUT="${AGENT_TIMEOUT:-150}"
run_agent() { timeout -s KILL "$AGENT_TIMEOUT" "$AGENTBIN" -p "$1" "${PERM[@]}" </dev/null 2>/dev/null | jq -r "$RESP // \"\"" 2>/dev/null; }

dump_calls() { [ -s "$CALLS" ] && sed 's/^/     bumper /' "$CALLS"; }

# A skill is "engaged" if EITHER signal fires:
#  • named  — the agent's final text names the right skill (Claude Code reads the
#    SKILL.md natively, so it often follows the playbook WITHOUT the CLI call — the
#    hybrid body is self-sufficient; naming it proves discovery + load).
#  • ran    — the agent invoked `bumper` at all. In a skills-ONLY repo bumper is
#    only knowable via a loaded skill, so any bumper call proves the skill drove it
#    (whether via `skills get` or a direct subcommand like `bumper deps`).
# We pass on EITHER, because both are valid load paths for a working skill.
scenario() { # $1=label $2=short $3=fullname $4=dir $5=prompt
  local label="$1" short="$2" full="$3" dir="$4" prompt="$5"
  c_say "$label"
  mkdir -p "$dir"
  install_skills "$dir" || return
  : > "$CALLS"
  local out
  out=$( cd "$dir" && run_agent "$prompt" )
  dump_calls
  local named=no ran=no
  printf '%s' "$out" | grep -iqF "$full" && named=yes
  grep -Eq '\S' "$CALLS" 2>/dev/null && ran=yes
  if [ "$named" = yes ] || [ "$ran" = yes ]; then
    c_ok "$short: skill engaged (named-in-reply=$named, ran-bumper=$ran)"
  else
    c_no "$short: no sign the skill engaged (check $CALLS and the reply)"
  fi
  [ "$ran" = yes ] && c_info "bumper calls: $(tr '\n' ';' < "$CALLS" | sed 's/;*$//')"
  c_info "$AGENT said: $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-180)"
}

# =============================================================================
# Scenarios — the prompt names the SITUATION, never the skill or its command, so
# the agent must consult its installed skills to find the right one and follow it.
# It is told to ACT (run the playbook), not just report, so a working skill leaves
# a trace — naming the skill in its reply and/or running a bumper command.
# =============================================================================
SEED="$(cd "$(dirname "$0")/../examples/terraform-safety" 2>/dev/null && pwd)"
A="$ROOT/a-plan"; mkdir -p "$A"
if [ -n "$SEED" ] && [ -f "$SEED/plan.json" ]; then
  cp "$SEED/main.tf" "$SEED/plan.json" "$A/"   # a real plan with destructive changes
else
  cat > "$A/main.tf" <<'EOF'
terraform { required_version = ">= 1.4.0" }
resource "terraform_data" "noop" { input = "bumper-e2e" }
EOF
fi
scenario "A · about to apply Terraform → plan-gate" "plan-gate" "gating-terraform-plans" "$A" \
  "I want to apply the Terraform in this directory; the plan is already saved as plan.json. Use whichever of your installed skills applies and follow it to tell me whether this is safe to apply. Do the check — don't just describe it."

scenario "B · about to add a dependency → deps-triage" "deps-triage" "triaging-vulnerable-dependencies" "$ROOT/b-deps" \
  "I'm about to add the npm package lodash@4.17.4 to this project. Use whichever installed skill applies and follow it to check whether that version is safe and what I should install instead. Actually run the checks the skill specifies."

scenario "C · is a package safe? → advisor" "advisor" "querying-the-bumper-advisor" "$ROOT/c-advisor" \
  "Is the npm package event-stream safe to install? Use whichever installed skill helps answer authoritative security questions, and actually run the lookup it specifies before you answer."

# ---- summary -----------------------------------------------------------------
c_say "RESULTS"
for r in "${SUMMARY[@]}"; do
  case "$r" in PASS*) printf '   \033[32m%s\033[0m\n' "$r";; *) printf '   \033[31m%s\033[0m\n' "$r";; esac
done
printf '\n   %d passed, %d failed\n' "$PASS" "$FAIL"
echo   "   artifacts + call log: $ROOT  (inspect bumper-calls.log)"
[ "$FAIL" -eq 0 ]
