package safety

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// DefaultMaxAge is how long a verdict stays valid; past this, guard asks for a
// re-verify (the plan may predate drift). 0 disables expiry.
const DefaultMaxAge = 24 * time.Hour

// HookInput is the subset of Claude Code's PreToolUse stdin payload we read.
type HookInput struct {
	HookEventName string `json:"hook_event_name"`
	ToolName      string `json:"tool_name"`
	CWD           string `json:"cwd"`
	ToolInput     struct {
		Command string `json:"command"`
	} `json:"tool_input"`
}

// Decision is guard's verdict on a tool call. A zero Decision means "no opinion"
// — guard stays silent and defers to Claude Code's normal permission flow.
type Decision struct {
	Deny   bool
	Reason string
}

// hookOutput is the PreToolUse JSON contract for denying a tool call.
type hookOutput struct {
	HookSpecificOutput hookSpecificOutput `json:"hookSpecificOutput"`
}

type hookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

// Guard reads a PreToolUse payload, decides, and writes a deny decision (if any)
// as the hook's JSON output. It is fail-open on malformed input: a bumper bug
// must never wedge the user's shell. The decision to block is conveyed purely
// through the JSON output, so the process still exits 0.
func Guard(r io.Reader, w io.Writer, now time.Time, maxAge time.Duration) error {
	in, err := readHookInput(r)
	if err != nil {
		return nil // fail-open: can't understand the payload, don't block
	}
	return writeDecision(w, Decide(in, now, maxAge))
}

func readHookInput(r io.Reader) (HookInput, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return HookInput{}, err
	}
	var in HookInput
	if err := json.Unmarshal(b, &in); err != nil {
		return HookInput{}, fmt.Errorf("parsing hook input: %w", err)
	}
	return in, nil
}

func writeDecision(w io.Writer, d Decision) error {
	if !d.Deny {
		return nil // silent allow: defer to the normal permission flow
	}
	enc := json.NewEncoder(w)
	return enc.Encode(hookOutput{HookSpecificOutput: hookSpecificOutput{
		HookEventName:            "PreToolUse",
		PermissionDecision:       "deny",
		PermissionDecisionReason: d.Reason,
	}})
}

// Decide inspects a Bash tool call and blocks unverified terraform apply/destroy.
// Any other tool or command yields a zero (silent) Decision, which is what makes
// guard safe to install as a global, always-on hook.
func Decide(in HookInput, now time.Time, maxAge time.Duration) Decision {
	if in.ToolName != "Bash" {
		return Decision{}
	}
	for _, c := range parseTerraformCommands(in.ToolInput.Command) {
		if d := decideOne(in.CWD, c, now, maxAge); d.Deny {
			return d // first dangerous command in a chain wins
		}
	}
	return Decision{}
}

// tfCommand is a single parsed terraform/tofu invocation.
type tfCommand struct {
	Subcommand  string // apply | destroy | plan | ...
	Chdir       string // -chdir=DIR (global flag)
	CdDir       string // dir set by a preceding `cd DIR &&` in the chain
	PlanFile    string // first positional arg (saved plan) for apply
	HasPlanFile bool
}

var segSplit = regexp.MustCompile(`&&|\|\||;|\n|\|`)

// parseTerraformCommands extracts every terraform/tofu apply|destroy invocation
// from a (possibly chained) shell command, tracking `cd` across the chain.
func parseTerraformCommands(command string) []tfCommand {
	var out []tfCommand
	runningCd := ""
	for _, seg := range segSplit.Split(command, -1) {
		toks := strings.Fields(seg)
		toks = stripPrefixNoise(toks)
		if len(toks) == 0 {
			continue
		}
		if toks[0] == "cd" {
			if len(toks) > 1 {
				runningCd = unquote(toks[1])
			}
			continue
		}
		bin, rest := findTerraform(toks)
		if bin == "" {
			continue
		}
		c := tfCommand{CdDir: runningCd}
		parseTFArgs(rest, &c)
		if c.Subcommand == "apply" || c.Subcommand == "destroy" {
			out = append(out, c)
		}
	}
	return out
}

// stripPrefixNoise drops leading `sudo` and KEY=VALUE env assignments.
func stripPrefixNoise(toks []string) []string {
	for len(toks) > 0 {
		t := toks[0]
		if t == "sudo" || (isEnvAssign(t)) {
			toks = toks[1:]
			continue
		}
		break
	}
	return toks
}

func isEnvAssign(t string) bool {
	i := strings.IndexByte(t, '=')
	if i <= 0 {
		return false
	}
	for _, r := range t[:i] {
		if !(r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// findTerraform returns ("terraform"/"tofu", argsAfterBinary) or ("", nil).
func findTerraform(toks []string) (string, []string) {
	for i, t := range toks {
		switch filepath.Base(t) {
		case "terraform", "tofu":
			return t, toks[i+1:]
		}
	}
	return "", nil
}

// parseTFArgs reads global flags (-chdir), the subcommand, and the first
// positional plan-file argument.
func parseTFArgs(args []string, c *tfCommand) {
	for _, a := range args {
		if strings.HasPrefix(a, "-chdir=") {
			c.Chdir = unquote(strings.TrimPrefix(a, "-chdir="))
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue // any other flag
		}
		if c.Subcommand == "" {
			c.Subcommand = a
			continue
		}
		// First positional after the subcommand is the plan file. Skip stray
		// `key=value` tokens (e.g. a space-separated -var value).
		if !c.HasPlanFile && !strings.Contains(a, "=") {
			c.PlanFile = unquote(a)
			c.HasPlanFile = true
		}
	}
}

func decideOne(cwd string, c tfCommand, now time.Time, maxAge time.Duration) Decision {
	switch c.Subcommand {
	case "destroy":
		return Decision{Deny: true, Reason: destroyMsg}
	case "apply":
		if !c.HasPlanFile {
			return Decision{Deny: true, Reason: bareApplyMsg}
		}
		planPath := resolvePath(effectiveDir(cwd, c), c.PlanFile)
		if !fileExists(planPath) {
			return Decision{Deny: true, Reason: fmt.Sprintf(
				"bumper: cannot verify %q — plan file not found at %s. Generate and verify a saved plan:\n"+
					"  terraform plan -out tfplan\n  bumper verify tfplan\n  terraform apply tfplan",
				c.PlanFile, planPath)}
		}
		sha, err := Sha256File(planPath)
		if err != nil {
			return Decision{Deny: true, Reason: fmt.Sprintf("bumper: could not hash plan %q (%v); run `bumper verify %s` first", c.PlanFile, err, c.PlanFile)}
		}
		store, err := StoreForPlan(planPath)
		if err != nil {
			return Decision{Deny: true, Reason: fmt.Sprintf("bumper: could not locate verdict store for %q (%v); run `bumper verify %s` first", c.PlanFile, err, c.PlanFile)}
		}
		v, ok, err := store.Load(sha)
		if err != nil || !ok {
			return Decision{Deny: true, Reason: notVerifiedMsg(c.PlanFile)}
		}
		if maxAge > 0 && now.Sub(v.VerifiedAt) > maxAge {
			return Decision{Deny: true, Reason: fmt.Sprintf(
				"bumper: verification of %q is stale (verified %s ago, limit %s). Re-run:\n  bumper verify %s",
				c.PlanFile, now.Sub(v.VerifiedAt).Round(time.Minute), maxAge, c.PlanFile)}
		}
		return Decision{} // verified and fresh — allow
	}
	return Decision{}
}

func effectiveDir(cwd string, c tfCommand) string {
	d := cwd
	if c.CdDir != "" {
		d = resolvePath(d, c.CdDir)
	}
	if c.Chdir != "" {
		d = resolvePath(d, c.Chdir)
	}
	return d
}

func resolvePath(base, p string) string {
	if filepath.IsAbs(p) || base == "" {
		return p
	}
	return filepath.Join(base, p)
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

const destroyMsg = "bumper: `terraform destroy` is blocked — it has no reviewable saved plan. " +
	"Run a reviewed destroy instead:\n" +
	"  terraform plan -destroy -out tfplan\n  bumper verify tfplan\n  terraform apply tfplan"

const bareApplyMsg = "bumper: bare `terraform apply` is blocked — it re-plans and applies in one step, " +
	"so nothing was reviewed. Use a saved plan:\n" +
	"  terraform plan -out tfplan\n  bumper verify tfplan\n  terraform apply tfplan"

func notVerifiedMsg(planFile string) string {
	return fmt.Sprintf("bumper: plan %q has not been verified. Run:\n  bumper verify %s\n"+
		"then retry the apply. If bumper reports high/critical findings, fix them — or record an explicit "+
		"override with `bumper verify --accept %s`.", planFile, planFile, planFile)
}
