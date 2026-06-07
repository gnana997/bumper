package deps

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
)

// hookInput is the subset of Claude Code's PreToolUse/PostToolUse stdin we read.
type hookInput struct {
	ToolName  string `json:"tool_name"`
	CWD       string `json:"cwd"`
	ToolInput struct {
		Command string `json:"command"`
	} `json:"tool_input"`
}

func readHookInput(r io.Reader) (hookInput, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return hookInput{}, err
	}
	var in hookInput
	if err := json.Unmarshal(b, &in); err != nil {
		return hookInput{}, err
	}
	return in, nil
}

// Guard is the PreToolUse pre-install hook: it blocks an install of a
// known-MALICIOUS package, with an informative reason so the agent self-corrects.
// Fail-open throughout — a bumper or network error must never wedge the shell.
// shellTool is the host agent's shell-execution tool name (e.g. "Bash" for Claude
// Code, "launch-process" for Augment); the hook is a no-op for any other tool.
func Guard(r io.Reader, w io.Writer, client *Client, shellTool string) error {
	in, err := readHookInput(r)
	if err != nil || in.ToolName != shellTool {
		return nil
	}
	var named []Dep
	for _, c := range parseInstallCommands(in.ToolInput.Command) {
		for _, p := range c.packages {
			named = append(named, Dep{Ecosystem: c.ecosystem, Package: p})
		}
	}
	if len(named) == 0 {
		return nil // bare/manifest install or non-install command — defer to post-install
	}
	res, err := client.MalwareCheck(named)
	if err != nil || res == nil || res.MaliciousCount == 0 || len(res.Results) == 0 {
		return nil // advisor down or nothing flagged — fail-open
	}
	return writeJSON(w, map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       "deny",
			"permissionDecisionReason": buildDenyReason(res),
		},
	})
}

// Watch is the PostToolUse post-install hook (model B): after an install, it runs
// the scan itself, stays silent when clean, and on findings injects context that
// nudges the main agent to spawn a triage subagent. Non-blocking, fail-open.
// shellTool is the host agent's shell-execution tool name (see Guard).
func Watch(r io.Reader, w io.Writer, client *Client, fallbackDir, shellTool string) error {
	in, err := readHookInput(r)
	if err != nil || in.ToolName != shellTool {
		return nil
	}
	if !isInstallish(in.ToolInput.Command) {
		return nil
	}
	dir := in.CWD
	if dir == "" {
		dir = fallbackDir
	}
	deps := CollectLockfileDeps(dir)
	if len(deps) == 0 {
		return nil
	}
	res, err := client.Scan(deps, true)
	if err != nil || res == nil {
		return nil // fail-open
	}
	if res.VulnerableCount == 0 && res.MalwareCount == 0 {
		return nil // clean → silent, zero friction
	}
	return writeJSON(w, map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":     "PostToolUse",
			"additionalContext": buildWatchContext(res),
		},
	})
}

func writeJSON(w io.Writer, v any) error {
	return json.NewEncoder(w).Encode(v)
}

func buildDenyReason(res *MalwareResult) string {
	var b strings.Builder
	b.WriteString("bumper blocked this install — KNOWN-MALICIOUS package(s) detected.\n\n")
	for _, hit := range res.Results {
		for _, a := range hit.Advisories {
			b.WriteString(fmt.Sprintf("  %s (%s) — %s: %q\n", hit.Package, hit.Ecosystem, a.ID, a.Summary))
			if len(a.Refs) > 0 && a.Refs[0].URL != "" {
				b.WriteString("    advisory: " + a.Refs[0].URL + "\n")
			}
		}
	}
	b.WriteString("\nMalicious packages run attacker code at install time, so this is a hard stop.\n")
	b.WriteString("What to do:\n")
	b.WriteString("  • Do NOT install these package(s).\n")
	b.WriteString("  • If a name looks like a typo of a real package, install the correct name.\n")
	b.WriteString("  • Otherwise pick a maintained, widely-used alternative.\n")
	return b.String()
}

func buildWatchContext(res *ScanResult) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf(
		"bumper: the install you just ran left %d vulnerable and %d malicious package(s) in the dependency tree.\n\n",
		res.VulnerableCount, res.MalwareCount))
	shown := 0
	for _, f := range res.Findings {
		if shown >= 12 {
			b.WriteString("  …\n")
			break
		}
		if len(f.Malware) > 0 {
			b.WriteString(fmt.Sprintf("  MALICIOUS  %s@%s (%s) — %s\n", f.Package, f.Version, f.Ecosystem, f.Malware[0].ID))
			shown++
			continue
		}
		if len(f.Vulns) > 0 {
			v := f.Vulns[0]
			fix := "no fix yet"
			if v.FixedVersion != "" {
				fix = "fix → " + v.FixedVersion
			}
			b.WriteString(fmt.Sprintf("  %s  %s@%s (%s) — %s (%s)\n",
				strings.ToUpper(v.Severity), f.Package, f.Version, f.Ecosystem, v.ID, fix))
			shown++
		}
	}
	b.WriteString("\nSpawn a subagent (Task) to run `bumper deps` in this directory, analyze these findings " +
		"(use get_vuln via the bumper-advisor MCP for the ones you fix), and apply or propose remediations — " +
		"keep this triage out of the main thread.\n")
	return b.String()
}

// --- install-command parsing -------------------------------------------------

var segSplit = regexp.MustCompile(`&&|\|\||;|\n|\|`)

type installCmd struct {
	ecosystem string
	packages  []string // names only, version stripped
}

// parseInstallCommands extracts every explicit `install <pkg>` invocation (with
// named packages) from a possibly-chained shell command.
func parseInstallCommands(command string) []installCmd {
	var out []installCmd
	for _, seg := range segSplit.Split(command, -1) {
		eco, args, ok := findInstall(strings.Fields(seg))
		if !ok {
			continue
		}
		var pkgs []string
		for i := 0; i < len(args); i++ {
			a := args[i]
			if strings.HasPrefix(a, "-") {
				if valueFlag(a) {
					i++ // skip the flag's value (e.g. -r requirements.txt)
				}
				continue
			}
			if name := packageName(eco, a); name != "" {
				pkgs = append(pkgs, name)
			}
		}
		if len(pkgs) > 0 {
			out = append(out, installCmd{eco, pkgs})
		}
	}
	return out
}

// isInstallish reports whether the command contains any package-manager install
// (named OR bare) — used by the post-install watch hook.
func isInstallish(command string) bool {
	for _, seg := range segSplit.Split(command, -1) {
		if _, _, ok := findInstall(strings.Fields(seg)); ok {
			return true
		}
	}
	return false
}

// findInstall recognizes a manager + install verb in one segment and returns the
// ecosystem and the args after the verb.
func findInstall(toks []string) (ecosystem string, args []string, ok bool) {
	toks = stripNoise(toks)
	if len(toks) == 0 {
		return "", nil, false
	}
	bin := filepath.Base(toks[0])
	rest := toks[1:]
	var verbs map[string]bool
	switch bin {
	case "npm", "pnpm", "bun":
		ecosystem, verbs = "npm", set("install", "i", "add")
	case "yarn":
		ecosystem, verbs = "npm", set("add")
	case "pip", "pip3":
		ecosystem, verbs = "PyPI", set("install")
	case "pipenv":
		ecosystem, verbs = "PyPI", set("install")
	case "poetry":
		ecosystem, verbs = "PyPI", set("add")
	case "uv":
		if len(rest) >= 1 && rest[0] == "pip" {
			ecosystem, rest, verbs = "PyPI", rest[1:], set("install")
		} else {
			ecosystem, verbs = "PyPI", set("add")
		}
	case "python", "python3":
		if len(rest) >= 2 && rest[0] == "-m" && rest[1] == "pip" {
			ecosystem, rest, verbs = "PyPI", rest[2:], set("install")
		} else {
			return "", nil, false
		}
	case "go":
		ecosystem, verbs = "Go", set("get")
	case "cargo":
		ecosystem, verbs = "crates.io", set("add")
	case "gem":
		ecosystem, verbs = "RubyGems", set("install")
	case "bundle", "bundler":
		ecosystem, verbs = "RubyGems", set("add")
	default:
		return "", nil, false
	}
	for i, t := range rest {
		if verbs[t] {
			return ecosystem, rest[i+1:], true
		}
	}
	return "", nil, false
}

// stripNoise drops leading `sudo` and KEY=VALUE env assignments.
func stripNoise(toks []string) []string {
	for len(toks) > 0 {
		if toks[0] == "sudo" || isEnvAssign(toks[0]) {
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

// valueFlag reports whether a flag consumes the following token as its value
// (so we don't mistake that value, e.g. a requirements file, for a package).
func valueFlag(f string) bool {
	switch f {
	case "-r", "--requirement", "-c", "--constraint", "-e", "--editable",
		"-i", "--index-url", "--extra-index-url", "-t", "--target",
		"-v", "--version", "--registry", "--features":
		return true
	}
	return false
}

// packageName strips version specifiers per ecosystem, returning the bare name
// (or "" for paths/urls). Over-extraction is harmless: a non-package name simply
// isn't in the malware feed, so it never causes a false block.
func packageName(ecosystem, tok string) string {
	tok = unquote(tok)
	if tok == "" || tok == "." || strings.Contains(tok, "://") {
		return ""
	}
	switch ecosystem {
	case "npm":
		if strings.HasPrefix(tok, "git+") || strings.HasPrefix(tok, "file:") {
			return ""
		}
		if strings.HasPrefix(tok, "@") { // @scope/name[@version]
			if i := strings.Index(tok[1:], "@"); i >= 0 {
				return tok[:i+1]
			}
			return tok
		}
		if i := strings.Index(tok, "@"); i >= 0 {
			return tok[:i]
		}
		return tok
	case "PyPI":
		// name is the leading run of [A-Za-z0-9._-]; cut at the first other char.
		i := strings.IndexFunc(tok, func(r rune) bool {
			return !(r == '.' || r == '_' || r == '-' ||
				(r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
		})
		if i >= 0 {
			tok = tok[:i]
		}
		return tok
	case "Go":
		if i := strings.Index(tok, "@"); i >= 0 {
			tok = tok[:i]
		}
		if strings.HasPrefix(tok, ".") || strings.HasPrefix(tok, "/") {
			return ""
		}
		return tok
	default: // crates.io, RubyGems
		if i := strings.Index(tok, "@"); i >= 0 {
			tok = tok[:i]
		}
		return tok
	}
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, it := range items {
		m[it] = true
	}
	return m
}
