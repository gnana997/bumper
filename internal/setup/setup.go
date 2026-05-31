// Package setup implements `bumper init`: wiring bumper into a coding agent
// (Claude Code) so its safety checks are always available and its apply-guard is
// always on. It registers the MCP server, installs the PreToolUse guard hook,
// ignores the verdict store, and drops a workflow note into CLAUDE.md.
//
// Every mutation is merge-not-clobber and idempotent: existing config is
// preserved, and re-running init changes nothing once wired. User-scope files
// are written atomically (temp + rename) with a one-time backup.
package setup

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Action describes what a single file mutation did.
type Action int

const (
	Unchanged Action = iota
	Created
	Updated
)

func (a Action) String() string {
	switch a {
	case Created:
		return "created"
	case Updated:
		return "updated"
	default:
		return "unchanged"
	}
}

// BinPath returns the command to invoke bumper in generated config: the bare
// "bumper" when it is on PATH (clean, relocatable), else the absolute path to
// the running binary.
func BinPath() string {
	if p, err := exec.LookPath("bumper"); err == nil {
		if abs, err := filepath.Abs(p); err == nil {
			return shellWord(abs, "bumper")
		}
	}
	if exe, err := os.Executable(); err == nil {
		return shellWord(exe, exe)
	}
	return "bumper"
}

// shellWord returns name unless it is plain enough to use bare; the absolute
// path is quoted if it contains spaces.
func shellWord(abs, name string) string {
	if name == "bumper" {
		return "bumper"
	}
	if strings.ContainsAny(abs, " \t") {
		return `"` + abs + `"`
	}
	return abs
}

// MergeMCP registers the bumper MCP server in an .mcp.json / ~/.claude.json file.
func MergeMCP(path, binPath string) (Action, error) {
	m, existed, err := loadJSONMap(path)
	if err != nil {
		return Unchanged, err
	}
	servers := childMap(m, "mcpServers")
	desired := map[string]any{
		"command": unquoteFirst(binPath),
		"args":    []any{"mcp"},
	}
	if cur, ok := servers["bumper"]; ok && jsonEqual(cur, desired) {
		return Unchanged, nil
	}
	servers["bumper"] = desired
	m["mcpServers"] = servers
	if err := writeJSONMap(path, m, existed); err != nil {
		return Unchanged, err
	}
	return actionFor(existed), nil
}

// unquoteFirst strips surrounding quotes added for shell use; the MCP "command"
// field is exec'd directly (not shell-parsed), so it must be the raw path.
func unquoteFirst(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// MergeHook installs the guard as a PreToolUse Bash hook in a settings.json file.
func MergeHook(path, binPath string) (Action, error) {
	m, existed, err := loadJSONMap(path)
	if err != nil {
		return Unchanged, err
	}
	hooks := childMap(m, "hooks")
	pre := childSlice(hooks, "PreToolUse")

	if hookInstalled(pre) {
		return Unchanged, nil
	}
	pre = append(pre, map[string]any{
		"matcher": "Bash",
		"hooks": []any{map[string]any{
			"type":    "command",
			"command": binPath + " guard",
		}},
	})
	hooks["PreToolUse"] = pre
	m["hooks"] = hooks
	if err := writeJSONMap(path, m, existed); err != nil {
		return Unchanged, err
	}
	return actionFor(existed), nil
}

// hookInstalled reports whether a bumper guard hook is already present.
func hookInstalled(pre []any) bool {
	for _, e := range pre {
		em, ok := e.(map[string]any)
		if !ok {
			continue
		}
		inner, _ := em["hooks"].([]any)
		for _, h := range inner {
			hm, ok := h.(map[string]any)
			if !ok {
				continue
			}
			if cmd, _ := hm["command"].(string); strings.Contains(cmd, "bumper") && strings.Contains(cmd, "guard") {
				return true
			}
		}
	}
	return false
}

// gitignoreEntry is the verdict store; it is machine- and time-specific.
const gitignoreEntry = ".bumper/"

// EnsureGitignore adds the verdict-store directory to .gitignore if absent.
func EnsureGitignore(path string) (Action, error) {
	b, err := os.ReadFile(path)
	existed := err == nil
	if err != nil && !os.IsNotExist(err) {
		return Unchanged, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == gitignoreEntry {
			return Unchanged, nil
		}
	}
	out := string(b)
	if existed && len(b) > 0 && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	out += "# bumper verdict store (machine-specific)\n" + gitignoreEntry + "\n"
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		return Unchanged, err
	}
	return actionFor(existed), nil
}

const claudeMdMarker = "<!-- bumper-workflow -->"

// claudeMdStanza tells the agent the required plan→verify→apply flow so it
// cooperates rather than just hitting the guard.
const claudeMdStanza = claudeMdMarker + `
## Terraform safety (bumper)

Before applying any Terraform, use the saved-plan flow so bumper can verify it:

    terraform plan -out tfplan
    bumper verify tfplan      # scans the plan; blocks on high/critical findings
    terraform apply tfplan

Bare ` + "`terraform apply`" + ` and ` + "`terraform destroy`" + ` are blocked by the bumper guard
hook — they have no reviewable saved plan. To destroy, use:

    terraform plan -destroy -out tfplan && bumper verify tfplan && terraform apply tfplan

You can also call the bumper MCP ` + "`scan_plan`" + ` tool on a plan before applying.
<!-- /bumper-workflow -->
`

// EnsureClaudeMd appends the bumper workflow stanza if its marker is absent.
func EnsureClaudeMd(path string) (Action, error) {
	b, err := os.ReadFile(path)
	existed := err == nil
	if err != nil && !os.IsNotExist(err) {
		return Unchanged, err
	}
	if strings.Contains(string(b), claudeMdMarker) {
		return Unchanged, nil
	}
	out := string(b)
	if existed && len(b) > 0 && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	if existed && len(b) > 0 {
		out += "\n"
	}
	out += claudeMdStanza
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		return Unchanged, err
	}
	return actionFor(existed), nil
}

// ---- generic JSON merge helpers -------------------------------------------

func loadJSONMap(path string) (m map[string]any, existed bool, err error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]any{}, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return map[string]any{}, true, nil
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, true, fmt.Errorf("%s is not valid JSON (refusing to overwrite): %w", path, err)
	}
	return m, true, nil
}

// writeJSONMap writes m as indented JSON, creating parent dirs. Existing files
// are updated atomically (temp + rename) with a one-time .bumper-bak backup so a
// crash mid-write can never corrupt user config.
func writeJSONMap(path string, m map[string]any, existed bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if !existed {
		return os.WriteFile(path, b, 0o644)
	}
	if orig, err := os.ReadFile(path); err == nil {
		_ = os.WriteFile(path+".bumper-bak", orig, 0o644)
	}
	tmp := path + ".bumper-tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func childMap(parent map[string]any, key string) map[string]any {
	if c, ok := parent[key].(map[string]any); ok {
		return c
	}
	return map[string]any{}
}

func childSlice(parent map[string]any, key string) []any {
	if c, ok := parent[key].([]any); ok {
		return c
	}
	return nil
}

func jsonEqual(a, b any) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(ab) == string(bb)
}

func actionFor(existed bool) Action {
	if existed {
		return Updated
	}
	return Created
}
