package setup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	return m
}

func TestMergeAdvisorPreservesOtherServers(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".mcp.json")
	seed := `{"mcpServers":{"other":{"command":"other-srv"}},"someTopLevel":42}`
	if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}

	if a, err := MergeAdvisorMCP(path, "https://advisor.bumper.sh"); err != nil || a != Updated {
		t.Fatalf("merge: action=%v err=%v, want updated", a, err)
	}
	m := readJSON(t, path)
	if m["someTopLevel"].(float64) != 42 {
		t.Error("top-level key not preserved")
	}
	servers := m["mcpServers"].(map[string]any)
	if _, ok := servers["other"]; !ok {
		t.Error("existing 'other' server was clobbered")
	}
	if _, ok := servers["bumper-advisor"]; !ok {
		t.Error("advisor server not added")
	}
}

func TestMergeHookCreateIdempotentPreserve(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".claude", "settings.json")
	// Seed with an unrelated PreToolUse hook + an unrelated top-level setting.
	seed := `{"model":"opus","hooks":{"PreToolUse":[{"matcher":"Write","hooks":[{"type":"command","command":"my-linter"}]}]}}`
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}

	if a, err := MergeHook(path, "bumper"); err != nil || a != Updated {
		t.Fatalf("merge: action=%v err=%v, want updated", a, err)
	}
	m := readJSON(t, path)
	if m["model"] != "opus" {
		t.Error("top-level 'model' not preserved")
	}
	pre := m["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(pre) != 2 {
		t.Fatalf("PreToolUse len = %d, want 2 (existing + bumper)", len(pre))
	}
	if !hookInstalled(pre) {
		t.Error("bumper guard hook not detected after merge")
	}
	// The unrelated linter hook must survive.
	foundLinter := false
	for _, e := range pre {
		inner := e.(map[string]any)["hooks"].([]any)
		for _, h := range inner {
			if c, _ := h.(map[string]any)["command"].(string); c == "my-linter" {
				foundLinter = true
			}
		}
	}
	if !foundLinter {
		t.Error("unrelated 'my-linter' hook was clobbered")
	}

	if a, err := MergeHook(path, "bumper"); err != nil || a != Unchanged {
		t.Errorf("re-merge: action=%v err=%v, want unchanged", a, err)
	}
}

func TestMergeHookCommandIncludesGuard(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if _, err := MergeHook(path, "/opt/bumper"); err != nil {
		t.Fatal(err)
	}
	m := readJSON(t, path)
	pre := m["hooks"].(map[string]any)["PreToolUse"].([]any)
	entry := pre[0].(map[string]any)
	if entry["matcher"] != "Bash" {
		t.Errorf("matcher = %v, want Bash", entry["matcher"])
	}
	cmd := entry["hooks"].([]any)[0].(map[string]any)["command"].(string)
	if cmd != "/opt/bumper guard" {
		t.Errorf("command = %q, want '/opt/bumper guard'", cmd)
	}
}

func TestRefuseInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".mcp.json")
	if err := os.WriteFile(path, []byte("{ this is not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := MergeAdvisorMCP(path, "https://advisor.bumper.sh"); err == nil {
		t.Error("expected refusal to overwrite invalid JSON")
	}
	// The bad file must be left untouched.
	b, _ := os.ReadFile(path)
	if string(b) != "{ this is not json" {
		t.Error("invalid JSON file was modified")
	}
}

func TestUpdateIsAtomicNoStrayFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".mcp.json")
	os.WriteFile(path, []byte(`{"mcpServers":{}}`), 0o644)
	if _, err := MergeAdvisorMCP(path, "https://advisor.bumper.sh"); err != nil {
		t.Fatal(err)
	}
	// The atomic temp+rename must leave no .bumper-bak or .bumper-tmp behind.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".bumper-bak") || strings.HasSuffix(e.Name(), ".bumper-tmp") {
			t.Errorf("stray file left behind: %s", e.Name())
		}
	}
	// And the update actually landed.
	m := readJSON(t, path)
	if _, ok := m["mcpServers"].(map[string]any)["bumper-advisor"]; !ok {
		t.Error("advisor server not written")
	}
}

func TestEnsureGitignore(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".gitignore")
	if err := os.WriteFile(path, []byte("node_modules\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if a, err := EnsureGitignore(path); err != nil || a != Updated {
		t.Fatalf("action=%v err=%v, want updated", a, err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "node_modules") || !strings.Contains(string(b), ".bumper/") {
		t.Errorf("gitignore = %q, want both existing + .bumper/", b)
	}
	if a, _ := EnsureGitignore(path); a != Unchanged {
		t.Errorf("re-run action=%v, want unchanged", a)
	}
}

func TestPlanScopePaths(t *testing.T) {
	env := Env{Bin: "bumper", Cwd: "/proj", Home: "/home/u"}

	steps := Plan(Options{
		HookScope: ScopeUser, Terraform: true, Deps: true,
		Advisor: true, AdvisorScope: ScopeProject, Env: env,
	})
	got := map[string]string{}
	for _, s := range steps {
		got[s.Title] = s.Path
	}
	if p := got["register advisor MCP · project"]; p != "/proj/.mcp.json" {
		t.Errorf("project advisor MCP path = %q", p)
	}
	if p := got["install terraform guard · user"]; p != "/home/u/.claude/settings.json" {
		t.Errorf("user terraform hook path = %q", p)
	}
	if p := got["install dependency hooks · user"]; p != "/home/u/.claude/settings.json" {
		t.Errorf("user deps hook path = %q", p)
	}
	// gitignore + both CLAUDE.md notes present (Terraform + Deps wired).
	if _, ok := got["ignore .bumper/ verdict store"]; !ok {
		t.Error("plan missing gitignore step")
	}
	if _, ok := got["note terraform workflow in CLAUDE.md"]; !ok {
		t.Error("plan missing terraform CLAUDE.md step")
	}
	if _, ok := got["note deps workflow in CLAUDE.md"]; !ok {
		t.Error("plan missing deps CLAUDE.md step")
	}

	// RelPath collapses project + home paths.
	mcp := Step{Path: "/proj/.mcp.json"}
	if r := mcp.RelPath(env); r != ".mcp.json" {
		t.Errorf("RelPath project = %q, want .mcp.json", r)
	}
	hook := Step{Path: "/home/u/.claude/settings.json"}
	if r := hook.RelPath(env); r != "~/.claude/settings.json" {
		t.Errorf("RelPath home = %q, want ~/.claude/settings.json", r)
	}
}

func TestParseScope(t *testing.T) {
	for _, ok := range []string{"project", "user", "none"} {
		if _, valid := ParseScope(ok); !valid {
			t.Errorf("ParseScope(%q) should be valid", ok)
		}
	}
	if _, valid := ParseScope("bogus"); valid {
		t.Error("ParseScope(bogus) should be invalid")
	}
	if ScopeProject.Next() != ScopeUser || ScopeUser.Next() != ScopeNone || ScopeNone.Next() != ScopeProject {
		t.Error("Scope.Next cycle is wrong")
	}
}

func TestEnsureClaudeMd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "CLAUDE.md")
	if a, err := EnsureClaudeMd(path); err != nil || a != Created {
		t.Fatalf("action=%v err=%v, want created", a, err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "bumper verify tfplan") {
		t.Error("stanza missing the verify workflow")
	}
	if a, _ := EnsureClaudeMd(path); a != Unchanged {
		t.Errorf("re-run action=%v, want unchanged", a)
	}
}
