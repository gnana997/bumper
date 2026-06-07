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

	if a, err := MergeAdvisorMCP(path, "https://advisor.bumper.sh", AgentClaude); err != nil || a != Updated {
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

	if a, err := MergeHook(path, "bumper", AgentClaude); err != nil || a != Updated {
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

	if a, err := MergeHook(path, "bumper", AgentClaude); err != nil || a != Unchanged {
		t.Errorf("re-merge: action=%v err=%v, want unchanged", a, err)
	}
}

func TestMergeHookCommandIncludesGuard(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if _, err := MergeHook(path, "/opt/bumper", AgentClaude); err != nil {
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
	if _, err := MergeAdvisorMCP(path, "https://advisor.bumper.sh", AgentClaude); err == nil {
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
	if _, err := MergeAdvisorMCP(path, "https://advisor.bumper.sh", AgentClaude); err != nil {
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

func TestPlanAugment(t *testing.T) {
	dir := t.TempDir()
	env := Env{Bin: "bumper", Cwd: dir, Home: t.TempDir()}
	steps := Plan(Options{
		Agent: AgentAugment, HookScope: ScopeProject, Terraform: true, Deps: true,
		Advisor: true, AdvisorScope: ScopeProject, Env: env,
	})

	// All hook + MCP steps target the single .augment/settings.json; notes go to AGENTS.md.
	wantAugment := filepath.Join(dir, ".augment", "settings.json")
	sawHook, sawMCP, sawAgentsMd := false, false, false
	for _, s := range steps {
		switch {
		case strings.Contains(s.Title, "guard") || strings.Contains(s.Title, "dependency hooks"):
			if s.Path != wantAugment {
				t.Errorf("hook step %q path = %q, want %q", s.Title, s.Path, wantAugment)
			}
			sawHook = true
		case strings.Contains(s.Title, "advisor MCP"):
			if s.Path != wantAugment {
				t.Errorf("advisor MCP path = %q, want co-located %q", s.Path, wantAugment)
			}
			sawMCP = true
		case strings.Contains(s.Title, "AGENTS.md"):
			sawAgentsMd = true
		}
		if strings.Contains(s.Path, ".mcp.json") || strings.Contains(s.Path, ".claude") {
			t.Errorf("augment plan must not touch claude paths, got %q", s.Path)
		}
	}
	if !sawHook || !sawMCP || !sawAgentsMd {
		t.Fatalf("augment plan missing steps: hook=%v mcp=%v agentsmd=%v", sawHook, sawMCP, sawAgentsMd)
	}

	// Apply and verify the baked commands carry --client=augment + the launch-process matcher.
	for _, s := range steps {
		if _, err := s.Run(); err != nil {
			t.Fatalf("apply %q: %v", s.Title, err)
		}
	}
	b, err := os.ReadFile(wantAugment)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{"launch-process", "guard --client=augment", "deps guard --client=augment", "deps watch --client=augment", "bumper-advisor", "advisor.bumper.sh/mcp"} {
		if !strings.Contains(got, want) {
			t.Errorf(".augment/settings.json missing %q\n--- got ---\n%s", want, got)
		}
	}
	if strings.Contains(got, `"matcher": "Bash"`) {
		t.Error("augment config should not contain a Bash matcher")
	}
}

func TestAgentBasics(t *testing.T) {
	if AgentAugment.ShellTool() != "launch-process" || AgentClaude.ShellTool() != "Bash" || AgentGemini.ShellTool() != "run_shell_command" {
		t.Error("ShellTool mapping wrong")
	}
	// Event keys: Claude/Augment use PreToolUse/PostToolUse; Gemini uses BeforeTool/AfterTool.
	if AgentClaude.PreToolEvent() != "PreToolUse" || AgentClaude.PostToolEvent() != "PostToolUse" {
		t.Error("claude event keys wrong")
	}
	if AgentGemini.PreToolEvent() != "BeforeTool" || AgentGemini.PostToolEvent() != "AfterTool" {
		t.Error("gemini event keys wrong")
	}
	for _, ok := range []string{"claude", "augment", "gemini"} {
		if _, valid := ParseAgent(ok); !valid {
			t.Errorf("ParseAgent(%q) should be valid", ok)
		}
	}
	if _, ok := ParseAgent("bogus"); ok {
		t.Error("ParseAgent(bogus) should be invalid")
	}
}

func TestPlanGemini(t *testing.T) {
	dir := t.TempDir()
	env := Env{Bin: "bumper", Cwd: dir, Home: t.TempDir()}
	steps := Plan(Options{
		Agent: AgentGemini, HookScope: ScopeProject, Terraform: true, Deps: true,
		Advisor: true, AdvisorScope: ScopeProject, Env: env,
	})

	// All hook + MCP steps target the single .gemini/settings.json; notes go to GEMINI.md.
	wantGemini := filepath.Join(dir, ".gemini", "settings.json")
	sawHook, sawMCP, sawGeminiMd := false, false, false
	for _, s := range steps {
		switch {
		case strings.Contains(s.Title, "guard") || strings.Contains(s.Title, "dependency hooks"):
			if s.Path != wantGemini {
				t.Errorf("hook step %q path = %q, want %q", s.Title, s.Path, wantGemini)
			}
			sawHook = true
		case strings.Contains(s.Title, "advisor MCP"):
			if s.Path != wantGemini {
				t.Errorf("advisor MCP path = %q, want co-located %q", s.Path, wantGemini)
			}
			sawMCP = true
		case strings.Contains(s.Title, "GEMINI.md"):
			sawGeminiMd = true
		}
		if strings.Contains(s.Path, ".mcp.json") || strings.Contains(s.Path, ".claude") || strings.Contains(s.Path, ".augment") {
			t.Errorf("gemini plan must not touch claude/augment paths, got %q", s.Path)
		}
	}
	if !sawHook || !sawMCP || !sawGeminiMd {
		t.Fatalf("gemini plan missing steps: hook=%v mcp=%v geminimd=%v", sawHook, sawMCP, sawGeminiMd)
	}

	// Apply and verify the Gemini-specific output: run_shell_command matcher,
	// BeforeTool/AfterTool event keys, --client=gemini, and the httpUrl MCP shape.
	for _, s := range steps {
		if _, err := s.Run(); err != nil {
			t.Fatalf("apply %q: %v", s.Title, err)
		}
	}
	got := read(t, wantGemini)
	for _, want := range []string{
		"run_shell_command", "BeforeTool", "AfterTool",
		"guard --client=gemini", "deps guard --client=gemini", "deps watch --client=gemini",
		"bumper-advisor", "httpUrl", "advisor.bumper.sh/mcp",
	} {
		if !strings.Contains(got, want) {
			t.Errorf(".gemini/settings.json missing %q\n--- got ---\n%s", want, got)
		}
	}
	for _, unwant := range []string{`"matcher": "Bash"`, "PreToolUse", "PostToolUse", `"type": "http"`} {
		if strings.Contains(got, unwant) {
			t.Errorf("gemini config should not contain %q\n--- got ---\n%s", unwant, got)
		}
	}
}

func TestPlanSkills(t *testing.T) {
	env := Env{Bin: "bumper", Cwd: "/proj", Home: "/home/u"}

	// Claude reads skills → the step is planned at the hook scope.
	steps := Plan(Options{Agent: AgentClaude, HookScope: ScopeProject, Skills: true, Env: env})
	var claudePath string
	for _, s := range steps {
		if s.Title == "install agent skills · project" {
			claudePath = s.Path
		}
	}
	if claudePath != "/proj/.claude/skills" {
		t.Errorf("claude skills step path = %q, want /proj/.claude/skills", claudePath)
	}

	// Gemini also reads skills.
	gem := Plan(Options{Agent: AgentGemini, HookScope: ScopeUser, Skills: true, Env: env})
	var gemFound bool
	for _, s := range gem {
		if s.Title == "install agent skills · user" {
			gemFound = true
			if s.Path != "/home/u/.gemini/skills" {
				t.Errorf("gemini skills step path = %q", s.Path)
			}
		}
	}
	if !gemFound {
		t.Error("gemini plan missing skills step")
	}

	// Augment does not read SKILL.md → no skills step even with Skills:true.
	aug := Plan(Options{Agent: AgentAugment, HookScope: ScopeProject, Skills: true, Env: env})
	for _, s := range aug {
		if s.Title == "install agent skills · project" {
			t.Error("augment plan should not include a skills step")
		}
	}

	// Skills:false omits the step entirely.
	off := Plan(Options{Agent: AgentClaude, HookScope: ScopeProject, Skills: false, Env: env})
	for _, s := range off {
		if s.Title == "install agent skills · project" {
			t.Error("Skills:false should omit the skills step")
		}
	}
}

func TestSupportsSkillsAndDir(t *testing.T) {
	if !SupportsSkills(AgentClaude) || !SupportsSkills(AgentGemini) {
		t.Error("claude and gemini should support skills")
	}
	if SupportsSkills(AgentAugment) {
		t.Error("augment should not support skills")
	}
	env := Env{Cwd: "/proj", Home: "/home/u"}
	if d := SkillsDir(AgentClaude, ScopeProject, env); d != "/proj/.claude/skills" {
		t.Errorf("project skills dir = %q", d)
	}
	if d := SkillsDir(AgentGemini, ScopeUser, env); d != "/home/u/.gemini/skills" {
		t.Errorf("user skills dir = %q", d)
	}
	if d := SkillsDir(AgentClaude, ScopeNone, env); d != "" {
		t.Errorf("none scope should yield empty dir, got %q", d)
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
