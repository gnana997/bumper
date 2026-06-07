package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func TestMergeDepsHooks(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".claude", "settings.json")
	act, err := MergeDepsHooks(path, "bumper")
	if err != nil || act != Created {
		t.Fatalf("first MergeDepsHooks = %v, %v; want Created", act, err)
	}
	s := read(t, path)
	if !strings.Contains(s, "bumper deps guard") {
		t.Error("PreToolUse deps guard not installed")
	}
	if !strings.Contains(s, "bumper deps watch") {
		t.Error("PostToolUse deps watch not installed")
	}
	if !strings.Contains(s, "PreToolUse") || !strings.Contains(s, "PostToolUse") {
		t.Error("both hook events should be present")
	}
	// idempotent
	act, err = MergeDepsHooks(path, "bumper")
	if err != nil || act != Unchanged {
		t.Errorf("second MergeDepsHooks = %v, %v; want Unchanged", act, err)
	}
}

// The terraform guard and the deps guard must coexist, and installing one must
// never trick the other's "already installed?" check.
func TestGuardAndDepsHooksCoexist(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".claude", "settings.json")
	if _, err := MergeDepsHooks(path, "bumper"); err != nil {
		t.Fatal(err)
	}
	// deps guard present but NOT terraform guard — MergeHook must still install it.
	act, err := MergeHook(path, "bumper")
	if err != nil || act != Updated {
		t.Fatalf("MergeHook after deps = %v, %v; want Updated (tf guard must still install)", act, err)
	}
	s := read(t, path)
	if !strings.Contains(s, `"bumper guard"`) {
		t.Error("terraform guard not installed")
	}
	if !strings.Contains(s, "bumper deps guard") {
		t.Error("deps guard lost")
	}
}

func TestMergeAdvisorMCP(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".mcp.json")
	if _, err := MergeAdvisorMCP(path, "https://advisor.bumper.sh"); err != nil {
		t.Fatal(err)
	}
	s := read(t, path)
	if !strings.Contains(s, "bumper-advisor") || !strings.Contains(s, "https://advisor.bumper.sh/mcp") {
		t.Errorf("advisor MCP not registered: %s", s)
	}
	if !strings.Contains(s, `"http"`) {
		t.Error("advisor MCP should be type http")
	}
	act, err := MergeAdvisorMCP(path, "https://advisor.bumper.sh")
	if err != nil || act != Unchanged {
		t.Errorf("second MergeAdvisorMCP = %v, %v; want Unchanged", act, err)
	}
}

func TestEnsureDepsClaudeMd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "CLAUDE.md")
	if _, err := EnsureDepsClaudeMd(path); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(t, path), depsClaudeMdMarker) {
		t.Error("deps stanza marker missing")
	}
	act, err := EnsureDepsClaudeMd(path)
	if err != nil || act != Unchanged {
		t.Errorf("second EnsureDepsClaudeMd = %v, %v; want Unchanged", act, err)
	}
}

func TestPlanWithDepsAndAdvisor(t *testing.T) {
	env := Env{Bin: "bumper", Cwd: t.TempDir(), Home: t.TempDir()}
	steps := Plan(Options{MCP: ScopeProject, Hook: ScopeProject, Deps: ScopeProject, Advisor: true, Env: env})
	titles := map[string]bool{}
	for _, s := range steps {
		titles[s.Title] = true
	}
	for _, want := range []string{
		"install dependency hooks · project",
		"register Advisor MCP · hosted",
		"note deps workflow in CLAUDE.md",
	} {
		if !titles[want] {
			t.Errorf("plan missing step %q", want)
		}
	}
}
