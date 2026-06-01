package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/gnana997/bumper/internal/setup"
)

func key(t tea.KeyType) tea.KeyMsg            { return tea.KeyMsg{Type: t} }
func rkey(r rune) tea.KeyMsg                  { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}} }
func step(m tea.Model, msg tea.Msg) initModel { n, _ := m.Update(msg); return n.(initModel) }

func tempEnv(t *testing.T) setup.Env {
	t.Helper()
	return setup.Env{Bin: "bumper", ClaudeFound: true, Cwd: t.TempDir(), Home: t.TempDir(), GitRepo: true}
}

// TestInitWizardConfigure drives the configure phase and asserts the view holds
// up and scope cycling works, with no panic on render.
func TestInitWizardConfigure(t *testing.T) {
	m := newInitModel(tempEnv(t), setup.ScopeProject, setup.ScopeProject)
	m = step(m, tea.WindowSizeMsg{Width: 100, Height: 30})

	v := m.View()
	for _, want := range []string{"BUMPER", "INIT", "ENVIRONMENT", "WIRE IN", "MCP server", "guard hook", "ALWAYS"} {
		if !strings.Contains(v, want) {
			t.Errorf("configure view missing %q", want)
		}
	}

	// focus second row, cycle the hook scope project → user.
	m = step(m, key(tea.KeyDown))
	if m.focusRow != 1 {
		t.Fatalf("focusRow = %d, want 1", m.focusRow)
	}
	m = step(m, key(tea.KeyRight))
	if m.hook != setup.ScopeUser {
		t.Errorf("hook = %q, want user after one cycle", m.hook)
	}
	// left cycles back.
	m = step(m, key(tea.KeyLeft))
	if m.hook != setup.ScopeProject {
		t.Errorf("hook = %q, want project after cycling back", m.hook)
	}
}

// TestInitWizardApply walks the whole flow and asserts the files are written.
func TestInitWizardApply(t *testing.T) {
	env := tempEnv(t)
	m := newInitModel(env, setup.ScopeProject, setup.ScopeUser)
	m = step(m, tea.WindowSizeMsg{Width: 100, Height: 30})

	// configure → review
	var cmd tea.Cmd
	n, _ := m.Update(key(tea.KeyEnter))
	m = n.(initModel)
	if m.phase != ipReview {
		t.Fatalf("phase = %v, want review", m.phase)
	}
	if !strings.Contains(m.View(), "REVIEW") {
		t.Error("review view missing REVIEW header")
	}

	// review → applying (kicks off the first step command)
	n, cmd = m.Update(key(tea.KeyEnter))
	m = n.(initModel)
	if m.phase != ipApplying || cmd == nil {
		t.Fatalf("expected applying phase with a command, got phase=%v cmd=%v", m.phase, cmd)
	}
	// drive the apply command chain to completion.
	guard := 0
	for cmd != nil && guard < 20 {
		guard++
		msg := cmd()
		n, cmd = m.Update(msg)
		m = n.(initModel)
	}
	if m.phase != ipDone {
		t.Fatalf("phase = %v, want done after apply", m.phase)
	}

	// every step produced a result, none errored.
	if len(m.results) != len(m.steps) {
		t.Fatalf("results=%d steps=%d", len(m.results), len(m.steps))
	}
	for _, r := range m.results {
		if r.err != nil {
			t.Errorf("step %q errored: %v", r.title, r.err)
		}
	}

	// the files landed where the scopes said.
	mustExist(t, filepath.Join(env.Cwd, ".mcp.json"))
	mustExist(t, filepath.Join(env.Home, ".claude", "settings.json"))
	mustExist(t, filepath.Join(env.Cwd, ".gitignore"))
	mustExist(t, filepath.Join(env.Cwd, "CLAUDE.md"))

	if v := m.View(); !strings.Contains(v, "WIRED IN") {
		t.Error("done view missing WIRED IN")
	}

	res := m.result()
	if !res.Applied || len(res.Lines) != len(m.steps) {
		t.Errorf("result summary: applied=%v lines=%d", res.Applied, len(res.Lines))
	}
}

// TestInitWizardNoneScopes: both servers off still writes gitignore + CLAUDE.md.
func TestInitWizardNoneScopes(t *testing.T) {
	env := tempEnv(t)
	steps := setup.Plan(setup.Options{MCP: setup.ScopeNone, Hook: setup.ScopeNone, Env: env})
	if len(steps) != 2 {
		t.Fatalf("none/none plan = %d steps, want 2 (gitignore + CLAUDE.md)", len(steps))
	}
}

// TestInitWizardQuitNotApplied: quitting before apply reports nothing applied.
func TestInitWizardQuitNotApplied(t *testing.T) {
	m := newInitModel(tempEnv(t), setup.ScopeProject, setup.ScopeProject)
	m = step(m, tea.WindowSizeMsg{Width: 80, Height: 24})
	m = step(m, rkey('q'))
	if !m.quitting {
		t.Error("expected quitting after q")
	}
	if m.result().Applied {
		t.Error("nothing should be applied after an early quit")
	}
}

func mustExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected %s to exist: %v", path, err)
	}
}
