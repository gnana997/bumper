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

func TestInitWizardConfigure(t *testing.T) {
	m := newInitModel(tempEnv(t))
	m = step(m, tea.WindowSizeMsg{Width: 100, Height: 30})

	v := m.View()
	for _, want := range []string{"BUMPER", "INIT", "ENVIRONMENT", "HOOKS", "terraform", "dependencies", "advisor", "MCP", "ALWAYS"} {
		if !strings.Contains(v, want) {
			t.Errorf("configure view missing %q", want)
		}
	}

	// Default B: everything on.
	if !m.terraform || !m.deps || !m.advisor {
		t.Fatalf("defaults should all be on: tf=%v deps=%v adv=%v", m.terraform, m.deps, m.advisor)
	}
	// row 0 = terraform; space toggles it off.
	m = step(m, rkey(' '))
	if m.terraform {
		t.Error("space on row 0 should toggle terraform off")
	}
	// down to deps (row 1).
	m = step(m, key(tea.KeyDown))
	if m.focusRow != 1 {
		t.Fatalf("focusRow = %d, want 1", m.focusRow)
	}
}

func TestInitWizardDepsAdvisorCoupling(t *testing.T) {
	m := newInitModel(tempEnv(t))
	m = step(m, tea.WindowSizeMsg{Width: 100, Height: 30})

	// Turning advisor (row 3) off must turn deps off too (deps needs the advisor).
	for m.focusRow < 3 {
		m = step(m, key(tea.KeyDown))
	}
	m = step(m, rkey(' '))
	if m.advisor || m.deps {
		t.Errorf("advisor off must also drop deps: advisor=%v deps=%v", m.advisor, m.deps)
	}
	// Turning deps back on must re-force advisor on.
	for m.focusRow > 1 {
		m = step(m, key(tea.KeyUp))
	}
	m = step(m, rkey(' '))
	if !m.deps || !m.advisor {
		t.Errorf("deps on must force advisor on: deps=%v advisor=%v", m.deps, m.advisor)
	}
}

func TestInitWizardApply(t *testing.T) {
	env := tempEnv(t)
	m := newInitModel(env)
	m = step(m, tea.WindowSizeMsg{Width: 100, Height: 30})

	n, _ := m.Update(key(tea.KeyEnter)) // configure → review
	m = n.(initModel)
	if m.phase != ipReview {
		t.Fatalf("phase = %v, want review", m.phase)
	}

	var cmd tea.Cmd
	n, cmd = m.Update(key(tea.KeyEnter)) // review → applying
	m = n.(initModel)
	if m.phase != ipApplying || cmd == nil {
		t.Fatalf("expected applying with a command, got phase=%v cmd=%v", m.phase, cmd)
	}
	for guard := 0; cmd != nil && guard < 20; guard++ {
		n, cmd = m.Update(cmd())
		m = n.(initModel)
	}
	if m.phase != ipDone {
		t.Fatalf("phase = %v, want done", m.phase)
	}
	if len(m.results) != len(m.steps) {
		t.Fatalf("results=%d steps=%d", len(m.results), len(m.steps))
	}
	for _, r := range m.results {
		if r.err != nil {
			t.Errorf("step %q errored: %v", r.title, r.err)
		}
	}
	// Default scopes are project → everything lands in the project dir.
	mustExist(t, filepath.Join(env.Cwd, ".claude", "settings.json"))
	mustExist(t, filepath.Join(env.Cwd, ".mcp.json"))
	mustExist(t, filepath.Join(env.Cwd, ".gitignore"))
	mustExist(t, filepath.Join(env.Cwd, "CLAUDE.md"))

	if v := m.View(); !strings.Contains(v, "WIRED IN") {
		t.Error("done view missing WIRED IN")
	}
}

func TestPlanNothingSelected(t *testing.T) {
	env := setup.Env{Bin: "bumper", Cwd: t.TempDir(), Home: t.TempDir()}
	steps := setup.Plan(setup.Options{HookScope: setup.ScopeProject, Env: env})
	if len(steps) != 1 {
		t.Fatalf("nothing-selected plan = %d steps, want 1 (gitignore only)", len(steps))
	}
}

func TestInitWizardQuitNotApplied(t *testing.T) {
	m := newInitModel(tempEnv(t))
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
