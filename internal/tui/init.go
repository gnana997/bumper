package tui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/gnana997/bumper/internal/setup"
)

// The init wizard: an interactive, hazard-console front end for `bumper init`.
// It walks the user through choosing where the MCP server and guard hook are
// wired, previews the exact files, then applies them with live per-step status.

type initPhase int

const (
	ipConfigure initPhase = iota
	ipReview
	ipApplying
	ipDone
)

type stepResult struct {
	title, path string
	action      setup.Action
	err         error
}

type (
	initTickMsg    struct{}
	applyResultMsg struct {
		idx    int
		result stepResult
	}
)

type initModel struct {
	env          setup.Env
	agent        setup.Agent // which coding agent to wire (claude|augment)
	terraform    bool        // install the terraform apply-guard hook
	deps         bool        // install the dependency hooks
	hookScope    setup.Scope // project|user — where hooks go
	advisor      bool        // register the hosted advisor MCP
	advisorScope setup.Scope // project|user — where the advisor MCP goes

	phase    initPhase
	focusRow int // 0=agent 1=terraform 2=deps 3=hookScope 4=advisor 5=advisorScope

	steps    []setup.Step
	results  []stepResult
	applyIdx int

	frame    int
	quitting bool
	w, h     int
	ready    bool
	gl       glyphs
}

func newInitModel(env setup.Env) initModel {
	// Default B: wire everything (hooks self-filter, so it's safe and future-proof).
	// Default to Claude unless only Augment is present.
	agent := setup.AgentClaude
	if env.AugmentFound && !env.ClaudeFound {
		agent = setup.AgentAugment
	}
	return initModel{
		env: env, agent: agent, terraform: true, deps: true, advisor: true,
		hookScope: setup.ScopeProject, advisorScope: setup.ScopeProject, gl: pickGlyphs(),
	}
}

const initLastRow = 5 // 0=agent 1=terraform 2=deps 3=hookScope 4=advisor 5=advisorScope

func (m initModel) Init() tea.Cmd { return initTickCmd() }

func initTickCmd() tea.Cmd {
	return tea.Tick(110*time.Millisecond, func(time.Time) tea.Msg { return initTickMsg{} })
}

func (m initModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		m.ready = true
		return m, nil
	case initTickMsg:
		m.frame++
		return m, initTickCmd()
	case applyResultMsg:
		m.results = append(m.results, msg.result)
		m.applyIdx = msg.idx + 1
		if m.applyIdx >= len(m.steps) {
			m.phase = ipDone
			return m, nil
		}
		return m, m.applyStepCmd(m.applyIdx)
	case tea.KeyMsg:
		return m.onKey(msg)
	}
	return m, nil
}

func (m initModel) onKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	k := msg.String()
	if k == "ctrl+c" {
		m.quitting = true
		return m, tea.Quit
	}
	switch m.phase {
	case ipConfigure:
		switch k {
		case "q", "esc":
			m.quitting = true
			return m, tea.Quit
		case "up", "k":
			if m.focusRow > 0 {
				m.focusRow--
			}
		case "down", "j", "tab":
			if m.focusRow < initLastRow {
				m.focusRow++
			}
		case "enter":
			m.steps = setup.Plan(setup.Options{
				Agent: m.agent, HookScope: m.hookScope, Terraform: m.terraform, Deps: m.deps,
				Advisor: m.advisor, AdvisorScope: m.advisorScope, Env: m.env,
			})
			m.phase = ipReview
			return m, nil
		case "right", "l", " ", "left", "h":
			m.change()
		}
	case ipReview:
		switch k {
		case "esc", "left", "h":
			m.phase = ipConfigure
		case "enter", "y":
			m.phase = ipApplying
			m.results, m.applyIdx = nil, 0
			return m, m.applyStepCmd(0)
		case "q":
			m.quitting = true
			return m, tea.Quit
		}
	case ipApplying:
		// keys ignored while applying (ctrl+c handled above)
	case ipDone:
		if k == "q" || k == "enter" || k == "esc" {
			m.quitting = true
			return m, tea.Quit
		}
	}
	return m, nil
}

// change applies ←→/space on the focused row: toggles for the on/off rows,
// project↔user for the scope rows. It keeps the deps→advisor invariant: the
// dependency guardrail can't function without an advisor endpoint.
func (m *initModel) change() {
	switch m.focusRow {
	case 0:
		if m.agent == setup.AgentClaude {
			m.agent = setup.AgentAugment
		} else {
			m.agent = setup.AgentClaude
		}
	case 1:
		m.terraform = !m.terraform
	case 2:
		m.deps = !m.deps
		if m.deps {
			m.advisor = true // deps needs the advisor for CVE/malware data
		}
	case 3:
		m.hookScope = flipScope(m.hookScope)
	case 4:
		m.advisor = !m.advisor
		if !m.advisor {
			m.deps = false // can't scan deps without an advisor
		}
	case 5:
		m.advisorScope = flipScope(m.advisorScope)
	}
}

func flipScope(s setup.Scope) setup.Scope {
	if s == setup.ScopeUser {
		return setup.ScopeProject
	}
	return setup.ScopeUser
}

func (m initModel) applyStepCmd(idx int) tea.Cmd {
	step := m.steps[idx]
	env := m.env
	return func() tea.Msg {
		act, err := step.Run()
		return applyResultMsg{idx: idx, result: stepResult{
			title: step.Title, path: step.RelPath(env), action: act, err: err,
		}}
	}
}

// InitResult is what RunInit reports back so the CLI can leave a persistent
// record after the alt-screen is torn down.
type InitResult struct {
	Applied bool
	Lines   []string
}

func (m initModel) result() InitResult {
	r := InitResult{Applied: m.phase == ipDone}
	for _, s := range m.results {
		if s.err != nil {
			r.Lines = append(r.Lines, "error      "+s.path+": "+s.err.Error())
			continue
		}
		r.Lines = append(r.Lines, pad(s.action.String(), 10)+" "+s.path)
	}
	return r
}
