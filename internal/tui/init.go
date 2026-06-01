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
	env  setup.Env
	mcp  setup.Scope
	hook setup.Scope

	phase    initPhase
	focusRow int // configure: 0 = MCP, 1 = hook

	steps    []setup.Step
	results  []stepResult
	applyIdx int

	frame    int
	quitting bool
	w, h     int
	ready    bool
	gl       glyphs
}

func newInitModel(env setup.Env, mcp, hook setup.Scope) initModel {
	return initModel{env: env, mcp: mcp, hook: hook, gl: pickGlyphs()}
}

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
			if m.focusRow < 1 {
				m.focusRow++
			}
		case "right", "l", " ", "enter":
			if k == "enter" {
				m.steps = setup.Plan(setup.Options{MCP: m.mcp, Hook: m.hook, Env: m.env})
				m.phase = ipReview
				return m, nil
			}
			m.cycle(+1)
		case "left", "h":
			m.cycle(-1)
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

func (m *initModel) cycle(dir int) {
	next := func(s setup.Scope) setup.Scope {
		if dir < 0 {
			return s.Next().Next() // Prev == two Nexts over a 3-cycle
		}
		return s.Next()
	}
	if m.focusRow == 0 {
		m.mcp = next(m.mcp)
	} else {
		m.hook = next(m.hook)
	}
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
