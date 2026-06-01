package tui

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/gnana997/bumper/internal/engine"
	"github.com/gnana997/bumper/internal/enrich"
	"github.com/gnana997/bumper/internal/rules"
)

type mode int

const (
	modeFindings mode = iota
	modeRuleset
)

type focus int

const (
	focusList focus = iota
	focusDetail
)

type explainPhase int

const (
	expPending explainPhase = iota
	expDone
	expErr
)

type explainState struct {
	phase explainPhase
	text  string
	err   error
}

// messages
type (
	tickMsg          struct{}
	pulseMsg         struct{}
	explainResultMsg struct {
		key  string
		text string
		err  error
	}
)

var errNoCLI = errors.New("no AI CLI on PATH (tried claude, gemini, codex, opencode, auggie)")

// Model is the hazard-console state.
type Model struct {
	mode    mode
	entries []entry
	visible []int // indices into entries after filter/search
	cursor  int   // index into visible

	rset      *rules.Set // for provenance lookup in findings mode
	target    string     // plan name (findings mode), shown in the navbar
	canSwitch bool       // a plan was scanned, so Tab can toggle modes

	focus     focus
	searching bool
	showHelp  bool
	quitting  bool

	sevFilter string // "" | critical | high | medium | low
	srcFilter string // ruleset only: "" | trivy | custom
	search    textinput.Model
	detail    viewport.Model

	explain map[string]explainState
	llm     string

	frame   int
	pulseOn bool

	w, h  int
	ready bool
	gl    glyphs
}

func base(llm string) Model {
	ti := textinput.New()
	ti.Prompt = ""
	ti.CharLimit = 64
	return Model{
		search:  ti,
		detail:  viewport.New(0, 0),
		explain: map[string]explainState{},
		llm:     llm,
		gl:      pickGlyphs(),
	}
}

// NewFindings builds the board for a scanned plan. set is used to look up each
// finding's rule provenance (source/AVD); target is the plan name for the navbar.
func NewFindings(fs []engine.Finding, set *rules.Set, llm, target string) Model {
	m := base(llm)
	m.mode = modeFindings
	m.rset = set
	m.target = target
	m.entries = findingEntries(fs)
	m.recompute()
	return m
}

// NewRules builds the board for the rule set (`list --tui`).
func NewRules(rs []*rules.Rule) Model {
	m := base("auto")
	m.mode = modeRuleset
	m.entries = ruleEntries(rs)
	m.recompute()
	return m
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(tickCmd(), pulseCmd())
}

func tickCmd() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(time.Time) tea.Msg { return tickMsg{} })
}
func pulseCmd() tea.Cmd {
	return tea.Tick(700*time.Millisecond, func(time.Time) tea.Msg { return pulseMsg{} })
}

func (m Model) explainCmd(e entry) tea.Cmd {
	key := e.explainKey()
	llm := m.llm
	kind := e.kind
	var f engine.Finding
	var r *rules.Rule
	if kind == kindFinding {
		f = *e.finding
	} else {
		r = e.rule
	}
	return func() tea.Msg {
		cli, ok := enrich.Detect(llm)
		if !ok {
			return explainResultMsg{key: key, err: errNoCLI}
		}
		var txt string
		var err error
		if kind == kindFinding {
			txt, err = enrich.Explain(context.Background(), cli, []engine.Finding{f})
		} else {
			txt, err = enrich.Ask(context.Background(), cli, ruleExplainPrompt(r))
		}
		return explainResultMsg{key: key, text: txt, err: err}
	}
}

func ruleExplainPrompt(r *rules.Rule) string {
	applies := r.Resource
	if applies == "" {
		applies = "multiple resource types"
	}
	return fmt.Sprintf(
		"You are a senior AWS platform engineer. In 2-3 plain-English sentences, "+
			"explain what this Terraform/AWS security rule catches, the real-world risk "+
			"if it is violated (what an attacker or operator could actually do), and confirm "+
			"the fix. Be concrete and concise. Do not invent details.\n\n"+
			"Rule: %q\nApplies to: %s\nSuggested fix: %s",
		r.Title, applies, r.Fix)
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		m.ready = true
		m.applyLayout()
		m.refreshDetail()
		return m, nil

	case tickMsg:
		m.frame++
		if st, ok := m.currentExplain(); ok && st.phase == expPending {
			m.refreshDetail()
		}
		return m, tickCmd()

	case pulseMsg:
		m.pulseOn = !m.pulseOn
		return m, pulseCmd()

	case explainResultMsg:
		ph := expDone
		if msg.err != nil {
			ph = expErr
		}
		m.explain[msg.key] = explainState{phase: ph, text: msg.text, err: msg.err}
		m.refreshDetail()
		if e, ok := m.currentEntry(); ok && e.explainKey() == msg.key {
			m.detail.GotoBottom() // keep the freshly-arrived explanation in view
		}
		return m, nil

	case tea.KeyMsg:
		return m.onKey(msg)
	}
	return m, nil
}

func (m Model) onKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	k := msg.String()

	if m.showHelp {
		if k == "?" || k == "esc" || k == "q" {
			m.showHelp = false
		}
		if k == "ctrl+c" {
			m.quitting = true
			return m, tea.Quit
		}
		return m, nil
	}

	if m.searching {
		switch k {
		case "esc":
			m.searching = false
			m.search.Blur()
			m.search.SetValue("")
			m.recompute()
		case "enter":
			m.searching = false
			m.search.Blur()
		default:
			var cmd tea.Cmd
			m.search, cmd = m.search.Update(msg)
			m.recompute()
			return m, cmd
		}
		return m, nil
	}

	switch k {
	case "q", "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	case "?":
		m.showHelp = true
		return m, nil
	case "/":
		m.searching = true
		return m, m.search.Focus()
	case "tab":
		if m.canSwitch {
			if m.mode == modeFindings {
				m.mode = modeRuleset
			} else {
				m.mode = modeFindings
			}
			// entries for the other mode are swapped in by the caller via
			// SetModes; if not present we just no-op.
		}
		return m, nil
	}

	if m.focus == focusDetail {
		switch k {
		case "esc", "left", "h":
			m.focus = focusList
			return m, nil
		case "e":
			return m.triggerExplain()
		default:
			var cmd tea.Cmd
			m.detail, cmd = m.detail.Update(msg)
			return m, cmd
		}
	}

	// focus == list
	switch k {
	case "up", "k":
		m.move(-1)
	case "down", "j":
		m.move(1)
	case "g", "home":
		m.cursor = 0
		m.syncDetail()
	case "G", "end":
		m.cursor = len(m.visible) - 1
		if m.cursor < 0 {
			m.cursor = 0
		}
		m.syncDetail()
	case "right", "l", "enter":
		if len(m.visible) > 0 {
			m.focus = focusDetail
		}
	case "e":
		return m.triggerExplain()
	case "f", "v":
		m.sevFilter = cycle(m.sevFilter, "", "critical", "high", "medium", "low")
		m.recompute()
	case "s":
		if m.mode == modeRuleset {
			m.srcFilter = cycle(m.srcFilter, "", "trivy", "custom")
			m.recompute()
		}
	}
	return m, nil
}

func (m *Model) triggerExplain() (tea.Model, tea.Cmd) {
	e, ok := m.currentEntry()
	if !ok {
		return m, nil
	}
	key := e.explainKey()
	if st, exists := m.explain[key]; exists && st.phase != expErr {
		return m, nil // already pending or done
	}
	m.explain[key] = explainState{phase: expPending}
	m.refreshDetail()
	m.detail.GotoBottom() // reveal the explanation (it renders below the CEL check)
	return m, m.explainCmd(e)
}

func (m *Model) move(d int) {
	if len(m.visible) == 0 {
		return
	}
	m.cursor += d
	if m.cursor < 0 {
		m.cursor = 0
	}
	if m.cursor >= len(m.visible) {
		m.cursor = len(m.visible) - 1
	}
	m.syncDetail()
}

func (m *Model) recompute() {
	q := m.search.Value()
	m.visible = m.visible[:0]
	for i, e := range m.entries {
		if m.sevFilter != "" && e.severity != m.sevFilter {
			continue
		}
		if m.srcFilter != "" && (e.rule == nil || e.rule.Source != m.srcFilter) {
			continue
		}
		if !e.match(q) {
			continue
		}
		m.visible = append(m.visible, i)
	}
	if m.cursor >= len(m.visible) {
		m.cursor = len(m.visible) - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
	m.syncDetail()
}

func (m *Model) currentEntry() (entry, bool) {
	if m.cursor < 0 || m.cursor >= len(m.visible) {
		return entry{}, false
	}
	return m.entries[m.visible[m.cursor]], true
}

func (m *Model) currentExplain() (explainState, bool) {
	e, ok := m.currentEntry()
	if !ok {
		return explainState{}, false
	}
	st, ok := m.explain[e.explainKey()]
	return st, ok
}

// syncDetail re-renders the detail pane and resets scroll (selection changed).
func (m *Model) syncDetail() {
	m.refreshDetail()
	m.detail.GotoTop()
}

// refreshDetail re-renders without resetting scroll (e.g. spinner tick).
func (m *Model) refreshDetail() {
	e, ok := m.currentEntry()
	if !ok {
		m.detail.SetContent("")
		return
	}
	m.detail.SetContent(m.renderDetail(e))
}

func (m *Model) applyLayout() {
	L := m.layout()
	m.detail.Width = L.detailW
	m.detail.Height = L.bodyH - 1 // minus the pane title row
	if m.detail.Height < 1 {
		m.detail.Height = 1
	}
}

func cycle(cur string, order ...string) string {
	for i, v := range order {
		if v == cur {
			return order[(i+1)%len(order)]
		}
	}
	return order[0]
}
