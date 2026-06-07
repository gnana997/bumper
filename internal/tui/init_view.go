package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/gnana997/bumper/internal/setup"
)

func (m initModel) View() string {
	if m.quitting {
		return ""
	}
	if !m.ready {
		return "starting…"
	}
	var body string
	switch m.phase {
	case ipConfigure:
		body = m.bodyConfigure()
	case ipReview:
		body = m.bodyReview()
	case ipApplying:
		body = m.bodyApplying()
	case ipDone:
		body = m.bodyDone()
	}
	return m.compose(body)
}

// compose stacks the navbar, body (padded to fill), and footer.
func (m initModel) compose(body string) string {
	head := m.header()
	foot := stFooter.Render(m.footerKeys())
	bodyH := m.h - 3 // 2-line header + 1-line footer
	if bodyH < 1 {
		bodyH = 1
	}
	lines := strings.Split(body, "\n")
	for len(lines) < bodyH {
		lines = append(lines, "")
	}
	if len(lines) > bodyH {
		lines = lines[:bodyH]
	}
	return head + "\n" + strings.Join(lines, "\n") + "\n" + clampLine(foot, m.w)
}

func (m initModel) header() string {
	bar := lipgloss.NewStyle().Foreground(colLive).Render(m.gl.spineActive)
	left := bar + " " + stHeading.Render("BUMPER") + stDim.Render("  "+m.gl.arrow+"  ") + stLive.Render("INIT")
	sub := stDim.Render("wire the safety gate into your coding agent")
	right := stDim.Render("hazard console")
	gap := m.w - lipgloss.Width(left) - lipgloss.Width(sub) - lipgloss.Width(right) - 2
	if gap < 1 {
		gap = 1
	}
	top := clampLine(left+"  "+sub+strings.Repeat(" ", gap)+right, m.w)
	rule := lipgloss.NewStyle().Foreground(colChrome).Render(strings.Repeat(m.gl.hbar, max(m.w, 1)))
	return top + "\n" + rule
}

// --- configure ---

func (m initModel) bodyConfigure() string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(m.section("ENVIRONMENT"))
	b.WriteString(kvline("binary", stInk.Render(m.env.Bin)))
	git := stDim.Render("not a git repo")
	if m.env.GitRepo {
		git = stDim.Render("git repo")
	}
	b.WriteString(kvline("project", stInk.Render(collapseHome(m.env.Cwd, m.env.Home))+"  "+git))
	b.WriteString("\n")

	b.WriteString(m.section("AGENT") + stDim.Render("   ↑↓ pick row · ←→/space change") + "\n\n")
	b.WriteString(m.agentRow(0) + "\n\n")

	b.WriteString(m.section("HOOKS"))
	b.WriteString(m.toggleRow(1, "terraform", m.terraform, "apply-guard") + "\n")
	b.WriteString(m.toggleRow(2, "dependencies", m.deps, "install-block + post-install scan") + "\n")
	b.WriteString(m.scopeRow(3, m.hookScope) + "\n\n")

	b.WriteString(m.section("MCP"))
	b.WriteString(m.toggleRow(4, "advisor", m.advisor, "advisor.bumper.sh — security lookups") + "\n")
	b.WriteString("       " + stWarn.Render(m.gl.warn) + " " + stDim.Render("the dependency guardrail needs this for CVE/malware data —") + "\n")
	b.WriteString("         " + stDim.Render("only package names + versions leave your machine, never your code") + "\n")
	b.WriteString(m.scopeRow(5, m.advisorScope) + "\n\n")

	b.WriteString(m.section("ALWAYS"))
	b.WriteString("  " + stSafe.Render(m.gl.check) + " " + stDim.Render("ignore .bumper/ in .gitignore") + "\n")
	b.WriteString("  " + stSafe.Render(m.gl.check) + " " + stDim.Render("note the wired workflows in "+m.contextFileName()) + "\n")
	return b.String()
}

// contextFileName is the agent-instructions filename for the selected agent.
func (m initModel) contextFileName() string {
	if m.agent == setup.AgentAugment {
		return "AGENTS.md"
	}
	return "CLAUDE.md"
}

// agentRow renders the coding-agent selector (claude/augment chips + presence hint).
func (m initModel) agentRow(row int) string {
	focused := m.focusRow == row
	spine := stDim.Render(m.gl.spine)
	lbl := pad("  target", 13)
	lblStyled := stDim.Render(lbl)
	if focused {
		spine = lipgloss.NewStyle().Foreground(colLive).Render(m.gl.spineActive)
		lblStyled = lipgloss.NewStyle().Foreground(colLive).Bold(true).Render(lbl)
	}
	var chips []string
	for _, a := range []setup.Agent{setup.AgentClaude, setup.AgentAugment} {
		if a == m.agent {
			c := "[" + a.Label() + "]"
			if focused {
				chips = append(chips, lipgloss.NewStyle().Foreground(colLive).Bold(true).Render(c))
			} else {
				chips = append(chips, stInk.Render(c))
			}
		} else {
			chips = append(chips, stDim.Render(" "+a.Label()+" "))
		}
	}
	found := m.env.ClaudeFound
	if m.agent == setup.AgentAugment {
		found = m.env.AugmentFound
	}
	hint := stSafe.Render("  " + m.gl.check + " on PATH")
	if !found {
		hint = stWarn.Render("  "+m.gl.warn+" not found") + stDim.Render(" — config still written")
	}
	return spine + " " + lblStyled + " " + strings.Join(chips, " ") + hint
}

// toggleRow renders an on/off guardrail row ([x]/[ ] + label + hint).
func (m initModel) toggleRow(row int, label string, on bool, hint string) string {
	focused := m.focusRow == row
	spine := stDim.Render(m.gl.spine)
	lbl := stInk.Render(pad(label, 13))
	if focused {
		spine = lipgloss.NewStyle().Foreground(colLive).Render(m.gl.spineActive)
		lbl = lipgloss.NewStyle().Foreground(colLive).Bold(true).Render(pad(label, 13))
	}
	box := "[ ]"
	if on {
		box = "[x]"
	}
	if focused {
		box = lipgloss.NewStyle().Foreground(colLive).Bold(true).Render(box)
	} else {
		box = stInk.Render(box)
	}
	return spine + " " + box + " " + lbl + stDim.Render(hint)
}

// scopeRow renders a project/user scope selector for the row above it.
func (m initModel) scopeRow(row int, sel setup.Scope) string {
	focused := m.focusRow == row
	spine := stDim.Render(m.gl.spine)
	lbl := pad("  scope", 13)
	lblStyled := stDim.Render(lbl)
	if focused {
		spine = lipgloss.NewStyle().Foreground(colLive).Render(m.gl.spineActive)
		lblStyled = lipgloss.NewStyle().Foreground(colLive).Bold(true).Render(lbl)
	}
	var chips []string
	for _, s := range []setup.Scope{setup.ScopeProject, setup.ScopeUser} {
		if s == sel {
			c := "[" + string(s) + "]"
			if focused {
				chips = append(chips, lipgloss.NewStyle().Foreground(colLive).Bold(true).Render(c))
			} else {
				chips = append(chips, stInk.Render(c))
			}
		} else {
			chips = append(chips, stDim.Render(" "+string(s)+" "))
		}
	}
	return spine + " " + lblStyled + " " + strings.Join(chips, " ")
}

// --- review ---

func (m initModel) bodyReview() string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(m.section("REVIEW") + stDim.Render("   merge-safe · idempotent · re-runnable") + "\n\n")
	for _, s := range m.steps {
		b.WriteString("  " + stLive.Render(m.gl.arrow) + " " +
			stInk.Render(pad(s.Title, 34)) + stDim.Render(s.RelPath(m.env)) + "\n")
	}
	b.WriteString("\n  " + stDim.Render("Existing files are merged, not overwritten; a backup is kept.") + "\n")
	return b.String()
}

// --- applying ---

func (m initModel) bodyApplying() string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(m.section("APPLYING") + "\n")
	for i, s := range m.steps {
		switch {
		case i < len(m.results):
			r := m.results[i]
			mark, act := stSafe.Render(m.gl.check), stSafe.Render(pad(r.action.String(), 9))
			if r.err != nil {
				mark, act = stCrit.Render(m.gl.warn), stCrit.Render(pad("error", 9))
			}
			b.WriteString("  " + mark + " " + stInk.Render(pad(s.Title, 34)) + act + "\n")
		case i == m.applyIdx:
			sp := lipgloss.NewStyle().Foreground(colLive).Render(m.gl.spinner[m.frame%len(m.gl.spinner)])
			b.WriteString("  " + sp + " " + stLive.Render(pad(s.Title, 34)) + stDim.Render("…") + "\n")
		default:
			b.WriteString("  " + stDim.Render(m.gl.bullet+" "+s.Title) + "\n")
		}
	}
	return b.String()
}

// --- done ---

func (m initModel) bodyDone() string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString("  " + stSafe.Render(m.gl.check+"  BUMPER WIRED IN") + "\n\n")
	for _, r := range m.results {
		act := stSafe.Render(pad(r.action.String(), 10))
		if r.err != nil {
			act = stCrit.Render(pad("error", 10))
		}
		b.WriteString("    " + act + " " + stDim.Render(r.path) + "\n")
	}
	b.WriteString("\n" + m.section("NEXT"))
	for _, line := range []string{
		"commit the generated config to share the gate with your team",
		"restart " + m.agent.Label() + " to load the MCP server",
		"the guard blocks unverified terraform apply / destroy",
	} {
		b.WriteString("  " + stLive.Render(m.gl.bullet) + " " + stDim.Render(line) + "\n")
	}
	found := m.env.ClaudeFound
	if m.agent == setup.AgentAugment {
		found = m.env.AugmentFound
	}
	if !found {
		b.WriteString("\n  " + stWarn.Render(m.gl.warn+" "+m.agent.Label()+" CLI not on PATH") + stDim.Render(" — install it to use what you just wired.") + "\n")
	}
	return b.String()
}

// --- chrome helpers ---

func (m initModel) section(label string) string {
	return stLabel.Render(label) + "\n"
}

func (m initModel) footerKeys() string {
	switch m.phase {
	case ipConfigure:
		return strings.Join([]string{"↑↓ row", "←→ scope", "⏎ review", "q quit"}, "   ")
	case ipReview:
		return strings.Join([]string{"⏎ apply", "esc back", "q quit"}, "   ")
	case ipApplying:
		return "applying…"
	default:
		return "⏎ done"
	}
}

func kvline(label, value string) string {
	return "  " + stLabel.Render(pad(label, 9)) + value + "\n"
}

func collapseHome(path, home string) string {
	if home != "" && strings.HasPrefix(path, home) {
		return "~" + strings.TrimPrefix(path, home)
	}
	return path
}
