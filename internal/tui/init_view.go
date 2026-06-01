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
	sub := stDim.Render("wire the safety gate into Claude Code")
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
	if m.env.ClaudeFound {
		b.WriteString(kvline("claude", stSafe.Render(m.gl.check+" found on PATH")))
	} else {
		b.WriteString(kvline("claude", stWarn.Render(m.gl.warn+" not found")+stDim.Render(" — config still written; install Claude Code to use it")))
	}
	git := stDim.Render("not a git repo")
	if m.env.GitRepo {
		git = stDim.Render("git repo")
	}
	b.WriteString(kvline("project", stInk.Render(collapseHome(m.env.Cwd, m.env.Home))+"  "+git))
	b.WriteString("\n")

	b.WriteString(m.section("WIRE IN") + stDim.Render("   ↑↓ pick row · ←→ change scope") + "\n\n")
	b.WriteString(m.scopeRow(0, "MCP server", m.mcp, mcpTarget(m.mcp)) + "\n")
	b.WriteString(m.scopeRow(1, "guard hook", m.hook, hookTarget(m.hook)) + "\n\n")

	b.WriteString(m.section("ALWAYS"))
	b.WriteString("  " + stSafe.Render(m.gl.check) + " " + stDim.Render("ignore .bumper/ in .gitignore") + "\n")
	b.WriteString("  " + stSafe.Render(m.gl.check) + " " + stDim.Render("note the verify workflow in CLAUDE.md") + "\n")
	return b.String()
}

func (m initModel) scopeRow(row int, label string, sel setup.Scope, target string) string {
	focused := m.focusRow == row
	spine := stDim.Render(m.gl.spine)
	lbl := stInk.Render(pad(label, 12))
	if focused {
		spine = lipgloss.NewStyle().Foreground(colLive).Render(m.gl.spineActive)
		lbl = lipgloss.NewStyle().Foreground(colLive).Bold(true).Render(pad(label, 12))
	}
	var chips []string
	for _, s := range []setup.Scope{setup.ScopeProject, setup.ScopeUser, setup.ScopeNone} {
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
	arrow := stDim.Render("  " + m.gl.arrow + " " + target)
	return spine + " " + lbl + " " + strings.Join(chips, " ") + arrow
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
		"commit .mcp.json + .claude/settings.json to share the gate with your team",
		"restart Claude Code to load the MCP server",
		"the guard blocks unverified terraform apply / destroy",
	} {
		b.WriteString("  " + stLive.Render(m.gl.bullet) + " " + stDim.Render(line) + "\n")
	}
	if !m.env.ClaudeFound {
		b.WriteString("\n  " + stWarn.Render(m.gl.warn+" claude CLI not on PATH") + stDim.Render(" — install Claude Code to use what you just wired.") + "\n")
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

func mcpTarget(s setup.Scope) string {
	switch s {
	case setup.ScopeProject:
		return ".mcp.json"
	case setup.ScopeUser:
		return "~/.claude.json"
	}
	return "skip"
}

func hookTarget(s setup.Scope) string {
	switch s {
	case setup.ScopeProject:
		return ".claude/settings.json"
	case setup.ScopeUser:
		return "~/.claude/settings.json"
	}
	return "skip"
}

func collapseHome(path, home string) string {
	if home != "" && strings.HasPrefix(path, home) {
		return "~" + strings.TrimPrefix(path, home)
	}
	return path
}
