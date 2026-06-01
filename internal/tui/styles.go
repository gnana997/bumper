// Package tui is bumper's optional interactive terminal UI — the "hazard
// console". It is opt-in (`bumper tui` / `bumper list --tui`); the default CLI
// output stays plain and pipeable. The deterministic core never imports this.
package tui

import (
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Hazard-console palette: warm charcoal ground, burnt-amber chrome, severity as
// the one semantic signal. Matched to the web app's --term-* tokens so the CLI and
// the site read as one product. lipgloss/termenv downsamples truecolor and honors
// NO_COLOR.
var (
	colCrit   = lipgloss.Color("#FF5A4D") // term-crit
	colHigh   = lipgloss.Color("#E3A53C") // term-high
	colMed    = lipgloss.Color("#C9B27D") // warm amber-tan
	colLow    = lipgloss.Color("#8B8270") // term-dim
	colSafe   = lipgloss.Color("#74B491") // term-ok
	colChrome = lipgloss.Color("#6B6450") // warm structural lines/labels
	colLive   = lipgloss.Color("#E08A5C") // term-accent (burnt amber)
	colInk    = lipgloss.Color("#DCD5C4") // term-ink
	colDim    = lipgloss.Color("#8B8270") // term-dim
)

// glyphs has a Unicode set and an ASCII fallback (for non-UTF-8 terminals), so
// the layout never breaks into mojibake.
type glyphs struct {
	spine, spineActive              string
	histFull, histMed, histEmpty    string
	check, warn, arrow, bullet, cur string
	dash, vbar, hbar                string
	spinner                         []string
}

var glyphUnicode = glyphs{
	spine: "▌", spineActive: "█",
	histFull: "█", histMed: "▓", histEmpty: "░",
	check: "✓", warn: "⚠", arrow: "›", bullet: "·", cur: "▏",
	dash: "─", vbar: "│", hbar: "━",
	spinner: []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
}

var glyphASCII = glyphs{
	spine: "|", spineActive: "#",
	histFull: "#", histMed: "=", histEmpty: ".",
	check: "OK", warn: "!", arrow: ">", bullet: "-", cur: "_",
	dash: "-", vbar: "|", hbar: "=",
	spinner: []string{"-", "\\", "|", "/"},
}

func pickGlyphs() glyphs {
	for _, v := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		u := strings.ToUpper(os.Getenv(v))
		if strings.Contains(u, "UTF-8") || strings.Contains(u, "UTF8") {
			return glyphUnicode
		}
	}
	return glyphASCII
}

func sevColor(s string) lipgloss.Color {
	switch s {
	case "critical":
		return colCrit
	case "high":
		return colHigh
	case "medium":
		return colMed
	default:
		return colLow
	}
}

// sevTag is the color-independent severity marker (a11y: severity is never
// conveyed by color alone).
func sevTag(s string) string {
	if s == "" {
		return "?"
	}
	return strings.ToUpper(s[:1])
}

func sevRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// Reusable styles.
var (
	stLabel   = lipgloss.NewStyle().Foreground(colChrome)
	stDim     = lipgloss.NewStyle().Foreground(colDim)
	stInk     = lipgloss.NewStyle().Foreground(colInk)
	stLive    = lipgloss.NewStyle().Foreground(colLive).Bold(true)
	stHeading = lipgloss.NewStyle().Foreground(colLive).Bold(true)
	stFooter  = lipgloss.NewStyle().Foreground(colDim)
	stSafe    = lipgloss.NewStyle().Foreground(colSafe).Bold(true)
	stWarn    = lipgloss.NewStyle().Foreground(colHigh)
	stCrit    = lipgloss.NewStyle().Foreground(colCrit).Bold(true)
)
