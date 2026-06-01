// Package style is bumper's plain-output color palette — the terminal counterpart
// of the web app's <Terminal> components. It wraps lipgloss so that color is
// applied only when the destination is a real terminal: piping, redirecting, a
// non-TTY writer, or NO_COLOR all degrade to plain text automatically (lipgloss/
// termenv detects this from the writer), and truecolor downsamples to 16-color on
// terminals that lack it. Severity is always conveyed by the word, never by color
// alone, so the output stays legible with color off.
//
// Only semantic tokens are colored (severity, the ●/○ section glyphs, the accent
// prompt, sources, success/fix) — never body text — so it reads correctly on both
// light and dark terminal backgrounds. The deterministic engine never imports this.
package style

import (
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Palette holds the styles for one writer. Build it per destination with New.
type Palette struct {
	crit, high, med, low lipgloss.Style
	ok, accent           lipgloss.Style
	dim, faint, strong   lipgloss.Style
	// Glyphs is the Unicode/ASCII glyph set chosen for the current locale.
	Glyphs Glyphs
}

// New builds a palette bound to w. If w is a terminal it colors; otherwise (pipe,
// file, bytes.Buffer in tests) lipgloss yields plain text. Colors match the web
// app's --term-* tokens.
func New(w io.Writer) *Palette {
	r := lipgloss.NewRenderer(w)
	fg := func(hex string) lipgloss.Style { return r.NewStyle().Foreground(lipgloss.Color(hex)) }
	return &Palette{
		crit:   fg("#ff5a4d").Bold(true),
		high:   fg("#e3a53c").Bold(true),
		med:    fg("#c9b27d"),
		low:    fg("#8b8270"),
		ok:     fg("#74b491"),
		accent: fg("#e08a5c"),
		dim:    fg("#8b8270"),
		faint:  fg("#6b6450"),
		strong: r.NewStyle().Bold(true),
		Glyphs: pickGlyphs(),
	}
}

func (p *Palette) sevStyle(sev string) lipgloss.Style {
	switch sev {
	case "critical":
		return p.crit
	case "high":
		return p.high
	case "medium":
		return p.med
	case "low":
		return p.low
	default:
		return p.faint
	}
}

// Severity colors text with sev's color (pass already-padded text to keep columns
// aligned — the color wraps the whole cell, so width is preserved).
func (p *Palette) Severity(sev, text string) string { return p.sevStyle(sev).Render(text) }

// Sev colors the severity word itself.
func (p *Palette) Sev(sev string) string { return p.sevStyle(sev).Render(sev) }

func (p *Palette) OK(s string) string     { return p.ok.Render(s) }
func (p *Palette) Accent(s string) string { return p.accent.Render(s) }
func (p *Palette) Dim(s string) string    { return p.dim.Render(s) }
func (p *Palette) Faint(s string) string  { return p.faint.Render(s) }
func (p *Palette) Strong(s string) string { return p.strong.Render(s) }

// Glyphs is a small terminal glyph set with a plain-ASCII fallback.
type Glyphs struct {
	Dot, Ring, Check, Warn, Cross, Pause, Bullet, Mid string
}

var glyphUnicode = Glyphs{Dot: "●", Ring: "○", Check: "✓", Warn: "⚠", Cross: "✗", Pause: "⏸", Bullet: "·", Mid: "—"}
var glyphASCII = Glyphs{Dot: "*", Ring: "o", Check: "OK", Warn: "!", Cross: "x", Pause: "||", Bullet: "-", Mid: "-"}

func pickGlyphs() Glyphs {
	for _, v := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		u := strings.ToUpper(os.Getenv(v))
		if strings.Contains(u, "UTF-8") || strings.Contains(u, "UTF8") {
			return glyphUnicode
		}
	}
	return glyphASCII
}

// PadRight pads s with spaces to width n (n excludes any color codes since callers
// pad before coloring). Long strings are returned as-is plus two spaces of gap.
func PadRight(s string, n int) string {
	if len(s) >= n {
		return s + "  "
	}
	return s + strings.Repeat(" ", n-len(s))
}

// Trunc shortens s to n runes with an ellipsis, so titles never wrap the line.
func Trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}
