package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

type layoutDims struct {
	headerH, footerH, bodyH int
	listW, detailW          int
	single                  bool
}

func (m Model) layout() layoutDims {
	L := layoutDims{footerH: 1, headerH: 4}
	switch {
	case m.h < 16:
		L.headerH = 1 // tiny: one-line band
	case m.w < 84:
		L.headerH = 2 // compact: wordmark + blast
	}
	L.bodyH = m.h - L.headerH - L.footerH
	if L.bodyH < 3 {
		L.bodyH = 3
	}
	if m.w < 84 {
		L.single = true
		L.listW = m.w
		L.detailW = m.w
	} else {
		L.listW = m.w * 38 / 100
		if L.listW < 28 {
			L.listW = 28
		}
		L.detailW = m.w - L.listW - 3
		if L.detailW < 20 {
			L.detailW = 20
		}
	}
	return L
}

func (m Model) View() string {
	if m.quitting {
		return ""
	}
	if !m.ready {
		return "starting…"
	}
	if m.mode == modeFindings && len(m.entries) == 0 {
		return m.renderClean()
	}

	L := m.layout()
	if m.showHelp {
		return m.renderHelp()
	}
	return strings.Join([]string{
		m.renderHeader(L),
		m.renderBody(L),
		m.renderFooter(L),
	}, "\n")
}

// --- navbar (k9s-style: info grid · blast panel · wordmark) ---

func (m Model) renderHeader(L layoutDims) string {
	crit, high, med := m.counts()
	total := len(m.entries)

	switch L.headerH {
	case 1:
		return m.headerTiny(crit, high, med, total)
	case 2:
		return m.headerCompact(crit, high, med, total)
	}

	leftW, rightW := 30, 20
	gap := 2
	midW := m.w - leftW - rightW - gap
	if midW < 18 {
		midW = 18
	}
	left := m.infoPanel(total)
	mid := m.blastPanel(crit, high, med, total, midW)
	right := m.logoLines()

	rows := make([]string, 3)
	for i := 0; i < 3; i++ {
		l := pad(getLine(left, i), leftW)
		md := pad(getLine(mid, i), midW)
		rt := alignRight(getLine(right, i), rightW)
		rows[i] = clampLine(l+" "+md+" "+rt, m.w)
	}
	rule := lipgloss.NewStyle().Foreground(colChrome).Render(strings.Repeat(m.gl.hbar, m.w))
	return strings.Join(append(rows, rule), "\n")
}

// kv renders an aligned "LABEL  value" navbar line.
func kv(label, value string) string {
	return stLabel.Render(pad(strings.ToUpper(label), 7)) + value
}

func (m Model) infoPanel(total int) []string {
	if m.mode == modeRuleset {
		tr, cu := m.sourceCounts()
		return []string{
			kv("mode", stLive.Render("RULESET")),
			kv("rules", stInk.Render(fmt.Sprintf("%d", total))),
			kv("source", stInk.Render(fmt.Sprintf("%d trivy · %d custom", tr, cu))),
		}
	}
	plan := m.target
	if plan == "" {
		plan = "terraform plan"
	}
	verdict := stCrit.Render("DANGER")
	if total == 0 {
		verdict = stSafe.Render("clean")
	}
	return []string{
		kv("mode", stLive.Render("SCAN")),
		kv("plan", stInk.Render(truncate(plan, 22))),
		kv("status", verdict+stDim.Render(fmt.Sprintf("  %d issues", total))),
	}
}

func (m Model) blastPanel(c, h, md, total, width int) []string {
	histW := width - 30
	if histW < 8 {
		histW = 8
	}
	if histW > 24 {
		histW = 24
	}
	counts := fmt.Sprintf("%s %d   %s %d   %s %d",
		lipgloss.NewStyle().Foreground(colCrit).Render("CRIT"), c,
		lipgloss.NewStyle().Foreground(colHigh).Render("HIGH"), h,
		lipgloss.NewStyle().Foreground(colMed).Render("MED"), md)

	third := ""
	if shown := len(m.visible); shown != total {
		third = stDim.Render(fmt.Sprintf("%d shown", shown))
	}
	if chip := m.filterChip(); chip != "" {
		if third != "" {
			third += "   "
		}
		third += stLive.Render(chip)
	}
	return []string{
		stLabel.Render("BLAST RADIUS"),
		m.histogram(histW, c, h, md, total) + "  " + counts,
		third,
	}
}

func (m Model) logoLines() []string {
	bar := lipgloss.NewStyle().Foreground(colLive).Render(m.gl.spineActive)
	return []string{
		bar + " " + stHeading.Render("BUMPER"),
		bar + " " + lipgloss.NewStyle().Foreground(colChrome).Render(strings.Repeat(m.gl.dash, 6)),
		"  " + stDim.Render("hazard console"),
	}
}

func (m Model) headerTiny(c, h, md, total int) string {
	mode := "SCAN"
	if m.mode == modeRuleset {
		mode = "RULESET"
	}
	s := stHeading.Render("BUMPER") + " " + stLabel.Render(mode) + "  " +
		m.histogram(12, c, h, md, total) + stDim.Render(fmt.Sprintf("  %d", total))
	return clampLine(s, m.w)
}

func (m Model) headerCompact(c, h, md, total int) string {
	mode := "SCAN"
	meta := m.target
	if m.mode == modeRuleset {
		tr, cu := m.sourceCounts()
		mode, meta = "RULESET", fmt.Sprintf("%d trivy · %d custom", tr, cu)
	}
	line1 := stHeading.Render("BUMPER") + "  " + stLive.Render(mode) + "  " + stDim.Render(meta)
	counts := fmt.Sprintf("%s %d  %s %d  %s %d",
		lipgloss.NewStyle().Foreground(colCrit).Render("C"), c,
		lipgloss.NewStyle().Foreground(colHigh).Render("H"), h,
		lipgloss.NewStyle().Foreground(colMed).Render("M"), md)
	line2 := m.histogram(14, c, h, md, total) + "  " + counts
	if chip := m.filterChip(); chip != "" {
		line2 += "  " + stLive.Render(chip)
	}
	return clampLine(line1, m.w) + "\n" + clampLine(line2, m.w)
}

func getLine(lines []string, i int) string {
	if i < len(lines) {
		return lines[i]
	}
	return ""
}

func alignRight(s string, width int) string {
	w := lipgloss.Width(s)
	if w >= width {
		return s
	}
	return strings.Repeat(" ", width-w) + s
}

func (m Model) histogram(width, c, h, md, total int) string {
	if total == 0 || width <= 0 {
		return stDim.Render(strings.Repeat(m.gl.histEmpty, width))
	}
	cw := c * width / total
	hw := h * width / total
	mw := md * width / total
	// ensure any nonzero category shows at least one cell
	for _, p := range []struct {
		n int
		w *int
	}{{c, &cw}, {h, &hw}, {md, &mw}} {
		if p.n > 0 && *p.w == 0 {
			*p.w = 1
		}
	}
	used := cw + hw + mw
	if used > width {
		used = width
	}
	seg := func(col lipgloss.Color, n int) string {
		if n <= 0 {
			return ""
		}
		return lipgloss.NewStyle().Foreground(col).Render(strings.Repeat(m.gl.histFull, n))
	}
	out := seg(colCrit, cw) + seg(colHigh, hw) + seg(colMed, mw)
	if rem := width - used; rem > 0 {
		out += stDim.Render(strings.Repeat(m.gl.histEmpty, rem))
	}
	return out
}

// --- body ---

func (m Model) renderBody(L layoutDims) string {
	if L.single {
		if m.focus == focusDetail {
			return m.renderDetailPane(L)
		}
		return m.renderListPane(L)
	}
	left := m.renderListPane(L)
	right := m.renderDetailPane(L)
	div := m.dividerColumn(L.bodyH)
	return lipgloss.JoinHorizontal(lipgloss.Top, left, div, right)
}

func (m Model) dividerColumn(h int) string {
	col := stLabel.Render(" " + m.gl.vbar + " ")
	lines := make([]string, h)
	for i := range lines {
		lines[i] = col
	}
	return strings.Join(lines, "\n")
}

func (m Model) renderListPane(L layoutDims) string {
	w := L.listW
	title := m.paneTitle("FINDINGS", w, m.focus == focusList)
	if m.mode == modeRuleset {
		title = m.paneTitle("RULES", w, m.focus == focusList)
	}

	contentH := L.bodyH - 1
	if len(m.visible) == 0 {
		empty := stDim.Render("  no entries match")
		return title + "\n" + padBlock(empty, w, contentH)
	}

	perRow := 2
	fit := contentH / perRow
	if fit < 1 {
		fit = 1
	}
	start := 0
	if m.cursor >= fit {
		start = m.cursor - fit + 1
	}
	end := start + fit
	if end > len(m.visible) {
		end = len(m.visible)
	}

	var rows []string
	for i := start; i < end; i++ {
		e := m.entries[m.visible[i]]
		rows = append(rows, m.renderRow(e, i == m.cursor, w))
	}
	body := strings.Join(rows, "\n")
	return title + "\n" + padBlock(body, w, contentH)
}

func (m Model) renderRow(e entry, selected bool, width int) string {
	sc := sevColor(e.severity)
	spineCh := m.gl.spine
	if selected || (e.severity == "critical" && m.pulseOn) {
		spineCh = m.gl.spineActive
	}
	spine := lipgloss.NewStyle().Foreground(sc).Render(spineCh)

	titleStyle := stInk
	if selected {
		titleStyle = lipgloss.NewStyle().Foreground(colLive).Bold(true)
	}
	title := titleStyle.Render(truncate(e.primary, width-3))
	sub := stDim.Render(truncate(sevTag(e.severity)+" "+m.gl.bullet+" "+e.secondary, width-4))

	return spine + " " + title + "\n" + spine + "  " + sub
}

func (m Model) renderDetailPane(L layoutDims) string {
	active := m.focus == focusDetail || L.single
	title := m.paneTitle(m.detailTitle(), L.detailW, active)
	return title + "\n" + m.detail.View()
}

func (m Model) detailTitle() string {
	if m.mode == modeRuleset {
		return "RULE"
	}
	return "DETAIL"
}

// renderDetail returns the scrollable detail CONTENT for the current entry.
func (m Model) renderDetail(e entry) string {
	w := m.detail.Width
	if w < 8 {
		w = 8
	}
	wrap := lipgloss.NewStyle().Width(w)
	sc := sevColor(e.severity)

	var b strings.Builder
	head := lipgloss.NewStyle().Foreground(sc).Bold(true).Render(m.gl.spine+" "+strings.ToUpper(e.severity)) +
		stDim.Render("  "+e.id)
	b.WriteString(head + "\n\n")

	if e.kind == kindFinding {
		b.WriteString(stLabel.Render("resource") + "  " + stInk.Render(e.secondary) + "\n\n")
		b.WriteString(wrap.Foreground(colInk).Render(e.primary) + "\n\n")
		if e.finding.Fix != "" {
			b.WriteString(stLabel.Render("FIX") + "\n")
			b.WriteString(wrap.Foreground(colDim).Render(e.finding.Fix) + "\n\n")
		}
		if m.rset != nil {
			if r, ok := m.rset.ByID(e.id); ok {
				b.WriteString(provLine(r.Source, r.AVD))
			}
		}
		for _, ref := range e.finding.Refs {
			b.WriteString(stLabel.Render("ref") + "     " + stDim.Render(ref) + "\n")
		}
		b.WriteString("\n" + m.explainBlock(e, w))
	} else {
		r := e.rule
		b.WriteString(provLine(r.Source, r.AVD))
		res := r.Resource
		if res == "" {
			res = "(any resource — see check)"
		}
		actions := "any change"
		if len(r.On) > 0 {
			actions = strings.Join(r.On, ", ")
		}
		b.WriteString(stLabel.Render("applies") + "  " + stInk.Render(res) + stDim.Render("  on "+actions) + "\n\n")
		b.WriteString(wrap.Foreground(colInk).Render(r.Title) + "\n\n")
		if r.Fix != "" {
			b.WriteString(stLabel.Render("FIX") + "\n" + wrap.Foreground(colDim).Render(r.Fix) + "\n\n")
		}
		b.WriteString(stLabel.Render("CHECK (CEL)") + "\n")
		for _, line := range strings.Split(strings.TrimRight(r.When, "\n"), "\n") {
			b.WriteString(lipgloss.NewStyle().Foreground(colChrome).Render("  "+line) + "\n")
		}
		b.WriteString("\n" + m.explainBlock(e, w))
	}
	return b.String()
}

func provLine(source, avd string) string {
	prov := source
	if avd != "" {
		prov += " · " + avd
	}
	return stLabel.Render("source") + "  " + stInk.Render(prov) + "\n\n"
}

func (m Model) explainBlock(e entry, w int) string {
	st, ok := m.explain[e.explainKey()]
	wrap := lipgloss.NewStyle().Width(w)
	if !ok {
		return stLive.Render(m.gl.arrow + " press e for a plain-English explanation")
	}
	switch st.phase {
	case expPending:
		sp := m.gl.spinner[m.frame%len(m.gl.spinner)]
		return stLive.Render(sp+" consulting AI…") + stDim.Render("  (finding above stands on its own)")
	case expErr:
		return stWarn.Render(m.gl.warn+" "+st.err.Error()) + "\n" +
			stDim.Render("the deterministic finding above is complete.")
	default:
		return stLabel.Render("PLAIN ENGLISH") + "\n" + wrap.Foreground(colInk).Render(st.text)
	}
}

// --- footer ---

func (m Model) renderFooter(L layoutDims) string {
	if m.searching {
		return stLive.Render("search ") + m.gl.cur + " " + m.search.View() + stDim.Render("   esc cancel  ⏎ apply")
	}
	var keys []string
	if m.focus == focusDetail {
		keys = []string{"↑↓ scroll", "← back", "e explain", "? help", "q quit"}
	} else if m.mode == modeRuleset {
		keys = []string{"↑↓ move", "→ detail", "v sev", "s source", "/ search", "e explain", "? help", "q quit"}
	} else {
		keys = []string{"↑↓ move", "→ detail", "f filter", "/ search", "e explain", "? help", "q quit"}
	}
	return clampLine(stFooter.Render(strings.Join(keys, "   ")), m.w)
}

// --- overlays / states ---

func (m Model) renderClean() string {
	body := stSafe.Render(m.gl.check+"  NO DANGEROUS CHANGES") + "\n\n" +
		stDim.Render("nothing in this plan exposes or destroys infrastructure") + "\n" +
		stSafe.Render("safe to apply")
	card := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).BorderForeground(colSafe).
		Padding(1, 4).Render(body)
	return lipgloss.Place(m.w, max(m.h, 3), lipgloss.Center, lipgloss.Center, card)
}

func (m Model) renderHelp() string {
	row := func(k, d string) string {
		return stLive.Render(pad(k, 12)) + stDim.Render(d)
	}
	content := stHeading.Render("BUMPER · KEYS") + "\n\n" +
		stLabel.Render("NAVIGATE") + "\n" +
		row("↑ ↓ j k", "move selection") + "\n" +
		row("→ enter", "focus detail") + "\n" +
		row("← esc", "back to list") + "\n" +
		row("g G", "top / bottom") + "\n\n" +
		stLabel.Render("FILTER") + "\n" +
		row("f / v", "cycle severity") + "\n" +
		row("s", "cycle source (ruleset)") + "\n" +
		row("/", "search") + "\n\n" +
		stLabel.Render("ACT") + "\n" +
		row("e", "AI plain-English explain") + "\n" +
		row("tab", "findings ⇄ ruleset") + "\n" +
		row("q ctrl-c", "quit")
	card := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).BorderForeground(colLive).
		Padding(1, 3).Render(content)
	return lipgloss.Place(m.w, max(m.h, 3), lipgloss.Center, lipgloss.Center, card)
}

// --- helpers ---

func (m Model) counts() (crit, high, med int) {
	for _, e := range m.entries {
		switch e.severity {
		case "critical":
			crit++
		case "high":
			high++
		case "medium":
			med++
		}
	}
	return
}

func (m Model) sourceCounts() (trivy, custom int) {
	for _, e := range m.entries {
		if e.rule == nil {
			continue
		}
		if e.rule.Source == "trivy" {
			trivy++
		} else {
			custom++
		}
	}
	return
}

func (m Model) filterChip() string {
	var parts []string
	if m.sevFilter != "" {
		parts = append(parts, "sev="+m.sevFilter)
	}
	if m.srcFilter != "" {
		parts = append(parts, "source="+m.srcFilter)
	}
	if len(parts) == 0 {
		return ""
	}
	return "⦗ " + strings.Join(parts, " ") + " ⦘"
}

func (m Model) paneTitle(label string, width int, active bool) string {
	lab := stLabel.Render(label)
	if active {
		lab = stLive.Render(label)
	}
	used := lipgloss.Width(lab) + 1
	n := width - used
	if n < 0 {
		n = 0
	}
	return lab + " " + lipgloss.NewStyle().Foreground(colChrome).Render(strings.Repeat(m.gl.dash, n))
}

func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n == 1 {
		return string(r[:1])
	}
	return string(r[:n-1]) + "…"
}

// pad a single line to exactly width (right-pad with spaces).
func pad(s string, width int) string {
	w := lipgloss.Width(s)
	if w >= width {
		return s
	}
	return s + strings.Repeat(" ", width-w)
}

// clampLine truncates respecting ANSI styling (safe for styled strings).
func clampLine(s string, width int) string {
	return lipgloss.NewStyle().MaxWidth(width).Render(s)
}

// padBlock normalizes a block to exactly h lines, each exactly width wide
// (ANSI-aware), so horizontal joins stay aligned.
func padBlock(s string, width, h int) string {
	raw := strings.Split(s, "\n")
	lines := make([]string, 0, h)
	for _, ln := range raw {
		ln = lipgloss.NewStyle().MaxWidth(width).Render(ln)
		lines = append(lines, pad(ln, width))
	}
	for len(lines) < h {
		lines = append(lines, strings.Repeat(" ", width))
	}
	if len(lines) > h {
		lines = lines[:h]
	}
	return strings.Join(lines, "\n")
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
