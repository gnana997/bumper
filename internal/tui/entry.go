package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gnana997/bumper/internal/engine"
	"github.com/gnana997/bumper/internal/rules"
)

type entryKind int

const (
	kindFinding entryKind = iota
	kindRule
)

// entry is the shared row model for both modes (findings and ruleset), so the
// list and detail panes are built once.
type entry struct {
	kind      entryKind
	severity  string
	id        string // rule id
	primary   string // title
	secondary string // resource/address (finding) or "source · severity" (rule)
	finding   *engine.Finding
	rule      *rules.Rule
}

// explainKey identifies an AI explanation in the cache. Findings key on
// rule+resource (each occurrence explained once); rules key on id.
func (e entry) explainKey() string {
	if e.kind == kindFinding {
		return "f\x00" + e.id + "\x00" + e.finding.Address
	}
	return "r\x00" + e.id
}

func (e entry) match(q string) bool {
	if q == "" {
		return true
	}
	return strings.Contains(strings.ToLower(e.id+" "+e.primary+" "+e.secondary), strings.ToLower(q))
}

func findingEntries(fs []engine.Finding) []entry {
	out := make([]entry, 0, len(fs))
	for i := range fs {
		f := &fs[i]
		out = append(out, entry{
			kind: kindFinding, severity: f.Severity, id: f.RuleID,
			primary: f.Title, secondary: f.Address, finding: f,
		})
	}
	return out
}

func ruleEntries(rs []*rules.Rule) []entry {
	out := make([]entry, 0, len(rs))
	for _, r := range rs {
		out = append(out, entry{
			kind: kindRule, severity: r.Severity, id: r.ID,
			primary: r.Title, secondary: fmt.Sprintf("%s · %s", r.Source, r.Severity),
			rule: r,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if a, b := sevRank(out[i].severity), sevRank(out[j].severity); a != b {
			return a > b
		}
		return out[i].id < out[j].id
	})
	return out
}
