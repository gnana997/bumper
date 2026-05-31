// Package engine evaluates a compiled rule set against normalized plan changes
// and returns ranked findings. It is deliberately dependency-light: the LLM
// enrichment lives elsewhere, so findings here are complete on their own.
package engine

import (
	"sort"

	"github.com/gnana097/bumper/internal/plan"
	"github.com/gnana097/bumper/internal/rules"
)

// Finding is one triggered rule against one resource.
type Finding struct {
	RuleID   string   `json:"rule_id"`
	Severity string   `json:"severity"`
	Title    string   `json:"title"`
	Address  string   `json:"address"`
	Fix      string   `json:"fix,omitempty"`
	Refs     []string `json:"refs,omitempty"`
	Provider string   `json:"provider,omitempty"`
	Source   string   `json:"source,omitempty"`
}

var severityRank = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
	"info":     0,
}

// Rank returns the numeric severity rank (higher = more severe); unknown
// severities rank as 0.
func Rank(severity string) int { return severityRank[severity] }

// Evaluate runs every applicable rule against every change. Findings are sorted
// by severity (highest first), then by resource address.
func Evaluate(changes []plan.ResourceChange, set *rules.Set) ([]Finding, error) {
	var findings []Finding
	for _, c := range changes {
		activation := map[string]interface{}{
			"address": c.Address,
			"type":    c.Type,
			"actions": c.Actions,
			"before":  c.Before,
			"after":   c.After,
		}
		for _, r := range set.Rules {
			if r.Resource != "" && r.Resource != c.Type {
				continue
			}
			if !actionMatches(r.On, c.Actions) {
				continue
			}
			out, _, err := r.Program().Eval(activation)
			if err != nil {
				// A rule that errors on this resource (typically a missing
				// field the predicate didn't guard) is treated as "no match"
				// rather than failing the whole run.
				continue
			}
			if b, ok := out.Value().(bool); ok && b {
				findings = append(findings, Finding{
					RuleID:   r.ID,
					Severity: r.Severity,
					Title:    r.Title,
					Address:  c.Address,
					Fix:      r.Fix,
					Refs:     r.Refs,
					Provider: r.Provider,
					Source:   r.Source,
				})
			}
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if ri, rj := severityRank[findings[i].Severity], severityRank[findings[j].Severity]; ri != rj {
			return ri > rj
		}
		return findings[i].Address < findings[j].Address
	})
	return findings, nil
}

func actionMatches(on, actions []string) bool {
	if len(on) == 0 {
		return true
	}
	for _, o := range on {
		for _, a := range actions {
			if o == a {
				return true
			}
		}
	}
	return false
}
