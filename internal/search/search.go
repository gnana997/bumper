// Package search provides relevance-ranked lookup over bumper's rule corpus.
//
// Today it searches the enforced rule set (the 100+ executable CEL rules). It is
// deliberately structured so an *advisory* catalog (Trivy/KICS/Prowler metadata,
// embedded later) can be added as a second corpus without changing callers: a
// Result carries an Enforced flag, and the ranking is corpus-agnostic. The
// agent-facing value is "what should I bake in before writing Terraform for X" —
// so search ranks by relevance to a free-text query and/or a resource type.
package search

import (
	"sort"
	"strings"

	"github.com/gnana997/bumper/internal/engine"
	"github.com/gnana997/bumper/internal/rules"
)

// DefaultLimit caps results when Query.Limit is unset.
const DefaultLimit = 20

// Query is a search request. Text is the free-text query; Provider/Severity/
// Resource are exact-ish filters. An empty Text with a filter set returns all
// matching rules ranked by severity (useful for "all rules for this resource").
type Query struct {
	Text     string
	Provider string
	Severity string
	Resource string
	Limit    int // 0 => DefaultLimit
}

// Result is one ranked hit. Enforced is true for the executable rule set; an
// advisory-catalog corpus would surface Enforced=false entries here later.
type Result struct {
	Rule     *rules.Rule
	Score    int
	Enforced bool
}

// Rules ranks the enforced rule set against q and returns the top matches,
// most relevant first (ties broken by severity, then id).
func Rules(set *rules.Set, q Query) []Result {
	terms := tokenize(q.Text)
	limit := q.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}

	var out []Result
	for _, r := range set.Rules {
		if q.Provider != "" && !strings.EqualFold(r.Provider, q.Provider) {
			continue
		}
		if q.Severity != "" && !strings.EqualFold(r.Severity, q.Severity) {
			continue
		}
		if q.Resource != "" && !matchesResource(r, q.Resource) {
			continue
		}
		score := relevance(r, terms)
		if len(terms) > 0 && score == 0 {
			continue // a text query that matched nothing in this rule
		}
		out = append(out, Result{Rule: r, Score: score, Enforced: true})
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		if ri, rj := engine.Rank(out[i].Rule.Severity), engine.Rank(out[j].Rule.Severity); ri != rj {
			return ri > rj
		}
		return out[i].Rule.ID < out[j].Rule.ID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// tokenize lowercases and splits a free-text query into whitespace-separated
// terms. Matching is substring-based, so "s3" still hits "aws_s3_bucket".
func tokenize(text string) []string {
	return strings.Fields(strings.ToLower(text))
}

// relevance scores a rule against the query terms. With no terms (pure filter
// query) every rule scores a base 1 so it passes through, ranked by severity.
// Otherwise each term contributes its best-matching field weight; a rule that
// matches no term scores 0 and is dropped by the caller.
func relevance(r *rules.Rule, terms []string) int {
	if len(terms) == 0 {
		return 1
	}
	id := strings.ToLower(r.ID)
	title := strings.ToLower(r.Title)
	resource := strings.ToLower(r.Resource)
	fix := strings.ToLower(r.Fix)

	score := 0
	for _, t := range terms {
		s := 0
		if id == t {
			s = max(s, 12)
		} else if strings.Contains(id, t) {
			s = max(s, 5)
		}
		if strings.Contains(resource, t) {
			s = max(s, 4)
		}
		if strings.Contains(title, t) {
			s = max(s, 3)
		}
		if strings.Contains(fix, t) {
			s = max(s, 1)
		}
		score += s
	}
	return score
}

// matchesResource matches a rule against a wanted resource type. For a
// resource-filtered rule it compares the resource field; for a type-less rule
// (the destruction / cross-type families, whose types live in the CEL `type in
// [...]` guard) it falls back to the predicate text so e.g. searching
// "aws_db_instance" still surfaces AWS_STATEFUL_RESOURCE_DESTROY.
func matchesResource(r *rules.Rule, want string) bool {
	w := strings.ToLower(want)
	if r.Resource != "" {
		return strings.Contains(strings.ToLower(r.Resource), w)
	}
	return strings.Contains(strings.ToLower(r.When), w)
}
