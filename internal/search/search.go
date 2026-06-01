// Package search is bumper's unified, cross-corpus rule search. It builds a
// single in-memory BM25 index over BOTH corpora — the enforced rules (which fire
// on a plan) and the embedded advisory catalog (Trivy/Checkov/KICS/Prowler
// knowledge) — then re-ranks with a small custom policy (enforced boost +
// severity + source priority).
//
// It is deliberately hand-rolled (stdlib only): the corpus is ~2,800 short docs,
// BM25 is stable write-once math, and a transparent scorer fits bumper's
// single-static-binary, CGO-free, auditable supply chain better than pulling in
// a full-text-search engine. Heavy machinery (semantic/vector, hybrid RRF) is
// reserved for the hosted Advisor, which has no CGO/offline constraint.
package search

import (
	"math"
	"sort"
	"strings"

	"github.com/gnana997/bumper/internal/catalog"
	"github.com/gnana997/bumper/internal/engine"
	"github.com/gnana997/bumper/internal/rules"
)

// DefaultLimit caps results when Query.Limit is unset.
const DefaultLimit = 30

// BM25 parameters (Okapi). k1 controls term-frequency saturation, b the
// document-length normalization.
const (
	bm25K1 = 1.2
	bm25B  = 0.75
)

// Field weights — repeated tokens bias BM25 toward the most identifying fields.
const (
	wResource = 3
	wID       = 2
	wTitle    = 2
	wText     = 1
)

// Query is a search request. Empty Text with a filter set returns all matching
// docs ranked by the re-rank policy.
type Query struct {
	Text     string
	Provider string
	Severity string
	Resource string
	Limit    int // 0 => DefaultLimit
}

// Doc is one searchable document spanning both corpora. Exactly one of Rule /
// Entry is set; callers render from the back-pointer so we don't duplicate
// fields. The lowercase fields are the indexed text.
type Doc struct {
	Corpus   string         // "enforced" | "advisory"
	Enforced bool           // true for the executable rule set
	Rule     *rules.Rule    // set iff enforced
	Entry    *catalog.Entry // set iff advisory

	id        string
	provider  string
	severity  string
	source    string
	title     string
	text      string
	resources []string
}

// Hit is a ranked document: Score is the final re-ranked score, Relevance is the
// raw BM25 contribution (used for the topicality floor).
type Hit struct {
	Doc       Doc
	Score     float64
	Relevance float64
}

// Index is a BM25 index over a fixed set of docs.
type Index struct {
	docs []Doc
	tf   []map[string]int // weighted term frequency per doc
	len  []float64        // weighted length per doc
	df   map[string]int   // document frequency per term
	avg  float64          // average doc length
	n    int
}

// BuildDocs flattens both corpora into searchable docs.
func BuildDocs(set *rules.Set, cat *catalog.Catalog) []Doc {
	docs := make([]Doc, 0, len(set.Rules)+cat.Total())
	for _, r := range set.Rules {
		var res []string
		if r.Resource != "" {
			res = []string{r.Resource}
		}
		docs = append(docs, Doc{
			Corpus: "enforced", Enforced: true, Rule: r,
			id: r.ID, provider: r.Provider, severity: r.Severity, source: r.Source,
			title: r.Title, text: r.Fix + " " + r.When, resources: res,
		})
	}
	for _, e := range cat.Entries() {
		ee := e
		docs = append(docs, Doc{
			Corpus: "advisory", Enforced: false, Entry: &ee,
			id: e.SourceID, provider: e.Provider, severity: e.Severity, source: e.Source,
			title: e.Title, text: e.Remediation + " " + e.Category, resources: e.Resources,
		})
	}
	return docs
}

// New builds an index directly from the two corpora.
func New(set *rules.Set, cat *catalog.Catalog) *Index { return NewIndex(BuildDocs(set, cat)) }

// NewIndex builds a BM25 index over docs.
func NewIndex(docs []Doc) *Index {
	ix := &Index{docs: docs, df: make(map[string]int), n: len(docs)}
	total := 0.0
	for _, d := range docs {
		tf := docTermFreq(d)
		ix.tf = append(ix.tf, tf)
		l := 0.0
		for t, c := range tf {
			l += float64(c)
			ix.df[t]++
		}
		ix.len = append(ix.len, l)
		total += l
	}
	if ix.n > 0 {
		ix.avg = total / float64(ix.n)
	}
	return ix
}

// Search runs the query and returns ranked hits across both corpora.
func (ix *Index) Search(q Query) []Hit {
	limit := q.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}
	core := tokenize(q.Text)

	// Expand query terms via the synonym map (synonyms at reduced weight).
	weights := map[string]float64{}
	addTerm := func(t string, w float64) {
		if len(t) >= 2 && w > weights[t] {
			weights[t] = w
		}
	}
	for _, t := range core {
		addTerm(t, 1.0)
		for _, s := range synonymsOf(t) {
			addTerm(s, 0.5)
		}
	}

	// Topicality gate: a doc must contain the single most discriminating
	// (highest-IDF) core term, or one of its synonyms. This is what keeps
	// "s3 public" from returning every public-anything rule.
	var required map[string]bool
	if len(core) > 0 {
		best, bestIDF := "", -1.0
		for _, t := range core {
			if idf := ix.idf(t); idf > bestIDF {
				bestIDF, best = idf, t
			}
		}
		required = map[string]bool{best: true}
		for _, s := range synonymsOf(best) {
			required[s] = true
		}
	}

	var hits []Hit
	for i, d := range ix.docs {
		if !passesFilters(d, q) {
			continue
		}
		rel := 0.0
		if len(core) > 0 {
			if !ix.hasAny(i, required) {
				continue
			}
			for t, w := range weights {
				rel += w * ix.bm25(i, t)
			}
			if rel <= 0 {
				continue
			}
		} else {
			rel = 1 // pure-filter query
		}
		hits = append(hits, Hit{Doc: d, Score: rel, Relevance: rel})
	}

	// Rank by PURE relevance (severity breaks ties). Whether a hit is enforced or
	// advisory is expressed by the section split below, NOT by a score boost — so
	// the ranking stays query-stable and easy to reason about (no magic constants
	// added onto an unbounded BM25 score).
	sort.SliceStable(hits, func(a, b int) bool {
		if hits[a].Relevance != hits[b].Relevance {
			return hits[a].Relevance > hits[b].Relevance
		}
		if ra, rb := engine.Rank(hits[a].Doc.severity), engine.Rank(hits[b].Doc.severity); ra != rb {
			return ra > rb
		}
		return hits[a].Doc.id < hits[b].Doc.id
	})

	// Partition. Enforced ("must-fix") stays in relevance order. Advisory is
	// round-robined across its four sources so they share the top, instead of the
	// highest-quality-metadata source (Prowler) dominating the list.
	var enf, adv []Hit
	for _, h := range hits {
		if h.Doc.Enforced {
			enf = append(enf, h)
		} else {
			adv = append(adv, h)
		}
	}
	if len(enf) > limit {
		enf = enf[:limit]
	}
	return append(enf, roundRobinBySource(adv, limit)...)
}

// Split partitions ranked hits into the enforced and advisory groups, each
// preserving rank order.
func Split(hits []Hit) (enforced, advisory []Hit) {
	for _, h := range hits {
		if h.Doc.Enforced {
			enforced = append(enforced, h)
		} else {
			advisory = append(advisory, h)
		}
	}
	return
}

// advisorySources is the round-robin order for the advisory section (sources not
// listed are appended, sorted, so nothing is dropped).
var advisorySources = []string{"prowler", "trivy", "kics", "checkov"}

// roundRobinBySource interleaves advisory hits across their sources — best of
// each, then second-best of each, … — so the four corpora share the top of the
// list rather than one dominating. Each source's slice is already in relevance
// order; the total is capped at limit. This is the diversity policy that
// replaces the old source-priority score boost.
func roundRobinBySource(hits []Hit, limit int) []Hit {
	groups := map[string][]Hit{}
	for _, h := range hits {
		groups[h.Doc.source] = append(groups[h.Doc.source], h)
	}
	ring := make([]string, 0, len(groups))
	seen := map[string]bool{}
	for _, s := range advisorySources {
		if len(groups[s]) > 0 {
			ring, seen[s] = append(ring, s), true
		}
	}
	var extra []string
	for s := range groups {
		if !seen[s] {
			extra = append(extra, s)
		}
	}
	sort.Strings(extra)
	ring = append(ring, extra...)

	out := make([]Hit, 0, limit)
	for len(out) < limit {
		progressed := false
		for _, s := range ring {
			if len(groups[s]) == 0 {
				continue
			}
			out = append(out, groups[s][0])
			groups[s] = groups[s][1:]
			progressed = true
			if len(out) >= limit {
				break
			}
		}
		if !progressed {
			break
		}
	}
	return out
}

func (ix *Index) bm25(i int, term string) float64 {
	tf := ix.tf[i][term]
	if tf == 0 {
		return 0
	}
	idf := ix.idf(term)
	if idf <= 0 {
		return 0
	}
	norm := 1 - bm25B + bm25B*ix.len[i]/ix.avg
	return idf * (float64(tf) * (bm25K1 + 1)) / (float64(tf) + bm25K1*norm)
}

func (ix *Index) idf(term string) float64 {
	df := ix.df[term]
	if df == 0 {
		return 0
	}
	return math.Log(1 + (float64(ix.n)-float64(df)+0.5)/(float64(df)+0.5))
}

func (ix *Index) hasAny(i int, terms map[string]bool) bool {
	for t := range terms {
		if ix.tf[i][t] > 0 {
			return true
		}
	}
	return false
}

func passesFilters(d Doc, q Query) bool {
	if q.Provider != "" && !strings.EqualFold(d.provider, q.Provider) {
		return false
	}
	if q.Severity != "" && !strings.EqualFold(d.severity, q.Severity) {
		return false
	}
	if q.Resource != "" {
		w := strings.ToLower(q.Resource)
		ok := false
		for _, r := range d.resources {
			if strings.Contains(strings.ToLower(r), w) {
				ok = true
				break
			}
		}
		// type-less enforced rules carry their types in the predicate text
		if !ok && strings.Contains(strings.ToLower(d.text), w) {
			ok = true
		}
		if !ok {
			return false
		}
	}
	return true
}

func docTermFreq(d Doc) map[string]int {
	tf := make(map[string]int)
	addField(tf, d.id, wID)
	addField(tf, d.title, wTitle)
	addField(tf, d.text, wText)
	for _, r := range d.resources {
		addField(tf, r, wResource)
	}
	return tf
}

func addField(tf map[string]int, s string, weight int) {
	for _, t := range tokenize(s) {
		tf[t] += weight
	}
}

func tokenize(s string) []string {
	fields := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
	})
	out := fields[:0]
	for _, f := range fields {
		if len(f) >= 2 {
			out = append(out, f)
		}
	}
	return out
}
