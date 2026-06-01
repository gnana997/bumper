// Package catalog is bumper's embedded advisory corpus: ~2,600 security
// best-practice records harvested from four Apache-2.0 sources (Trivy/tfsec,
// Checkov, KICS, Prowler), normalized to a common envelope.
//
// It is deliberately FEDERATED, not merged — each source is its own map, with no
// dedup across sources. A query spreads across all four maps in parallel and the
// ranked hits are merged on the way out. This keeps every source independent: a
// source refresh touches only its own files, and the same intent legitimately
// appears from several sources (Trivy's severity, Prowler's fix code, etc.),
// which an agent reconciles.
//
// This is the ADVISORY corpus (knowledge only — no executable predicate). It is
// distinct from internal/rules (the enforced rules that actually fire on a plan).
// IaC misconfig data is stable over months, so it ships embedded for fully
// offline search; the hosted Advisor is for the daily-churn CVE/container domain.
package catalog

import (
	"embed"
	"encoding/json"
	"io/fs"
	"strings"
)

//go:embed data
var dataFS embed.FS

// Sources is the fixed set of corpora, in default priority order (severity +
// real fix code first; coverage filler last).
var Sources = []string{"prowler", "trivy", "kics", "checkov"}

// Entry is one normalized advisory record. Severity may be "" (Checkov OSS ships
// none); FixTerraform is populated only by Prowler.
type Entry struct {
	Source       string   `json:"source"`
	SourceID     string   `json:"source_id"`
	Provider     string   `json:"provider"`
	Resources    []string `json:"resources"`
	Severity     string   `json:"severity"`
	Title        string   `json:"title"`
	Remediation  string   `json:"remediation"`
	FixTerraform string   `json:"fix_terraform,omitempty"`
	Refs         []string `json:"refs"`
	CWE          string   `json:"cwe"`
	Category     string   `json:"category"`
}

// Catalog holds the advisory corpus, one slice per source (the four maps).
type Catalog struct {
	bySource map[string][]Entry
}

// Load reads the embedded data into per-source maps.
func Load() (*Catalog, error) {
	c := &Catalog{bySource: make(map[string][]Entry, len(Sources))}
	err := fs.WalkDir(dataFS, "data", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".json") {
			return err
		}
		b, err := dataFS.ReadFile(path)
		if err != nil {
			return err
		}
		var entries []Entry
		if err := json.Unmarshal(b, &entries); err != nil {
			return err
		}
		// path is data/<source>/<provider>.json
		parts := strings.Split(path, "/")
		src := parts[1]
		c.bySource[src] = append(c.bySource[src], entries...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Count returns the number of entries in a source (0 if unknown).
func (c *Catalog) Count(source string) int { return len(c.bySource[source]) }

// Total returns the total entry count across all sources.
func (c *Catalog) Total() int {
	n := 0
	for _, src := range Sources {
		n += len(c.bySource[src])
	}
	return n
}

// Entries returns every advisory entry across all sources, in source order.
// Ranking/search lives in the unified internal/search index, which spans this
// corpus and the enforced rules together.
func (c *Catalog) Entries() []Entry {
	out := make([]Entry, 0, c.Total())
	for _, src := range Sources {
		out = append(out, c.bySource[src]...)
	}
	return out
}
