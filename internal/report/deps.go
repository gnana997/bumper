package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/gnana997/bumper/internal/deps"
	"github.com/gnana997/bumper/internal/style"
)

var depsSevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}

func depsWorst(f deps.ScanFinding) int {
	if len(f.Malware) > 0 {
		return -1
	}
	r := 9
	for _, v := range f.Vulns {
		if x, ok := depsSevRank[v.Severity]; ok && x < r {
			r = x
		}
	}
	return r
}

func depsSorted(res *deps.ScanResult) []deps.ScanFinding {
	out := append([]deps.ScanFinding(nil), res.Findings...)
	sort.SliceStable(out, func(i, j int) bool {
		if wi, wj := depsWorst(out[i]), depsWorst(out[j]); wi != wj {
			return wi < wj
		}
		return out[i].Package < out[j].Package
	})
	return out
}

// DepsText prints a human-readable, severity-sorted dependency scan summary.
func DepsText(w io.Writer, res *deps.ScanResult, label string) {
	p := style.New(w)
	if res.VulnerableCount == 0 && res.MalwareCount == 0 {
		fmt.Fprintf(w, "%s bumper deps: scanned %d dependencies (%s) — no known vulnerabilities or malicious packages.\n",
			p.OK(p.Glyphs.Check), res.Scanned, label)
		return
	}
	fmt.Fprintf(w, "bumper deps — %d dependencies scanned (%s)\n\n", res.Scanned, label)
	for _, f := range depsSorted(res) {
		for _, m := range f.Malware {
			fmt.Fprintf(w, "  %s  %s@%s (%s) — %s: %s\n",
				p.Severity("critical", "MALICIOUS"), f.Package, f.Version, f.Ecosystem, m.ID, m.Summary)
		}
		for _, v := range f.Vulns {
			fix := "no fix yet"
			if v.FixedVersion != "" {
				fix = "fix → " + v.FixedVersion
			}
			fmt.Fprintf(w, "  %s  %s@%s (%s)  %s  %s\n",
				p.Severity(v.Severity, fmt.Sprintf("%-8s", strings.ToUpper(v.Severity))),
				f.Package, f.Version, f.Ecosystem, v.ID, fix)
		}
	}
	fmt.Fprintf(w, "\n%d vulnerable, %d malicious package(s). Full detail via the bumper-advisor MCP (get_vuln).\n",
		res.VulnerableCount, res.MalwareCount)
}

// DepsJSON writes the raw scan result as indented JSON (for agents / further tooling).
func DepsJSON(w io.Writer, res *deps.ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}

// DepsSARIF writes the scan as a SARIF 2.1.0 log GitHub code scanning ingests; each
// CVE/MAL id is a rule, each affected package an attributed result.
func DepsSARIF(w io.Writer, res *deps.ScanResult, artifactURI string) error {
	if artifactURI == "" || artifactURI == "-" {
		artifactURI = "lockfile"
	}
	ruleIndex := map[string]int{}
	var rules []sarifRuleDesc
	var results []sarifResult

	emit := func(id, sev, title, helpURI string, f deps.ScanFinding) {
		idx, ok := ruleIndex[id]
		if !ok {
			idx = len(rules)
			ruleIndex[id] = idx
			rules = append(rules, sarifRuleDesc{
				ID:                   id,
				Name:                 id,
				ShortDescription:     sarifText{Text: title},
				HelpURI:              helpURI,
				Help:                 sarifText{Text: title},
				DefaultConfiguration: sarifConfig{Level: sarifLevel(sev)},
				Properties: map[string]interface{}{
					"security-severity": securitySeverity(sev),
					"tags":              []string{"security", "dependencies", f.Ecosystem},
				},
			})
		}
		pv := f.Package + "@" + f.Version
		results = append(results, sarifResult{
			RuleID:    id,
			RuleIndex: idx,
			Level:     sarifLevel(sev),
			Message:   sarifText{Text: fmt.Sprintf("%s in %s (%s)", id, pv, f.Ecosystem)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: artifactURI},
					Region:           sarifRegion{StartLine: 1},
				},
				LogicalLocations: []sarifLogical{{Name: pv, Kind: "module"}},
			}},
			PartialFingerprints: map[string]string{"bumper/v1": id + ":" + pv},
		})
	}

	for _, f := range res.Findings {
		for _, m := range f.Malware {
			title := m.Summary
			if title == "" {
				title = "Malicious package"
			}
			emit(m.ID, "critical", title, "", f)
		}
		for _, v := range f.Vulns {
			emit(v.ID, v.Severity, v.ID+" affects "+f.Package, "", f)
		}
	}
	if rules == nil {
		rules = []sarifRuleDesc{}
	}
	if results == nil {
		results = []sarifResult{}
	}
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "bumper-deps",
				InformationURI: "https://github.com/gnana997/bumper",
				Version:        Version,
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// DepsMarkdown writes a sticky-PR-comment summary (its own marker, so it coexists
// with the terraform comment).
func DepsMarkdown(w io.Writer, res *deps.ScanResult) {
	fmt.Fprintln(w, "<!-- bumper-deps -->")
	if res.VulnerableCount == 0 && res.MalwareCount == 0 {
		fmt.Fprintf(w, "### ✅ bumper deps\n\nScanned **%d** dependencies — no known vulnerabilities or malicious packages.\n", res.Scanned)
		return
	}
	fmt.Fprintf(w, "### 🛡️ bumper deps — %d vulnerable, %d malicious\n\n", res.VulnerableCount, res.MalwareCount)
	fmt.Fprintln(w, "| severity | package | id | fix |")
	fmt.Fprintln(w, "| --- | --- | --- | --- |")
	for _, f := range depsSorted(res) {
		for _, m := range f.Malware {
			fmt.Fprintf(w, "| **MALICIOUS** | `%s@%s` | %s | remove |\n", f.Package, f.Version, m.ID)
		}
		for _, v := range f.Vulns {
			fix := "—"
			if v.FixedVersion != "" {
				fix = "`" + v.FixedVersion + "`"
			}
			fmt.Fprintf(w, "| %s | `%s@%s` | %s | %s |\n", v.Severity, f.Package, f.Version, v.ID, fix)
		}
	}
	fmt.Fprintf(w, "\n_Scanned %d dependencies · only package coordinates left the machine. <sub>via [bumper](https://bumper.sh)</sub>_\n", res.Scanned)
}

// FilterDepsSeverity returns a copy keeping only vulns at or above min severity;
// malicious packages are always kept (treated as critical). Recomputes counts.
func FilterDepsSeverity(res *deps.ScanResult, min string) *deps.ScanResult {
	thr, ok := depsSevRank[strings.ToLower(min)]
	if !ok {
		thr = 3 // unknown → "low" (keep everything)
	}
	out := &deps.ScanResult{Status: res.Status, Scanned: res.Scanned, Skipped: res.Skipped, Truncated: res.Truncated}
	for _, f := range res.Findings {
		var vulns []deps.ScanVuln
		for _, v := range f.Vulns {
			if r, ok := depsSevRank[v.Severity]; ok && r <= thr {
				vulns = append(vulns, v)
			}
		}
		if len(vulns) == 0 && len(f.Malware) == 0 {
			continue
		}
		nf := f
		nf.Vulns = vulns
		out.Findings = append(out.Findings, nf)
		if len(vulns) > 0 {
			out.VulnerableCount++
		}
		if len(f.Malware) > 0 {
			out.MalwareCount++
		}
	}
	return out
}
