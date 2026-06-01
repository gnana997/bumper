// Package report renders engine findings as text or JSON.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/gnana997/bumper/internal/engine"
	"github.com/gnana997/bumper/internal/rules"
	"github.com/gnana997/bumper/internal/style"
)

// Text writes a human-readable report — colored on a terminal, plain when piped.
// Layout mirrors the web app's --explain terminal: a colored severity token, the
// resource, the message, then labeled rule/fix/ref rows, with a severity tally.
func Text(w io.Writer, findings []engine.Finding) {
	p := style.New(w)
	if len(findings) == 0 {
		fmt.Fprintf(w, "%s %s\n", p.OK(p.Glyphs.Check), "bumper: no dangerous changes found in this plan.")
		return
	}
	fmt.Fprintf(w, "bumper found %s in this plan:\n\n", p.Strong(fmt.Sprintf("%d issue(s)", len(findings))))
	for _, f := range findings {
		sev := strings.ToUpper(f.Severity)
		fmt.Fprintf(w, "%s  %s   %s\n", p.Severity(f.Severity, style.PadRight(sev, 8)), p.Strong(f.Address), p.Dim(f.Title))
		fmt.Fprintf(w, "  %s%s\n", p.Faint(fmt.Sprintf("%-6s", "rule")), f.RuleID)
		if f.Fix != "" {
			fmt.Fprintf(w, "  %s%s\n", p.Faint(fmt.Sprintf("%-6s", "fix")), p.OK(f.Fix))
		}
		for _, ref := range f.Refs {
			fmt.Fprintf(w, "  %s%s\n", p.Faint(fmt.Sprintf("%-6s", "ref")), p.Dim(ref))
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, severityTally(p, findings))
}

// severityTally renders "3 findings   2 critical · 1 high" with each count colored
// by its severity — the calm summary line under a findings block.
func severityTally(p *style.Palette, findings []engine.Finding) string {
	var n [5]int // critical, high, medium, low, other
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			n[0]++
		case "high":
			n[1]++
		case "medium":
			n[2]++
		case "low":
			n[3]++
		default:
			n[4]++
		}
	}
	parts := []string{}
	add := func(sev string, c int) {
		if c > 0 {
			parts = append(parts, p.Severity(sev, fmt.Sprintf("%d %s", c, sev)))
		}
	}
	add("critical", n[0])
	add("high", n[1])
	add("medium", n[2])
	add("low", n[3])
	head := p.Faint(fmt.Sprintf("%d finding(s)", len(findings)))
	if len(parts) == 0 {
		return head
	}
	return head + "   " + strings.Join(parts, p.Faint(" · "))
}

// JSON writes findings as an indented JSON array.
func JSON(w io.Writer, findings []engine.Finding) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(findings)
}

// CommentMarker is the hidden HTML marker that lets the PR-comment surface find
// and update its previous comment in place rather than posting a new one.
const CommentMarker = "<!-- bumper -->"

func sarifLevel(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

// securitySeverity is the CVSS-like 0-10 score GitHub code scanning uses to
// bucket findings in the Security tab.
func securitySeverity(severity string) string {
	switch severity {
	case "critical":
		return "9.0"
	case "high":
		return "7.0"
	case "medium":
		return "5.0"
	case "low":
		return "3.0"
	default:
		return "1.0"
	}
}

func severityEmoji(severity string) string {
	switch severity {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	default:
		return "⚪"
	}
}

// --- SARIF 2.1.0 ---

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string          `json:"name"`
	InformationURI string          `json:"informationUri"`
	Version        string          `json:"version"`
	Rules          []sarifRuleDesc `json:"rules"`
}

type sarifRuleDesc struct {
	ID                   string                 `json:"id"`
	Name                 string                 `json:"name"`
	ShortDescription     sarifText              `json:"shortDescription"`
	HelpURI              string                 `json:"helpUri,omitempty"`
	Help                 sarifText              `json:"help"`
	DefaultConfiguration sarifConfig            `json:"defaultConfiguration"`
	Properties           map[string]interface{} `json:"properties"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical  `json:"physicalLocation"`
	LogicalLocations []sarifLogical `json:"logicalLocations,omitempty"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifLogical struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// Version is the tool version embedded in SARIF output.
var Version = "0.1.0"

// SARIF writes findings as a SARIF 2.1.0 log that GitHub code scanning ingests.
// artifactURI is the file the results are attributed to (the plan file).
func SARIF(w io.Writer, findings []engine.Finding, artifactURI string) error {
	if artifactURI == "" || artifactURI == "-" {
		artifactURI = "terraform-plan.json"
	}

	ruleIndex := map[string]int{}
	var rules []sarifRuleDesc
	var results []sarifResult

	for _, f := range findings {
		idx, ok := ruleIndex[f.RuleID]
		if !ok {
			idx = len(rules)
			ruleIndex[f.RuleID] = idx
			helpURI := ""
			if len(f.Refs) > 0 {
				helpURI = f.Refs[0]
			}
			rules = append(rules, sarifRuleDesc{
				ID:                   f.RuleID,
				Name:                 f.RuleID,
				ShortDescription:     sarifText{Text: f.Title},
				HelpURI:              helpURI,
				Help:                 sarifText{Text: f.Fix},
				DefaultConfiguration: sarifConfig{Level: sarifLevel(f.Severity)},
				Properties: map[string]interface{}{
					"security-severity": securitySeverity(f.Severity),
					"tags":              []string{"security", "terraform"},
				},
			})
		}
		results = append(results, sarifResult{
			RuleID:    f.RuleID,
			RuleIndex: idx,
			Level:     sarifLevel(f.Severity),
			Message:   sarifText{Text: f.Title + " (resource: " + f.Address + ")"},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: artifactURI},
					Region:           sarifRegion{StartLine: 1},
				},
				LogicalLocations: []sarifLogical{{Name: f.Address, Kind: "resource"}},
			}},
			PartialFingerprints: map[string]string{"bumper/v1": f.RuleID + ":" + f.Address},
		})
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
				Name:           "bumper",
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

// --- Markdown PR comment ---

// --- Rule listing (`bumper list` / `bumper explain`) ---

type ruleRow struct {
	ID       string   `json:"id"`
	Severity string   `json:"severity"`
	Source   string   `json:"source"`
	AVD      string   `json:"avd,omitempty"`
	Resource string   `json:"resource,omitempty"`
	Title    string   `json:"title"`
	Fix      string   `json:"fix,omitempty"`
	Refs     []string `json:"refs,omitempty"`
}

// RuleList renders a rule set as an aligned text table or JSON. The text table is
// colored on a terminal: severity by its color, the id in bold, source/resource
// dimmed. Columns are padded as plain text first, then colored, so the ANSI codes
// (zero display width) never throw off the alignment.
func RuleList(w io.Writer, rs []*rules.Rule, format string) error {
	if format == "json" {
		rows := make([]ruleRow, 0, len(rs))
		for _, r := range rs {
			rows = append(rows, ruleRow{r.ID, r.Severity, r.Source, r.AVD, r.Resource, r.Title, r.Fix, r.Refs})
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
	}

	p := style.New(w)
	type trow struct{ sev, src, id, res, title string }
	rows := make([]trow, len(rs))
	wSev, wSrc, wID, wRes := len("SEVERITY"), len("SOURCE"), len("ID"), len("RESOURCE")
	for i, r := range rs {
		res := r.Resource
		if res == "" {
			res = "(multiple)"
		}
		rows[i] = trow{r.Severity, r.Source, r.ID, res, truncate(r.Title, 60)}
		wSev, wSrc = max(wSev, len(r.Severity)), max(wSrc, len(r.Source))
		wID, wRes = max(wID, len(r.ID)), max(wRes, len(res))
	}
	fmt.Fprintln(w, p.Faint(fmt.Sprintf("%-*s  %-*s  %-*s  %-*s  %s",
		wSev, "SEVERITY", wSrc, "SOURCE", wID, "ID", wRes, "RESOURCE", "TITLE")))
	for _, r := range rows {
		fmt.Fprintf(w, "%s  %s  %s  %s  %s\n",
			p.Severity(r.sev, fmt.Sprintf("%-*s", wSev, r.sev)),
			p.Dim(fmt.Sprintf("%-*s", wSrc, r.src)),
			p.Strong(fmt.Sprintf("%-*s", wID, r.id)),
			p.Dim(fmt.Sprintf("%-*s", wRes, r.res)),
			r.title)
	}
	fmt.Fprintf(w, "\n%s\n", p.Faint(fmt.Sprintf("%d rule(s)", len(rs))))
	return nil
}

// RuleDetail prints one rule, including its CEL check (the spec's
// "reproducible, explainable" pillar — you can see exactly what fires).
func RuleDetail(w io.Writer, r *rules.Rule) {
	p := style.New(w)
	fmt.Fprintf(w, "%s  %s\n", p.Strong(r.ID), p.Severity(r.Severity, "["+r.Severity+"]"))
	fmt.Fprintf(w, "%s\n\n", r.Title)

	label := func(s string) string { return p.Faint(fmt.Sprintf("  %-9s", s)) }

	prov := r.Source
	if r.AVD != "" {
		prov += " · " + r.AVD
	}
	fmt.Fprintf(w, "%s%s\n", label("source:"), p.Dim(prov))

	resource := r.Resource
	if resource == "" {
		resource = "(any resource — see check)"
	}
	actions := "any change"
	if len(r.On) > 0 {
		actions = strings.Join(r.On, ", ")
	}
	fmt.Fprintf(w, "%s%s  %s\n", label("applies:"), p.Strong(resource), p.Faint("on ["+actions+"]"))
	if r.Fix != "" {
		fmt.Fprintf(w, "%s%s\n", label("fix:"), p.OK(r.Fix))
	}
	for _, ref := range r.Refs {
		fmt.Fprintf(w, "%s%s\n", label("ref:"), p.Dim(ref))
	}
	fmt.Fprintln(w, p.Faint("  check (CEL):"))
	for _, line := range strings.Split(strings.TrimRight(r.When, "\n"), "\n") {
		fmt.Fprintf(w, "    %s\n", p.Dim(line))
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// Markdown writes a PR-comment body: a hidden marker (so the comment can be
// updated in place), a severity summary, the critical/high findings inline, and
// the full list in a collapsible section.
func Markdown(w io.Writer, findings []engine.Finding) {
	fmt.Fprintln(w, CommentMarker)
	fmt.Fprintln(w, "## 🛡️ bumper — Terraform plan safety")
	fmt.Fprintln(w)

	if len(findings) == 0 {
		fmt.Fprintln(w, "✅ No dangerous changes found in this plan.")
		return
	}

	var crit, high, med, other int
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			crit++
		case "high":
			high++
		case "medium":
			med++
		default:
			other++
		}
	}
	fmt.Fprintf(w, "**%d issue(s)** — %s %d critical · %s %d high · %s %d medium\n",
		len(findings), severityEmoji("critical"), crit, severityEmoji("high"), high, severityEmoji("medium"), med)
	fmt.Fprintln(w)

	// Inline the must-fix (critical + high) findings.
	shown := 0
	for _, f := range findings {
		if f.Severity != "critical" && f.Severity != "high" {
			continue
		}
		fmt.Fprintf(w, "- %s **%s** — `%s`\n", severityEmoji(f.Severity), f.Title, f.Address)
		shown++
	}
	if shown == 0 {
		fmt.Fprintln(w, "_No critical/high findings; see details below._")
	}
	fmt.Fprintln(w)

	// Full list, collapsed.
	fmt.Fprintln(w, "<details><summary>All findings</summary>")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Severity | Rule | Resource | Fix |")
	fmt.Fprintln(w, "|---|---|---|---|")
	for _, f := range findings {
		fix := strings.ReplaceAll(f.Fix, "|", "\\|")
		fmt.Fprintf(w, "| %s %s | `%s` | `%s` | %s |\n",
			severityEmoji(f.Severity), f.Severity, f.RuleID, f.Address, fix)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "</details>")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "<sub>Posted by bumper — deterministic Terraform plan safety gate.</sub>")
}
