// Package report renders engine findings as text or JSON.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/gnana097/bumper/internal/engine"
)

// Text writes a human-readable report.
func Text(w io.Writer, findings []engine.Finding) {
	if len(findings) == 0 {
		fmt.Fprintln(w, "✓ bumper: no dangerous changes found in this plan.")
		return
	}
	fmt.Fprintf(w, "bumper found %d issue(s) in this plan:\n\n", len(findings))
	for _, f := range findings {
		fmt.Fprintf(w, "  [%s] %s\n", strings.ToUpper(f.Severity), f.Title)
		fmt.Fprintf(w, "    resource: %s\n", f.Address)
		fmt.Fprintf(w, "    rule:     %s\n", f.RuleID)
		if f.Fix != "" {
			fmt.Fprintf(w, "    fix:      %s\n", f.Fix)
		}
		for _, ref := range f.Refs {
			fmt.Fprintf(w, "    ref:      %s\n", ref)
		}
		fmt.Fprintln(w)
	}
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
				InformationURI: "https://github.com/gnana097/bumper",
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
