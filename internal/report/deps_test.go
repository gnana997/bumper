package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/gnana997/bumper/internal/deps"
)

func sampleScan() *deps.ScanResult {
	return &deps.ScanResult{
		Status: "ok", Scanned: 3,
		Findings: []deps.ScanFinding{
			{Ecosystem: "npm", Package: "lodash", Version: "4.17.4", Vulns: []deps.ScanVuln{
				{ID: "CVE-2019-10744", Severity: "critical", FixedVersion: "4.17.12"},
				{ID: "CVE-2020-8203", Severity: "high", FixedVersion: "4.17.19"},
				{ID: "CVE-2020-28500", Severity: "medium", FixedVersion: "4.17.21"},
			}},
			{Ecosystem: "npm", Package: "evil", Version: "1.0.0", Malware: []deps.ScanMalware{
				{ID: "MAL-2026-1", Summary: "Malicious code in evil"},
			}},
		},
	}
}

func TestFilterDepsSeverity(t *testing.T) {
	r := FilterDepsSeverity(sampleScan(), "high")
	// lodash keeps critical+high (drops medium); evil keeps malware.
	var ld *deps.ScanFinding
	for i := range r.Findings {
		if r.Findings[i].Package == "lodash" {
			ld = &r.Findings[i]
		}
	}
	if ld == nil || len(ld.Vulns) != 2 {
		t.Fatalf("lodash vulns after high filter = %v, want 2 (critical+high)", ld)
	}
	if r.MalwareCount != 1 {
		t.Errorf("malware should always survive the filter, got %d", r.MalwareCount)
	}
	// critical-only drops the high too.
	if r2 := FilterDepsSeverity(sampleScan(), "critical"); len(r2.Findings[0].Vulns)+len(r2.Findings[1].Vulns) != 1 {
		t.Errorf("critical filter should leave exactly 1 vuln across findings")
	}
}

func TestDepsSARIF(t *testing.T) {
	var buf bytes.Buffer
	if err := DepsSARIF(&buf, sampleScan(), "package-lock.json"); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct{ ID string } `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid SARIF json: %v", err)
	}
	if doc.Version != "2.1.0" {
		t.Errorf("version = %q", doc.Version)
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "bumper-deps" {
		t.Errorf("driver = %q", run.Tool.Driver.Name)
	}
	if len(run.Results) != 4 { // 3 vulns + 1 malware
		t.Errorf("results = %d, want 4", len(run.Results))
	}
	// malware maps to error level.
	var malLevel string
	for _, r := range run.Results {
		if r.RuleID == "MAL-2026-1" {
			malLevel = r.Level
		}
	}
	if malLevel != "error" {
		t.Errorf("malware level = %q, want error", malLevel)
	}
}

func TestDepsMarkdownMarker(t *testing.T) {
	var buf bytes.Buffer
	DepsMarkdown(&buf, sampleScan())
	if !strings.Contains(buf.String(), "<!-- bumper-deps -->") {
		t.Error("markdown missing sticky-comment marker")
	}
	var clean bytes.Buffer
	DepsMarkdown(&clean, &deps.ScanResult{Status: "ok", Scanned: 5})
	if !strings.Contains(clean.String(), "no known vulnerabilities") {
		t.Error("clean markdown should say no vulns")
	}
}
