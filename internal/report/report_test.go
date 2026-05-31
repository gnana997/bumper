package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/gnana097/bumper/internal/engine"
	"github.com/gnana097/bumper/internal/report"
)

func sampleFindings() []engine.Finding {
	return []engine.Finding{
		{RuleID: "AWS_SG_PUBLIC_INGRESS", Severity: "critical", Title: "SG open to the world",
			Address: "aws_security_group.web", Fix: "Restrict cidr_blocks", Refs: []string{"https://example.com/sg"}},
		{RuleID: "AWS_RDS_STORAGE_UNENCRYPTED", Severity: "high", Title: "RDS unencrypted",
			Address: "aws_db_instance.main", Fix: "storage_encrypted = true"},
		// duplicate rule id on a second resource -> one descriptor, two results
		{RuleID: "AWS_SG_PUBLIC_INGRESS", Severity: "critical", Title: "SG open to the world",
			Address: "aws_security_group.api", Fix: "Restrict cidr_blocks", Refs: []string{"https://example.com/sg"}},
	}
}

func TestSARIFStructure(t *testing.T) {
	var buf bytes.Buffer
	if err := report.SARIF(&buf, sampleFindings(), "plan.json"); err != nil {
		t.Fatal(err)
	}

	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID         string                 `json:"id"`
						Properties map[string]interface{} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	if doc.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "bumper" {
		t.Errorf("driver name = %q", run.Tool.Driver.Name)
	}
	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("unique rules = %d, want 2", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 3 {
		t.Errorf("results = %d, want 3", len(run.Results))
	}
	// security-severity must be present for GitHub bucketing.
	if _, ok := run.Tool.Driver.Rules[0].Properties["security-severity"]; !ok {
		t.Error("rule missing security-severity property")
	}
	// critical maps to error.
	if run.Results[0].Level != "error" {
		t.Errorf("critical level = %q, want error", run.Results[0].Level)
	}
	// ruleIndex must point at a valid descriptor.
	for _, r := range run.Results {
		if r.RuleIndex < 0 || r.RuleIndex >= len(run.Tool.Driver.Rules) {
			t.Errorf("ruleIndex %d out of range", r.RuleIndex)
		}
	}
}

func TestSARIFEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := report.SARIF(&buf, nil, "-"); err != nil {
		t.Fatal(err)
	}
	// Must still be valid SARIF with empty (not null) arrays.
	if !json.Valid(buf.Bytes()) {
		t.Fatal("empty SARIF is not valid JSON")
	}
	if !strings.Contains(buf.String(), `"results": []`) {
		t.Error("expected empty results array")
	}
}

func TestMarkdownWithFindings(t *testing.T) {
	var buf bytes.Buffer
	report.Markdown(&buf, sampleFindings())
	out := buf.String()

	for _, want := range []string{
		report.CommentMarker,          // sticky-comment marker
		"3 issue(s)",                  // count
		"2 critical",                  // severity tally
		"aws_security_group.web",      // a resource
		"<details>",                   // collapsible
		"AWS_RDS_STORAGE_UNENCRYPTED", // appears in the table
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
}

func TestMarkdownClean(t *testing.T) {
	var buf bytes.Buffer
	report.Markdown(&buf, nil)
	out := buf.String()
	if !strings.Contains(out, report.CommentMarker) {
		t.Error("clean markdown missing marker (needed to update the sticky comment to green)")
	}
	if !strings.Contains(out, "No dangerous changes") {
		t.Error("clean markdown should report no findings")
	}
}
