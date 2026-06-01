package mcpserver

import (
	"context"
	"os"
	"testing"

	"github.com/gnana997/bumper/internal/rules"
)

func testHandlers(t *testing.T) *handlers {
	t.Helper()
	set, err := rules.Load("")
	if err != nil {
		t.Fatalf("rules.Load: %v", err)
	}
	return &handlers{set: set}
}

// TestNewServer makes sure the server constructs and registers its tools without
// panicking on the inferred schemas.
func TestNewServer(t *testing.T) {
	if _, err := NewServer(""); err != nil {
		t.Fatalf("NewServer: %v", err)
	}
}

func TestScanPlanFindings(t *testing.T) {
	h := testHandlers(t)
	data, err := os.ReadFile("../engine/testdata/plan_sg.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	_, out, err := h.scanPlan(context.Background(), nil, ScanPlanInput{PlanJSON: string(data)})
	if err != nil {
		t.Fatalf("scanPlan: %v", err)
	}
	if out.Summary.Total == 0 {
		t.Fatalf("expected findings from plan_sg.json, got none")
	}
	if out.Summary.Verdict != "findings" {
		t.Errorf("verdict = %q, want findings", out.Summary.Verdict)
	}
	if out.Summary.Source != "inline" {
		t.Errorf("source = %q, want inline", out.Summary.Source)
	}
	if len(out.Findings) != out.Summary.Total {
		t.Errorf("findings len %d != summary total %d", len(out.Findings), out.Summary.Total)
	}
	// plan_sg.json triggers a critical/high public-ingress rule.
	if !out.Summary.Blocking {
		t.Errorf("expected Blocking=true for a public-ingress plan")
	}
}

func TestScanPlanClean(t *testing.T) {
	h := testHandlers(t)
	// A valid plan with a no-op change triggers nothing.
	const clean = `{"format_version":"1.0","resource_changes":[
		{"address":"aws_s3_bucket.x","type":"aws_s3_bucket","name":"x",
		 "change":{"actions":["no-op"],"before":{},"after":{}}}]}`

	_, out, err := h.scanPlan(context.Background(), nil, ScanPlanInput{PlanJSON: clean})
	if err != nil {
		t.Fatalf("scanPlan: %v", err)
	}
	if out.Summary.Total != 0 {
		t.Fatalf("expected clean, got %d findings", out.Summary.Total)
	}
	if out.Summary.Verdict != "clean" {
		t.Errorf("verdict = %q, want clean", out.Summary.Verdict)
	}
	if out.Summary.Blocking {
		t.Errorf("clean plan must not be Blocking")
	}
}

func TestScanPlanMinSeverity(t *testing.T) {
	h := testHandlers(t)
	data, _ := os.ReadFile("../engine/testdata/plan_sg.json")

	_, all, _ := h.scanPlan(context.Background(), nil, ScanPlanInput{PlanJSON: string(data)})
	_, crit, _ := h.scanPlan(context.Background(), nil, ScanPlanInput{PlanJSON: string(data), MinSeverity: "critical"})
	if crit.Summary.Total > all.Summary.Total {
		t.Fatalf("critical-only (%d) should not exceed unfiltered (%d)", crit.Summary.Total, all.Summary.Total)
	}
	for _, f := range crit.Findings {
		if f.Severity != "critical" {
			t.Errorf("min_severity=critical returned %s finding %s", f.Severity, f.RuleID)
		}
	}
}

func TestScanPlanInputErrors(t *testing.T) {
	h := testHandlers(t)
	if _, _, err := h.scanPlan(context.Background(), nil, ScanPlanInput{}); err == nil {
		t.Error("expected error when neither plan_json nor path given")
	}
	if _, _, err := h.scanPlan(context.Background(), nil, ScanPlanInput{Path: "/no/such/plan.json"}); err == nil {
		t.Error("expected error for missing path")
	}
	if _, _, err := h.scanPlan(context.Background(), nil, ScanPlanInput{PlanJSON: "not json"}); err == nil {
		t.Error("expected parse error for non-JSON plan_json")
	}
}

func TestListRules(t *testing.T) {
	h := testHandlers(t)

	_, all, err := h.listRules(context.Background(), nil, ListRulesInput{})
	if err != nil {
		t.Fatalf("listRules: %v", err)
	}
	if all.Count != len(h.set.Rules) {
		t.Fatalf("unfiltered count = %d, want %d", all.Count, len(h.set.Rules))
	}

	_, custom, _ := h.listRules(context.Background(), nil, ListRulesInput{Source: "custom"})
	if custom.Count == 0 || custom.Count >= all.Count {
		t.Errorf("custom-only count = %d, want a non-empty subset of %d", custom.Count, all.Count)
	}
	for _, r := range custom.Rules {
		if r.Source != "custom" {
			t.Errorf("source filter leaked %s rule %s", r.Source, r.ID)
		}
	}

	_, crit, _ := h.listRules(context.Background(), nil, ListRulesInput{Severity: "critical"})
	for _, r := range crit.Rules {
		if r.Severity != "critical" {
			t.Errorf("severity filter leaked %s rule %s", r.Severity, r.ID)
		}
	}
}

func TestExplainRule(t *testing.T) {
	h := testHandlers(t)
	// Pick a real id from the loaded set.
	id := h.set.Rules[0].ID

	_, out, err := h.explainRule(context.Background(), nil, ExplainRuleInput{RuleID: id})
	if err != nil {
		t.Fatalf("explainRule(%s): %v", id, err)
	}
	if out.ID != id {
		t.Errorf("id = %q, want %q", out.ID, id)
	}
	if out.When == "" {
		t.Errorf("expected a CEL predicate for %s", id)
	}
	if out.Source == "" {
		t.Errorf("expected provenance for %s", id)
	}

	if _, _, err := h.explainRule(context.Background(), nil, ExplainRuleInput{RuleID: "NO_SUCH_RULE"}); err == nil {
		t.Error("expected error for unknown rule id")
	}
}
