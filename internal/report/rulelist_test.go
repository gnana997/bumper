package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/gnana097/bumper/internal/report"
	"github.com/gnana097/bumper/internal/rules"
)

func TestRuleDetail(t *testing.T) {
	set, err := rules.Load("")
	if err != nil {
		t.Fatal(err)
	}
	r, ok := set.ByID("AWS_RDS_PUBLICLY_ACCESSIBLE")
	if !ok {
		t.Fatal("missing expected rule")
	}
	var buf bytes.Buffer
	report.RuleDetail(&buf, r)
	out := buf.String()
	for _, want := range []string{
		"AWS_RDS_PUBLICLY_ACCESSIBLE", "critical", "trivy", "AVD-AWS-0180",
		"check (CEL):", "publicly_accessible",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("RuleDetail missing %q", want)
		}
	}
}

func TestRuleListText(t *testing.T) {
	set, _ := rules.Load("")
	var buf bytes.Buffer
	if err := report.RuleList(&buf, set.Rules, "text"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "SEVERITY") || !strings.Contains(out, "SOURCE") {
		t.Error("text listing missing header")
	}
	if !strings.Contains(out, "AWS_RDS_PUBLICLY_ACCESSIBLE") {
		t.Error("text listing missing a known rule")
	}
}

func TestRuleListJSON(t *testing.T) {
	set, _ := rules.Load("")
	var buf bytes.Buffer
	if err := report.RuleList(&buf, set.Rules, "json"); err != nil {
		t.Fatal(err)
	}
	if !json.Valid(buf.Bytes()) {
		t.Fatal("json listing is not valid JSON")
	}
	if !strings.Contains(buf.String(), `"source": "trivy"`) {
		t.Error("json listing missing source field")
	}
}
