package tui

import (
	"os"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/gnana097/bumper/internal/engine"
	"github.com/gnana097/bumper/internal/rules"
)

func sample() []engine.Finding {
	return []engine.Finding{
		{RuleID: "AWS_RDS_PUBLICLY_ACCESSIBLE", Severity: "critical",
			Title:   "RDS instance is publicly accessible from the internet",
			Address: "aws_db_instance.public", Fix: "Set publicly_accessible = false and use private subnets.",
			Refs: []string{"https://docs.aws.amazon.com/rds"}},
		{RuleID: "AWS_SG_PUBLIC_INGRESS", Severity: "critical",
			Title:   "Security group allows public internet ingress (0.0.0.0/0 or ::/0)",
			Address: "aws_security_group.open"},
		{RuleID: "AWS_STATEFUL_RESOURCE_DESTROY", Severity: "high",
			Title:   "This apply will DELETE or REPLACE a stateful data resource",
			Address: "aws_dynamodb_table.sessions"},
		{RuleID: "AWS_EBS_VOLUME_UNENCRYPTED", Severity: "high",
			Title: "EBS volume is not encrypted at rest", Address: "aws_ebs_volume.data"},
	}
}

func sized(m Model, w, h int) Model {
	mm, _ := m.Update(tea.WindowSizeMsg{Width: w, Height: h})
	return mm.(Model)
}

func TestRenderStates(t *testing.T) {
	set, err := rules.Load("")
	if err != nil {
		t.Fatal(err)
	}

	// S3 — findings, list focused
	fb := sized(NewFindings(sample(), set, "auto", "plan_expanded.json"), 110, 28)
	dump(t, "/tmp/tui_findings.txt", fb.View())
	mustContain(t, "findings", fb.View(), "BLAST RADIUS", "RDS instance", "FINDINGS", "DETAIL", "explain")

	// S4 — detail focused
	df := fb
	df.focus = focusDetail
	df.syncDetail()
	dump(t, "/tmp/tui_detail.txt", df.View())
	mustContain(t, "detail", df.View(), "resource", "FIX", "source", "scroll")

	// S5 — severity filter active
	flt := fb
	flt.sevFilter = "critical"
	flt.recompute()
	dump(t, "/tmp/tui_filter.txt", flt.View())
	mustContain(t, "filter", flt.View(), "sev=critical")

	// S2 — all clear
	clean := sized(NewFindings(nil, set, "auto", "empty.json"), 110, 28)
	dump(t, "/tmp/tui_clean.txt", clean.View())
	mustContain(t, "clean", clean.View(), "NO DANGEROUS CHANGES", "safe to apply")

	// S10 — ruleset mode
	rs := sized(NewRules(set.Rules), 110, 28)
	dump(t, "/tmp/tui_rules.txt", rs.View())
	mustContain(t, "ruleset", rs.View(), "RULESET", "RULES", "RULE", "CHECK (CEL)")

	// S12 — help overlay
	h := fb
	h.showHelp = true
	dump(t, "/tmp/tui_help.txt", h.View())
	mustContain(t, "help", h.View(), "KEYS", "NAVIGATE", "explain")

	// narrow single-pane (no panic, list only)
	narrow := sized(NewFindings(sample(), set, "auto", "plan_expanded.json"), 60, 20)
	dump(t, "/tmp/tui_narrow.txt", narrow.View())
	if strings.TrimSpace(narrow.View()) == "" {
		t.Error("narrow view rendered empty")
	}
}

// dump writes a rendered screen to disk for visual inspection, only when
// BUMPER_TUI_DUMP is set (keeps normal/CI runs side-effect free).
func dump(t *testing.T, path, s string) {
	t.Helper()
	if os.Getenv("BUMPER_TUI_DUMP") == "" {
		return
	}
	_ = os.WriteFile(path, []byte(s), 0o644)
}

func mustContain(t *testing.T, name, out string, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if !strings.Contains(out, s) {
			t.Errorf("[%s] view missing %q", name, s)
		}
	}
}
