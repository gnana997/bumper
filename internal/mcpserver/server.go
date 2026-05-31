// Package mcpserver exposes bumper's deterministic checks as MCP tools so an
// agentic coding assistant (Claude Code, etc.) can call them directly — most
// importantly, scan a Terraform plan before it runs `terraform apply`.
//
// It is a thin shell over the same engine/rules/plan packages the CLI uses; the
// tools return structured data (not the human text report) so the agent reasons
// over fields. The deterministic core never imports this package.
package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/gnana097/bumper/internal/engine"
	"github.com/gnana097/bumper/internal/plan"
	"github.com/gnana097/bumper/internal/report"
	"github.com/gnana097/bumper/internal/rules"
	"github.com/gnana097/bumper/internal/safety"
)

// handlers carries the loaded rule set shared by every tool call.
type handlers struct{ set *rules.Set }

// NewServer builds an MCP server with bumper's tools registered. rulesDir may be
// "" (built-in rules only).
func NewServer(rulesDir string) (*mcp.Server, error) {
	set, err := rules.Load(rulesDir)
	if err != nil {
		return nil, err
	}
	h := &handlers{set: set}

	s := mcp.NewServer(&mcp.Implementation{
		Name:    "bumper",
		Title:   "bumper — Terraform safety gate",
		Version: report.Version,
	}, nil)

	mcp.AddTool(s, &mcp.Tool{Name: "scan_plan", Description: scanDesc}, h.scanPlan)
	mcp.AddTool(s, &mcp.Tool{Name: "list_rules", Description: listDesc}, h.listRules)
	mcp.AddTool(s, &mcp.Tool{Name: "explain_rule", Description: explainDesc}, h.explainRule)
	return s, nil
}

// Serve runs the MCP server over stdio until ctx is cancelled or the client
// disconnects.
func Serve(ctx context.Context, rulesDir string) error {
	s, err := NewServer(rulesDir)
	if err != nil {
		return err
	}
	return s.Run(ctx, &mcp.StdioTransport{})
}

// ---- scan_plan -------------------------------------------------------------

const scanDesc = `Scan a Terraform plan for dangerous changes BEFORE running ` +
	`'terraform apply'. Catches public exposure, unencrypted resources, and ` +
	`destructive replaces/deletes of stateful resources (databases, volumes). ` +
	`Always call this after 'terraform plan -out <file>' and before applying. ` +
	`Pass either inline 'terraform show -json' output as plan_json, OR a path to ` +
	`a plan file as path (a binary .tfplan is accepted — bumper runs ` +
	`'terraform show -json' on it). Returns deterministic findings with severity, ` +
	`resource address, and a fix. Any finding at high or critical severity means ` +
	`the apply should be blocked pending human review.`

// ScanPlanInput selects the plan to scan. Provide exactly one of plan_json or path.
type ScanPlanInput struct {
	PlanJSON    string `json:"plan_json,omitempty" jsonschema:"Inline 'terraform show -json' output. Provide this OR path."`
	Path        string `json:"path,omitempty" jsonschema:"Path to a plan file: either 'terraform show -json' output, or a binary .tfplan (bumper will run 'terraform show -json' on it). Provide this OR plan_json."`
	MinSeverity string `json:"min_severity,omitempty" jsonschema:"Only return findings at or above this severity: info|low|medium|high|critical. Default low."`
}

// ScanPlanOutput is the structured result of a scan.
type ScanPlanOutput struct {
	Findings []engine.Finding `json:"findings" jsonschema:"The dangerous changes found, most severe first."`
	Summary  ScanSummary      `json:"summary"`
}

// ScanSummary is the at-a-glance verdict.
type ScanSummary struct {
	Total      int            `json:"total" jsonschema:"Number of findings returned."`
	BySeverity map[string]int `json:"by_severity" jsonschema:"Count of findings per severity."`
	Verdict    string         `json:"verdict" jsonschema:"\"clean\" if no findings, otherwise \"findings\"."`
	Blocking   bool           `json:"blocking" jsonschema:"True if any finding is at high or critical severity (apply should be blocked)."`
	Source     string         `json:"source" jsonschema:"How the plan was obtained: inline|json-file|terraform-show."`
}

func (h *handlers) scanPlan(ctx context.Context, _ *mcp.CallToolRequest, in ScanPlanInput) (*mcp.CallToolResult, ScanPlanOutput, error) {
	data, source, err := safety.ResolvePlanData(in.PlanJSON, in.Path)
	if err != nil {
		return nil, ScanPlanOutput{}, err
	}
	changes, err := plan.Load(data)
	if err != nil {
		return nil, ScanPlanOutput{}, err
	}
	findings, err := engine.Evaluate(changes, h.set)
	if err != nil {
		return nil, ScanPlanOutput{}, err
	}
	findings = filterMinSeverity(findings, in.MinSeverity)
	return nil, ScanPlanOutput{Findings: findings, Summary: summarize(findings, source)}, nil
}

// ---- list_rules ------------------------------------------------------------

const listDesc = `List bumper's built-in Terraform safety rules, optionally ` +
	`filtered by severity, source (trivy|custom), or a service/resource ` +
	`substring (e.g. rds, s3). Use to discover what bumper checks for.`

// ListRulesInput filters the rule set. All fields optional.
type ListRulesInput struct {
	Severity string `json:"severity,omitempty" jsonschema:"Filter by severity: critical|high|medium|low."`
	Source   string `json:"source,omitempty" jsonschema:"Filter by provenance: trivy|custom."`
	Service  string `json:"service,omitempty" jsonschema:"Filter by a substring of the rule id or resource type, e.g. rds, s3, iam."`
}

// RuleSummary is one rule, without the compiled predicate.
type RuleSummary struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Resource string `json:"resource,omitempty"`
	Title    string `json:"title"`
	Source   string `json:"source"`
	AVD      string `json:"avd,omitempty"`
}

// ListRulesOutput is the filtered rule list.
type ListRulesOutput struct {
	Rules []RuleSummary `json:"rules"`
	Count int           `json:"count"`
}

func (h *handlers) listRules(ctx context.Context, _ *mcp.CallToolRequest, in ListRulesInput) (*mcp.CallToolResult, ListRulesOutput, error) {
	out := ListRulesOutput{Rules: []RuleSummary{}}
	for _, r := range h.set.Rules {
		if in.Severity != "" && r.Severity != in.Severity {
			continue
		}
		if in.Source != "" && r.Source != in.Source {
			continue
		}
		if in.Service != "" && !strings.Contains(strings.ToLower(r.ID+" "+r.Resource), strings.ToLower(in.Service)) {
			continue
		}
		out.Rules = append(out.Rules, RuleSummary{
			ID:       r.ID,
			Severity: r.Severity,
			Resource: r.Resource,
			Title:    r.Title,
			Source:   r.Source,
			AVD:      r.AVD,
		})
	}
	out.Count = len(out.Rules)
	return nil, out, nil
}

// ---- explain_rule ----------------------------------------------------------

const explainDesc = `Explain a single bumper rule in detail: its severity, the ` +
	`resource it applies to, the exact CEL predicate it evaluates, the ` +
	`recommended fix, references, and provenance. Pass a rule_id from a ` +
	`scan_plan finding or from list_rules.`

// ExplainRuleInput names the rule to explain.
type ExplainRuleInput struct {
	RuleID string `json:"rule_id" jsonschema:"The rule id, e.g. AWS_SG_PUBLIC_INGRESS_SENSITIVE (see list_rules or a scan_plan finding)."`
}

// ExplainRuleOutput is the full detail of one rule.
type ExplainRuleOutput struct {
	ID       string   `json:"id"`
	Severity string   `json:"severity"`
	Resource string   `json:"resource,omitempty"`
	On       []string `json:"on,omitempty" jsonschema:"Change actions this rule applies to (create|update|delete|replace); empty means any."`
	Title    string   `json:"title"`
	Fix      string   `json:"fix,omitempty"`
	When     string   `json:"when" jsonschema:"The CEL predicate evaluated against the resource change."`
	Refs     []string `json:"refs,omitempty"`
	Source   string   `json:"source"`
	AVD      string   `json:"avd,omitempty"`
}

func (h *handlers) explainRule(ctx context.Context, _ *mcp.CallToolRequest, in ExplainRuleInput) (*mcp.CallToolResult, ExplainRuleOutput, error) {
	r, ok := h.set.ByID(in.RuleID)
	if !ok {
		return nil, ExplainRuleOutput{}, fmt.Errorf("unknown rule %q (call list_rules to see available ids)", in.RuleID)
	}
	return nil, ExplainRuleOutput{
		ID:       r.ID,
		Severity: r.Severity,
		Resource: r.Resource,
		On:       r.On,
		Title:    r.Title,
		Fix:      r.Fix,
		When:     r.When,
		Refs:     r.Refs,
		Source:   r.Source,
		AVD:      r.AVD,
	}, nil
}

// ---- helpers ---------------------------------------------------------------

func filterMinSeverity(findings []engine.Finding, min string) []engine.Finding {
	if min == "" {
		return findings
	}
	threshold := engine.Rank(min)
	out := make([]engine.Finding, 0, len(findings))
	for _, f := range findings {
		if engine.Rank(f.Severity) >= threshold {
			out = append(out, f)
		}
	}
	return out
}

func summarize(findings []engine.Finding, source string) ScanSummary {
	s := ScanSummary{
		Total:      len(findings),
		BySeverity: map[string]int{},
		Verdict:    "clean",
		Source:     source,
	}
	if len(findings) > 0 {
		s.Verdict = "findings"
	}
	for _, f := range findings {
		s.BySeverity[f.Severity]++
		if engine.Rank(f.Severity) >= engine.Rank("high") {
			s.Blocking = true
		}
	}
	return s
}
