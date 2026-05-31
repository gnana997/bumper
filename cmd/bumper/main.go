// Command bumper catches dangerous Terraform changes before you apply them.
//
//	terraform show -json plan.tfplan > plan.json
//	bumper plan.json          # scan
//	bumper list               # show the ruleset
//	bumper explain <RULE_ID>  # show one rule
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/gnana097/bumper/internal/engine"
	"github.com/gnana097/bumper/internal/enrich"
	"github.com/gnana097/bumper/internal/plan"
	"github.com/gnana097/bumper/internal/report"
	"github.com/gnana097/bumper/internal/rules"
)

const usage = `bumper — catch dangerous Terraform changes before you apply them.

Usage:
  bumper [flags] plan.json        scan a plan (use "-" for stdin)
  bumper list [flags]             list the rule set
  bumper explain <RULE_ID>        show one rule in detail
  bumper version

Produce a plan: terraform show -json plan.tfplan > plan.json

Scan flags:
  --format string        output: text|json|sarif|markdown (default "text")
  --min-severity string  report findings at or above: info|low|medium|high|critical (default "low")
  --rules string         directory of additional .yaml rules to load
  --explain              enrich findings via a locally-installed AI CLI (claude, gemini, ...)
  --llm string           AI CLI for --explain: auto|claude|gemini|codex|opencode|auggie (default "auto")
  --no-fail              always exit 0, even when findings are present

Exit codes: 0 = clean, 1 = findings present, 2 = usage/parse error.
`

func main() { os.Exit(run()) }

func run() int {
	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "list":
			return cmdList(args[1:])
		case "explain":
			return cmdExplain(args[1:])
		case "version", "--version", "-v":
			fmt.Println("bumper " + report.Version)
			return 0
		case "help", "-h", "--help":
			fmt.Fprint(os.Stderr, usage)
			return 0
		}
	}
	return cmdScan(args)
}

func cmdScan(args []string) int {
	fs := flag.NewFlagSet("bumper", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	format := fs.String("format", "text", "")
	minSeverity := fs.String("min-severity", "low", "")
	rulesDir := fs.String("rules", "", "")
	explainFindings := fs.Bool("explain", false, "")
	llm := fs.String("llm", "auto", "")
	noFail := fs.Bool("no-fail", false, "")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	planPath := fs.Arg(0)

	data, err := readInput(planPath)
	if err != nil {
		return fail("%v", err)
	}
	changes, err := plan.Load(data)
	if err != nil {
		return fail("%v", err)
	}
	set, err := rules.Load(*rulesDir)
	if err != nil {
		return fail("%v", err)
	}
	findings, err := engine.Evaluate(changes, set)
	if err != nil {
		return fail("%v", err)
	}
	findings = filterSeverity(findings, *minSeverity)

	switch *format {
	case "json":
		if err := report.JSON(os.Stdout, findings); err != nil {
			return fail("%v", err)
		}
	case "sarif":
		if err := report.SARIF(os.Stdout, findings, planPath); err != nil {
			return fail("%v", err)
		}
	case "markdown", "md":
		report.Markdown(os.Stdout, findings)
	default:
		report.Text(os.Stdout, findings)
	}

	if *explainFindings && len(findings) > 0 {
		enrichFindings(*llm, findings)
	}

	if len(findings) > 0 && !*noFail {
		return 1
	}
	return 0
}

// cmdList prints the rule set, optionally filtered.
func cmdList(args []string) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	severity := fs.String("severity", "", "filter by severity: critical|high|medium|low")
	source := fs.String("source", "", "filter by source: trivy|custom")
	service := fs.String("service", "", "filter by service/resource substring (e.g. rds, s3)")
	format := fs.String("format", "text", "text|json")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	set, err := rules.Load("")
	if err != nil {
		return fail("%v", err)
	}

	var sel []*rules.Rule
	for _, r := range set.Rules {
		if *severity != "" && r.Severity != *severity {
			continue
		}
		if *source != "" && r.Source != *source {
			continue
		}
		if *service != "" && !strings.Contains(strings.ToLower(r.ID+" "+r.Resource), strings.ToLower(*service)) {
			continue
		}
		sel = append(sel, r)
	}
	sort.SliceStable(sel, func(i, j int) bool {
		if ri, rj := engine.Rank(sel[i].Severity), engine.Rank(sel[j].Severity); ri != rj {
			return ri > rj
		}
		return sel[i].ID < sel[j].ID
	})

	if err := report.RuleList(os.Stdout, sel, *format); err != nil {
		return fail("%v", err)
	}
	return 0
}

// cmdExplain prints one rule in detail.
func cmdExplain(args []string) int {
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(os.Stderr, "usage: bumper explain <RULE_ID>   (see: bumper list)")
		return 2
	}
	set, err := rules.Load("")
	if err != nil {
		return fail("%v", err)
	}
	r, ok := set.ByID(args[0])
	if !ok {
		return fail("unknown rule %q (try: bumper list)", args[0])
	}
	report.RuleDetail(os.Stdout, r)
	return 0
}

// enrichFindings adds an AI plain-English explanation to a scan's findings.
func enrichFindings(llm string, findings []engine.Finding) {
	cli, ok := enrich.Detect(llm)
	if !ok {
		fmt.Fprintln(os.Stderr, "\nbumper: --explain requested but no AI CLI found on PATH "+
			"(tried claude, gemini, codex, opencode, auggie). Deterministic results above are complete.")
		return
	}
	text, err := enrich.Explain(context.Background(), cli, findings)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nbumper: enrichment via %s failed (%v). "+
			"Deterministic results above are complete.\n", cli.Name, err)
		return
	}
	fmt.Printf("\n── plain-English explanation (via %s) ──\n%s\n", cli.Name, text)
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func filterSeverity(findings []engine.Finding, min string) []engine.Finding {
	threshold := engine.Rank(min)
	out := findings[:0]
	for _, f := range findings {
		if engine.Rank(f.Severity) >= threshold {
			out = append(out, f)
		}
	}
	return out
}

func fail(format string, args ...interface{}) int {
	fmt.Fprintf(os.Stderr, "bumper: "+format+"\n", args...)
	return 2
}
