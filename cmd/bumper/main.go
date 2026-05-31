// Command bumper catches dangerous Terraform changes before you apply them.
//
//	terraform show -json plan.tfplan > plan.json
//	bumper plan.json
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/gnana097/bumper/internal/engine"
	"github.com/gnana097/bumper/internal/enrich"
	"github.com/gnana097/bumper/internal/plan"
	"github.com/gnana097/bumper/internal/report"
	"github.com/gnana097/bumper/internal/rules"
)

const usage = `bumper — catch dangerous Terraform changes before you apply them.

Usage:
  terraform show -json plan.tfplan > plan.json
  bumper [flags] plan.json        (use "-" to read the plan from stdin)

Flags:
  --format string        output format: text|json|sarif|markdown (default "text")
  --min-severity string  report findings at or above: info|low|medium|high|critical (default "low")
  --rules string         directory of additional .yaml rules to load
  --explain              enrich findings via a locally-installed AI CLI (claude, gemini, ...)
  --llm string           which AI CLI to use with --explain: auto|claude|gemini|codex|opencode|auggie (default "auto")
  --no-fail              always exit 0, even when findings are present

Exit codes: 0 = clean, 1 = findings present, 2 = usage/parse error.
`

func main() { os.Exit(run()) }

func run() int {
	format := flag.String("format", "text", "")
	minSeverity := flag.String("min-severity", "low", "")
	rulesDir := flag.String("rules", "", "")
	explain := flag.Bool("explain", false, "")
	llm := flag.String("llm", "auto", "")
	noFail := flag.Bool("no-fail", false, "")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		return 2
	}

	data, err := readInput(flag.Arg(0))
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
		if err := report.SARIF(os.Stdout, findings, flag.Arg(0)); err != nil {
			return fail("%v", err)
		}
	case "markdown", "md":
		report.Markdown(os.Stdout, findings)
	default:
		report.Text(os.Stdout, findings)
	}

	if *explain && len(findings) > 0 {
		runExplain(*llm, findings)
	}

	if len(findings) > 0 && !*noFail {
		return 1
	}
	return 0
}

func runExplain(llm string, findings []engine.Finding) {
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
