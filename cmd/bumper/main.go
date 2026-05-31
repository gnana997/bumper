// Command bumper catches dangerous Terraform changes before you apply them.
//
//	terraform show -json plan.tfplan > plan.json
//	bumper plan.json          # scan
//	bumper list               # show the ruleset
//	bumper explain <RULE_ID>  # show one rule
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/gnana097/bumper/internal/engine"
	"github.com/gnana097/bumper/internal/enrich"
	"github.com/gnana097/bumper/internal/mcpserver"
	"github.com/gnana097/bumper/internal/plan"
	"github.com/gnana097/bumper/internal/report"
	"github.com/gnana097/bumper/internal/rules"
	"github.com/gnana097/bumper/internal/safety"
	"github.com/gnana097/bumper/internal/setup"
	"github.com/gnana097/bumper/internal/tui"
)

const usage = `bumper — catch dangerous Terraform changes before you apply them.

Usage:
  bumper [flags] plan.json        scan a plan (use "-" for stdin)
  bumper tui plan.json            scan + open the interactive hazard console
  bumper list [flags] [--tui]     list the rule set (or browse it interactively)
  bumper explain <RULE_ID>        show one rule in detail
  bumper init [flags]             wire bumper into Claude Code (MCP server + apply-guard hook)
  bumper verify <plan.tfplan>     scan a saved plan and record a verdict that unblocks its apply
  bumper guard                    PreToolUse hook: block unverified terraform apply/destroy (reads stdin)
  bumper mcp                      run as an MCP server (scan/list/explain tools over stdio)
  bumper version

Enforce (agent context): terraform plan -out tfplan && bumper verify tfplan && terraform apply tfplan

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
		case "tui":
			return cmdTUI(args[1:])
		case "mcp":
			return cmdMCP(args[1:])
		case "verify":
			return cmdVerify(args[1:])
		case "guard":
			return cmdGuard(args[1:])
		case "init":
			return cmdInit(args[1:])
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
	useTUI := fs.Bool("tui", false, "open the interactive rule browser")
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

	if *useTUI {
		if err := tui.RunRules(sel); err != nil {
			return fail("%v", err)
		}
		return 0
	}
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

// cmdTUI scans a plan and opens the interactive hazard console.
func cmdTUI(args []string) int {
	fs := flag.NewFlagSet("tui", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	rulesDir := fs.String("rules", "", "")
	llm := fs.String("llm", "auto", "")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: bumper tui plan.json")
		return 2
	}
	data, err := readInput(fs.Arg(0))
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
	if err := tui.RunFindings(findings, set, *llm, filepath.Base(fs.Arg(0))); err != nil {
		return fail("%v", err)
	}
	return 0
}

// cmdInit wires bumper into Claude Code: registers the MCP server, installs the
// guard hook, ignores the verdict store, and notes the workflow in CLAUDE.md.
// Interactive terminals get the wizard; --print/--yes/non-TTY are flag-driven.
func cmdInit(args []string) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	mcpFlag := fs.String("mcp", "project", "MCP server scope: project|user|none")
	hookFlag := fs.String("hook", "project", "guard hook scope: project|user|none")
	printOnly := fs.Bool("print", false, "show what would change and exit without writing")
	assumeYes := fs.Bool("yes", false, "apply non-interactively (no wizard)")
	noTUI := fs.Bool("no-tui", false, "skip the wizard even on a TTY")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	mcp, ok := setup.ParseScope(*mcpFlag)
	if !ok {
		return fail("--mcp must be project|user|none, got %q", *mcpFlag)
	}
	hook, ok := setup.ParseScope(*hookFlag)
	if !ok {
		return fail("--hook must be project|user|none, got %q", *hookFlag)
	}

	env, err := setup.Detect()
	if err != nil {
		return fail("%v", err)
	}
	steps := setup.Plan(setup.Options{MCP: mcp, Hook: hook, Env: env})

	if *printOnly {
		fmt.Printf("bumper init — would wire bumper (%s) into Claude Code:\n\n", env.Bin)
		for _, s := range steps {
			fmt.Printf("  • %-34s %s\n", s.Title, s.RelPath(env))
		}
		fmt.Println("\n(--print) no files were changed.")
		return 0
	}

	// Interactive: launch the wizard.
	if !*assumeYes && !*noTUI && isInteractive() {
		res, err := tui.RunInit(env, mcp, hook)
		if err != nil {
			return fail("%v", err)
		}
		if !res.Applied {
			fmt.Println("aborted; no files changed.")
			return 0
		}
		for _, line := range res.Lines {
			fmt.Println("  " + line)
		}
		fmt.Println("\n✓ bumper is wired in. Commit .mcp.json and .claude/settings.json to share the gate with your team.")
		return 0
	}

	// Non-interactive: require an explicit --yes rather than writing silently.
	if !*assumeYes {
		fmt.Fprintln(os.Stderr, "refusing to modify files without confirmation; re-run with --yes (or --print to preview).")
		return 2
	}
	fmt.Printf("bumper init — wiring bumper (%s) into Claude Code:\n\n", env.Bin)
	for _, s := range steps {
		act, err := s.Run()
		if err != nil {
			return fail("%s: %v", s.Title, err)
		}
		fmt.Printf("  %-10s %s\n", act, s.RelPath(env))
	}
	fmt.Println("\n✓ bumper is wired in. Commit .mcp.json and .claude/settings.json to share the gate with your team.")
	return 0
}

// isInteractive reports whether stdin is a terminal (so the wizard can read keys).
func isInteractive() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// cmdMCP runs bumper as a stdio MCP server, exposing scan/list/explain as tools
// for agentic assistants (Claude Code, etc.).
func cmdMCP(args []string) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	rulesDir := fs.String("rules", "", "")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := mcpserver.Serve(ctx, *rulesDir)
	// A client disconnecting (stdin EOF → the SDK's unexported "server is closing"
	// error) or a shutdown signal (context cancelled) is a normal end of session,
	// not a failure.
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) ||
		strings.Contains(err.Error(), "server is closing") {
		return 0
	}
	return fail("%v", err)
}

// cmdVerify scans a saved plan and, on a pass, records a verdict bound to the
// plan's sha256 so a later `terraform apply <plan>` is unblocked by the guard.
func cmdVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	minSeverity := fs.String("min-severity", safety.DefaultMinSeverity, "")
	accept := fs.Bool("accept", false, "")
	rulesDir := fs.String("rules", "", "")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: bumper verify <plan.tfplan> [--min-severity high] [--accept] [--rules dir]")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	planPath := fs.Arg(0)

	set, err := rules.Load(*rulesDir)
	if err != nil {
		return fail("%v", err)
	}
	res, err := safety.Verify(set, planPath, *minSeverity, *accept, time.Now())
	if err != nil {
		return fail("%v", err)
	}

	if !res.Passed {
		report.Text(os.Stdout, res.Blocking)
		fmt.Fprintf(os.Stderr, "\nbumper: %s NOT verified — %d finding(s) at or above %q. "+
			"Fix them, or record an explicit override with `bumper verify --accept %s`.\n",
			planPath, len(res.Blocking), *minSeverity, planPath)
		return 1
	}

	if res.Verdict.Accepted {
		fmt.Printf("⚠ bumper: %s verified WITH OVERRIDE (%d blocking finding(s) accepted). apply unblocked.\n",
			planPath, res.Verdict.Blocking)
	} else {
		fmt.Printf("✓ bumper: %s verified (%d finding(s), none blocking). apply unblocked.\n",
			planPath, res.Verdict.FindingsTotal)
	}
	fmt.Printf("  plan sha256: %s\n", res.Verdict.PlanSHA)
	return 0
}

// cmdGuard is the Claude Code PreToolUse hook entrypoint: it reads a tool-call
// payload on stdin and blocks unverified `terraform apply`/`destroy`. It always
// exits 0 — a block is conveyed via the hook's JSON output, not the exit code.
func cmdGuard(args []string) int {
	fs := flag.NewFlagSet("guard", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	maxAge := fs.Duration("max-age", safety.DefaultMaxAge, "how long a verdict stays valid (0 = no expiry)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := safety.Guard(os.Stdin, os.Stdout, time.Now(), *maxAge); err != nil {
		// Fail-open: never wedge the user's shell on a guard error.
		fmt.Fprintf(os.Stderr, "bumper guard: %v\n", err)
	}
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
