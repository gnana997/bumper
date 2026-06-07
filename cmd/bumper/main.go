// Command bumper catches dangerous Terraform changes before you apply them.
//
//	terraform show -json plan.tfplan > plan.json
//	bumper plan.json          # scan
//	bumper list               # show the ruleset
//	bumper explain <RULE_ID>  # show one rule
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gnana997/bumper/internal/catalog"
	"github.com/gnana997/bumper/internal/deps"
	"github.com/gnana997/bumper/internal/engine"
	"github.com/gnana997/bumper/internal/enrich"
	"github.com/gnana997/bumper/internal/plan"
	"github.com/gnana997/bumper/internal/report"
	"github.com/gnana997/bumper/internal/rules"
	"github.com/gnana997/bumper/internal/safety"
	"github.com/gnana997/bumper/internal/search"
	"github.com/gnana997/bumper/internal/setup"
	"github.com/gnana997/bumper/internal/style"
	"github.com/gnana997/bumper/internal/tui"
)

const usage = `bumper — catch dangerous Terraform changes before you apply them.

Usage:
  bumper [flags] plan.json        scan a plan (use "-" for stdin)
  bumper tui plan.json            scan + open the interactive hazard console
  bumper list [flags] [--tui]     list the rule set (or browse it interactively)
  bumper search [flags] <query>   find rules by keyword/resource — what to bake in before writing TF
  bumper explain <RULE_ID>        show one rule in detail
  bumper init [flags]             wire bumper into your agent (guardrail hooks + advisor MCP)
  bumper deps [path]              scan a lockfile for known-vulnerable + malicious dependencies
  bumper deps guard               PreToolUse hook: block installs of known-malicious packages (stdin)
  bumper deps watch               PostToolUse hook: scan deps after an install, nudge on findings (stdin)
  bumper verify <plan.tfplan>     scan a saved plan and record a verdict that unblocks its apply
  bumper guard                    PreToolUse hook: block unverified terraform apply/destroy (reads stdin)
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
		case "search":
			return cmdSearch(args[1:])
		case "explain":
			return cmdExplain(args[1:])
		case "tui":
			return cmdTUI(args[1:])
		case "verify":
			return cmdVerify(args[1:])
		case "guard":
			return cmdGuard(args[1:])
		case "init":
			return cmdInit(args[1:])
		case "deps":
			return cmdDeps(args[1:])
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

// cmdSearch ranks rules by relevance to a query / resource type — the
// "what should I bake in before writing Terraform for X" lookup. Same corpus as
// list, but ranked rather than enumerated.
func cmdSearch(args []string) int {
	fs := flag.NewFlagSet("search", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	provider := fs.String("provider", "", "filter by cloud: aws|gcp|azure")
	severity := fs.String("severity", "", "filter by severity: critical|high|medium|low")
	resource := fs.String("resource", "", "resource type to get rules for, e.g. aws_s3_bucket")
	limit := fs.Int("limit", search.DefaultLimit, "max results")
	enforcedOnly := fs.Bool("enforced-only", false, "only bumper's enforced rules; skip the advisory catalog")
	format := fs.String("format", "text", "text|json")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: bumper search [--resource T] [--provider C] [--severity S] [--limit N] [query...]")
	}
	// Parse allowing flags and the query to interleave (Go's flag package stops
	// at the first non-flag, so we collect positionals across repeated parses).
	var positional []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		rest = fs.Args()
		if len(rest) == 0 {
			break
		}
		positional = append(positional, rest[0])
		rest = rest[1:]
	}
	query := strings.Join(positional, " ")
	if query == "" && *provider == "" && *severity == "" && *resource == "" {
		fs.Usage()
		return 2
	}
	set, err := rules.Load("")
	if err != nil {
		return fail("%v", err)
	}
	cat, err := catalog.Load()
	if err != nil {
		return fail("%v", err)
	}
	idx := search.New(set, cat)
	hits := idx.Search(search.Query{Text: query, Provider: *provider, Severity: *severity, Resource: *resource, Limit: *limit})
	enforced, advisory := search.Split(hits)
	if *enforcedOnly {
		advisory = nil
	}

	if *format == "json" {
		return searchJSON(enforced, advisory)
	}
	sel := make([]*rules.Rule, len(enforced))
	for i, h := range enforced {
		sel[i] = h.Doc.Rule
	}
	p := style.New(os.Stdout)
	g := p.Glyphs

	if !*enforcedOnly {
		fmt.Printf("%s    %s\n\n",
			p.Strong(fmt.Sprintf("%d matches", len(sel)+len(advisory))),
			p.Faint(fmt.Sprintf("%d enforced · %d advisory", len(sel), len(advisory))))
	}

	// Enforced — minimal severity / id / title rows under a green section dot.
	fmt.Printf("%s %s  %s\n\n", p.OK(g.Dot), p.Strong("enforced"),
		p.Faint(fmt.Sprintf("%d   fires on your plan", len(sel))))
	if len(sel) == 0 {
		fmt.Printf("  %s\n", p.Faint("no enforced rules match this query"))
	}
	wID := 0
	for _, r := range sel {
		wID = max(wID, len(r.ID))
	}
	for _, r := range sel {
		fmt.Printf("  %s%s%s\n",
			p.Severity(r.Severity, style.PadRight(r.Severity, 9)),
			p.Strong(fmt.Sprintf("%-*s", wID+2, r.ID)),
			p.Dim(style.Trunc(r.Title, 52)))
	}

	if !*enforcedOnly {
		printAdvisory(p, advisory)
	}
	return 0
}

// printAdvisory renders the advisory hits as a compact section under a hollow ring,
// so they read as knowledge — never as enforced. Severity / source / title, colored.
func printAdvisory(p *style.Palette, adv []search.Hit) {
	fmt.Printf("\n%s %s  %s\n\n", p.Dim(p.Glyphs.Ring), p.Strong("advisory"),
		p.Faint(fmt.Sprintf("%d   knowledge, not enforced — Trivy · Checkov · KICS · Prowler", len(adv))))
	wSrc := 0
	for _, h := range adv {
		wSrc = max(wSrc, len(h.Doc.Entry.Source))
	}
	for _, h := range adv {
		e := h.Doc.Entry
		sev := e.Severity
		if sev == "" {
			sev = "-"
		}
		fmt.Printf("  %s%s%s\n",
			p.Severity(e.Severity, style.PadRight(sev, 9)),
			p.Dim(fmt.Sprintf("%-*s", wSrc+2, e.Source)),
			p.Dim(style.Trunc(e.Title, 60)))
	}
}

func searchJSON(enforced, advisory []search.Hit) int {
	type advOut struct {
		Source, SourceID, Provider, Severity, Title, Remediation string
		Resources, Refs                                          []string
		Enforced                                                 bool
	}
	out := struct {
		Enforced []*rules.Rule `json:"enforced"`
		Advisory []advOut      `json:"advisory"`
	}{Enforced: []*rules.Rule{}}
	for _, h := range enforced {
		out.Enforced = append(out.Enforced, h.Doc.Rule)
	}
	for _, h := range advisory {
		e := h.Doc.Entry
		out.Advisory = append(out.Advisory, advOut{
			Source: e.Source, SourceID: e.SourceID, Provider: e.Provider, Severity: e.Severity,
			Title: e.Title, Remediation: e.Remediation, Resources: e.Resources, Refs: e.Refs, Enforced: false,
		})
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
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
	hookFlag := fs.String("hook", "project", "hook scope: project|user|none")
	agentFlag := fs.String("agent", "", "coding agent to wire: claude|augment (default: auto-detect)")
	terraformFlag := fs.Bool("terraform", true, "install the terraform apply-guard hook")
	depsFlag := fs.Bool("deps", true, "install the dependency hooks (install-block + post-install scan)")
	advisorFlag := fs.String("advisor", "project", "advisor MCP scope: project|user|none (none = skip)")
	advisorURLFlag := fs.String("advisor-url", "", "Advisor base URL for self-hosting (default https://advisor.bumper.sh)")
	printOnly := fs.Bool("print", false, "show what would change and exit without writing")
	assumeYes := fs.Bool("yes", false, "apply non-interactively (no wizard)")
	noTUI := fs.Bool("no-tui", false, "skip the wizard even on a TTY")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	hookScope, ok := setup.ParseScope(*hookFlag)
	if !ok {
		return fail("--hook must be project|user|none, got %q", *hookFlag)
	}
	advisorScope, ok := setup.ParseScope(*advisorFlag)
	if !ok {
		return fail("--advisor must be project|user|none, got %q", *advisorFlag)
	}

	env, err := setup.Detect()
	if err != nil {
		return fail("%v", err)
	}
	agent := setup.AgentClaude
	if *agentFlag != "" {
		a, ok := setup.ParseAgent(*agentFlag)
		if !ok {
			return fail("--agent must be claude|augment, got %q", *agentFlag)
		}
		agent = a
	} else if env.AugmentFound && !env.ClaudeFound {
		agent = setup.AgentAugment // only Augment is present — wire it
	}
	advisorURL := deps.ResolveAdvisorURL(*advisorURLFlag)
	advisorOn := advisorScope != setup.ScopeNone
	// The dependency guardrail needs an advisor endpoint for CVE/malware data.
	if *depsFlag && !advisorOn {
		fmt.Fprintln(os.Stderr, "note: --deps needs the advisor for CVE/malware data — enabling it at project scope (use --advisor-url to self-host).")
		advisorScope, advisorOn = setup.ScopeProject, true
	}
	steps := setup.Plan(setup.Options{
		Agent: agent, HookScope: hookScope, Terraform: *terraformFlag, Deps: *depsFlag,
		Advisor: advisorOn, AdvisorScope: advisorScope, AdvisorURL: advisorURL, Env: env,
	})
	p := style.New(os.Stdout)

	if *printOnly {
		fmt.Printf("bumper init — would wire bumper (%s) into %s:\n\n", env.Bin, agent.Label())
		for _, s := range steps {
			fmt.Printf("  • %-34s %s\n", s.Title, s.RelPath(env))
		}
		if advisorOn {
			printAdvisorDisclosure(advisorURL)
		}
		fmt.Println("\n(--print) no files were changed.")
		return 0
	}

	// Interactive: launch the wizard.
	if !*assumeYes && !*noTUI && isInteractive() {
		res, err := tui.RunInit(env)
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
		fmt.Printf("\n%s bumper is wired in. Commit the generated config to share the gate with your team.\n", p.OK(p.Glyphs.Check))
		return 0
	}

	// Non-interactive: require an explicit --yes rather than writing silently.
	if !*assumeYes {
		fmt.Fprintln(os.Stderr, "refusing to modify files without confirmation; re-run with --yes (or --print to preview).")
		return 2
	}
	if advisorOn {
		printAdvisorDisclosure(advisorURL)
		fmt.Println()
	}
	fmt.Printf("bumper init — wiring bumper (%s) into %s:\n\n", env.Bin, agent.Label())
	for _, s := range steps {
		act, err := s.Run()
		if err != nil {
			return fail("%s: %v", s.Title, err)
		}
		fmt.Printf("  %-10s %s\n", act, s.RelPath(env))
	}
	fmt.Println("\n✓ bumper is wired in. Commit the generated config to share the gate with your team.")
	return 0
}

// printAdvisorDisclosure is the consent notice for wiring the hosted CVE-data MCP.
func printAdvisorDisclosure(url string) {
	fmt.Printf("  CVE data → adds an MCP at %s so the agent can look up CVE & malware data for your packages\n", url)
	fmt.Println("    ! only package names + versions leave your machine — never your code")
	fmt.Println("    Skip with --advisor=none, or self-host with --advisor-url.")
}

// isInteractive reports whether stdin is a terminal (so the wizard can read keys).
func isInteractive() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
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

	p := style.New(os.Stdout)
	g := p.Glyphs
	if !res.Passed {
		report.Text(os.Stdout, res.Blocking)
		pe := style.New(os.Stderr)
		fmt.Fprintf(os.Stderr, "\n%s bumper: %s NOT verified — %d finding(s) at or above %q. "+
			"Fix them, or record an explicit override with `bumper verify --accept %s`.\n",
			pe.Severity("critical", pe.Glyphs.Cross), planPath, len(res.Blocking), *minSeverity, planPath)
		return 1
	}

	if res.Verdict.Accepted {
		fmt.Printf("%s bumper: %s verified WITH OVERRIDE (%d blocking finding(s) accepted). apply unblocked.\n",
			p.Severity("high", g.Warn), planPath, res.Verdict.Blocking)
	} else {
		fmt.Printf("%s bumper: %s verified (%d finding(s), none blocking). apply unblocked.\n",
			p.OK(g.Check), planPath, res.Verdict.FindingsTotal)
	}
	fmt.Printf("  %s%s\n", p.Faint("plan sha256: "), p.Dim(res.Verdict.PlanSHA))
	return 0
}

// cmdGuard is the Claude Code PreToolUse hook entrypoint: it reads a tool-call
// payload on stdin and blocks unverified `terraform apply`/`destroy`. It always
// exits 0 — a block is conveyed via the hook's JSON output, not the exit code.
func cmdGuard(args []string) int {
	fs := flag.NewFlagSet("guard", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	maxAge := fs.Duration("max-age", safety.DefaultMaxAge, "how long a verdict stays valid (0 = no expiry)")
	client := fs.String("client", "claude", "host agent whose shell tool to match: claude|augment")
	logPath := fs.String("log", "", "append raw hook payload + decision to this file (debug; or $BUMPER_HOOK_LOG)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	return runHook("guard", *logPath, func(r io.Reader, w io.Writer) (hookOutcome, error) {
		d, err := safety.Guard(r, w, shellToolForClient(*client), time.Now(), *maxAge)
		return hookOutcome{deny: d.Deny, reason: d.Reason}, err
	})
}

// shellToolForClient resolves the --client flag to the host agent's shell-tool
// name (what the hook matches). Unknown/empty falls back to Claude's "Bash", so
// existing config without the flag behaves exactly as before.
func shellToolForClient(client string) string {
	if a, ok := setup.ParseAgent(client); ok {
		return a.ShellTool()
	}
	return setup.AgentClaude.ShellTool()
}

// hookOutcome is what a hook body reports back: whether it denied a PreToolUse
// call and the reason. A PostToolUse hook (deps watch) never denies.
type hookOutcome struct {
	deny   bool
	reason string
}

// runHook executes a hook body (guard / deps guard / deps watch) with optional
// debug logging, and returns the process exit code.
//
// It buffers stdin so the raw payload AND the emitted decision can both be appended
// to logPath, then writes the decision to real stdout. When a PreToolUse hook denies
// it ALSO writes the reason to stderr and returns exit code 2 — the universal block
// signal every agent honors (and the only one Gemini accepts, since it ignores the
// JSON deny). Agents that read the stdout JSON get the clean structured deny; the
// exit-2 path is the backstop if the JSON is ever ignored. Logging and errors are
// fail-open and never turn an allow into a block.
//
// logPath comes from --log; if empty, $BUMPER_HOOK_LOG is used, so logging can be
// toggled globally without rewiring config (handy when wiring a new agent).
func runHook(name, logPath string, body func(r io.Reader, w io.Writer) (hookOutcome, error)) int {
	if logPath == "" {
		logPath = os.Getenv("BUMPER_HOOK_LOG")
	}
	in, _ := io.ReadAll(os.Stdin)
	var out bytes.Buffer
	outcome, err := body(bytes.NewReader(in), &out)
	_, _ = os.Stdout.Write(out.Bytes())
	if err != nil {
		// Fail-open: surface the error but never block the agent's shell.
		fmt.Fprintf(os.Stderr, "bumper %s: %v\n", name, err)
	}
	if logPath != "" {
		logHookEvent(logPath, name, in, out.Bytes(), err)
	}
	if outcome.deny {
		if outcome.reason != "" {
			fmt.Fprintln(os.Stderr, outcome.reason)
		}
		return 2 // universal block signal — covers agents that ignore the JSON deny
	}
	return 0
}

// logHookEvent appends one JSON line: timestamp, hook name, the raw stdin payload
// the agent sent, and the decision bumper emitted ("" = silent allow). Any failure
// to write is swallowed — debug logging must never wedge a hook.
func logHookEvent(path, name string, in, out []byte, hookErr error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	entry := map[string]any{
		"ts":   time.Now().Format(time.RFC3339),
		"hook": name,
		"in":   asJSONOrString(in),
		"out":  asJSONOrString(out),
	}
	if hookErr != nil {
		entry["err"] = hookErr.Error()
	}
	b, err := json.Marshal(entry)
	if err != nil {
		return
	}
	_, _ = f.Write(append(b, '\n'))
}

// asJSONOrString embeds b as nested JSON when it's valid (readable logs), else as
// a plain string (so a malformed payload can't corrupt the log line).
func asJSONOrString(b []byte) any {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return ""
	}
	if json.Valid(b) {
		return json.RawMessage(b)
	}
	return string(b)
}

// cmdDeps routes the dependency-guardrail subcommands: the scanner (default),
// the pre-install guard hook, and the post-install watch hook.
func cmdDeps(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "guard":
			return cmdDepsGuard(args[1:])
		case "watch":
			return cmdDepsWatch(args[1:])
		}
	}
	return cmdDepsScan(args)
}

// cmdDepsScan parses a lockfile (or auto-detects them in cwd) and scans the
// resolved dependencies against the Advisor for known vulns + malicious packages.
func cmdDepsScan(args []string) int {
	fs := flag.NewFlagSet("deps", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	format := fs.String("format", "text", "output: text|json|sarif|markdown")
	asJSON := fs.Bool("json", false, "shorthand for --format json")
	minSeverity := fs.String("min-severity", "low", "report findings at or above: low|medium|high|critical")
	advisorURL := fs.String("advisor-url", "", "Advisor base URL (default https://advisor.bumper.sh, or $BUMPER_ADVISOR_URL)")
	noFail := fs.Bool("no-fail", false, "always exit 0, even when findings are present")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: bumper deps [path] [--format text|json|sarif|markdown] [--min-severity low] [--advisor-url URL] [--no-fail]")
	}
	// Tolerate flags placed after the path (the Go flag pkg otherwise stops at the
	// first positional) — agents don't always order them flags-first.
	if err := fs.Parse(hoistFlags(args, map[string]bool{
		"-advisor-url": true, "--advisor-url": true,
		"-format": true, "--format": true,
		"-min-severity": true, "--min-severity": true,
	})); err != nil {
		return 2
	}

	var (
		depList []deps.Dep
		label   string
	)
	if fs.NArg() >= 1 {
		path := fs.Arg(0)
		data, err := readInput(path)
		if err != nil {
			return fail("%v", err)
		}
		res, err := deps.ParseLockfile(filepath.Base(path), string(data))
		if err != nil {
			return fail("%v", err)
		}
		depList, label = res.Deps, res.Label
	} else {
		cwd, _ := os.Getwd()
		depList = deps.CollectLockfileDeps(cwd)
		if len(depList) == 0 {
			return fail("no lockfile found here (looked for package-lock.json, requirements.txt, " +
				"poetry.lock, uv.lock, Pipfile.lock, go.sum, Cargo.lock, Gemfile.lock). Pass a path explicitly.")
		}
		label = "auto-detected lockfiles"
	}

	client := deps.NewClient(deps.ResolveAdvisorURL(*advisorURL))
	res, err := client.Scan(depList, true)
	if err != nil {
		if errors.Is(err, deps.ErrRateLimited) {
			return fail("rate limited by the Advisor — wait a moment and retry, or self-host with --advisor-url.")
		}
		return fail("scan failed: %v", err)
	}

	res = report.FilterDepsSeverity(res, *minSeverity)

	outFmt := *format
	if *asJSON {
		outFmt = "json"
	}
	switch outFmt {
	case "json":
		_ = report.DepsJSON(os.Stdout, res)
	case "sarif":
		artifact := "lockfile"
		if fs.NArg() >= 1 {
			artifact = fs.Arg(0)
		}
		_ = report.DepsSARIF(os.Stdout, res, artifact)
	case "markdown", "md":
		report.DepsMarkdown(os.Stdout, res)
	default:
		report.DepsText(os.Stdout, res, label)
	}
	if res.Status == "unavailable" {
		fmt.Fprintln(os.Stderr, "bumper: advisor mirror is unavailable right now — results may be incomplete.")
	}
	if (res.VulnerableCount > 0 || res.MalwareCount > 0) && !*noFail {
		return 1
	}
	return 0
}

// hoistFlags moves flag tokens (and the values of space-separated value-flags)
// ahead of positional args so `flag.Parse` sees them even when a user/agent puts
// the path first.
func hoistFlags(args []string, valueFlags map[string]bool) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			if valueFlags[a] && i+1 < len(args) { // space-separated value, e.g. --advisor-url URL
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		pos = append(pos, a)
	}
	return append(flags, pos...)
}

// cmdDepsGuard is the PreToolUse pre-install hook: it blocks installs of known-
// malicious packages with an informative reason. Always exits 0 (the block is in
// the JSON output); fail-open on any error.
func cmdDepsGuard(args []string) int {
	fs := flag.NewFlagSet("deps guard", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	advisorURL := fs.String("advisor-url", "", "Advisor base URL (or $BUMPER_ADVISOR_URL)")
	clientFlag := fs.String("client", "claude", "host agent whose shell tool to match: claude|augment")
	logPath := fs.String("log", "", "append raw hook payload + decision to this file (debug; or $BUMPER_HOOK_LOG)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	client := deps.NewClient(deps.ResolveAdvisorURL(*advisorURL))
	return runHook("deps guard", *logPath, func(r io.Reader, w io.Writer) (hookOutcome, error) {
		reason, err := deps.Guard(r, w, client, shellToolForClient(*clientFlag))
		return hookOutcome{deny: reason != "", reason: reason}, err
	})
}

// cmdDepsWatch is the PostToolUse post-install hook: after an install it scans the
// resolved tree and, on findings, injects context nudging the agent to spawn a
// triage subagent. Non-blocking; always exits 0; fail-open.
func cmdDepsWatch(args []string) int {
	fs := flag.NewFlagSet("deps watch", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	advisorURL := fs.String("advisor-url", "", "Advisor base URL (or $BUMPER_ADVISOR_URL)")
	clientFlag := fs.String("client", "claude", "host agent whose shell tool to match: claude|augment")
	logPath := fs.String("log", "", "append raw hook payload + decision to this file (debug; or $BUMPER_HOOK_LOG)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cwd, _ := os.Getwd()
	client := deps.NewClient(deps.ResolveAdvisorURL(*advisorURL))
	// PostToolUse: the install already ran, so this hook never blocks (no exit 2);
	// it only injects context. Always exits 0.
	return runHook("deps watch", *logPath, func(r io.Reader, w io.Writer) (hookOutcome, error) {
		return hookOutcome{}, deps.Watch(r, w, client, cwd, shellToolForClient(*clientFlag))
	})
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
