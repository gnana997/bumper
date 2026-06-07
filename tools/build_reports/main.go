// Command build_reports generates the self-scan showcase reports consumed by
// bumper-web. It runs the bumper binary (plan + deps) over the committed example
// fixtures and the repo's own go.sum, then writes a single self-contained
// reports.json manifest (per-target summary + a trimmed findings sample) plus the
// full raw output per target. The self-scan workflow uploads these to the rolling
// reports-latest release asset; bumper-web fetches reports.json (ISR-cached) and
// renders the "See it in action" page.
//
// Usage: BUMPER_BIN=./bumper go run ./tools/build_reports [--out reports]
// Findings are real — deps targets query the hosted Advisor, so counts track the
// daily mirror and drift over time (that's the point: the showcase stays current).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
)

type target struct {
	ID, Kind, Label, Subtitle, Path, Command, Action, Ecosystem string
}

// Showcase targets. Kind selects the bumper subcommand + output schema. Paths are
// relative to the repo root (run from there).
var targets = []target{
	{ID: "terraform-safety", Kind: "plan",
		Label: "Terraform plan safety", Subtitle: "a destructive + exposing AWS apply",
		Path:    "examples/terraform-safety/plan.json",
		Command: "bumper plan.json",
		Action:  "- uses: gnana997/bumper@v1\n  with:\n    plan-json: plan.json"},
	{ID: "deps-npm-crafted", Kind: "deps", Ecosystem: "npm",
		Label: "npm — crafted sample", Subtitle: "vulnerable + a malicious package",
		Path:    "examples/dependency-scan/package-lock.json",
		Command: "bumper deps package-lock.json",
		Action:  "- uses: gnana997/bumper/deps@v1"},
	{ID: "deps-python-crafted", Kind: "deps", Ecosystem: "PyPI",
		Label: "Python — crafted sample", Subtitle: "known CVEs (requirements.txt)",
		Path:    "examples/dependency-scan/requirements.txt",
		Command: "bumper deps requirements.txt",
		Action:  "- uses: gnana997/bumper/deps@v1"},
	{ID: "deps-npm-real", Kind: "deps", Ecosystem: "npm",
		Label: "npm — real-world project", Subtitle: "anonymized lockfile, full dependency tree",
		Path:    "examples/dependency-scan/real-world/npm/package-lock.json",
		Command: "bumper deps package-lock.json",
		Action:  "- uses: gnana997/bumper/deps@v1"},
	{ID: "deps-python-real", Kind: "deps", Ecosystem: "PyPI",
		Label: "Python (uv) — real-world project", Subtitle: "anonymized uv.lock, full dependency tree",
		Path:    "examples/dependency-scan/real-world/python/uv.lock",
		Command: "bumper deps uv.lock",
		Action:  "- uses: gnana997/bumper/deps@v1"},
	{ID: "deps-rust-real", Kind: "deps", Ecosystem: "crates.io",
		Label: "Rust — real-world project", Subtitle: "anonymized Cargo.lock, full dependency tree",
		Path:    "examples/dependency-scan/real-world/rust/Cargo.lock",
		Command: "bumper deps Cargo.lock",
		Action:  "- uses: gnana997/bumper/deps@v1"},
	{ID: "deps-go-self", Kind: "deps", Ecosystem: "Go",
		Label: "Go — bumper's own dependencies", Subtitle: "dogfood: bumper scans itself",
		Path:    "go.sum",
		Command: "bumper deps go.sum",
		Action:  "- uses: gnana997/bumper/deps@v1"},
}

var sevOrder = map[string]int{"malicious": -1, "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

const sampleLimit = 8

// --- bumper JSON shapes -------------------------------------------------------

type planFinding struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Address  string `json:"address"`
}

type depVuln struct {
	ID           string `json:"id"`
	Severity     string `json:"severity"`
	FixedVersion string `json:"fixed_version"`
}
type depMal struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
}
type depFinding struct {
	Ecosystem string    `json:"ecosystem"`
	Package   string    `json:"package"`
	Version   string    `json:"version"`
	Vulns     []depVuln `json:"vulns"`
	Malware   []depMal  `json:"malware"`
}
type depsResult struct {
	Scanned         int          `json:"scanned"`
	VulnerableCount int          `json:"vulnerable_count"`
	MalwareCount    int          `json:"malware_count"`
	Findings        []depFinding `json:"findings"`
}

// --- manifest output ----------------------------------------------------------

type entry struct {
	ID        string           `json:"id"`
	Kind      string           `json:"kind"`
	Label     string           `json:"label"`
	Subtitle  string           `json:"subtitle"`
	Command   string           `json:"command"`
	Action    string           `json:"action"`
	Ecosystem string           `json:"ecosystem,omitempty"`
	Summary   map[string]int   `json:"summary"`
	Sample    []map[string]any `json:"sample"`
}
type manifest struct {
	GeneratedAt   string  `json:"generated_at"`
	BumperVersion string  `json:"bumper_version"`
	Reports       []entry `json:"reports"`
}

// runBumper runs `bumper [deps] --format json --no-fail <path>`. A clean scan
// emits JSON null / findings:null, which is success — only exit 2 or unparseable
// output is an error.
func runBumper(bin string, t target) ([]byte, bool) {
	args := []string{}
	if t.Kind == "deps" {
		args = append(args, "deps")
	}
	args = append(args, "--format", "json", "--no-fail", t.Path)
	cmd := exec.Command(bin, args...)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
			return out, true // exit 1 = findings present, still success
		}
		fmt.Fprintf(os.Stderr, "  ! %s: %v\n", t.Path, err)
		return nil, false
	}
	return out, true
}

func summarizePlan(raw []byte) (map[string]int, []map[string]any) {
	var rows []planFinding
	_ = json.Unmarshal(raw, &rows) // null -> empty
	sort.SliceStable(rows, func(i, j int) bool { return sevOrder[rows[i].Severity] < sevOrder[rows[j].Severity] })
	by := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	var sample []map[string]any
	for _, f := range rows {
		by[f.Severity]++
		if len(sample) < sampleLimit {
			sample = append(sample, map[string]any{
				"severity": f.Severity, "title": f.Title, "address": f.Address, "rule_id": f.RuleID})
		}
	}
	by["findings"] = len(rows)
	return by, sample
}

func summarizeDeps(raw []byte) (map[string]int, []map[string]any) {
	var d depsResult
	_ = json.Unmarshal(raw, &d)
	by := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	var rows []map[string]any
	for _, f := range d.Findings {
		for _, m := range f.Malware {
			rows = append(rows, map[string]any{"ecosystem": f.Ecosystem, "package": f.Package,
				"version": f.Version, "severity": "malicious", "id": m.ID, "fixed_version": "", "malicious": true})
		}
		for _, v := range f.Vulns {
			by[v.Severity]++
			rows = append(rows, map[string]any{"ecosystem": f.Ecosystem, "package": f.Package,
				"version": f.Version, "severity": v.Severity, "id": v.ID, "fixed_version": v.FixedVersion, "malicious": false})
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		return sevOrder[rows[i]["severity"].(string)] < sevOrder[rows[j]["severity"].(string)]
	})
	if len(rows) > sampleLimit {
		rows = rows[:sampleLimit]
	}
	by["scanned"] = d.Scanned
	by["vulnerable"] = d.VulnerableCount
	by["malicious"] = d.MalwareCount
	return by, rows
}

func main() {
	out := flag.String("out", "reports", "output directory")
	flag.Parse()
	bin := os.Getenv("BUMPER_BIN")
	if bin == "" {
		bin = "./bumper"
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var reports []entry
	for _, t := range targets {
		fmt.Printf("scanning %s (%s) …\n", t.ID, t.Path)
		raw, ok := runBumper(bin, t)
		if !ok {
			continue
		}
		var summary map[string]int
		var sample []map[string]any
		if t.Kind == "plan" {
			summary, sample = summarizePlan(raw)
		} else {
			summary, sample = summarizeDeps(raw)
		}
		if err := os.WriteFile(filepath.Join(*out, t.ID+".json"), raw, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if sample == nil {
			sample = []map[string]any{}
		}
		reports = append(reports, entry{
			ID: t.ID, Kind: t.Kind, Label: t.Label, Subtitle: t.Subtitle,
			Command: t.Command, Action: t.Action, Ecosystem: t.Ecosystem,
			Summary: summary, Sample: sample,
		})
		fmt.Printf("  -> %v\n", summary)
	}

	m := manifest{
		GeneratedAt:   os.Getenv("GENERATED_AT"),
		BumperVersion: envOr("BUMPER_VERSION", "dev"),
		Reports:       reports,
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(filepath.Join(*out, "reports.json"), b, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("\nwrote %d reports -> %s/reports.json\n", len(reports), *out)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
