// Package enrich translates deterministic findings into plain English by
// shelling out to a locally-installed, already-authenticated AI CLI (claude,
// gemini, ...). This costs nothing and needs no API key. Enrichment is pure
// garnish: the deterministic report is always complete without it, and any
// failure here is non-fatal.
package enrich

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/gnana097/bumper/internal/engine"
)

// CLI describes how to invoke a local AI CLI for a one-shot prompt.
type CLI struct {
	Name string
	Bin  string
	Args func(prompt string) []string
}

// known is the preference-ordered set of AI CLIs bumper can use.
var known = []CLI{
	{Name: "claude", Bin: "claude", Args: func(p string) []string { return []string{"-p", p} }},
	{Name: "gemini", Bin: "gemini", Args: func(p string) []string { return []string{"-p", p} }},
	{Name: "codex", Bin: "codex", Args: func(p string) []string { return []string{"exec", p} }},
	{Name: "opencode", Bin: "opencode", Args: func(p string) []string { return []string{"run", p} }},
	{Name: "auggie", Bin: "auggie", Args: func(p string) []string { return []string{"-p", p} }},
}

// Detect returns the first CLI on PATH matching prefer ("auto" = first found).
func Detect(prefer string) (CLI, bool) {
	for _, c := range known {
		if prefer != "auto" && prefer != c.Name {
			continue
		}
		if _, err := exec.LookPath(c.Bin); err == nil {
			return c, true
		}
	}
	return CLI{}, false
}

// Explain asks the detected CLI to translate findings into plain English.
func Explain(ctx context.Context, c CLI, findings []engine.Finding) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.Bin, c.Args(buildPrompt(findings))...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

func buildPrompt(findings []engine.Finding) string {
	var b strings.Builder
	b.WriteString("You are a senior AWS platform engineer reviewing a Terraform plan. ")
	b.WriteString("A deterministic scanner flagged the issues below. For each, in 1-2 plain-English sentences, ")
	b.WriteString("explain the concrete real-world consequence (what an attacker or operator could actually do) ")
	b.WriteString("and confirm the suggested fix. Be concise. Do not invent issues beyond those listed.\n\n")
	for i, f := range findings {
		fmt.Fprintf(&b, "%d. [%s] %s (resource: %s, rule: %s)\n",
			i+1, strings.ToUpper(f.Severity), f.Title, f.Address, f.RuleID)
	}
	return b.String()
}
