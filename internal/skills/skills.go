// Package skills serves bumper's agent skills — playbooks that teach a coding
// agent to drive bumper's plan gate, dependency guardrail, and Advisor. The
// SKILL.md content is embedded into the binary so `bumper skills get` and
// `bumper skills install` work offline and always match the installed version.
// The same files under content/ are published to the npx-skills and Claude
// plugin-marketplace channels via the repo-root .claude-plugin/marketplace.json.
package skills

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

//go:embed content
var content embed.FS

// Skill is one published playbook.
type Skill struct {
	Name  string // SKILL.md `name` and folder (gerund), e.g. "gating-terraform-plans"
	Short string // CLI alias for `bumper skills get`, e.g. "plan-gate"
	Title string // human title for `bumper skills list`
	Desc  string // one-line summary for `bumper skills list`
}

// All lists the skills bumper ships, in display order. Each Name must match a
// content/<Name>/SKILL.md directory embedded above.
var All = []Skill{
	{
		Name:  "gating-terraform-plans",
		Short: "plan-gate",
		Title: "Gating Terraform plans",
		Desc:  "Scan a plan and block apply until it is clean and verified.",
	},
	{
		Name:  "triaging-vulnerable-dependencies",
		Short: "deps-triage",
		Title: "Triaging vulnerable dependencies",
		Desc:  "Scan lockfiles, pull CVE/malware detail, pick a safe version.",
	},
	{
		Name:  "querying-the-bumper-advisor",
		Short: "advisor",
		Title: "Querying the bumper Advisor",
		Desc:  "Look up CVEs, malware reputation, and IaC rules from the Advisor.",
	},
}

// Find resolves a skill by its short alias or its full name.
func Find(nameOrShort string) (Skill, bool) {
	n := strings.TrimSpace(strings.ToLower(nameOrShort))
	for _, s := range All {
		if n == s.Short || n == s.Name {
			return s, true
		}
	}
	return Skill{}, false
}

// raw returns the embedded SKILL.md bytes for a skill (frontmatter included).
func (s Skill) raw() (string, error) {
	b, err := content.ReadFile("content/" + s.Name + "/SKILL.md")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Get returns the SKILL.md playbook with the YAML frontmatter stripped — the
// body an agent wants when it runs `bumper skills get <name>`.
func Get(nameOrShort string) (string, error) {
	s, ok := Find(nameOrShort)
	if !ok {
		return "", fmt.Errorf("unknown skill %q (try: %s)", nameOrShort, strings.Join(shorts(), ", "))
	}
	raw, err := s.raw()
	if err != nil {
		return "", err
	}
	return stripFrontmatter(raw), nil
}

func shorts() []string {
	out := make([]string, len(All))
	for i, s := range All {
		out[i] = s.Short
	}
	return out
}

// stripFrontmatter removes a leading "---\n...\n---\n" YAML block.
func stripFrontmatter(s string) string {
	if !strings.HasPrefix(s, "---\n") {
		return s
	}
	rest := s[len("---\n"):]
	i := strings.Index(rest, "\n---\n")
	if i < 0 {
		return s
	}
	return strings.TrimLeft(rest[i+len("\n---\n"):], "\n")
}

// Result is the outcome of installing one skill file.
type Result struct {
	Skill   Skill
	Path    string
	Created bool // a new file was written
	Updated bool // an existing file changed; neither set → unchanged
}

// Install writes each skill's SKILL.md into skillsDir/<name>/SKILL.md, creating
// directories as needed. skillsDir is typically <agentcfg>/skills (for example
// .claude/skills). Writes are idempotent: unchanged files are left untouched.
func Install(skillsDir string) ([]Result, error) {
	out := make([]Result, 0, len(All))
	for _, s := range All {
		raw, err := s.raw()
		if err != nil {
			return out, err
		}
		path := filepath.Join(skillsDir, s.Name, "SKILL.md")
		created, updated, err := writeIfChanged(path, []byte(raw))
		if err != nil {
			return out, err
		}
		out = append(out, Result{Skill: s, Path: path, Created: created, Updated: updated})
	}
	return out, nil
}

func writeIfChanged(path string, data []byte) (created, updated bool, err error) {
	if existing, rerr := os.ReadFile(path); rerr == nil {
		if string(existing) == string(data) {
			return false, false, nil
		}
		if werr := os.WriteFile(path, data, 0o644); werr != nil {
			return false, false, werr
		}
		return false, true, nil
	}
	if merr := os.MkdirAll(filepath.Dir(path), 0o755); merr != nil {
		return false, false, merr
	}
	if werr := os.WriteFile(path, data, 0o644); werr != nil {
		return false, false, werr
	}
	return true, false, nil
}
