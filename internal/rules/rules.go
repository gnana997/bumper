// Package rules loads bumper's declarative rule set. Rules are authored in YAML
// with a CEL expression as the predicate; this package compiles each predicate
// once at load time so the engine can evaluate it against every change cheaply.
package rules

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/cel-go/cel"
	"gopkg.in/yaml.v3"
)

//go:embed builtin
var builtinFS embed.FS

// Rule is one declarative check. When (a CEL expression) is evaluated against a
// normalized resource change; if it returns true, the engine emits a finding.
type Rule struct {
	ID       string   `yaml:"id"`
	Severity string   `yaml:"severity"`
	Resource string   `yaml:"resource"` // resource-type filter, e.g. aws_security_group ("" = any)
	On       []string `yaml:"on"`       // change actions this rule applies to ("" = any)
	When     string   `yaml:"when"`     // CEL predicate, must evaluate to bool
	Title    string   `yaml:"title"`
	Fix      string   `yaml:"fix"`
	Refs     []string `yaml:"refs"`

	// Provenance — where this rule came from.
	Source   string `yaml:"source"`   // "custom" | "trivy"
	AVD      string `yaml:"avd"`      // original Trivy/AVD id, e.g. AVD-AWS-0180 ("" for custom)
	Provider string `yaml:"provider"` // "aws" | "gcp" | ... ("" = infer from resource prefix)

	program cel.Program // compiled When
}

// Program returns the compiled CEL program for this rule.
func (r *Rule) Program() cel.Program { return r.program }

// Set is a loaded, compiled collection of rules with an id index for O(1)
// lookup (used by `explain` and findings provenance).
type Set struct {
	Rules []*Rule
	byID  map[string]*Rule
}

// ByID returns the rule with the given id, or (nil, false).
func (s *Set) ByID(id string) (*Rule, bool) {
	r, ok := s.byID[id]
	return r, ok
}

// NewEnv builds the CEL environment exposing the variables a rule may read
// (before/after are dynamic; actions/type/address are strongly typed) plus
// bumper's custom function library.
func NewEnv() (*cel.Env, error) {
	opts := []cel.EnvOption{
		cel.Variable("address", cel.StringType),
		cel.Variable("type", cel.StringType),
		cel.Variable("actions", cel.ListType(cel.StringType)),
		cel.Variable("before", cel.DynType),
		cel.Variable("after", cel.DynType),
	}
	opts = append(opts, customFuncs()...)
	return cel.NewEnv(opts...)
}

// Load reads the embedded built-in rules plus any *.yaml rules under extraDir
// (may be ""), compiling every predicate.
func Load(extraDir string) (*Set, error) {
	env, err := NewEnv()
	if err != nil {
		return nil, fmt.Errorf("building CEL env: %w", err)
	}

	var raw []Rule
	if err := loadEmbedded(&raw); err != nil {
		return nil, err
	}
	if extraDir != "" {
		if err := loadDir(extraDir, &raw); err != nil {
			return nil, err
		}
	}

	set := &Set{byID: make(map[string]*Rule, len(raw))}
	for i := range raw {
		r := raw[i]
		if r.ID == "" {
			return nil, fmt.Errorf("rule with empty id (title %q)", r.Title)
		}
		if r.Source != "custom" && r.Source != "trivy" {
			return nil, fmt.Errorf("rule %s: source must be \"custom\" or \"trivy\", got %q", r.ID, r.Source)
		}
		if _, dup := set.byID[r.ID]; dup {
			return nil, fmt.Errorf("duplicate rule id %s", r.ID)
		}
		prg, err := compile(env, r.When)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.ID, err)
		}
		r.program = prg
		if r.Provider == "" {
			r.Provider = providerFromType(r.Resource)
		}
		set.Rules = append(set.Rules, &r)
		set.byID[r.ID] = set.Rules[len(set.Rules)-1]
	}
	return set, nil
}

func compile(env *cel.Env, expr string) (cel.Program, error) {
	if strings.TrimSpace(expr) == "" {
		return nil, fmt.Errorf("empty when expression")
	}
	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return nil, iss.Err()
	}
	if ot := ast.OutputType().String(); ot != "bool" && ot != "dyn" {
		return nil, fmt.Errorf("when must evaluate to bool, got %s", ot)
	}
	return env.Program(ast)
}

func loadEmbedded(out *[]Rule) error {
	return fs.WalkDir(builtinFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return err
		}
		b, err := builtinFS.ReadFile(path)
		if err != nil {
			return err
		}
		return appendYAML(b, out)
	})
}

func loadDir(dir string, out *[]Rule) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return appendYAML(b, out)
	})
}

func appendYAML(b []byte, out *[]Rule) error {
	var rs []Rule
	if err := yaml.Unmarshal(b, &rs); err != nil {
		return fmt.Errorf("parsing rules yaml: %w", err)
	}
	*out = append(*out, rs...)
	return nil
}

// providerFromType infers the cloud from a resource-type prefix, so existing
// rules need no `provider:` field. Type-less rules (the destruction family that
// matches via `type in [...]` in CEL) fall back to "" and can set it explicitly.
func providerFromType(resource string) string {
	switch {
	case strings.HasPrefix(resource, "aws_"):
		return "aws"
	case strings.HasPrefix(resource, "google_"):
		return "gcp"
	case strings.HasPrefix(resource, "azurerm_"):
		return "azure"
	case strings.HasPrefix(resource, "digitalocean_"):
		return "do"
	default:
		return ""
	}
}
