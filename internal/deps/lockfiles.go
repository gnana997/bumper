// Package deps implements bumper's dependency guardrail: it parses lockfiles
// entirely locally and talks to the hosted Advisor (advisor.bumper.sh) over REST.
// Only package coordinates ({ecosystem, name, version}) ever leave the machine —
// never source. The parsers here mirror the browser parsers shipped in
// bumper-web/lib/lockfiles.ts so the CLI and the free web tool agree.
package deps

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Dep is a single resolved dependency coordinate — the only thing sent to the Advisor.
type Dep struct {
	Ecosystem string `json:"ecosystem"`
	Package   string `json:"package"`
	Version   string `json:"version"`
}

// Format describes a supported lockfile.
type Format struct {
	ID        string
	Label     string
	Ecosystem string
	Filenames []string // lowercase, for case-insensitive matching
}

// Formats is the v1 set: npm + Python + Go + Rust + Ruby (parity with the web tool).
var Formats = []Format{
	{"npm", "npm · package-lock.json", "npm", []string{"package-lock.json", "npm-shrinkwrap.json"}},
	{"pip", "Python · requirements.txt", "PyPI", []string{"requirements.txt"}},
	{"poetry", "Python · poetry.lock", "PyPI", []string{"poetry.lock"}},
	{"uv", "Python · uv.lock", "PyPI", []string{"uv.lock"}},
	{"pipfile", "Python · Pipfile.lock", "PyPI", []string{"pipfile.lock"}},
	{"gosum", "Go · go.sum", "Go", []string{"go.sum"}},
	{"gomod", "Go · go.mod", "Go", []string{"go.mod"}},
	{"cargo", "Rust · Cargo.lock", "crates.io", []string{"cargo.lock"}},
	{"gemfile", "Ruby · Gemfile.lock", "RubyGems", []string{"gemfile.lock"}},
}

// LockfileCandidates are the real on-disk filenames probed when auto-detecting a
// directory (preserves the real casing — Linux is case-sensitive).
var LockfileCandidates = []string{
	"package-lock.json", "npm-shrinkwrap.json",
	"requirements.txt", "poetry.lock", "uv.lock", "Pipfile.lock",
	"go.sum", "go.mod", "Cargo.lock", "Gemfile.lock",
}

func formatByFilename(name string) (Format, bool) {
	low := strings.ToLower(name)
	for _, f := range Formats {
		for _, fn := range f.Filenames {
			if fn == low {
				return f, true
			}
		}
	}
	return Format{}, false
}

var (
	rePackageBlock = regexp.MustCompile(`(^|\n)\[\[package\]\]`)
	reGemSpecs     = regexp.MustCompile(`(^|\n)\s{2}specs:`)
	reGemHeader    = regexp.MustCompile(`(^|\n)GEM(\n|$)`)
	reGoSumSniff   = regexp.MustCompile(`\sh1:[A-Za-z0-9+/=]+`)
)

// DetectFormat resolves a format id from the filename, falling back to content
// sniffing for renamed/pasted files. Returns "" if unrecognized.
func DetectFormat(filename, content string) string {
	if f, ok := formatByFilename(filepath.Base(filename)); ok {
		return f.ID
	}
	t := strings.TrimLeft(content, " \t\r\n")
	if strings.HasPrefix(t, "{") {
		var o map[string]json.RawMessage
		if json.Unmarshal([]byte(content), &o) == nil {
			if _, ok := o["lockfileVersion"]; ok {
				return "npm"
			}
			if _, ok := o["packages"]; ok {
				return "npm"
			}
			_, meta := o["_meta"]
			_, def := o["default"]
			_, dev := o["develop"]
			if meta && (def || dev) {
				return "pipfile"
			}
		}
	}
	if rePackageBlock.MatchString(content) && strings.Contains(content, "name =") {
		// poetry.lock / uv.lock / Cargo.lock all use [[package]]; filename normally
		// disambiguates. For a renamed file, PyPI markers route to the PyPI parser.
		if strings.Contains(content, "python-versions") || strings.Contains(content, "category =") ||
			strings.Contains(content, "requires-python") || strings.Contains(content, "pypi.org") {
			return "poetry"
		}
		return "cargo"
	}
	if reGemSpecs.MatchString(content) && reGemHeader.MatchString(content) {
		return "gemfile"
	}
	if reGoSumSniff.MatchString(content) {
		return "gosum"
	}
	return ""
}

// ParseResult is a parsed lockfile.
type ParseResult struct {
	Format    string
	Label     string
	Ecosystem string
	Deps      []Dep
}

// ParseLockfile detects + parses a lockfile's content into deduped coordinates.
func ParseLockfile(filename, content string) (*ParseResult, error) {
	id := DetectFormat(filename, content)
	if id == "" {
		return nil, fmt.Errorf("unrecognized file %q — expected a lockfile "+
			"(package-lock.json, requirements.txt, poetry.lock, uv.lock, Pipfile.lock, go.sum, Cargo.lock, Gemfile.lock)",
			filepath.Base(filename))
	}
	var meta Format
	for _, f := range Formats {
		if f.ID == id {
			meta = f
		}
	}
	var (
		deps []Dep
		err  error
	)
	switch id {
	case "npm":
		deps, err = parseNpm(content)
	case "pip":
		deps = parseRequirements(content)
	case "poetry", "uv":
		deps = parseTomlPackages(content, "PyPI")
	case "cargo":
		deps = parseTomlPackages(content, "crates.io")
	case "pipfile":
		deps, err = parsePipfile(content)
	case "gosum":
		deps = parseGoSum(content)
	case "gomod":
		deps = parseGoMod(content)
	case "gemfile":
		deps = parseGemfileLock(content)
	}
	if err != nil {
		return nil, fmt.Errorf("could not parse %s: %w", meta.Label, err)
	}
	deps = dedupe(deps)
	if len(deps) == 0 {
		return nil, fmt.Errorf("no pinned dependencies found in %s (requirements.txt scans only exact == pins)", meta.Label)
	}
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Package != deps[j].Package {
			return deps[i].Package < deps[j].Package
		}
		return deps[i].Version < deps[j].Version
	})
	return &ParseResult{id, meta.Label, meta.Ecosystem, deps}, nil
}

func dedupe(in []Dep) []Dep {
	seen := map[string]bool{}
	var out []Dep
	for _, d := range in {
		if d.Package == "" || d.Version == "" {
			continue
		}
		k := d.Ecosystem + "|" + d.Package + "|" + d.Version
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, d)
	}
	return out
}

// --- npm ---------------------------------------------------------------------

type npmV1Node struct {
	Version      string               `json:"version"`
	Dependencies map[string]npmV1Node `json:"dependencies"`
}

func parseNpm(content string) ([]Dep, error) {
	var data map[string]json.RawMessage
	if err := json.Unmarshal([]byte(content), &data); err != nil {
		return nil, err
	}
	var deps []Dep
	// lockfileVersion 2/3: a `packages` map keyed by install path.
	if raw, ok := data["packages"]; ok {
		var pkgs map[string]struct {
			Version string `json:"version"`
			Name    string `json:"name"`
			Link    bool   `json:"link"`
		}
		if err := json.Unmarshal(raw, &pkgs); err == nil {
			for path, info := range pkgs {
				if path == "" || info.Link || info.Version == "" {
					continue
				}
				name := info.Name
				if i := strings.LastIndex(path, "node_modules/"); i >= 0 {
					name = path[i+len("node_modules/"):]
				} else if name == "" {
					name = path
				}
				deps = append(deps, Dep{"npm", name, info.Version})
			}
			return deps, nil
		}
	}
	// lockfileVersion 1: a nested `dependencies` tree.
	if raw, ok := data["dependencies"]; ok {
		var tree map[string]npmV1Node
		if err := json.Unmarshal(raw, &tree); err == nil {
			var walk func(map[string]npmV1Node)
			walk = func(m map[string]npmV1Node) {
				for name, info := range m {
					if info.Version != "" && !strings.HasPrefix(info.Version, "git") && !strings.Contains(info.Version, "://") {
						deps = append(deps, Dep{"npm", name, info.Version})
					}
					if len(info.Dependencies) > 0 {
						walk(info.Dependencies)
					}
				}
			}
			walk(tree)
		}
	}
	return deps, nil
}

// --- Python ------------------------------------------------------------------

var reRequirement = regexp.MustCompile(`^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9._!+-]+)`)

func parseRequirements(content string) []Dep {
	var deps []Dep
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimRight(raw, "\r")
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if i := strings.Index(line, " #"); i >= 0 {
			line = line[:i]
		}
		if i := strings.Index(line, ";"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if m := reRequirement.FindStringSubmatch(line); m != nil {
			deps = append(deps, Dep{"PyPI", m[1], m[2]}) // only exact == pins are usable
		}
	}
	return deps
}

func parsePipfile(content string) ([]Dep, error) {
	var data map[string]json.RawMessage
	if err := json.Unmarshal([]byte(content), &data); err != nil {
		return nil, err
	}
	var deps []Dep
	for _, sect := range []string{"default", "develop"} {
		raw, ok := data[sect]
		if !ok {
			continue
		}
		var m map[string]struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(raw, &m) != nil {
			continue
		}
		for name, info := range m {
			v := strings.TrimSpace(strings.TrimPrefix(info.Version, "=="))
			if v != "" {
				deps = append(deps, Dep{"PyPI", name, v})
			}
		}
	}
	return deps, nil
}

// --- TOML (poetry.lock / Cargo.lock) -----------------------------------------

var (
	reTomlName    = regexp.MustCompile(`(?:^|\n)\s*name\s*=\s*"([^"]+)"`)
	reTomlVersion = regexp.MustCompile(`(?:^|\n)\s*version\s*=\s*"([^"]+)"`)
)

func parseTomlPackages(content, ecosystem string) []Dep {
	var deps []Dep
	for _, block := range strings.Split(content, "[[package]]") {
		name := reTomlName.FindStringSubmatch(block)
		ver := reTomlVersion.FindStringSubmatch(block)
		if name != nil && ver != nil {
			deps = append(deps, Dep{ecosystem, name[1], ver[1]})
		}
	}
	return deps
}

// --- Go ----------------------------------------------------------------------

var reGoSumLine = regexp.MustCompile(`^(\S+)\s+v(\S+?)(/go\.mod)?\s+h1:`)

func parseGoSum(content string) []Dep {
	// go.sum is a hash ledger, NOT the resolved dependency set: it records a hash for
	// every module version touched while computing the module graph. A line whose
	// version is suffixed "/go.mod" means only that version's go.mod was read during
	// resolution — its code was never downloaded and is (very often) not in the build.
	// Only a *zip* hash line (no "/go.mod" suffix) means the module was actually
	// fetched and compiled in. Counting the go.mod-only entries over-reports vulns in
	// versions that were never part of the binary, so we emit a dep only for versions
	// that have a zip hash. (The truly precise source is `go list -m all`, but that
	// needs a build; this is the correct static read of go.sum.)
	zipped := map[string]bool{}
	var deps []Dep
	for _, line := range strings.Split(content, "\n") {
		m := reGoSumLine.FindStringSubmatch(line)
		if m == nil || m[3] != "" { // m[3] == "/go.mod" → graph metadata, not the build
			continue
		}
		ver := strings.ReplaceAll(m[2], "+incompatible", "")
		key := m[1] + "@" + ver
		if zipped[key] {
			continue
		}
		zipped[key] = true
		deps = append(deps, Dep{"Go", m[1], ver})
	}
	return deps
}

var (
	reGoModReq  = regexp.MustCompile(`^(\S+)\s+v(\S+)`)
	reGoModSkip = regexp.MustCompile(`^(module|go|require|replace|exclude|retract)\b`)
)

func parseGoMod(content string) []Dep {
	var deps []Dep
	for _, raw := range strings.Split(content, "\n") {
		line := raw
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" || line == ")" || reGoModSkip.MatchString(line) {
			continue
		}
		if m := reGoModReq.FindStringSubmatch(line); m != nil {
			deps = append(deps, Dep{"Go", m[1], strings.ReplaceAll(m[2], "+incompatible", "")})
		}
	}
	return deps
}

// --- Ruby --------------------------------------------------------------------

var reGemSpec = regexp.MustCompile(`^    ([A-Za-z0-9._-]+) \(([^)]+)\)`)

func parseGemfileLock(content string) []Dep {
	var deps []Dep
	inSpecs := false
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimRight(raw, "\r")
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			inSpecs = false // any non-indented line ends the section
		}
		if strings.TrimSpace(line) == "specs:" && strings.HasPrefix(line, "  ") {
			inSpecs = true
			continue
		}
		if !inSpecs {
			continue
		}
		if m := reGemSpec.FindStringSubmatch(line); m != nil { // 4-space indent = a resolved gem
			deps = append(deps, Dep{"RubyGems", m[1], m[2]})
		}
	}
	return deps
}
