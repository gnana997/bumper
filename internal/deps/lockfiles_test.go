package deps

import (
	"strings"
	"testing"
)

func names(ds []Dep) string {
	var s []string
	for _, d := range ds {
		s = append(s, d.Package+"@"+d.Version)
	}
	return strings.Join(s, ",")
}

func TestParseLockfiles(t *testing.T) {
	cases := []struct {
		name    string
		file    string
		content string
		want    string // comma-joined name@version, sorted by ParseLockfile
		eco     string
	}{
		{
			"npm v3", "package-lock.json",
			`{"lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0"},` +
				`"node_modules/lodash":{"version":"4.17.4"},` +
				`"node_modules/@scope/thing":{"version":"2.0.0"},` +
				`"node_modules/leftpad":{"version":"1.0.0","link":true}}}`,
			"@scope/thing@2.0.0,lodash@4.17.4", "npm",
		},
		{
			"npm v1", "package-lock.json",
			`{"lockfileVersion":1,"dependencies":{"a":{"version":"1.0.0","dependencies":{"b":{"version":"2.0.0"}}},"c":{"version":"git+https://x"}}}`,
			"a@1.0.0,b@2.0.0", "npm",
		},
		{
			"requirements", "requirements.txt",
			"django==3.2.0\nrequests>=2.0  # range skipped\nflask==2.0.1 ; python_version>='3.7'\n# comment\n-r other.txt",
			"django@3.2.0,flask@2.0.1", "PyPI",
		},
		{
			"poetry", "poetry.lock",
			"[[package]]\nname = \"jinja2\"\nversion = \"2.11.0\"\npython-versions = \">=3.6\"\n\n[[package]]\nname = \"click\"\nversion = \"8.0.0\"\npython-versions = \">=3.6\"",
			"click@8.0.0,jinja2@2.11.0", "PyPI",
		},
		{
			"pipfile", "Pipfile.lock",
			`{"_meta":{},"default":{"django":{"version":"==3.2.0"}},"develop":{"pytest":{"version":"==6.2.0"}}}`,
			"django@3.2.0,pytest@6.2.0", "PyPI",
		},
		{
			"go.sum", "go.sum",
			"github.com/gin-gonic/gin v1.6.0 h1:abc=\ngithub.com/gin-gonic/gin v1.6.0/go.mod h1:def=\ngolang.org/x/text v0.3.2 h1:xyz=",
			"github.com/gin-gonic/gin@1.6.0,golang.org/x/text@0.3.2", "Go",
		},
		{
			"uv", "uv.lock",
			"version = 1\nrequires-python = \">=3.8\"\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n\n[[package]]\nname = \"urllib3\"\nversion = \"2.0.7\"",
			"requests@2.31.0,urllib3@2.0.7", "PyPI",
		},
		{
			"cargo", "Cargo.lock",
			"[[package]]\nname = \"regex\"\nversion = \"1.5.4\"\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.130\"",
			"regex@1.5.4,serde@1.0.130", "crates.io",
		},
		{
			"gemfile", "Gemfile.lock",
			"GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.10.0)\n    rack (2.0.6)\n      json (>= 1.0)\n\nDEPENDENCIES\n  nokogiri",
			"nokogiri@1.10.0,rack@2.0.6", "RubyGems",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ParseLockfile(tc.file, tc.content)
			if err != nil {
				t.Fatalf("ParseLockfile: %v", err)
			}
			if got := names(res.Deps); got != tc.want {
				t.Errorf("deps = %q, want %q", got, tc.want)
			}
			if res.Ecosystem != tc.eco {
				t.Errorf("ecosystem = %q, want %q", res.Ecosystem, tc.eco)
			}
			for _, d := range res.Deps {
				if d.Ecosystem != tc.eco {
					t.Errorf("dep %s ecosystem = %q, want %q", d.Package, d.Ecosystem, tc.eco)
				}
			}
		})
	}
}

func TestParseLockfileErrors(t *testing.T) {
	if _, err := ParseLockfile("mystery.bin", "not a lockfile"); err == nil {
		t.Error("expected error for unrecognized file")
	}
	if _, err := ParseLockfile("requirements.txt", "# only comments\n-e .\n"); err == nil {
		t.Error("expected error for no pinned deps")
	}
}

func TestDetectFormatSniff(t *testing.T) {
	// renamed npm lock detected by content
	if id := DetectFormat("deps.json", `{"lockfileVersion":3,"packages":{}}`); id != "npm" {
		t.Errorf("npm sniff = %q", id)
	}
}
