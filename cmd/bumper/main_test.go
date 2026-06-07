package main

import (
	"reflect"
	"testing"
)

// depsValueFlags mirrors the set passed by cmdDepsScan; kept here so the
// regression test fails loudly if a new space-separated value flag is added to
// the command but forgotten in the hoist map.
var depsValueFlags = map[string]bool{
	"-advisor-url": true, "--advisor-url": true,
	"-format": true, "--format": true,
	"-min-severity": true, "--min-severity": true,
}

func TestHoistFlags(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			// The bug: `--format json` after the path left `json` as a positional.
			name: "space-separated value flag after path",
			in:   []string{"go.sum", "--format", "json"},
			want: []string{"--format", "json", "go.sum"},
		},
		{
			name: "min-severity space form after path",
			in:   []string{"go.sum", "--min-severity", "high", "--format", "json"},
			want: []string{"--min-severity", "high", "--format", "json", "go.sum"},
		},
		{
			name: "equals form is untouched",
			in:   []string{"go.sum", "--format=json"},
			want: []string{"--format=json", "go.sum"},
		},
		{
			name: "boolean flag after path",
			in:   []string{"go.sum", "--json"},
			want: []string{"--json", "go.sum"},
		},
		{
			name: "already flags-first stays stable",
			in:   []string{"--format", "json", "go.sum"},
			want: []string{"--format", "json", "go.sum"},
		},
		{
			name: "advisor-url value not swallowed as path",
			in:   []string{"requirements.txt", "--advisor-url", "http://localhost:8080"},
			want: []string{"--advisor-url", "http://localhost:8080", "requirements.txt"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := hoistFlags(c.in, depsValueFlags)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("hoistFlags(%v)\n  got  %v\n  want %v", c.in, got, c.want)
			}
		})
	}
}
