package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

func TestLogHookEvent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.log")
	// A valid JSON payload + a JSON decision → both embed as nested JSON.
	logHookEvent(path, "deps guard",
		[]byte(`{"tool_name":"launch-process","tool_input":{"command":"npm i evil"}}`),
		[]byte(`{"hookSpecificOutput":{"permissionDecision":"deny"}}`), nil)
	// A silent allow (empty output) on a second call → appends, "out" is "".
	logHookEvent(path, "deps watch", []byte(`{"tool_name":"x"}`), nil, nil)

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 log lines, got %d", len(lines))
	}
	var first struct {
		Hook string          `json:"hook"`
		In   json.RawMessage `json:"in"`
		Out  json.RawMessage `json:"out"`
		TS   string          `json:"ts"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("log line is not valid JSON: %v\n%s", err, lines[0])
	}
	if first.Hook != "deps guard" || first.TS == "" {
		t.Errorf("bad entry: %+v", first)
	}
	if !strings.Contains(string(first.In), "launch-process") || !strings.Contains(string(first.Out), "deny") {
		t.Errorf("payload/decision not captured: in=%s out=%s", first.In, first.Out)
	}
}

func TestLogHookEventFailSafe(t *testing.T) {
	// An unwritable path must not panic — logging is best-effort.
	logHookEvent(filepath.Join(t.TempDir(), "no-such-dir", "x.log"), "guard", []byte("not json"), nil, nil)
}
