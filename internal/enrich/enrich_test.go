package enrich

import "testing"

// TestMatchesPrefer guards the regression where prefer="" (used by the ruleset
// TUI) matched no CLI, so explain always reported "no AI CLI on PATH".
func TestMatchesPrefer(t *testing.T) {
	cases := []struct {
		prefer, name string
		want         bool
	}{
		{"", "claude", true},        // empty = any
		{"auto", "claude", true},    // auto = any
		{"", "gemini", true},        // empty = any (all CLIs)
		{"claude", "claude", true},  // pinned, match
		{"claude", "gemini", false}, // pinned, no match
		{"gemini", "claude", false}, // pinned, no match
	}
	for _, c := range cases {
		if got := matchesPrefer(c.prefer, c.name); got != c.want {
			t.Errorf("matchesPrefer(%q, %q) = %v, want %v", c.prefer, c.name, got, c.want)
		}
	}
}
