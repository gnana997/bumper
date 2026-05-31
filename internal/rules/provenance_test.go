package rules_test

import (
	"regexp"
	"testing"

	"github.com/gnana097/bumper/internal/rules"
)

// TestProvenance enforces the provenance invariants across the whole built-in
// set: every rule has a valid source, trivy rules carry a well-formed AVD id,
// custom rules carry none, and the id index round-trips.
func TestProvenance(t *testing.T) {
	set, err := rules.Load("")
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Rules) < 50 {
		t.Fatalf("expected the full built-in set, got %d rules", len(set.Rules))
	}

	avd := regexp.MustCompile(`^AVD-AWS-\d{4}$`)
	for _, r := range set.Rules {
		switch r.Source {
		case "trivy":
			if !avd.MatchString(r.AVD) {
				t.Errorf("%s: trivy rule needs an AVD-AWS-NNNN id, got %q", r.ID, r.AVD)
			}
		case "custom":
			if r.AVD != "" {
				t.Errorf("%s: custom rule should have no AVD, got %q", r.ID, r.AVD)
			}
		default:
			t.Errorf("%s: invalid source %q", r.ID, r.Source)
		}
		if got, ok := set.ByID(r.ID); !ok || got != r {
			t.Errorf("ByID(%s) did not round-trip", r.ID)
		}
	}

	if _, ok := set.ByID("NO_SUCH_RULE"); ok {
		t.Error("ByID should miss an unknown id")
	}
}
