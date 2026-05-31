package safety

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writePlan(t *testing.T, body string) (dir, path string) {
	t.Helper()
	dir = t.TempDir()
	path = filepath.Join(dir, "tfplan")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, path
}

func TestVerifyCleanWritesVerdict(t *testing.T) {
	set := loadSet(t)
	_, path := writePlan(t, cleanPlanJSON)

	res, err := Verify(set, path, DefaultMinSeverity, false, time.Now())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Passed || len(res.Blocking) != 0 {
		t.Fatalf("clean plan: passed=%v blocking=%d", res.Passed, len(res.Blocking))
	}
	if res.Verdict.Accepted {
		t.Error("clean plan should not be marked accepted")
	}

	// The verdict must be loadable by the plan's sha.
	sha, _ := Sha256File(path)
	store, _ := StoreForPlan(path)
	if _, ok, _ := store.Load(sha); !ok {
		t.Error("expected a saved verdict for the clean plan")
	}
}

func TestVerifyBlockingWritesNoVerdict(t *testing.T) {
	set := loadSet(t)
	_, path := writePlan(t, destructivePlanJSON)

	res, err := Verify(set, path, DefaultMinSeverity, false, time.Now())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Passed {
		t.Fatal("destructive plan should not pass without --accept")
	}
	if len(res.Blocking) == 0 {
		t.Fatal("expected blocking findings for the destructive plan")
	}

	sha, _ := Sha256File(path)
	store, _ := StoreForPlan(path)
	if _, ok, _ := store.Load(sha); ok {
		t.Error("a failed verify must NOT write a verdict")
	}
}

func TestVerifyAcceptOverride(t *testing.T) {
	set := loadSet(t)
	_, path := writePlan(t, destructivePlanJSON)

	res, err := Verify(set, path, DefaultMinSeverity, true, time.Now())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Passed {
		t.Fatal("--accept should make a blocking plan pass")
	}
	if !res.Verdict.Accepted || res.Verdict.Verdict != "accepted" {
		t.Errorf("override not recorded: accepted=%v verdict=%q", res.Verdict.Accepted, res.Verdict.Verdict)
	}
	if res.Verdict.Blocking == 0 {
		t.Error("accepted verdict should record the blocking count it overrode")
	}
}
