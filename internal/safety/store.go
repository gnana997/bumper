package safety

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// verifiedDirName is the on-disk store of plan verdicts, rooted next to the plan
// file so `verify` and `guard` always agree on where to look regardless of the
// caller's cwd or terraform's -chdir. Add it to .gitignore (verdicts are
// machine- and time-specific).
const verifiedDirName = ".bumper"

// Verdict is the record written when a plan passes (or is explicitly accepted).
// It binds a scan result to the exact plan bytes via PlanSHA.
type Verdict struct {
	PlanSHA       string    `json:"plan_sha"`
	PlanFile      string    `json:"plan_file"`
	Verdict       string    `json:"verdict"` // "pass" | "accepted"
	MinSeverity   string    `json:"min_severity"`
	FindingsTotal int       `json:"findings_total"`
	Blocking      int       `json:"blocking"` // count of findings at/above the threshold
	Accepted      bool      `json:"accepted"` // true when recorded via --accept despite blocking findings
	BumperVersion string    `json:"bumper_version"`
	VerifiedAt    time.Time `json:"verified_at"`
}

// Store is a directory of verdict files keyed by plan sha256.
type Store struct{ dir string }

// StoreForPlan returns the verdict store rooted at the plan file's directory
// (<plan-dir>/.bumper/verified). Both verify and guard derive the store this way
// from the same plan path, so the lookup is location-independent.
func StoreForPlan(planPath string) (*Store, error) {
	abs, err := filepath.Abs(planPath)
	if err != nil {
		return nil, err
	}
	return &Store{dir: filepath.Join(filepath.Dir(abs), verifiedDirName, "verified")}, nil
}

func (s *Store) path(sha string) string { return filepath.Join(s.dir, sha+".json") }

// Save writes a verdict, creating the store directory if needed.
func (s *Store) Save(v Verdict) error {
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return fmt.Errorf("creating verdict store: %w", err)
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path(v.PlanSHA), b, 0o644)
}

// Load returns the verdict for a plan sha, or ok=false if none is recorded.
func (s *Store) Load(sha string) (Verdict, bool, error) {
	b, err := os.ReadFile(s.path(sha))
	if os.IsNotExist(err) {
		return Verdict{}, false, nil
	}
	if err != nil {
		return Verdict{}, false, err
	}
	var v Verdict
	if err := json.Unmarshal(b, &v); err != nil {
		return Verdict{}, false, fmt.Errorf("corrupt verdict %s: %w", sha, err)
	}
	return v, true, nil
}
