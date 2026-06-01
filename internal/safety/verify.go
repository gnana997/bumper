package safety

import (
	"fmt"
	"time"

	"github.com/gnana997/bumper/internal/engine"
	"github.com/gnana997/bumper/internal/plan"
	"github.com/gnana997/bumper/internal/report"
	"github.com/gnana997/bumper/internal/rules"
)

// DefaultMinSeverity is the threshold at or above which a finding blocks an
// apply (and fails `verify` unless --accept is given).
const DefaultMinSeverity = "high"

// VerifyResult is the outcome of verifying a plan.
type VerifyResult struct {
	Verdict  Verdict
	Findings []engine.Finding // all findings (not just blocking ones)
	Blocking []engine.Finding // findings at/above the threshold
	Passed   bool             // true if no blocking findings, or accepted
}

// Verify scans the plan at planPath and decides whether it may be applied. On a
// pass (no blocking findings) — or when accept is true despite blocking
// findings — it writes a verdict bound to the plan's sha256 and returns
// Passed=true. It does not write a verdict on a hard fail.
//
// now is injected so callers/tests control the timestamp.
func Verify(set *rules.Set, planPath, minSeverity string, accept bool, now time.Time) (VerifyResult, error) {
	if minSeverity == "" {
		minSeverity = DefaultMinSeverity
	}
	sha, err := Sha256File(planPath)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("hashing plan: %w", err)
	}
	data, _, err := ResolvePlanData("", planPath)
	if err != nil {
		return VerifyResult{}, err
	}
	changes, err := plan.Load(data)
	if err != nil {
		return VerifyResult{}, err
	}
	findings, err := engine.Evaluate(changes, set)
	if err != nil {
		return VerifyResult{}, err
	}

	threshold := engine.Rank(minSeverity)
	var blocking []engine.Finding
	for _, f := range findings {
		if engine.Rank(f.Severity) >= threshold {
			blocking = append(blocking, f)
		}
	}

	res := VerifyResult{Findings: findings, Blocking: blocking}
	res.Passed = len(blocking) == 0 || accept

	if !res.Passed {
		return res, nil
	}

	verdict := Verdict{
		PlanSHA:       sha,
		PlanFile:      planPath,
		Verdict:       "pass",
		MinSeverity:   minSeverity,
		FindingsTotal: len(findings),
		Blocking:      len(blocking),
		BumperVersion: report.Version,
		VerifiedAt:    now,
	}
	if len(blocking) > 0 && accept {
		verdict.Verdict = "accepted"
		verdict.Accepted = true
	}

	store, err := StoreForPlan(planPath)
	if err != nil {
		return res, err
	}
	if err := store.Save(verdict); err != nil {
		return res, err
	}
	res.Verdict = verdict
	return res, nil
}
