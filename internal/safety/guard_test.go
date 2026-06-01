package safety

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gnana997/bumper/internal/rules"
)

func TestParseTerraformCommands(t *testing.T) {
	cases := []struct {
		name        string
		cmd         string
		wantSub     string // "" means no apply/destroy command parsed
		wantPlan    string
		wantHasPlan bool
		wantChdir   string
		wantCd      string
	}{
		{"plain apply", "terraform apply tfplan", "apply", "tfplan", true, "", ""},
		{"bare apply", "terraform apply", "apply", "", false, "", ""},
		{"apply auto-approve", "terraform apply -auto-approve tfplan", "apply", "tfplan", true, "", ""},
		{"chdir", "terraform -chdir=infra apply tfplan", "apply", "tfplan", true, "infra", ""},
		{"cd chain", "cd infra && terraform apply tfplan", "apply", "tfplan", true, "", "infra"},
		{"bare destroy", "terraform destroy", "destroy", "", false, "", ""},
		{"destroy auto", "terraform destroy -auto-approve", "destroy", "", false, "", ""},
		{"plan is ignored", "terraform plan -out tfplan", "", "", false, "", ""},
		{"tofu", "tofu apply tfplan", "apply", "tfplan", true, "", ""},
		{"env prefix", "AWS_PROFILE=prod terraform apply tfplan", "apply", "tfplan", true, "", ""},
		{"echo chain", "echo deploying && terraform apply tfplan", "apply", "tfplan", true, "", ""},
		{"var space arg skipped", "terraform apply -var foo=bar tfplan", "apply", "tfplan", true, "", ""},
		{"absolute binary", "/usr/local/bin/terraform apply tfplan", "apply", "tfplan", true, "", ""},
		{"quoted plan", `terraform apply "tfplan"`, "apply", "tfplan", true, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseTerraformCommands(tc.cmd)
			if tc.wantSub == "" {
				if len(got) != 0 {
					t.Fatalf("expected no apply/destroy, got %+v", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("expected 1 command, got %d: %+v", len(got), got)
			}
			c := got[0]
			if c.Subcommand != tc.wantSub {
				t.Errorf("subcommand = %q, want %q", c.Subcommand, tc.wantSub)
			}
			if c.HasPlanFile != tc.wantHasPlan {
				t.Errorf("hasPlanFile = %v, want %v", c.HasPlanFile, tc.wantHasPlan)
			}
			if c.PlanFile != tc.wantPlan {
				t.Errorf("planFile = %q, want %q", c.PlanFile, tc.wantPlan)
			}
			if c.Chdir != tc.wantChdir {
				t.Errorf("chdir = %q, want %q", c.Chdir, tc.wantChdir)
			}
			if c.CdDir != tc.wantCd {
				t.Errorf("cdDir = %q, want %q", c.CdDir, tc.wantCd)
			}
		})
	}
}

func hookInput(tool, cmd, cwd string) HookInput {
	in := HookInput{HookEventName: "PreToolUse", ToolName: tool, CWD: cwd}
	in.ToolInput.Command = cmd
	return in
}

func TestDecideSilentForNonTerraform(t *testing.T) {
	now := time.Now()
	for _, tc := range []HookInput{
		hookInput("Read", "", "/repo"),
		hookInput("Bash", "ls -la", "/repo"),
		hookInput("Bash", "terraform plan -out tfplan", "/repo"),
		hookInput("Bash", "git commit -m apply", "/repo"),
	} {
		if d := Decide(tc, now, DefaultMaxAge); d.Deny {
			t.Errorf("expected silent allow for %q, got deny: %s", tc.ToolInput.Command, d.Reason)
		}
	}
}

func TestDecideBareApplyAndDestroyDeny(t *testing.T) {
	now := time.Now()
	bare := Decide(hookInput("Bash", "terraform apply", "/repo"), now, DefaultMaxAge)
	if !bare.Deny || !strings.Contains(bare.Reason, "saved plan") {
		t.Errorf("bare apply: deny=%v reason=%q", bare.Deny, bare.Reason)
	}
	destroy := Decide(hookInput("Bash", "terraform destroy -auto-approve", "/repo"), now, DefaultMaxAge)
	if !destroy.Deny || !strings.Contains(destroy.Reason, "destroy") {
		t.Errorf("destroy: deny=%v reason=%q", destroy.Deny, destroy.Reason)
	}
}

func TestDecideUnverifiedApplyDeny(t *testing.T) {
	dir := t.TempDir()
	planPath := filepath.Join(dir, "tfplan")
	if err := os.WriteFile(planPath, []byte(cleanPlanJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	// No verdict written → must deny.
	d := Decide(hookInput("Bash", "terraform apply tfplan", dir), time.Now(), DefaultMaxAge)
	if !d.Deny || !strings.Contains(d.Reason, "bumper verify") {
		t.Errorf("unverified apply: deny=%v reason=%q", d.Deny, d.Reason)
	}
}

func TestDecideMissingPlanDeny(t *testing.T) {
	d := Decide(hookInput("Bash", "terraform apply ghost.tfplan", t.TempDir()), time.Now(), DefaultMaxAge)
	if !d.Deny || !strings.Contains(d.Reason, "not found") {
		t.Errorf("missing plan: deny=%v reason=%q", d.Deny, d.Reason)
	}
}

// TestVerifyThenGuardAllow is the core round-trip: verify a clean plan, then the
// guard must allow `terraform apply <plan>` for that exact file.
func TestVerifyThenGuardAllow(t *testing.T) {
	set := loadSet(t)
	dir := t.TempDir()
	planPath := filepath.Join(dir, "tfplan")
	if err := os.WriteFile(planPath, []byte(cleanPlanJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Verify(set, planPath, DefaultMinSeverity, false, time.Now())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Passed {
		t.Fatalf("clean plan should pass, blocking=%d", len(res.Blocking))
	}

	d := Decide(hookInput("Bash", "terraform apply tfplan", dir), time.Now(), DefaultMaxAge)
	if d.Deny {
		t.Fatalf("verified plan should be allowed, got deny: %s", d.Reason)
	}

	// Tamper with the plan after verification → sha changes → deny.
	if err := os.WriteFile(planPath, []byte(destructivePlanJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	d2 := Decide(hookInput("Bash", "terraform apply tfplan", dir), time.Now(), DefaultMaxAge)
	if !d2.Deny {
		t.Error("tampered plan (sha mismatch) should be denied")
	}
}

func TestDecideStaleVerdict(t *testing.T) {
	set := loadSet(t)
	dir := t.TempDir()
	planPath := filepath.Join(dir, "tfplan")
	os.WriteFile(planPath, []byte(cleanPlanJSON), 0o644)

	verifiedAt := time.Now().Add(-48 * time.Hour)
	if _, err := Verify(set, planPath, DefaultMinSeverity, false, verifiedAt); err != nil {
		t.Fatal(err)
	}
	// max-age 24h, verdict is 48h old → stale → deny.
	d := Decide(hookInput("Bash", "terraform apply tfplan", dir), time.Now(), 24*time.Hour)
	if !d.Deny || !strings.Contains(d.Reason, "stale") {
		t.Errorf("stale verdict: deny=%v reason=%q", d.Deny, d.Reason)
	}
	// max-age 0 disables expiry → allow.
	if d := Decide(hookInput("Bash", "terraform apply tfplan", dir), time.Now(), 0); d.Deny {
		t.Errorf("max-age 0 should never expire, got deny: %s", d.Reason)
	}
}

func TestGuardEndToEnd(t *testing.T) {
	// A non-Bash payload produces no output (silent allow).
	payload, _ := json.Marshal(hookInput("Read", "", "/repo"))
	var out bytes.Buffer
	if err := Guard(bytes.NewReader(payload), &out, time.Now(), DefaultMaxAge); err != nil {
		t.Fatalf("Guard: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("expected no output for non-Bash, got %q", out.String())
	}

	// A bare apply produces a deny decision in the hook JSON contract.
	payload, _ = json.Marshal(hookInput("Bash", "terraform apply", "/repo"))
	out.Reset()
	if err := Guard(bytes.NewReader(payload), &out, time.Now(), DefaultMaxAge); err != nil {
		t.Fatalf("Guard: %v", err)
	}
	var decoded hookOutput
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("guard output is not valid hook JSON: %v (%q)", err, out.String())
	}
	if decoded.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("permissionDecision = %q, want deny", decoded.HookSpecificOutput.PermissionDecision)
	}
	if decoded.HookSpecificOutput.HookEventName != "PreToolUse" {
		t.Errorf("hookEventName = %q, want PreToolUse", decoded.HookSpecificOutput.HookEventName)
	}

	// Malformed payload is fail-open (no error, no output).
	out.Reset()
	if err := Guard(strings.NewReader("not json"), &out, time.Now(), DefaultMaxAge); err != nil {
		t.Errorf("malformed payload should fail-open, got err: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("malformed payload should produce no decision, got %q", out.String())
	}
}

func loadSet(t *testing.T) *rules.Set {
	t.Helper()
	set, err := rules.Load("")
	if err != nil {
		t.Fatalf("rules.Load: %v", err)
	}
	return set
}

const cleanPlanJSON = `{"format_version":"1.0","resource_changes":[
	{"address":"aws_s3_bucket.x","type":"aws_s3_bucket","name":"x",
	 "change":{"actions":["no-op"],"before":{},"after":{}}}]}`

const destructivePlanJSON = `{"format_version":"1.0","resource_changes":[
	{"address":"aws_db_instance.prod","type":"aws_db_instance","name":"prod",
	 "change":{"actions":["delete","create"],"before":{"skip_final_snapshot":false},
	 "after":{"skip_final_snapshot":true}}}]}`
