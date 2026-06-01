package engine_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gnana997/bumper/internal/engine"
	"github.com/gnana997/bumper/internal/plan"
	"github.com/gnana997/bumper/internal/rules"
)

// evalFixture runs the full pipeline (parse -> normalize -> evaluate) against a
// plan fixture using the real built-in rule set.
func evalFixture(t *testing.T, name string) []engine.Finding {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	changes, err := plan.Load(data)
	if err != nil {
		t.Fatalf("plan.Load: %v", err)
	}
	set, err := rules.Load("")
	if err != nil {
		t.Fatalf("rules.Load: %v", err)
	}
	findings, err := engine.Evaluate(changes, set)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return findings
}

func has(findings []engine.Finding, ruleID, address string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID && f.Address == address {
			return true
		}
	}
	return false
}

func mentions(findings []engine.Finding, address string) bool {
	for _, f := range findings {
		if f.Address == address {
			return true
		}
	}
	return false
}

func TestExposureAndDestruction(t *testing.T) {
	f := evalFixture(t, "plan.json")

	if !has(f, "AWS_SG_PUBLIC_INGRESS", "aws_security_group.web") {
		t.Error("expected public-ingress finding on aws_security_group.web")
	}
	if !has(f, "AWS_DB_DESTRUCTIVE_REPLACE_NO_SNAPSHOT", "aws_db_instance.main") {
		t.Error("expected destructive-replace finding on aws_db_instance.main")
	}
	if !has(f, "AWS_STATEFUL_RESOURCE_DESTROY", "aws_db_instance.main") {
		t.Error("expected stateful-destroy finding on aws_db_instance.main")
	}
	if mentions(f, "aws_s3_bucket.logs") {
		t.Error("benign aws_s3_bucket.logs should produce no findings")
	}
}

func TestPortedRules(t *testing.T) {
	f := evalFixture(t, "plan_expanded.json")

	for _, c := range []struct{ rule, addr string }{
		{"AWS_RDS_PUBLICLY_ACCESSIBLE", "aws_db_instance.public"},
		{"AWS_RDS_STORAGE_UNENCRYPTED", "aws_db_instance.public"},
		{"AWS_EBS_VOLUME_UNENCRYPTED", "aws_ebs_volume.data"},
		{"AWS_STATEFUL_RESOURCE_DESTROY", "aws_dynamodb_table.sessions"},
		{"AWS_SG_PUBLIC_INGRESS", "aws_security_group.open"},
	} {
		if !has(f, c.rule, c.addr) {
			t.Errorf("expected finding %s on %s; got %+v", c.rule, c.addr, f)
		}
	}
}

// TestSecurityGroupShapes covers the hardened SG matching: IPv6 (::/0), the
// standalone rule resource, the modern VPC ingress-rule resource, and a private
// CIDR that must NOT fire.
func TestSecurityGroupShapes(t *testing.T) {
	f := evalFixture(t, "plan_sg.json")

	for _, c := range []struct{ rule, addr string }{
		{"AWS_SG_PUBLIC_INGRESS", "aws_security_group.inline_v6"},
		{"AWS_SG_RULE_PUBLIC_INGRESS", "aws_security_group_rule.standalone"},
		{"AWS_VPC_SG_INGRESS_PUBLIC", "aws_vpc_security_group_ingress_rule.modern"},
	} {
		if !has(f, c.rule, c.addr) {
			t.Errorf("expected finding %s on %s; got %+v", c.rule, c.addr, f)
		}
	}
	if mentions(f, "aws_security_group.private") {
		t.Error("private-CIDR security group should produce no findings")
	}
}

// TestIAMPolicies covers the parse_json depth path: wildcard admin policy and
// wildcard trust principal fire; a scoped policy and a service-principal trust
// must NOT.
func TestIAMPolicies(t *testing.T) {
	f := evalFixture(t, "plan_iam.json")

	if !has(f, "AWS_IAM_WILDCARD_ADMIN", "aws_iam_policy.admin") {
		t.Error("expected wildcard-admin finding on aws_iam_policy.admin")
	}
	if !has(f, "AWS_IAM_TRUST_POLICY_WILDCARD_PRINCIPAL", "aws_iam_role.open_trust") {
		t.Error("expected wildcard-principal finding on aws_iam_role.open_trust")
	}
	if mentions(f, "aws_iam_policy.scoped") {
		t.Error("scoped IAM policy should produce no findings")
	}
	if mentions(f, "aws_iam_role.svc_trust") {
		t.Error("service-principal trust policy should produce no findings")
	}
}

// TestBreadthRules covers the newly ported exposure family.
func TestBreadthRules(t *testing.T) {
	f := evalFixture(t, "plan_breadth.json")

	for _, c := range []struct{ rule, addr string }{
		{"AWS_S3_BUCKET_PUBLIC_ACL", "aws_s3_bucket.legacy"},
		{"AWS_S3_ACL_PUBLIC", "aws_s3_bucket_acl.modern"},
		{"AWS_S3_PUBLIC_ACCESS_BLOCK_WEAK", "aws_s3_bucket_public_access_block.weak"},
		{"AWS_EFS_UNENCRYPTED", "aws_efs_file_system.data"},
		{"AWS_ELASTICACHE_TRANSIT_UNENCRYPTED", "aws_elasticache_replication_group.cache"},
		{"AWS_RDS_NO_DELETION_PROTECTION", "aws_db_instance.prod"},
	} {
		if !has(f, c.rule, c.addr) {
			t.Errorf("expected finding %s on %s; got %+v", c.rule, c.addr, f)
		}
	}
}
