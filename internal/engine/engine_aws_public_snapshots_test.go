package engine_test

import "testing"

// TestAWSPublicSnapshots covers the public-image / public-snapshot baseline:
// publicly-shared AMIs (group = "all"), public RDS/Aurora snapshots
// (shared_accounts contains "all"), and the EBS snapshot public-access block
// being disabled (state = "unblocked"). Discriminating negatives — an AMI or
// RDS snapshot shared with a specific account, a private snapshot, a properly
// blocked EBS public-access guard, and aws_snapshot_create_volume_permission
// scoped to an account (which has no public path at all) — must stay silent.
func TestAWSPublicSnapshots(t *testing.T) {
	f := evalFixture(t, "plan_aws_public_snapshots.json")

	// Positive cases.
	for _, c := range []struct{ rule, addr string }{
		{"AWS_AMI_PUBLIC", "aws_ami_launch_permission.public_ami"},
		{"AWS_RDS_SNAPSHOT_PUBLIC", "aws_db_snapshot.public"},
		{"AWS_RDS_SNAPSHOT_PUBLIC", "aws_db_cluster_snapshot.public"},
		{"AWS_EBS_SNAPSHOT_PUBLIC", "aws_ebs_snapshot_block_public_access.unblocked"},
	} {
		if !has(f, c.rule, c.addr) {
			t.Errorf("expected %s on %s; got %+v", c.rule, c.addr, f)
		}
	}

	// Negative cases — these must produce no findings at all.
	for _, addr := range []string{
		"aws_ami_launch_permission.shared_account",             // shared to a specific account, group not "all"
		"aws_db_snapshot.shared_account",                       // shared to specific accounts, no "all"
		"aws_db_snapshot.private",                              // empty shared_accounts
		"aws_ebs_snapshot_block_public_access.blocked",         // public access blocked
		"aws_snapshot_create_volume_permission.shared_account", // account-scoped; no public path exists
	} {
		if mentions(f, addr) {
			t.Errorf("%s should be silent; got %+v", addr, f)
		}
	}
}
