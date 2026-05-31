package engine_test

import "testing"

// TestCatalogBatch2 covers the third porting pass: TLS hygiene, network ACLs,
// CloudTrail tamper-protection, additional encryption, resource-policy exposure,
// ECS plaintext secrets, and durability checks.
func TestCatalogBatch2(t *testing.T) {
	f := evalFixture(t, "plan_catalog_batch2.json")

	for _, c := range []struct{ rule, addr string }{
		{"AWS_CLOUDFRONT_OUTDATED_TLS", "aws_cloudfront_distribution.oldtls"},
		{"AWS_APIGW_OUTDATED_TLS", "aws_api_gateway_domain_name.dom"},
		{"AWS_ES_OUTDATED_TLS", "aws_opensearch_domain.os"},
		{"AWS_ES_NODE_TO_NODE_UNENCRYPTED", "aws_opensearch_domain.os"},
		{"AWS_NACL_PUBLIC_INGRESS", "aws_network_acl_rule.open"},
		{"AWS_CLOUDTRAIL_NO_LOG_VALIDATION", "aws_cloudtrail.trail"},
		{"AWS_CLOUDTRAIL_NO_CMK", "aws_cloudtrail.trail"},
		{"AWS_KMS_NO_ROTATION", "aws_kms_key.key"},
		{"AWS_EC2_BLOCK_DEVICE_UNENCRYPTED", "aws_instance.unenc"},
		{"AWS_DAX_UNENCRYPTED", "aws_dax_cluster.dax"},
		{"AWS_MSK_TRANSIT_UNENCRYPTED", "aws_msk_cluster.msk"},
		{"AWS_WORKSPACES_UNENCRYPTED", "aws_workspaces_workspace.ws"},
		{"AWS_EKS_SECRETS_UNENCRYPTED", "aws_eks_cluster.noenc"},
		{"AWS_CODEBUILD_ARTIFACT_UNENCRYPTED", "aws_codebuild_project.cb"},
		{"AWS_EBS_DEFAULT_ENCRYPTION_DISABLED", "aws_ebs_encryption_by_default.def"},
		{"AWS_ECR_PUBLIC_POLICY", "aws_ecr_repository_policy.pub"},
		{"AWS_SQS_POLICY_PUBLIC", "aws_sqs_queue_policy.pub"},
		{"AWS_LAMBDA_PERMISSION_NO_SOURCE_ARN", "aws_lambda_permission.perm"},
		{"AWS_ECS_PLAINTEXT_SECRETS", "aws_ecs_task_definition.task"},
		{"AWS_ELASTICACHE_NO_BACKUP", "aws_elasticache_replication_group.nobackup"},
		{"AWS_ELB_DROP_INVALID_HEADERS", "aws_lb.alb"},
	} {
		if !has(f, c.rule, c.addr) {
			t.Errorf("expected finding %s on %s", c.rule, c.addr)
		}
	}

	// Negatives: validated+CMK CloudTrail and a scoped lambda permission stay clean.
	if mentions(f, "aws_cloudtrail.good") {
		t.Error("validated, CMK-encrypted CloudTrail should produce no findings")
	}
	if mentions(f, "aws_lambda_permission.scoped") {
		t.Error("lambda permission with source_arn should produce no findings")
	}
}
