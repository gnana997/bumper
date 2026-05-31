package engine_test

import "testing"

// TestCatalogBatch covers the rules ported from the Trivy catalog in the second
// porting pass (transport/exposure, encryption-at-rest, EC2/ECR hardening, and
// recovery). Each entry asserts a specific (rule, resource) pair fires.
func TestCatalogBatch(t *testing.T) {
	f := evalFixture(t, "plan_catalog_batch.json")

	for _, c := range []struct{ rule, addr string }{
		// transport / public exposure
		{"AWS_CLOUDFRONT_NO_HTTPS", "aws_cloudfront_distribution.cdn"},
		{"AWS_ELB_PLAIN_HTTP_LISTENER", "aws_lb_listener.http"},
		{"AWS_ES_NO_HTTPS_ENFORCED", "aws_elasticsearch_domain.search"},
		{"AWS_EKS_PUBLIC_ENDPOINT_OPEN", "aws_eks_cluster.k8s"},
		{"AWS_MQ_BROKER_PUBLIC", "aws_mq_broker.broker"},
		// encryption at rest
		{"AWS_SNS_UNENCRYPTED", "aws_sns_topic.topic"},
		{"AWS_SQS_UNENCRYPTED", "aws_sqs_queue.queue"},
		{"AWS_KINESIS_UNENCRYPTED", "aws_kinesis_stream.stream"},
		{"AWS_ES_UNENCRYPTED_AT_REST", "aws_elasticsearch_domain.search"},
		{"AWS_REDSHIFT_UNENCRYPTED", "aws_redshift_cluster.rs"},
		{"AWS_NEPTUNE_UNENCRYPTED", "aws_neptune_cluster.neptune"},
		{"AWS_DOCDB_UNENCRYPTED", "aws_docdb_cluster.docdb"},
		{"AWS_RDS_CLUSTER_UNENCRYPTED", "aws_rds_cluster.aurora"},
		{"AWS_ELASTICACHE_AT_REST_UNENCRYPTED", "aws_elasticache_replication_group.cache2"},
		// EC2 / ECR hardening
		{"AWS_EC2_IMDSV2_NOT_ENFORCED", "aws_instance.box"},
		{"AWS_ECR_SCAN_ON_PUSH_DISABLED", "aws_ecr_repository.repo"},
		// recovery / durability
		{"AWS_DYNAMODB_PITR_DISABLED", "aws_dynamodb_table.tbl"},
		{"AWS_S3_VERSIONING_DISABLED", "aws_s3_bucket_versioning.ver"},
		{"AWS_RDS_SHORT_BACKUP_RETENTION", "aws_db_instance.bak"},
		{"AWS_RDS_SHORT_BACKUP_RETENTION", "aws_rds_cluster.aurora"},
		{"AWS_RDS_CLUSTER_NO_DELETION_PROTECTION", "aws_rds_cluster.aurora"},
	} {
		if !has(f, c.rule, c.addr) {
			t.Errorf("expected finding %s on %s", c.rule, c.addr)
		}
	}

	// Negatives: IMDSv2-enforced instance and KMS-encrypted SNS topic stay clean.
	if mentions(f, "aws_instance.hardened") {
		t.Error("IMDSv2-enforced instance should produce no findings")
	}
	if mentions(f, "aws_sns_topic.enc") {
		t.Error("KMS-encrypted SNS topic should produce no findings")
	}
}
