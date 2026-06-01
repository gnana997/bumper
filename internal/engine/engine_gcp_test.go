package engine_test

import "testing"

// TestGCPRules covers the curated GCP rule set: every new rule fires on its
// positive fixture, and the hardened/benign counterparts stay silent.
func TestGCPRules(t *testing.T) {
	f := evalFixture(t, "plan_gcp.json")

	// Positive cases — each rule must fire on the intended resource.
	for _, c := range []struct{ rule, addr string }{
		{"GCP_SQL_PUBLIC_ACCESS", "google_sql_database_instance.public"},
		{"GCP_SQL_NO_SSL", "google_sql_database_instance.public"},
		{"GCP_SQL_LOCAL_INFILE_ON", "google_sql_database_instance.public"},
		{"GCP_STORAGE_BUCKET_PUBLIC_ACL", "google_storage_bucket_access_control.public"},
		{"GCP_STORAGE_UNIFORM_ACCESS_OFF", "google_storage_bucket.lake"},
		{"GCP_BIGQUERY_DATASET_PUBLIC", "google_bigquery_dataset.public"},
		{"GCP_COMPUTE_INSTANCE_PUBLIC_IP", "google_compute_instance.web"},
		{"GCP_COMPUTE_IP_FORWARDING", "google_compute_instance.web"},
		{"GCP_COMPUTE_DEFAULT_SERVICE_ACCOUNT", "google_compute_instance.web"},
		{"GCP_GKE_PUBLIC_CONTROL_PLANE", "google_container_cluster.gke"},
		{"GCP_GKE_LEGACY_ABAC", "google_container_cluster.gke"},
		{"GCP_GKE_SHIELDED_NODES_OFF", "google_container_cluster.gke"},
		{"GCP_GKE_NETWORK_POLICY_OFF", "google_container_cluster.gke"},
		{"GCP_KMS_KEY_NO_ROTATION", "google_kms_crypto_key.norotate"},
		{"GCP_SSL_POLICY_WEAK_TLS", "google_compute_ssl_policy.lb"},
		{"GCP_STATEFUL_RESOURCE_DESTROY", "google_bigquery_dataset.dropped"},
		{"GCP_STATEFUL_RESOURCE_DESTROY", "google_sql_database_instance.legacy_dropped"},
	} {
		if !has(f, c.rule, c.addr) {
			t.Errorf("expected finding %s on %s; got %+v", c.rule, c.addr, f)
		}
	}

	// Negative cases — hardened resources must produce no findings at all.
	for _, addr := range []string{
		"google_sql_database_instance.private",
		"google_storage_bucket.secure",
		"google_bigquery_dataset.private",
		"google_compute_instance.private_vm",
		"google_container_cluster.private_gke",
		"google_kms_crypto_key.rotated",
		"google_compute_ssl_policy.strong",
	} {
		if mentions(f, addr) {
			t.Errorf("hardened resource %s should produce no findings; got %+v", addr, f)
		}
	}
}
