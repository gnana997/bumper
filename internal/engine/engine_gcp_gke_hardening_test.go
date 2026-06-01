package engine_test

import "testing"

// TestGCPGKEHardening covers the GKE node/cluster hardening rule set: missing
// master authorized networks (cluster-only), legacy metadata endpoints, metadata
// concealment off, and default node service account (the latter three type-less
// over google_container_cluster + google_container_node_pool). Negatives assert
// hardened variants stay silent, including a node pool with no
// workload_metadata_config block (concealment rule must NOT fire on absence).
func TestGCPGKEHardening(t *testing.T) {
	f := evalFixture(t, "plan_gcp_gke_hardening.json")

	// Positive cases.
	for _, c := range []struct{ rule, addr string }{
		{"GCP_GKE_NO_MASTER_AUTHORIZED_NETWORKS", "google_container_cluster.no_master_networks"},
		{"GCP_GKE_LEGACY_METADATA_ENDPOINTS", "google_container_cluster.legacy_metadata"},
		{"GCP_GKE_METADATA_CONCEALMENT_OFF", "google_container_node_pool.concealment_off"},
		{"GCP_GKE_NODE_DEFAULT_SA", "google_container_node_pool.default_sa"},
		{"GCP_GKE_NODE_DEFAULT_SA", "google_container_node_pool.no_sa"},
	} {
		if !has(f, c.rule, c.addr) {
			t.Errorf("expected finding %s on %s; got %+v", c.rule, c.addr, f)
		}
	}

	// Negative cases — these must produce no findings at all.
	for _, addr := range []string{
		"google_container_cluster.hardened",   // master networks + hardened node config
		"google_container_node_pool.hardened", // dedicated SA, GKE_METADATA, legacy off
		"google_container_node_pool.no_wmc",   // no workload_metadata_config -> concealment silent
	} {
		if mentions(f, addr) {
			t.Errorf("resource %s should produce no findings; got %+v", addr, f)
		}
	}
}
