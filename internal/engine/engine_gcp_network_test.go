package engine_test

import "testing"

// TestGCPNetworkRules covers the networking rule set: the modern firewall-policy
// rules (global / regional / hierarchical), auto-mode VPC, public-zone DNSSEC,
// and subnetwork flow logs — with discriminating negatives (private source,
// deny/disabled rules, non-sensitive port, private DNS zone, proxy subnet).
func TestGCPNetworkRules(t *testing.T) {
	f := evalFixture(t, "plan_gcp_network.json")

	// Positive cases.
	for _, c := range []struct{ rule, addr string }{
		{"GCP_FW_POLICY_PUBLIC_INGRESS_SENSITIVE", "google_compute_network_firewall_policy_rule.open_ssh"},
		{"GCP_FW_POLICY_PUBLIC_INGRESS_SENSITIVE", "google_compute_region_network_firewall_policy_rule.open_allproto"},
		{"GCP_FW_POLICY_PUBLIC_INGRESS_SENSITIVE", "google_compute_firewall_policy_rule.open_rdp_v6"},
		{"GCP_NETWORK_AUTO_MODE", "google_compute_network.auto"},
		{"GCP_DNS_NO_DNSSEC", "google_dns_managed_zone.public_plain"},
		{"GCP_SUBNETWORK_NO_FLOW_LOGS", "google_compute_subnetwork.nolog"},
	} {
		if !has(f, c.rule, c.addr) {
			t.Errorf("expected finding %s on %s; got %+v", c.rule, c.addr, f)
		}
	}

	// Negative cases — these must produce no findings at all.
	for _, addr := range []string{
		"google_compute_network_firewall_policy_rule.https_ok",      // public but port 443 (not sensitive)
		"google_compute_network_firewall_policy_rule.internal_ssh",  // ssh but private source
		"google_compute_network_firewall_policy_rule.deny_ssh",      // public ssh but action deny
		"google_compute_network_firewall_policy_rule.disabled_ssh",  // public ssh but disabled
		"google_compute_network.custom",                             // custom-mode VPC
		"google_dns_managed_zone.public_signed",                     // DNSSEC on
		"google_dns_managed_zone.private_zone",                      // private zone (DNSSEC N/A)
		"google_compute_subnetwork.logged",                          // flow logs on
		"google_compute_subnetwork.proxy",                           // proxy-only subnet (flow logs N/A)
	} {
		if mentions(f, addr) {
			t.Errorf("resource %s should produce no findings; got %+v", addr, f)
		}
	}
}
