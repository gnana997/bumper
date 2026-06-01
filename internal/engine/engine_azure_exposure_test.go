package engine_test

import "testing"

// TestAzureExposure covers the Azure public-exposure family: storage container
// public access (AVD-AZU-0007), storage account permits-public-blob (v3/v4
// rename), single-server DB public network access (excluding flexible servers),
// Redis public network access, AKS public API server (AVD-AZU-0041, both the
// nested and top-level authorized-IP shapes), and ACR public exposure. Each rule
// has discriminating negatives (private/locked-down variants, flexible server).
func TestAzureExposure(t *testing.T) {
	f := evalFixture(t, "plan_azure_exposure.json")

	// Positive cases.
	for _, c := range []struct{ rule, addr string }{
		{"AZURE_STORAGE_CONTAINER_PUBLIC", "azurerm_storage_container.public_blob"},
		{"AZURE_STORAGE_CONTAINER_PUBLIC", "azurerm_storage_container.public_container"},
		{"AZURE_STORAGE_ACCOUNT_ALLOWS_PUBLIC_BLOB", "azurerm_storage_account.permits_public_v4"},
		{"AZURE_STORAGE_ACCOUNT_ALLOWS_PUBLIC_BLOB", "azurerm_storage_account.permits_public_v2"},
		{"AZURE_SQL_PUBLIC_NETWORK", "azurerm_mssql_server.public"},
		{"AZURE_SQL_PUBLIC_NETWORK", "azurerm_postgresql_server.public"},
		{"AZURE_REDIS_PUBLIC_NETWORK", "azurerm_redis_cache.public"},
		{"AZURE_AKS_PUBLIC_API_SERVER", "azurerm_kubernetes_cluster.public_api"},
		{"AZURE_ACR_PUBLIC", "azurerm_container_registry.public_network"},
		{"AZURE_ACR_PUBLIC", "azurerm_container_registry.anon_pull"},
	} {
		if !has(f, c.rule, c.addr) {
			t.Errorf("expected %s on %s; got %+v", c.rule, c.addr, f)
		}
	}

	// Negative cases — these must produce no findings at all.
	for _, addr := range []string{
		"azurerm_storage_container.private",                     // container_access_type private
		"azurerm_storage_account.locked_down",                   // allow_nested_items_to_be_public false
		"azurerm_mssql_server.private",                          // public_network_access_enabled false
		"azurerm_postgresql_flexible_server.flex",               // flexible server excluded (computed field)
		"azurerm_redis_cache.private",                           // public_network_access_enabled false
		"azurerm_kubernetes_cluster.private",                    // private_cluster_enabled true
		"azurerm_kubernetes_cluster.authorized_ranges_nested",   // nested authorized_ip_ranges set
		"azurerm_kubernetes_cluster.authorized_ranges_toplevel", // top-level authorized ranges set
		"azurerm_container_registry.locked_down",                // both public flags false
	} {
		if mentions(f, addr) {
			t.Errorf("%s should be silent; got %+v", addr, f)
		}
	}
}
