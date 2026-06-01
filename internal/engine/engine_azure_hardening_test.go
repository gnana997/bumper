package engine_test

import "testing"

// TestAzureHardening covers the Azure TLS / IAM / Key Vault / compute hardening
// wave: storage insecure transfer (v3 and v4 field names) and weak min TLS,
// mssql weak/disabled TLS, single-server SSL enforcement off, app-service
// https_only absence/false, privileged role assignments at subscription /
// management-group scope, key vault purge protection off, and the advisory
// public-IP creation rule. Negatives assert the secure/private variants stay
// silent — notably an Owner assignment at RESOURCE-GROUP scope must NOT fire.
func TestAzureHardening(t *testing.T) {
	f := evalFixture(t, "plan_azure_hardening.json")

	// Positive cases.
	for _, c := range []struct{ rule, addr string }{
		{"AZURE_STORAGE_INSECURE_TRANSFER", "azurerm_storage_account.insecure_transfer_v4"},
		{"AZURE_STORAGE_INSECURE_TRANSFER", "azurerm_storage_account.insecure_transfer_v3"},
		{"AZURE_STORAGE_WEAK_TLS", "azurerm_storage_account.weak_tls"},
		{"AZURE_SQL_SERVER_WEAK_TLS", "azurerm_mssql_server.weak_tls"},
		{"AZURE_SQL_SERVER_WEAK_TLS", "azurerm_mssql_server.disabled_tls"},
		{"AZURE_DB_SSL_DISABLED", "azurerm_postgresql_server.ssl_off"},
		{"AZURE_DB_SSL_DISABLED", "azurerm_mysql_server.ssl_off"},
		{"AZURE_APP_SERVICE_NOT_HTTPS_ONLY", "azurerm_linux_web_app.no_https_only"},
		{"AZURE_APP_SERVICE_NOT_HTTPS_ONLY", "azurerm_function_app.absent_https_only"},
		{"AZURE_ROLE_ASSIGNMENT_PRIVILEGED", "azurerm_role_assignment.owner_subscription"},
		{"AZURE_ROLE_ASSIGNMENT_PRIVILEGED", "azurerm_role_assignment.contributor_mgmt_group"},
		{"AZURE_KEY_VAULT_NO_PURGE_PROTECTION", "azurerm_key_vault.no_purge"},
		{"AZURE_VM_PUBLIC_IP", "azurerm_public_ip.vm_ip"},
	} {
		if !has(f, c.rule, c.addr) {
			t.Errorf("expected finding %s on %s; got %+v", c.rule, c.addr, f)
		}
	}

	// Negative cases — these must produce no findings at all.
	for _, addr := range []string{
		"azurerm_storage_account.secure",               // https-only + TLS1_2, both rename fields set
		"azurerm_mssql_server.secure",                  // minimum_tls_version 1.2
		"azurerm_postgresql_server.ssl_on",             // ssl_enforcement_enabled true
		"azurerm_windows_web_app.https_only",           // https_only true
		"azurerm_role_assignment.owner_resource_group", // Owner but RG scope => must be silent
		"azurerm_role_assignment.reader_subscription",  // Reader at sub scope => not privileged
		"azurerm_key_vault.purge_on",                   // purge_protection_enabled true
	} {
		if mentions(f, addr) {
			t.Errorf("resource %s should produce no findings; got %+v", addr, f)
		}
	}
}
