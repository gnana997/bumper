# Trivy AZURE check catalog (porting worklist)

73 checks harvested from trivy-checks (Apache-2.0). Logic is hand-ported to bumper's plan-JSON + CEL model.

| id | service | severity | cis | title |
|---|---|---|---|---|
| AZU-0004 | appservice | critical | - | Ensure the Function App can only be accessed via HTTPS. The default is false. |
| AZU-0041 | container | critical | - | Ensure AKS has an API Server Authorized IP Ranges enabled |
| AZU-0035 | datafactory | critical | - | Data Factory should have public access disabled, the default is enabled. |
| AZU-0013 | keyvault | critical | - | Key vault should have the network acl block specified |
| AZU-0047 | network | critical | - | A security group rule should not allow unrestricted ingress from any IP address. |
| AZU-0048 | network | critical | - | A security group should not allow unrestricted ingress to the RDP port from any  |
| AZU-0050 | network | critical | - | Security group should not allow unrestricted ingress to SSH port from any IP add |
| AZU-0051 | network | critical | - | A security rule should not allow unrestricted egress to any IP address. |
| AZU-0011 | storage | critical | - | The minimum TLS version for Storage Accounts should be TLS1_2 or higher |
| AZU-0012 | storage | critical | - | The default action on Storage account network rules should be set to deny |
| AZU-0006 | appservice | high | - | Web App uses latest TLS version |
| AZU-0038 | compute | high | - | Enable disk encryption on managed disk |
| AZU-0039 | compute | high | - | Password authentication should be disabled on Azure virtual machines |
| AZU-0042 | container | high | - | Ensure RBAC is enabled on AKS clusters |
| AZU-0043 | container | high | - | Ensure AKS cluster has Network Policy configured |
| AZU-0029 | database | high | - | Ensure database firewalls do not permit public access |
| AZU-0036 | datalake | high | - | Unencrypted data lake storage. |
| AZU-0074 | network | high | - | Sensitive Port Is Exposed To Entire Network |
| AZU-0064 | security-center | high | - | Security Contact Disabled |
| AZU-0007 | storage | high | - | Storage containers in blob storage mode should not have public access |
| AZU-0008 | storage | high | - | Storage accounts should be configured to only accept transfers that are over sec |
| AZU-0010 | storage | high | - | Trusted Microsoft Services should have bypass access to Storage accounts |
| AZU-0059 | storage | high | - | Storage account should have secure transfer and minimum TLS version configured |
| AZU-0003 | appservice | medium | - | App Service authentication is activated |
| AZU-0069 | appservice | medium | - | App Service Using Unsupported PHP Version |
| AZU-0070 | appservice | medium | - | App Service Using Unsupported Python Version |
| AZU-0071 | appservice | medium | - | App Service FTPS Enforce Disabled |
| AZU-0072 | appservice | medium | - | Web App Accepting Traffic Other Than HTTPS |
| AZU-0030 | authorization | medium | - | Roles limited to the required actions |
| AZU-0052 | authorization | medium | - | Role Definition Allows Custom Role Creation |
| AZU-0037 | compute | medium | - | Ensure that no sensitive credentials are exposed in VM custom_data |
| AZU-0068 | compute | medium | - | VM Not Attached To Network |
| AZU-0040 | container | medium | - | Ensure AKS logging to Azure Monitoring is Configured |
| AZU-0065 | container | medium | - | Ensure AKS cluster has private cluster enabled |
| AZU-0018 | database | medium | - | At least one email address is set for threat alerts |
| AZU-0019 | database | medium | - | Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database |
| AZU-0020 | database | medium | - | SSL should be enforced on database connections where applicable |
| AZU-0021 | database | medium | - | Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Da |
| AZU-0022 | database | medium | - | Ensure databases are not publicly accessible |
| AZU-0024 | database | medium | - | Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database |
| AZU-0025 | database | medium | - | Database auditing retention period should be longer than 90 days |
| AZU-0026 | database | medium | - | Databases should have the minimum TLS set for connections |
| AZU-0027 | database | medium | - | Auditing should be enabled on Azure SQL Databases |
| AZU-0028 | database | medium | - | No threat detections are set |
| AZU-0014 | keyvault | medium | - | Ensure that the expiration date is set on all keys |
| AZU-0016 | keyvault | medium | - | Key vault should have purge protection enabled |
| AZU-0031 | monitor | medium | - | Ensure the activity retention log is set to at least a year |
| AZU-0032 | monitor | medium | - | Ensure activitys are captured for all locations |
| AZU-0033 | monitor | medium | - | Ensure log profile captures all activities |
| AZU-0073 | network | medium | - | Network Watcher Flow Disabled |
| AZU-0075 | network | medium | - | Network Interfaces IP Forwarding Enabled |
| AZU-0076 | network | medium | - | Network Interfaces With Public IP |
| AZU-0044 | security-center | medium | - | Send notification emails for high severity alerts |
| AZU-0062 | security-center | medium | - | Security Contact Email |
| AZU-0063 | security-center | medium | - | Email Alerts Disabled |
| AZU-0009 | storage | medium | - | When using Queue Services for a storage account, logging should be enabled. |
| AZU-0056 | storage | medium | - | Storage account should have blob soft delete enabled |
| AZU-0057 | storage | medium | - | Storage account should have logging enabled |
| AZU-0060 | storage | medium | - | Storage account should use customer-managed keys for encryption |
| AZU-0061 | storage | medium | - | Storage account should have infrastructure encryption enabled |
| AZU-0034 | synapse | medium | - | Synapse Workspace should have managed virtual network enabled, the default is di |
| AZU-0001 | appservice | low | - | Web App accepts incoming client certificate |
| AZU-0002 | appservice | low | - | Web App has registration with AD enabled |
| AZU-0005 | appservice | low | - | Web App uses the latest HTTP version |
| AZU-0066 | container | low | - | Ensure AKS cluster has Azure Policy add-on enabled |
| AZU-0067 | container | low | - | Ensure AKS cluster has disk encryption set ID configured |
| AZU-0023 | database | low | - | Security threat alerts go to subscription owners and co-administrators |
| AZU-0015 | keyvault | low | - | Key vault Secret should have a content type set |
| AZU-0017 | keyvault | low | - | Key Vault Secret should have an expiration date set |
| AZU-0049 | network | low | - | Retention policy for flow logs should be enabled and set to greater than 90 days |
| AZU-0045 | security-center | low | - | Enable the standard security center subscription tier |
| AZU-0046 | security-center | low | - | The required contact details should be set for security center |
| AZU-0058 | storage | low | - | Storage account should use geo-redundant replication |
