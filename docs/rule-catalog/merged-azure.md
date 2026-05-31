# Merged AZURE catalog — Trivy + Checkov (porting worklist)

372 checks grouped by **service**, so a Trivy check and the Checkov check(s) for the same intent sit together — port ONE bumper rule per intent, citing both ids in provenance. Trivy supplies severity; Checkov (OSS) does not (assign at port time). The `resource` column is the Terraform type to write the rule against.

### api — 0 trivy + 5 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AZURE_107 | — | networking | azurerm_api_management | Ensure that API management services use virtual networks |
| checkov | CKV_AZURE_152 | — | encryption | azurerm_api_management | Ensure Client Certificates are enforced for API management |
| checkov | CKV_AZURE_173 | — | encryption | azurerm_api_management | Ensure API management uses at least TLS 1.2 |
| checkov | CKV_AZURE_174 | — | networking | azurerm_api_management | Ensure API management public access is disabled |
| checkov | CKV_AZURE_215 | — | encryption | azurerm_api_management_backend | Ensure API management backend uses https |

### app — 0 trivy + 5 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AZURE_184 | — | iam | azurerm_app_configuration | Ensure 'local_auth_enabled' is set to 'False' |
| checkov | CKV_AZURE_185 | — | networking | azurerm_app_configuration | Ensure 'Public Access' is not Enabled for App configuration |
| checkov | CKV_AZURE_186 | — | encryption | azurerm_app_configuration | Ensure App configuration encryption block is set. |
| checkov | CKV_AZURE_187 | — | backup and recovery | azurerm_app_configuration | Ensure App configuration purge protection is enabled |
| checkov | CKV_AZURE_188 | — | general security | azurerm_app_configuration | Ensure App configuration Sku is standard |

### application — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AZURE_249 | — | iam | azuread_application_federated_identity_c | Ensure Azure GitHub Actions OIDC trust policy is configured secu |

### appservice — 10 trivy + 32 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AZU-0004 | critical | — | — | Ensure the Function App can only be accessed via HTTPS. The defa |
| trivy | AZU-0006 | high | — | — | Web App uses latest TLS version |
| trivy | AZU-0003 | medium | — | — | App Service authentication is activated |
| trivy | AZU-0069 | medium | — | — | App Service Using Unsupported PHP Version |
| trivy | AZU-0070 | medium | — | — | App Service Using Unsupported Python Version |
| trivy | AZU-0071 | medium | — | — | App Service FTPS Enforce Disabled |
| trivy | AZU-0072 | medium | — | — | Web App Accepting Traffic Other Than HTTPS |
| trivy | AZU-0001 | low | — | — | Web App accepts incoming client certificate |
| trivy | AZU-0002 | low | — | — | Web App has registration with AD enabled |
| trivy | AZU-0005 | low | — | — | Web App uses the latest HTTP version |
| checkov | CKV_AZURE_13 | — | general security | azurerm_app_service, azurerm_linux_web_a | Ensure App Service Authentication is set on Azure App Service |
| checkov | CKV_AZURE_14 | — | networking | azurerm_app_service, azurerm_linux_web_a | Ensure web app redirects all HTTP traffic to HTTPS in Azure App  |
| checkov | CKV_AZURE_145 | — | networking | azurerm_function_app, azurerm_linux_func | Ensure Function app is using the latest version of TLS encryptio |
| checkov | CKV_AZURE_15 | — | networking | azurerm_app_service, azurerm_linux_web_a | Ensure web app is using the latest version of TLS encryption |
| checkov | CKV_AZURE_153 | — | networking | azurerm_app_service_slot, azurerm_linux_ | Ensure web app redirects all HTTP traffic to HTTPS in Azure App  |
| checkov | CKV_AZURE_154 | — | networking | azurerm_app_service_slot | Ensure the App service slot is using the latest version of TLS e |
| checkov | CKV_AZURE_155 | — | networking | azurerm_app_service_slot | Ensure debugging is disabled for the App service slot |
| checkov | CKV_AZURE_159 | — | logging | azurerm_function_app, azurerm_function_a | Ensure function app builtin logging is enabled |
| checkov | CKV_AZURE_16 | — | iam | azurerm_app_service, azurerm_linux_web_a | Ensure that Register with Azure Active Directory is enabled on A |
| checkov | CKV_AZURE_17 | — | networking | azurerm_app_service, azurerm_linux_web_a | Ensure the web app has 'Client Certificates (Incoming client cer |
| checkov | CKV_AZURE_18 | — | networking | azurerm_app_service, azurerm_linux_web_a | Ensure that 'HTTP Version' is the latest if used to run the web  |
| checkov | CKV_AZURE_213 | — | networking | azurerm_app_service, azurerm_linux_web_a | Ensure that App Service configures health check |
| checkov | CKV_AZURE_214 | — | general security | azurerm_linux_web_app, azurerm_windows_w | Ensure App Service is set to be always on |
| checkov | CKV_AZURE_221 | — | networking | azurerm_linux_function_app, azurerm_linu | Ensure that Azure Function App public network access is disabled |
| checkov | CKV_AZURE_222 | — | networking | azurerm_linux_web_app, azurerm_windows_w | Ensure that Azure Web App public network access is disabled |
| checkov | CKV_AZURE_231 | — | backup and recovery | azurerm_app_service_environment_v3 | Ensure App Service Environment is zone redundant |
| checkov | CKV_AZURE_56 | — | general security | azurerm_function_app | Ensure that function apps enables Authentication |
| checkov | CKV_AZURE_57 | — | general security | azurerm_app_service, azurerm_linux_web_a | Ensure that CORS disallows every resource to access app services |
| checkov | CKV_AZURE_62 | — | general security | azurerm_function_app | Ensure function apps are not accessible from all regions |
| checkov | CKV_AZURE_63 | — | logging | azurerm_app_service, azurerm_linux_web_a | Ensure that App service enables HTTP logging |
| checkov | CKV_AZURE_65 | — | logging | azurerm_app_service, azurerm_linux_web_a | Ensure that App service enables detailed error messages |
| checkov | CKV_AZURE_66 | — | logging | azurerm_linux_web_app, azurerm_windows_w | Ensure that App service enables failed request tracing |
| checkov | CKV_AZURE_67 | — | general security | azurerm_function_app, azurerm_function_a | Ensure that 'HTTP Version' is the latest, if used to run the Fun |
| checkov | CKV_AZURE_70 | — | networking | azurerm_function_app, azurerm_linux_func | Ensure that Function apps is only accessible over HTTPS |
| checkov | CKV_AZURE_71 | — | general security | azurerm_app_service, azurerm_linux_web_a | Ensure that Managed identity provider is enabled for app service |
| checkov | CKV_AZURE_72 | — | general security | azurerm_app_service, azurerm_linux_funct | Ensure that remote debugging is not enabled for app services |
| checkov | CKV_AZURE_78 | — | application security | azurerm_app_service, azurerm_linux_web_a | Ensure FTP deployments are disabled |
| checkov | CKV_AZURE_80 | — | general security | azurerm_app_service, azurerm_windows_web | Ensure that 'Net Framework' version is the latest, if used as a  |
| checkov | CKV_AZURE_81 | — | general security | azurerm_app_service | Ensure that 'PHP version' is the latest, if used to run the web  |
| checkov | CKV_AZURE_82 | — | general security | azurerm_app_service | Ensure that 'Python version' is the latest, if used to run the w |
| checkov | CKV_AZURE_83 | — | general security | azurerm_app_service | Ensure that 'Java version' is the latest, if used to run the web |
| checkov | CKV_AZURE_88 | — | general security | azurerm_app_service, azurerm_linux_web_a | Ensure that app services use Azure Files |

### authorization — 2 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AZU-0030 | medium | — | — | Roles limited to the required actions |
| trivy | AZU-0052 | medium | — | — | Role Definition Allows Custom Role Creation |
| checkov | CKV_AZURE_39 | — | iam | azurerm_role_definition | Ensure that no custom subscription owner roles are created |

### automation — 0 trivy + 3 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_AZURE_24 | — | general security | azurerm_automation_account | Ensure Azure automation account does NOT have overly permissive  |
| checkov | CKV2_AZURE_36 | — | iam | azurerm_automation_account | Ensure Azure automation account is configured with managed ident |
| checkov | CKV_AZURE_73 | — | encryption | azurerm_automation_variable_bool, azurer | Ensure that Automation account variables are encrypted |

### batch — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AZURE_248 | — | networking | azurerm_batch_account | Ensure that if Azure Batch account public network access in case |
| checkov | CKV_AZURE_76 | — | encryption | azurerm_batch_account | Ensure that Azure Batch account uses key vault to encrypt data |

### cdn — 0 trivy + 3 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AZURE_197 | — | networking | azurerm_cdn_endpoint | Ensure the Azure CDN disables the HTTP endpoint |
| checkov | CKV_AZURE_198 | — | networking | azurerm_cdn_endpoint | Ensure the Azure CDN enables the HTTPS endpoint |
| checkov | CKV_AZURE_200 | — | networking | azurerm_cdn_endpoint_custom_domain | Ensure the Azure CDN endpoint is using the latest version of TLS |

### cognitive — 0 trivy + 5 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_AZURE_22 | — | encryption | azurerm_cognitive_account, azurerm_cogni | Ensure that Cognitive Services enables customer-managed key for  |
| checkov | CKV_AZURE_134 | — | networking | azurerm_cognitive_account | Ensure that Cognitive Services accounts disable public network a |
| checkov | CKV_AZURE_236 | — | networking | azurerm_cognitive_account | Ensure that Cognitive Services accounts disable local authentica |
| checkov | CKV_AZURE_238 | — | networking | azurerm_cognitive_account | Ensure that all Azure Cognitive Services accounts are configured |
| checkov | CKV_AZURE_247 | — | networking | azurerm_cognitive_account | Ensure that Azure Cognitive Services account hosted with OpenAI  |

### compute — 4 trivy + 20 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AZU-0038 | high | — | — | Enable disk encryption on managed disk |
| trivy | AZU-0039 | high | — | — | Password authentication should be disabled on Azure virtual mach |
| trivy | AZU-0037 | medium | — | — | Ensure that no sensitive credentials are exposed in VM custom_da |
| trivy | AZU-0068 | medium | — | — | VM Not Attached To Network |
| checkov | CKV2_AZURE_10 | — | general security | azurerm_virtual_machine, azurerm_virtual | Ensure that Microsoft Antimalware is configured to automatically |
| checkov | CKV2_AZURE_12 | — | backup and recovery | azurerm_virtual_machine | Ensure that virtual machines are backed up using Azure Backup |
| checkov | CKV2_AZURE_14 | — | encryption | azurerm_managed_disk, azurerm_virtual_ma | Ensure that Unattached disks are encrypted |
| checkov | CKV2_AZURE_39 | — | networking | azurerm_linux_virtual_machine, azurerm_n | Ensure Azure VM is not configured with public IP and serial cons |
| checkov | CKV2_AZURE_9 | — | general security | azurerm_virtual_machine | Ensure Virtual Machines are utilizing Managed Disks |
| checkov | CKV_AZURE_1 | — | general security | azurerm_virtual_machine, azurerm_linux_v | Ensure Azure Instance does not use basic authentication(Use SSH  |
| checkov | CKV_AZURE_149 | — | encryption | azurerm_linux_virtual_machine_scale_set, | Ensure that Virtual machine does not enable password authenticat |
| checkov | CKV_AZURE_151 | — | encryption | azurerm_windows_virtual_machine | Ensure Windows VM enables encryption |
| checkov | CKV_AZURE_177 | — | general security | azurerm_windows_virtual_machine, azurerm | Ensure Windows VM enables automatic updates |
| checkov | CKV_AZURE_178 | — | general security | azurerm_linux_virtual_machine, azurerm_l | Ensure linux VM enables SSH with keys for secure communication |
| checkov | CKV_AZURE_179 | — | general security | azurerm_windows_virtual_machine, azurerm | Ensure VM agent is installed |
| checkov | CKV_AZURE_2 | — | encryption | azurerm_managed_disk | Ensure Azure managed disk has encryption enabled |
| checkov | CKV_AZURE_251 | — | networking | azurerm_managed_disk | Ensure Azure Virtual Machine disks are configured without public |
| checkov | CKV_AZURE_45 | — | secrets | azurerm_virtual_machine | Ensure that no sensitive credentials are exposed in VM custom_da |
| checkov | CKV_AZURE_49 | — | general security | azurerm_linux_virtual_machine_scale_set | Ensure Azure linux scale set does not use basic authentication(U |
| checkov | CKV_AZURE_50 | — | general security | azurerm_linux_virtual_machine, azurerm_w | Ensure Virtual Machine Extensions are not Installed |
| checkov | CKV_AZURE_92 | — | general security | azurerm_linux_virtual_machine, azurerm_w | Ensure that Virtual Machines use managed disks |
| checkov | CKV_AZURE_93 | — | encryption | azurerm_managed_disk | Ensure that managed disks use a specific set of disk encryption  |
| checkov | CKV_AZURE_95 | — | general security | azurerm_virtual_machine_scale_set | Ensure that automatic OS image patching is enabled for Virtual M |
| checkov | CKV_AZURE_97 | — | encryption | azurerm_linux_virtual_machine_scale_set, | Ensure that Virtual machine scale sets have encryption at host e |

### container — 7 trivy + 35 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AZU-0041 | critical | — | — | Ensure AKS has an API Server Authorized IP Ranges enabled |
| trivy | AZU-0042 | high | — | — | Ensure RBAC is enabled on AKS clusters |
| trivy | AZU-0043 | high | — | — | Ensure AKS cluster has Network Policy configured |
| trivy | AZU-0040 | medium | — | — | Ensure AKS logging to Azure Monitoring is Configured |
| trivy | AZU-0065 | medium | — | — | Ensure AKS cluster has private cluster enabled |
| trivy | AZU-0066 | low | — | — | Ensure AKS cluster has Azure Policy add-on enabled |
| trivy | AZU-0067 | low | — | — | Ensure AKS cluster has disk encryption set ID configured |
| checkov | CKV2_AZURE_28 | — | general security | azurerm_container_group | Ensure Container Instance is configured with managed identity |
| checkov | CKV2_AZURE_29 | — | general security | azurerm_kubernetes_cluster | Ensure AKS cluster has Azure CNI networking enabled |
| checkov | CKV2_AZURE_30 | — | general security | azurerm_container_registry_webhook | Ensure Azure Container Registry (ACR) has HTTPS enabled for webh |
| checkov | CKV_AZURE_115 | — | networking | azurerm_kubernetes_cluster | Ensure that AKS enables private clusters |
| checkov | CKV_AZURE_116 | — | networking | azurerm_kubernetes_cluster | Ensure that AKS uses Azure Policies Add-on |
| checkov | CKV_AZURE_117 | — | networking | azurerm_kubernetes_cluster | Ensure that AKS uses disk encryption set |
| checkov | CKV_AZURE_137 | — | iam | azurerm_container_registry | Ensure ACR admin account is disabled |
| checkov | CKV_AZURE_138 | — | iam | azurerm_container_registry | Ensures that ACR disables anonymous pulling of images |
| checkov | CKV_AZURE_139 | — | networking | azurerm_container_registry | Ensure ACR set to disable public networking |
| checkov | CKV_AZURE_141 | — | iam | azurerm_kubernetes_cluster | Ensure AKS local admin account is disabled |
| checkov | CKV_AZURE_143 | — | networking | azurerm_kubernetes_cluster | Ensure AKS cluster nodes do not have public IP addresses |
| checkov | CKV_AZURE_163 | — | general security | azurerm_container_registry | Enable vulnerability scanning for container images. |
| checkov | CKV_AZURE_164 | — | general security | azurerm_container_registry | Ensures that ACR uses signed/trusted images |
| checkov | CKV_AZURE_165 | — | networking | azurerm_container_registry | Ensure geo-replicated container registries to match multi-region |
| checkov | CKV_AZURE_166 | — | supply chain | azurerm_container_registry | Ensure container image quarantine, scan, and mark images verifie |
| checkov | CKV_AZURE_167 | — | general security | azurerm_container_registry | Ensure a retention policy is set to cleanup untagged manifests. |
| checkov | CKV_AZURE_168 | — | kubernetes | azurerm_kubernetes_cluster, azurerm_kube | Ensure Azure Kubernetes Cluster (AKS) nodes should use a minimum |
| checkov | CKV_AZURE_169 | — | kubernetes | azurerm_kubernetes_cluster | Ensure Azure Kubernetes Cluster (AKS) nodes use scale sets |
| checkov | CKV_AZURE_170 | — | general security | azurerm_kubernetes_cluster | Ensure that AKS use the Paid Sku for its SLA |
| checkov | CKV_AZURE_171 | — | networking | azurerm_kubernetes_cluster | Ensure AKS cluster upgrade channel is chosen |
| checkov | CKV_AZURE_172 | — | general security | azurerm_kubernetes_cluster | Ensure autorotation of Secrets Store CSI Driver secrets for AKS  |
| checkov | CKV_AZURE_226 | — | kubernetes | azurerm_kubernetes_cluster | Ensure ephemeral disks are used for OS disks |
| checkov | CKV_AZURE_227 | — | kubernetes | azurerm_kubernetes_cluster, azurerm_kube | Ensure that the AKS cluster encrypt temp disks, caches, and data |
| checkov | CKV_AZURE_232 | — | kubernetes | azurerm_kubernetes_cluster | Ensure that only critical system pods run on system nodes |
| checkov | CKV_AZURE_233 | — | backup and recovery | azurerm_container_registry | Ensure Azure Container Registry (ACR) is zone redundant |
| checkov | CKV_AZURE_235 | — | general security | azurerm_container_group | Ensure that Azure container environment variables are configured |
| checkov | CKV_AZURE_237 | — | general security | azurerm_container_registry | Ensure dedicated data endpoints are enabled. |
| checkov | CKV_AZURE_245 | — | networking | azurerm_container_group | Ensure that Azure Container group is deployed into virtual netwo |
| checkov | CKV_AZURE_246 | — | networking | azurerm_kubernetes_cluster | Ensure Azure AKS cluster HTTP application routing is disabled |
| checkov | CKV_AZURE_4 | — | kubernetes | azurerm_kubernetes_cluster | Ensure AKS logging to Azure Monitoring is Configured |
| checkov | CKV_AZURE_5 | — | kubernetes | azurerm_kubernetes_cluster | Ensure RBAC is enabled on AKS clusters |
| checkov | CKV_AZURE_6 | — | kubernetes | azurerm_kubernetes_cluster | Ensure AKS has an API Server Authorized IP Ranges enabled |
| checkov | CKV_AZURE_7 | — | kubernetes | azurerm_kubernetes_cluster | Ensure AKS cluster has Network Policy configured |
| checkov | CKV_AZURE_8 | — | kubernetes | azurerm_kubernetes_cluster | Ensure Kubernetes Dashboard is disabled |
| checkov | CKV_AZURE_98 | — | networking | azurerm_container_group | Ensure that Azure Container group is deployed into virtual netwo |

### data — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AZURE_105 | — | encryption | azurerm_data_lake_store | Ensure that Data Lake Store accounts enables encryption |

### database — 12 trivy + 56 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AZU-0029 | high | — | — | Ensure database firewalls do not permit public access |
| trivy | AZU-0018 | medium | — | — | At least one email address is set for threat alerts |
| trivy | AZU-0019 | medium | — | — | Ensure server parameter 'log_connections' is set to 'ON' for Pos |
| trivy | AZU-0020 | medium | — | — | SSL should be enforced on database connections where applicable |
| trivy | AZU-0021 | medium | — | — | Ensure server parameter 'connection_throttling' is set to 'ON' f |
| trivy | AZU-0022 | medium | — | — | Ensure databases are not publicly accessible |
| trivy | AZU-0024 | medium | — | — | Ensure server parameter 'log_checkpoints' is set to 'ON' for Pos |
| trivy | AZU-0025 | medium | — | — | Database auditing retention period should be longer than 90 days |
| trivy | AZU-0026 | medium | — | — | Databases should have the minimum TLS set for connections |
| trivy | AZU-0027 | medium | — | — | Auditing should be enabled on Azure SQL Databases |
| trivy | AZU-0028 | medium | — | — | No threat detections are set |
| trivy | AZU-0023 | low | — | — | Security threat alerts go to subscription owners and co-administ |
| checkov | CKV2_AZURE_13 | — | general security | azurerm_mssql_server_security_alert_poli | Ensure that sql servers enables data security policy |
| checkov | CKV2_AZURE_16 | — | encryption | azurerm_mysql_server, azurerm_mysql_serv | Ensure that MySQL server enables customer-managed key for encryp |
| checkov | CKV2_AZURE_17 | — | encryption | azurerm_postgresql_server, azurerm_postg | Ensure that PostgreSQL server enables customer-managed key for e |
| checkov | CKV2_AZURE_2 | — | general security | azurerm_mssql_server, azurerm_mssql_serv | Ensure that Vulnerability Assessment (VA) is enabled on a SQL se |
| checkov | CKV2_AZURE_25 | — | general security | azurerm_mssql_database | Ensure Azure SQL database Transparent Data Encryption (TDE) is e |
| checkov | CKV2_AZURE_26 | — | general security | azurerm_postgresql_flexible_server_firew | Ensure Azure PostgreSQL Flexible server is not configured with o |
| checkov | CKV2_AZURE_27 | — | general security | azurerm_mssql_server | Ensure Azure AD authentication is enabled for Azure SQL (MSSQL) |
| checkov | CKV2_AZURE_3 | — | general security | azurerm_mssql_server, azurerm_mssql_serv | Ensure that VA setting Periodic Recurring Scans is enabled on a  |
| checkov | CKV2_AZURE_34 | — | networking | azurerm_mssql_firewall_rule, azurerm_sql | Ensure Azure SQL server firewall is not overly permissive |
| checkov | CKV2_AZURE_37 | — | encryption | azurerm_mariadb_server | Ensure Azure MariaDB server is using latest TLS (1.2) |
| checkov | CKV2_AZURE_4 | — | general security | azurerm_mssql_server, azurerm_mssql_serv | Ensure Azure SQL server ADS VA Send scan reports to is configure |
| checkov | CKV2_AZURE_42 | — | general security | azurerm_postgresql_server | Ensure Azure PostgreSQL server is configured with private endpoi |
| checkov | CKV2_AZURE_43 | — | general security | azurerm_mariadb_server | Ensure Azure MariaDB server is configured with private endpoint |
| checkov | CKV2_AZURE_44 | — | general security | azurerm_mysql_server | Ensure Azure MySQL server is configured with private endpoint |
| checkov | CKV2_AZURE_45 | — | general security | azurerm_mssql_server | Ensure Microsoft SQL server is configured with private endpoint |
| checkov | CKV2_AZURE_5 | — | general security | azurerm_mssql_server, azurerm_mssql_serv | Ensure that VA setting 'Also send email notifications to admins  |
| checkov | CKV2_AZURE_56 | — | networking | azurerm_mysql_flexible_server | Ensure Azure MySQL Flexible Server is configured with private en |
| checkov | CKV2_AZURE_57 | — | general security | azurerm_postgresql_flexible_server | Ensure PostgreSQL Flexible Server is configured with private end |
| checkov | CKV2_AZURE_6 | — | general security | azurerm_sql_firewall_rule, azurerm_sql_s | Ensure 'Allow access to Azure services' for PostgreSQL Database  |
| checkov | CKV2_AZURE_7 | — | general security | azurerm_sql_server | Ensure that Azure Active Directory Admin is configured |
| checkov | CKV_AZURE_100 | — | networking | azurerm_cosmosdb_account | Ensure that Cosmos DB accounts have customer-managed keys to enc |
| checkov | CKV_AZURE_101 | — | networking | azurerm_cosmosdb_account | Ensure that Azure Cosmos DB disables public network access |
| checkov | CKV_AZURE_102 | — | backup and recovery | azurerm_postgresql_server | Ensure that PostgreSQL server enables geo-redundant backups |
| checkov | CKV_AZURE_11 | — | networking | azurerm_mariadb_firewall_rule, azurerm_s | Ensure no SQL Databases allow ingress from 0.0.0.0/0 (ANY IP) |
| checkov | CKV_AZURE_113 | — | networking | azurerm_mssql_server | Ensure that SQL server disables public network access |
| checkov | CKV_AZURE_127 | — | general security | azurerm_mysql_server | Ensure that My SQL server enables Threat detection policy |
| checkov | CKV_AZURE_128 | — | general security | azurerm_postgresql_server | Ensure that PostgreSQL server enables Threat detection policy |
| checkov | CKV_AZURE_129 | — | backup and recovery | azurerm_mariadb_server | Ensure that MariaDB server enables geo-redundant backups |
| checkov | CKV_AZURE_130 | — | encryption | azurerm_postgresql_server | Ensure that PostgreSQL server enables infrastructure encryption |
| checkov | CKV_AZURE_132 | — | general security | azurerm_cosmosdb_account | Ensure cosmosdb does not allow privileged escalation by restrict |
| checkov | CKV_AZURE_136 | — | backup and recovery | azurerm_postgresql_flexible_server | Ensure that PostgreSQL Flexible server enables geo-redundant bac |
| checkov | CKV_AZURE_140 | — | iam | azurerm_cosmosdb_account | Ensure that Local Authentication is disabled on CosmosDB |
| checkov | CKV_AZURE_146 | — | logging | azurerm_postgresql_configuration | Ensure server parameter 'log_retention' is set to 'ON' for Postg |
| checkov | CKV_AZURE_147 | — | networking | azurerm_postgresql_server | Ensure PostgreSQL is using the latest version of TLS encryption |
| checkov | CKV_AZURE_156 | — | logging | azurerm_mssql_database_extended_auditing | Ensure default Auditing policy for a SQL Server is configured to |
| checkov | CKV_AZURE_224 | — | logging | azurerm_mssql_database | Ensure that the Ledger feature is enabled on database that  |
| checkov | CKV_AZURE_229 | — | backup and recovery | azurerm_mssql_database | Ensure the Azure SQL Database Namespace is zone redundant |
| checkov | CKV_AZURE_23 | — | logging | azurerm_mssql_server, azurerm_mssql_serv | Ensure that 'Auditing' is set to 'On' for SQL servers |
| checkov | CKV_AZURE_24 | — | logging | azurerm_mssql_server, azurerm_mssql_serv | Ensure that 'Auditing' Retention is 'greater than 90 days' for S |
| checkov | CKV_AZURE_25 | — | general security | azurerm_mssql_server_security_alert_poli | Ensure that 'Threat Detection types' is set to 'All' |
| checkov | CKV_AZURE_26 | — | general security | azurerm_mssql_server_security_alert_poli | Ensure that 'Send Alerts To' is enabled for MSSQL servers |
| checkov | CKV_AZURE_27 | — | general security | azurerm_mssql_server_security_alert_poli | Ensure that 'Email service and co-administrators' is 'Enabled' f |
| checkov | CKV_AZURE_28 | — | networking | azurerm_mysql_server | Ensure 'Enforce SSL connection' is set to 'ENABLED' for MySQL Da |
| checkov | CKV_AZURE_29 | — | networking | azurerm_postgresql_server | Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreS |
| checkov | CKV_AZURE_30 | — | logging | azurerm_postgresql_configuration | Ensure server parameter 'log_checkpoints' is set to 'ON' for Pos |
| checkov | CKV_AZURE_31 | — | logging | azurerm_postgresql_configuration | Ensure server parameter 'log_connections' is set to 'ON' for Pos |
| checkov | CKV_AZURE_32 | — | networking | azurerm_postgresql_configuration | Ensure server parameter 'connection_throttling' is set to 'ON' f |
| checkov | CKV_AZURE_47 | — | networking | azurerm_mariadb_server | Ensure 'Enforce SSL connection' is set to 'ENABLED' for MariaDB  |
| checkov | CKV_AZURE_48 | — | networking | azurerm_mariadb_server | Ensure 'public network access enabled' is set to 'False' for Mar |
| checkov | CKV_AZURE_52 | — | networking | azurerm_mssql_server | Ensure MSSQL is using the latest version of TLS encryption |
| checkov | CKV_AZURE_53 | — | networking | azurerm_mysql_server | Ensure 'public network access enabled' is set to 'False' for myS |
| checkov | CKV_AZURE_54 | — | networking | azurerm_mysql_server | Ensure MySQL is using the latest version of TLS encryption |
| checkov | CKV_AZURE_68 | — | networking | azurerm_postgresql_server | Ensure that PostgreSQL server disables public network access |
| checkov | CKV_AZURE_94 | — | backup and recovery | azurerm_mysql_server, azurerm_mysql_flex | Ensure that My SQL server enables geo-redundant backups |
| checkov | CKV_AZURE_96 | — | encryption | azurerm_mysql_server | Ensure that MySQL server enables infrastructure encryption |
| checkov | CKV_AZURE_99 | — | networking | azurerm_cosmosdb_account | Ensure Cosmos DB accounts have restricted access |

### databricks — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_AZURE_48 | — | encryption | azurerm_databricks_workspace | Ensure that Databricks Workspaces enables customer-managed key f |
| checkov | CKV_AZURE_158 | — | networking | azurerm_databricks_workspace | Ensure Databricks Workspace data plane to control plane communic |

### datafactory — 1 trivy + 3 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AZU-0035 | critical | — | — | Data Factory should have public access disabled, the default is  |
| checkov | CKV2_AZURE_15 | — | encryption | azurerm_data_factory | Ensure that Azure data factories are encrypted with a customer-m |
| checkov | CKV_AZURE_103 | — | general security | azurerm_data_factory | Ensure that Azure Data Factory uses Git repository for source co |
| checkov | CKV_AZURE_104 | — | networking | azurerm_data_factory | Ensure that Azure Data factory public network access is disabled |

### datalake — 1 trivy + 0 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AZU-0036 | high | — | — | Unencrypted data lake storage. |

### eventgrid — 0 trivy + 6 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AZURE_106 | — | networking | azurerm_eventgrid_domain | Ensure that Azure Event Grid Domain public network access is dis |
| checkov | CKV_AZURE_191 | — | iam | azurerm_eventgrid_topic | Ensure that Managed identity provider is enabled for Azure Event |
| checkov | CKV_AZURE_192 | — | iam | azurerm_eventgrid_topic | Ensure that Azure Event Grid Topic local Authentication is disab |
| checkov | CKV_AZURE_193 | — | networking | azurerm_eventgrid_topic | Ensure public network access is disabled for Azure Event Grid To |
| checkov | CKV_AZURE_194 | — | iam | azurerm_eventgrid_domain | Ensure that Managed identity provider is enabled for Azure Event |
| checkov | CKV_AZURE_195 | — | iam | azurerm_eventgrid_domain | Ensure that Azure Event Grid Domain local Authentication is disa |

### eventhub — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AZURE_223 | — | encryption | azurerm_eventhub_namespace | Ensure Event Hub Namespace uses at least TLS 1.2 |
| checkov | CKV_AZURE_228 | — | backup and recovery | azurerm_eventhub_namespace | Ensure the Azure Event Hub Namespace is zone redundant |

### firewall — 0 trivy + 3 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AZURE_216 | — | networking | azurerm_firewall | Ensure DenyIntelMode is set to Deny for Azure Firewalls |
| checkov | CKV_AZURE_219 | — | networking | azurerm_firewall | Ensure Firewall defines a firewall policy |
| checkov | CKV_AZURE_220 | — | networking | azurerm_firewall_policy | Ensure Firewall policy has IDPS mode as deny |

### frontdoor — 0 trivy + 3 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AZURE_121 | — | networking | azurerm_frontdoor | Ensure that Azure Front Door enables WAF |
| checkov | CKV_AZURE_123 | — | networking | azurerm_frontdoor_firewall_policy | Ensure that Azure Front Door uses WAF in "Detection" or "Prevent |
| checkov | CKV_AZURE_133 | — | application security | azurerm_frontdoor_firewall_policy | Ensure Front Door WAF prevents message lookup in Log4j2. See CVE |

### iothub — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AZURE_108 | — | networking | azurerm_iothub | Ensure that Azure IoT Hub disables public network access |

### keyvault — 5 trivy + 10 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AZU-0013 | critical | — | — | Key vault should have the network acl block specified |
| trivy | AZU-0014 | medium | — | — | Ensure that the expiration date is set on all keys |
| trivy | AZU-0016 | medium | — | — | Key vault should have purge protection enabled |
| trivy | AZU-0015 | low | — | — | Key vault Secret should have a content type set |
| trivy | AZU-0017 | low | — | — | Key Vault Secret should have an expiration date set |
| checkov | CKV2_AZURE_32 | — | general security | azurerm_key_vault | Ensure private endpoint is configured to key vault |
| checkov | CKV_AZURE_109 | — | networking | azurerm_key_vault | Ensure that key vault allows firewall rules settings |
| checkov | CKV_AZURE_110 | — | networking | azurerm_key_vault | Ensure that key vault enables purge protection |
| checkov | CKV_AZURE_111 | — | logging | azurerm_key_vault | Ensure that key vault enables soft delete |
| checkov | CKV_AZURE_112 | — | backup and recovery | azurerm_key_vault_key | Ensure that key vault key is backed by HSM |
| checkov | CKV_AZURE_114 | — | general security | azurerm_key_vault_secret | Ensure that key vault secrets have "content_type" set |
| checkov | CKV_AZURE_189 | — | networking | azurerm_key_vault | Ensure that Azure Key Vault disables public network access |
| checkov | CKV_AZURE_40 | — | general security | azurerm_key_vault_key | Ensure that the expiration date is set on all keys |
| checkov | CKV_AZURE_41 | — | general security | azurerm_key_vault_secret | Ensure that the expiration date is set on all secrets |
| checkov | CKV_AZURE_42 | — | backup and recovery | azurerm_key_vault | Ensure the key vault is recoverable |

### kusto — 0 trivy + 5 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_AZURE_11 | — | encryption | azurerm_kusto_cluster | Ensure that Azure Data Explorer encryption at rest uses a custom |
| checkov | CKV_AZURE_180 | — | general security | azurerm_kusto_cluster | Ensure that data explorer uses Sku with an SLA |
| checkov | CKV_AZURE_181 | — | iam | azurerm_kusto_cluster | Ensure that data explorer/Kusto uses managed identities to acces |
| checkov | CKV_AZURE_74 | — | encryption | azurerm_kusto_cluster | Ensure that Azure Data Explorer (Kusto) uses disk encryption |
| checkov | CKV_AZURE_75 | — | encryption | azurerm_kusto_cluster | Ensure that Azure Data Explorer uses double encryption |

### log — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_AZURE_20 | — | logging | azurerm_log_analytics_storage_insights,  | Ensure Storage logging is enabled for Table service for read req |
| checkov | CKV2_AZURE_21 | — | logging | azurerm_log_analytics_storage_insights,  | Ensure Storage logging is enabled for Blob service for read requ |

### machine — 0 trivy + 5 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_AZURE_49 | — | networking | azurerm_machine_learning_workspace | Ensure that Azure Machine learning workspace is not configured w |
| checkov | CKV2_AZURE_50 | — | networking | azurerm_machine_learning_workspace, azur | Ensure Azure Storage Account storing Machine Learning workspace  |
| checkov | CKV_AZURE_142 | — | iam | azurerm_machine_learning_compute_cluster | Ensure Machine Learning Compute Cluster Local Authentication is  |
| checkov | CKV_AZURE_144 | — | networking | azurerm_machine_learning_workspace | Ensure that Public Access is disabled for Machine Learning Works |
| checkov | CKV_AZURE_150 | — | general security | azurerm_machine_learning_compute_cluster | Ensure Machine Learning Compute Cluster Minimum Nodes Set To 0 |

### monitor — 3 trivy + 3 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AZU-0031 | medium | — | — | Ensure the activity retention log is set to at least a year |
| trivy | AZU-0032 | medium | — | — | Ensure activitys are captured for all locations |
| trivy | AZU-0033 | medium | — | — | Ensure log profile captures all activities |
| checkov | CKV2_AZURE_8 | — | logging | azurerm_monitor_activity_log_alert, azur | Ensure the storage container storing the activity logs is not pu |
| checkov | CKV_AZURE_37 | — | logging | azurerm_monitor_log_profile | Ensure that Activity Log Retention is set 365 days or greater |
| checkov | CKV_AZURE_38 | — | logging | azurerm_monitor_log_profile | Ensure audit profile captures all the activities |

### network — 9 trivy + 10 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AZU-0047 | critical | — | — | A security group rule should not allow unrestricted ingress from |
| trivy | AZU-0048 | critical | — | — | A security group should not allow unrestricted ingress to the RD |
| trivy | AZU-0050 | critical | — | — | Security group should not allow unrestricted ingress to SSH port |
| trivy | AZU-0051 | critical | — | — | A security rule should not allow unrestricted egress to any IP a |
| trivy | AZU-0074 | high | — | — | Sensitive Port Is Exposed To Entire Network |
| trivy | AZU-0073 | medium | — | — | Network Watcher Flow Disabled |
| trivy | AZU-0075 | medium | — | — | Network Interfaces IP Forwarding Enabled |
| trivy | AZU-0076 | medium | — | — | Network Interfaces With Public IP |
| trivy | AZU-0049 | low | — | — | Retention policy for flow logs should be enabled and set to grea |
| checkov | CKV2_AZURE_31 | — | general security | azurerm_subnet | Ensure VNET subnet is configured with a Network Security Group ( |
| checkov | CKV_AZURE_118 | — | networking | azurerm_network_interface | Ensure that Network Interfaces disable IP forwarding |
| checkov | CKV_AZURE_119 | — | networking | azurerm_network_interface | Ensure that Network Interfaces don't use public IPs |
| checkov | CKV_AZURE_12 | — | logging | azurerm_network_watcher_flow_log | Ensure that Network Security Group Flow Log retention period is  |
| checkov | CKV_AZURE_120 | — | application security | azurerm_application_gateway, azurerm_web | Ensure that Application Gateway enables WAF |
| checkov | CKV_AZURE_182 | — | networking | azurerm_virtual_network, azurerm_virtual | Ensure that VNET has at least 2 connected DNS Endpoints |
| checkov | CKV_AZURE_183 | — | networking | azurerm_virtual_network | Ensure that VNET uses local DNS addresses |
| checkov | CKV_AZURE_217 | — | encryption | azurerm_application_gateway | Ensure Azure Application gateways listener that allow connection |
| checkov | CKV_AZURE_218 | — | encryption | azurerm_application_gateway | Ensure Application Gateway defines secure protocols for in trans |
| checkov | CKV_AZURE_77 | — | networking | azurerm_network_security_group, azurerm_ | Ensure that UDP Services are restricted from the Internet  |

### recovery — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_AZURE_35 | — | iam | azurerm_recovery_services_vault | Ensure Azure recovery services vault is configured with managed  |

### redis — 0 trivy + 4 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AZURE_148 | — | networking | azurerm_redis_cache | Ensure Redis Cache is using the latest version of TLS encryption |
| checkov | CKV_AZURE_230 | — | backup and recovery | azurerm_redis_cache | Standard Replication should be enabled |
| checkov | CKV_AZURE_89 | — | networking | azurerm_redis_cache | Ensure that Azure Cache for Redis disables public network access |
| checkov | CKV_AZURE_91 | — | networking | azurerm_redis_cache | Ensure that only SSL are enabled for Cache for Redis |

### search — 0 trivy + 5 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AZURE_124 | — | networking | azurerm_search_service | Ensure that Azure Cognitive Search disables public network acces |
| checkov | CKV_AZURE_207 | — | iam | azurerm_search_service | Ensure Azure Cognitive Search service uses managed identities to |
| checkov | CKV_AZURE_208 | — | general security | azurerm_search_service | Ensure that Azure Cognitive Search maintains SLA for index updat |
| checkov | CKV_AZURE_209 | — | general security | azurerm_search_service | Ensure that Azure Cognitive Search maintains SLA for search inde |
| checkov | CKV_AZURE_210 | — | networking | azurerm_search_service | Ensure Azure Cognitive Search service allowed IPS does not give  |

### security — 0 trivy + 14 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AZURE_131 | — | general security | azurerm_security_center_contact | Ensure that 'Security contact emails' is set |
| checkov | CKV_AZURE_19 | — | general security | azurerm_security_center_subscription_pri | Ensure that standard pricing tier is selected |
| checkov | CKV_AZURE_20 | — | general security | azurerm_security_center_contact | Ensure that security contact 'Phone number' is set |
| checkov | CKV_AZURE_21 | — | general security | azurerm_security_center_contact | Ensure that 'Send email notification for high severity alerts' i |
| checkov | CKV_AZURE_22 | — | general security | azurerm_security_center_contact | Ensure that 'Send email notification for high severity alerts' i |
| checkov | CKV_AZURE_234 | — | general security | azurerm_security_center_subscription_pri | Ensure that Azure Defender for cloud is set to On for Resource M |
| checkov | CKV_AZURE_55 | — | general security | azurerm_security_center_subscription_pri | Ensure that Azure Defender is set to On for Servers |
| checkov | CKV_AZURE_61 | — | general security | azurerm_security_center_subscription_pri | Ensure that Azure Defender is set to On for App Service |
| checkov | CKV_AZURE_69 | — | general security | azurerm_security_center_subscription_pri | Ensure that Azure Defender is set to On for Azure SQL database s |
| checkov | CKV_AZURE_79 | — | general security | azurerm_security_center_subscription_pri | Ensure that Azure Defender is set to On for SQL servers on machi |
| checkov | CKV_AZURE_84 | — | general security | azurerm_security_center_subscription_pri | Ensure that Azure Defender is set to On for Storage |
| checkov | CKV_AZURE_85 | — | general security | azurerm_security_center_subscription_pri | Ensure that Azure Defender is set to On for Kubernetes |
| checkov | CKV_AZURE_86 | — | general security | azurerm_security_center_subscription_pri | Ensure that Azure Defender is set to On for Container Registries |
| checkov | CKV_AZURE_87 | — | general security | azurerm_security_center_subscription_pri | Ensure that Azure Defender is set to On for Key Vault |

### security_center — 6 trivy + 0 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AZU-0064 | high | — | — | Security Contact Disabled |
| trivy | AZU-0044 | medium | — | — | Send notification emails for high severity alerts |
| trivy | AZU-0062 | medium | — | — | Security Contact Email |
| trivy | AZU-0063 | medium | — | — | Email Alerts Disabled |
| trivy | AZU-0045 | low | — | — | Enable the standard security center subscription tier |
| trivy | AZU-0046 | low | — | — | The required contact details should be set for security center |

### service — 0 trivy + 5 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AZURE_125 | — | encryption | azurerm_service_fabric_cluster | Ensures that Service Fabric use three levels of protection avail |
| checkov | CKV_AZURE_126 | — | general security | azurerm_service_fabric_cluster | Ensures that Active Directory is used for authentication for Ser |
| checkov | CKV_AZURE_211 | — | general security | azurerm_service_plan | Ensure App Service plan suitable for production use |
| checkov | CKV_AZURE_212 | — | general security | azurerm_service_plan | Ensure App Service has a minimum number of instances for failove |
| checkov | CKV_AZURE_225 | — | backup and recovery | azurerm_service_plan | Ensure the App Service Plan is zone redundant |

### servicebus — 0 trivy + 6 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AZURE_199 | — | encryption | azurerm_servicebus_namespace | Ensure that Azure Service Bus uses double encryption |
| checkov | CKV_AZURE_201 | — | encryption | azurerm_servicebus_namespace | Ensure that Azure Service Bus uses a customer-managed key to enc |
| checkov | CKV_AZURE_202 | — | iam | azurerm_servicebus_namespace | Ensure that Managed identity provider is enabled for Azure Servi |
| checkov | CKV_AZURE_203 | — | iam | azurerm_servicebus_namespace | Ensure Azure Service Bus Local Authentication is disabled |
| checkov | CKV_AZURE_204 | — | networking | azurerm_servicebus_namespace | Ensure 'public network access enabled' is set to 'False' for Azu |
| checkov | CKV_AZURE_205 | — | networking | azurerm_servicebus_namespace | Ensure Azure Service Bus is using the latest version of TLS encr |

### signalr — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AZURE_196 | — | general security | azurerm_signalr_service | Ensure that SignalR uses a Paid Sku for its SLA |

### spring — 0 trivy + 4 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_AZURE_23 | — | networking | azurerm_spring_cloud_service | Ensure Azure spring cloud is configured with Virtual network (Vn |
| checkov | CKV2_AZURE_55 | — | networking | azurerm_spring_cloud_app, azurerm_spring | Ensure Azure Spring Cloud app end-to-end TLS is enabled |
| checkov | CKV_AZURE_161 | — | networking | azurerm_spring_cloud_api_portal | Ensures Spring Cloud API Portal is enabled on for HTTPS |
| checkov | CKV_AZURE_162 | — | networking | azurerm_spring_cloud_api_portal | Ensures Spring Cloud API Portal Public Access Is Disabled |

### storage — 12 trivy + 19 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AZU-0011 | critical | — | — | The minimum TLS version for Storage Accounts should be TLS1_2 or |
| trivy | AZU-0012 | critical | — | — | The default action on Storage account network rules should be se |
| trivy | AZU-0007 | high | — | — | Storage containers in blob storage mode should not have public a |
| trivy | AZU-0008 | high | — | — | Storage accounts should be configured to only accept transfers t |
| trivy | AZU-0010 | high | — | — | Trusted Microsoft Services should have bypass access to Storage  |
| trivy | AZU-0059 | high | — | — | Storage account should have secure transfer and minimum TLS vers |
| trivy | AZU-0009 | medium | — | — | When using Queue Services for a storage account, logging should  |
| trivy | AZU-0056 | medium | — | — | Storage account should have blob soft delete enabled |
| trivy | AZU-0057 | medium | — | — | Storage account should have logging enabled |
| trivy | AZU-0060 | medium | — | — | Storage account should use customer-managed keys for encryption |
| trivy | AZU-0061 | medium | — | — | Storage account should have infrastructure encryption enabled |
| trivy | AZU-0058 | low | — | — | Storage account should use geo-redundant replication |
| checkov | CKV2_AZURE_1 | — | encryption | azurerm_storage_account | Ensure storage for critical data are encrypted with Customer Man |
| checkov | CKV2_AZURE_33 | — | general security | azurerm_storage_account | Ensure storage account is configured with private endpoint |
| checkov | CKV2_AZURE_38 | — | general security | azurerm_storage_account | Ensure soft-delete is enabled on Azure storage account |
| checkov | CKV2_AZURE_40 | — | iam | azurerm_storage_account | Ensure storage account is not configured with Shared Key authori |
| checkov | CKV2_AZURE_41 | — | iam | azurerm_storage_account | Ensure storage account is configured with SAS expiration policy |
| checkov | CKV2_AZURE_47 | — | iam | azurerm_storage_account | Ensure storage account is configured without blob anonymous acce |
| checkov | CKV_AZURE_190 | — | networking | azurerm_storage_account | Ensure that Storage blobs restrict public access |
| checkov | CKV_AZURE_206 | — | backup and recovery | azurerm_storage_account | Ensure that Storage Accounts use replication |
| checkov | CKV_AZURE_244 | — | general security | azurerm_storage_account | Avoid the use of local users for Azure Storage unless necessary |
| checkov | CKV_AZURE_250 | — | networking | azurerm_storage_sync | Ensure Storage Sync Service is not configured with overly permis |
| checkov | CKV_AZURE_3 | — | encryption | azurerm_storage_account | Ensure that 'enable_https_traffic_only' is enabled |
| checkov | CKV_AZURE_33 | — | logging | azurerm_storage_account | Ensure Storage logging is enabled for Queue service for read, wr |
| checkov | CKV_AZURE_34 | — | networking | azurerm_storage_container | Ensure that 'Public access level' is set to Private for blob con |
| checkov | CKV_AZURE_35 | — | networking | azurerm_storage_account, azurerm_storage | Ensure default network access rule for Storage Accounts is set t |
| checkov | CKV_AZURE_36 | — | networking | azurerm_storage_account, azurerm_storage | Ensure 'Trusted Microsoft Services' is enabled for Storage Accou |
| checkov | CKV_AZURE_43 | — | convention | azurerm_storage_account | Ensure Storage Accounts adhere to the naming rules |
| checkov | CKV_AZURE_44 | — | networking | azurerm_storage_account | Ensure Storage Account is using the latest version of TLS encryp |
| checkov | CKV_AZURE_59 | — | networking | azurerm_storage_account | Ensure that Storage accounts disallow public access |
| checkov | CKV_AZURE_64 | — | networking | azurerm_storage_sync | Ensure that Azure File Sync disables public network access |

### synapse — 1 trivy + 12 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AZU-0034 | medium | — | — | Synapse Workspace should have managed virtual network enabled, t |
| checkov | CKV2_AZURE_19 | — | networking | azurerm_synapse_workspace | Ensure that Azure Synapse workspaces have no IP firewall rules a |
| checkov | CKV2_AZURE_46 | — | general security | azurerm_synapse_workspace_security_alert | Ensure that Azure Synapse Workspace vulnerability assessment is  |
| checkov | CKV2_AZURE_51 | — | general security | azurerm_synapse_sql_pool, azurerm_synaps | Ensure Synapse SQL Pool has a security alert policy |
| checkov | CKV2_AZURE_52 | — | general security | azurerm_synapse_sql_pool, azurerm_synaps | Ensure Synapse SQL Pool has vulnerability assessment attached |
| checkov | CKV2_AZURE_53 | — | logging | azurerm_synapse_workspace | Ensure Azure Synapse Workspace has extended audit logs |
| checkov | CKV2_AZURE_54 | — | logging | azurerm_synapse_sql_pool, azurerm_synaps | Ensure log monitoring is enabled for Synapse SQL Pool |
| checkov | CKV_AZURE_157 | — | general security | azurerm_synapse_workspace | Ensure that Synapse workspace has data_exfiltration_protection_e |
| checkov | CKV_AZURE_239 | — | secrets | azurerm_synapse_workspace | Ensure Azure Synapse Workspace administrator login password is n |
| checkov | CKV_AZURE_240 | — | encryption | azurerm_synapse_workspace | Ensure Azure Synapse Workspace is encrypted with a CMK |
| checkov | CKV_AZURE_241 | — | encryption | azurerm_synapse_sql_pool | Ensure Synapse SQL pools are encrypted |
| checkov | CKV_AZURE_242 | — | general security | azurerm_synapse_spark_pool | Ensure isolated compute is enabled for Synapse Spark pools |
| checkov | CKV_AZURE_58 | — | networking | azurerm_synapse_workspace | Ensure that Azure Synapse workspaces enables managed virtual net |

### web — 0 trivy + 4 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AZURE_122 | — | networking | azurerm_web_application_firewall_policy | Ensure that Application Gateway uses WAF in "Detection" or "Prev |
| checkov | CKV_AZURE_135 | — | application security | azurerm_web_application_firewall_policy | Ensure Application Gateway WAF prevents message lookup in Log4j2 |
| checkov | CKV_AZURE_175 | — | general security | azurerm_web_pubsub | Ensure Web PubSub uses a SKU with an SLA |
| checkov | CKV_AZURE_176 | — | iam | azurerm_web_pubsub | Ensure Web PubSub uses managed identities to access Azure resour |

