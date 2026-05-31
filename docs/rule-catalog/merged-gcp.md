# Merged GCP catalog — Trivy + Checkov (porting worklist)

237 checks grouped by **service**, so a Trivy check and the Checkov check(s) for the same intent sit together — port ONE bumper rule per intent, citing both ids in provenance. Trivy supplies severity; Checkov (OSS) does not (assign at port time). The `resource` column is the Terraform type to write the rule against.

### artifact — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_GCP_101 | — | general security | google_artifact_registry_repository_iam_ | Ensure that Artifact Registry repositories are not anonymously o |
| checkov | CKV_GCP_84 | — | encryption | google_artifact_registry_repository | Ensure Artifact Registry Repositories are encrypted with Custome |

### bigquery — 1 trivy + 5 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | GCP-0046 | critical | — | — | BigQuery datasets should only be accessible within the organisat |
| checkov | CKV_GCP_100 | — | general security | google_bigquery_table_iam_member, google | Ensure that BigQuery Tables are not anonymously or publicly acce |
| checkov | CKV_GCP_121 | — | general security | google_bigquery_table | Ensure BigQuery tables have deletion protection enabled |
| checkov | CKV_GCP_15 | — | general security | google_bigquery_dataset | Ensure that BigQuery datasets are not anonymously or publicly ac |
| checkov | CKV_GCP_80 | — | encryption | google_bigquery_table | Ensure Big Query Tables are encrypted with Customer Supplied Enc |
| checkov | CKV_GCP_81 | — | encryption | google_bigquery_dataset | Ensure Big Query Datasets are encrypted with Customer Supplied E |

### bigtable — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_GCP_122 | — | encryption | google_bigtable_instance | Ensure Big Table Instances have deletion protection enabled |
| checkov | CKV_GCP_85 | — | encryption | google_bigtable_instance | Ensure Big Table Instances are encrypted with Customer Supplied  |

### cloud — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_GCP_102 | — | general security | google_cloud_run_service_iam_member, goo | Ensure that GCP Cloud Run services are not anonymously or public |

### cloudbuild — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_GCP_86 | — | general security | google_cloudbuild_worker_pool | Ensure Cloud build workers are private |

### cloudfunctions — 0 trivy + 3 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_GCP_10 | — | networking | google_cloudfunctions_function | Ensure GCP Cloud Function HTTP trigger is secured |
| checkov | CKV_GCP_107 | — | application security | google_cloudfunctions_function_iam_membe | Cloud functions should not be public |
| checkov | CKV_GCP_124 | — | networking | google_cloudfunctions_function, google_c | Ensure GCP Cloud Function is not configured with overly permissi |

### compute — 24 trivy + 27 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | GCP-0027 | critical | — | — | A firewall rule should not allow unrestricted ingress from any I |
| trivy | GCP-0035 | critical | — | — | A firewall rule should not allow unrestricted egress to any IP a |
| trivy | GCP-0037 | critical | — | — | The encryption key used to encrypt a compute disk has been speci |
| trivy | GCP-0039 | critical | — | — | SSL policies should enforce secure versions of TLS |
| trivy | GCP-0044 | critical | — | — | Instances should not use the default service account |
| trivy | GCP-0031 | high | — | — | Instances should not have public IP addresses |
| trivy | GCP-0043 | high | — | — | Instances should not have IP forwarding enabled |
| trivy | GCP-0070 | high | — | — | RDP Access Is Not Restricted |
| trivy | GCP-0030 | medium | — | — | Disable project-wide SSH keys for all instances |
| trivy | GCP-0032 | medium | — | — | Disable serial port connectivity for all instances |
| trivy | GCP-0036 | medium | — | — | Instances should not override the project setting for OS Login |
| trivy | GCP-0041 | medium | — | — | Instances should have Shielded VM VTPM enabled |
| trivy | GCP-0042 | medium | — | — | OS Login should be enabled at project level |
| trivy | GCP-0045 | medium | — | — | Instances should have Shielded VM integrity monitoring enabled |
| trivy | GCP-0067 | medium | — | — | Instances should have Shielded VM secure boot enabled |
| trivy | GCP-0071 | medium | — | — | SSH Access Is Not Restricted |
| trivy | GCP-0072 | medium | — | — | Google Compute Network Using Firewall Rule that Allows All Ports |
| trivy | GCP-0073 | medium | — | — | Disable Default Firewall Rules |
| trivy | GCP-0076 | medium | — | — | Google Compute Subnetwork Logging Disabled |
| trivy | GCP-0029 | low | — | — | VPC flow logs should be enabled for all subnetworks |
| trivy | GCP-0033 | low | — | — | VM disks should be encrypted with Customer Supplied Encryption K |
| trivy | GCP-0034 | low | — | — | Disks should be encrypted with customer managed encryption keys |
| trivy | GCP-0074 | low | — | — | Google Compute Network Using Firewall Rule that Allows Large Por |
| trivy | GCP-0075 | low | — | — | Google Compute Subnetwork with Private Google Access Disabled |
| checkov | CKV2_GCP_12 | — | networking | google_compute_firewall | Ensure GCP compute firewall ingress does not allow unrestricted  |
| checkov | CKV2_GCP_18 | — | networking | google_compute_network | Ensure GCP network defines a firewall and does not use the defau |
| checkov | CKV2_GCP_2 | — | networking | google_compute_network | Ensure legacy networks do not exist for a project |
| checkov | CKV2_GCP_37 | — | networking | google_compute_forwarding_rule | Ensure GCP compute regional forwarding rule does not use HTTP pr |
| checkov | CKV2_GCP_38 | — | networking | google_compute_global_forwarding_rule | Ensure GCP compute global forwarding rule does not use HTTP prox |
| checkov | CKV_GCP_106 | — | networking | google_compute_firewall | Ensure Google compute firewall ingress does not allow unrestrict |
| checkov | CKV_GCP_2 | — | networking | google_compute_firewall | Ensure Google compute firewall ingress does not allow unrestrict |
| checkov | CKV_GCP_26 | — | logging | google_compute_subnetwork | Ensure that VPC Flow Logs is enabled for every subnet in a VPC N |
| checkov | CKV_GCP_3 | — | networking | google_compute_firewall | Ensure Google compute firewall ingress does not allow unrestrict |
| checkov | CKV_GCP_30 | — | networking | google_compute_instance, google_compute_ | Ensure that instances are not configured to use the default serv |
| checkov | CKV_GCP_31 | — | networking | google_compute_instance, google_compute_ | Ensure that instances are not configured to use the default serv |
| checkov | CKV_GCP_32 | — | networking | google_compute_instance, google_compute_ | Ensure 'Block Project-wide SSH keys' is enabled for VM instances |
| checkov | CKV_GCP_33 | — | networking | google_compute_project_metadata | Ensure oslogin is enabled for a Project |
| checkov | CKV_GCP_34 | — | networking | google_compute_instance, google_compute_ | Ensure that no instance in the project overrides the project set |
| checkov | CKV_GCP_35 | — | networking | google_compute_instance, google_compute_ | Ensure 'Enable connecting to serial ports' is not enabled for VM |
| checkov | CKV_GCP_36 | — | networking | google_compute_instance, google_compute_ | Ensure that IP forwarding is not enabled on Instances |
| checkov | CKV_GCP_37 | — | encryption | google_compute_disk | Ensure VM disks for critical VMs are encrypted with Customer Sup |
| checkov | CKV_GCP_38 | — | encryption | google_compute_instance | Ensure VM disks for critical VMs are encrypted with Customer Sup |
| checkov | CKV_GCP_39 | — | general security | google_compute_instance, google_compute_ | Ensure Compute instances are launched with Shielded VM enabled |
| checkov | CKV_GCP_4 | — | networking | google_compute_ssl_policy | Ensure no HTTPS or SSL proxy load balancers permit SSL policies  |
| checkov | CKV_GCP_40 | — | networking | google_compute_instance, google_compute_ | Ensure that Compute instances do not have public IP addresses |
| checkov | CKV_GCP_73 | — | application security | google_compute_security_policy | Ensure Cloud Armor prevents message lookup in Log4j2. See CVE-20 |
| checkov | CKV_GCP_74 | — | general security | google_compute_subnetwork | Ensure that private_ip_google_access is enabled for Subnet |
| checkov | CKV_GCP_75 | — | networking | google_compute_firewall | Ensure Google compute firewall ingress does not allow unrestrict |
| checkov | CKV_GCP_76 | — | networking | google_compute_subnetwork | Ensure that Private google access is enabled for IPV6 |
| checkov | CKV_GCP_77 | — | networking | google_compute_firewall | Ensure Google compute firewall ingress does not allow on ftp por |
| checkov | CKV_GCP_88 | — | networking | google_compute_firewall | Ensure Google compute firewall ingress does not allow unrestrict |

### container — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_GCP_9 | — | general security | google_container_registry, google_storag | Ensure that Container Registry repositories are not anonymously  |

### data — 0 trivy + 3 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_GCP_104 | — | logging | google_data_fusion_instance | Ensure Datafusion has stack driver logging enabled |
| checkov | CKV_GCP_105 | — | logging | google_data_fusion_instance | Ensure Datafusion has stack driver monitoring enabled |
| checkov | CKV_GCP_87 | — | general security | google_data_fusion_instance | Ensure Data fusion instances are private |

### dataflow — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_GCP_90 | — | encryption | google_dataflow_job | Ensure data flow jobs are encrypted with Customer Supplied Encry |
| checkov | CKV_GCP_94 | — | general security | google_dataflow_job | Ensure Dataflow jobs are private |

### dataproc — 0 trivy + 3 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_GCP_103 | — | general security | google_dataproc_cluster | Ensure Dataproc Clusters do not have public IPs |
| checkov | CKV_GCP_91 | — | encryption | google_dataproc_cluster | Ensure Dataproc cluster is encrypted with Customer Supplied Encr |
| checkov | CKV_GCP_98 | — | general security | google_dataproc_cluster_iam_member, goog | Ensure that Dataproc clusters are not anonymously or publicly ac |

### dialogflow — 0 trivy + 3 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_GCP_29 | — | logging | google_dialogflow_agent | Ensure logging is enabled for Dialogflow agents |
| checkov | CKV2_GCP_30 | — | logging | google_dialogflow_cx_agent | Ensure logging is enabled for Dialogflow CX agents |
| checkov | CKV2_GCP_31 | — | logging | google_dialogflow_cx_webhook | Ensure logging is enabled for Dialogflow CX webhooks |

### dns — 2 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | GCP-0012 | medium | — | — | Zone signing should not use RSA SHA1 |
| trivy | GCP-0013 | medium | — | — | Cloud DNS should use DNSSEC |
| checkov | CKV_GCP_16 | — | encryption | google_dns_managed_zone | Ensure that DNSSEC is enabled for Cloud DNS |
| checkov | CKV_GCP_17 | — | encryption | google_dns_managed_zone | Ensure that RSASHA1 is not used for the zone-signing and key-sig |

### document — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_GCP_22 | — | encryption | google_document_ai_processor | Ensure Document AI Processors are encrypted with a Customer Mana |
| checkov | CKV2_GCP_23 | — | encryption | google_document_ai_warehouse_location | Ensure Document AI Warehouse Location is configured to use a Cus |

### gke — 17 trivy + 25 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | GCP-0048 | high | — | — | Legacy metadata endpoints enabled. |
| trivy | GCP-0053 | high | — | — | GKE Control Plane should not be publicly accessible |
| trivy | GCP-0055 | high | — | — | Shielded GKE nodes not enabled. |
| trivy | GCP-0057 | high | — | — | Node metadata value disables metadata concealment. |
| trivy | GCP-0061 | high | — | — | Master authorized networks should be configured on GKE clusters |
| trivy | GCP-0062 | high | — | — | Legacy ABAC permissions are enabled. |
| trivy | GCP-0064 | high | — | — | Legacy client authentication methods utilized. |
| trivy | GCP-0050 | medium | — | — | Checks for service account defined for GKE nodes |
| trivy | GCP-0056 | medium | — | — | Network Policy should be enabled on GKE clusters |
| trivy | GCP-0059 | medium | — | — | Clusters should be set to private |
| trivy | GCP-0049 | low | — | — | Clusters should have IP aliasing enabled |
| trivy | GCP-0051 | low | — | — | Clusters should be configured with Labels |
| trivy | GCP-0052 | low | — | — | Stackdriver Monitoring should be enabled |
| trivy | GCP-0054 | low | — | — | Ensure Container-Optimized OS (cos) is used for Kubernetes Engin |
| trivy | GCP-0058 | low | — | — | Kubernetes should have 'Automatic upgrade' enabled |
| trivy | GCP-0060 | low | — | — | Stackdriver Logging should be enabled |
| trivy | GCP-0063 | low | — | — | Kubernetes should have 'Automatic repair' enabled |
| checkov | CKV2_GCP_19 | — | kubernetes | google_container_cluster | Ensure GCP Kubernetes engine clusters have 'alpha cluster' featu |
| checkov | CKV_GCP_1 | — | kubernetes | google_container_cluster | Ensure Stackdriver Logging is set to Enabled on Kubernetes Engin |
| checkov | CKV_GCP_10 | — | kubernetes | google_container_node_pool | Ensure 'Automatic node upgrade' is enabled for Kubernetes Cluste |
| checkov | CKV_GCP_12 | — | kubernetes | google_container_cluster | Ensure Network Policy is enabled on Kubernetes Engine Clusters |
| checkov | CKV_GCP_123 | — | kubernetes | google_container_cluster | GKE Don't Use NodePools in the Cluster configuration |
| checkov | CKV_GCP_13 | — | kubernetes | google_container_cluster | Ensure client certificate authentication to Kubernetes Engine Cl |
| checkov | CKV_GCP_18 | — | kubernetes | google_container_cluster | Ensure GKE Control Plane is not public |
| checkov | CKV_GCP_20 | — | kubernetes | google_container_cluster | Ensure master authorized networks is set to enabled in GKE clust |
| checkov | CKV_GCP_21 | — | kubernetes | google_container_cluster | Ensure Kubernetes Clusters are configured with Labels |
| checkov | CKV_GCP_22 | — | kubernetes | google_container_node_pool | Ensure Container-Optimized OS (cos) is used for Kubernetes Engin |
| checkov | CKV_GCP_23 | — | kubernetes | google_container_cluster | Ensure Kubernetes Cluster is created with Alias IP ranges enable |
| checkov | CKV_GCP_24 | — | kubernetes | google_container_cluster | Ensure PodSecurityPolicy controller is enabled on the Kubernetes |
| checkov | CKV_GCP_25 | — | kubernetes | google_container_cluster | Ensure Kubernetes Cluster is created with Private cluster enable |
| checkov | CKV_GCP_61 | — | kubernetes | google_container_cluster | Enable VPC Flow Logs and Intranode Visibility |
| checkov | CKV_GCP_64 | — | kubernetes | google_container_cluster | Ensure clusters are created with Private Nodes |
| checkov | CKV_GCP_65 | — | kubernetes | google_container_cluster | Manage Kubernetes RBAC users with Google Groups for GKE |
| checkov | CKV_GCP_66 | — | kubernetes | google_container_cluster | Ensure use of Binary Authorization |
| checkov | CKV_GCP_68 | — | kubernetes | google_container_cluster, google_contain | Ensure Secure Boot for Shielded GKE Nodes is Enabled |
| checkov | CKV_GCP_69 | — | kubernetes | google_container_cluster, google_contain | Ensure the GKE Metadata Server is Enabled |
| checkov | CKV_GCP_7 | — | kubernetes | google_container_cluster | Ensure Legacy Authorization is set to Disabled on Kubernetes Eng |
| checkov | CKV_GCP_70 | — | kubernetes | google_container_cluster | Ensure the GKE Release Channel is set |
| checkov | CKV_GCP_71 | — | kubernetes | google_container_cluster | Ensure Shielded GKE Nodes are Enabled |
| checkov | CKV_GCP_72 | — | kubernetes | google_container_cluster, google_contain | Ensure Integrity Monitoring for Shielded GKE Nodes is Enabled |
| checkov | CKV_GCP_8 | — | kubernetes | google_container_cluster | Ensure Stackdriver Monitoring is set to Enabled on Kubernetes En |
| checkov | CKV_GCP_9 | — | kubernetes | google_container_node_pool | Ensure 'Automatic node repair' is enabled for Kubernetes Cluster |

### iam — 12 trivy + 15 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | GCP-0007 | high | — | — | Service accounts should not have roles assigned with excessive p |
| trivy | GCP-0010 | high | — | — | Default network should not be created at project level |
| trivy | GCP-0068 | high | — | — | A configuration for an external workload identity pool provider  |
| trivy | GCP-0003 | medium | — | — | IAM granted directly to user. |
| trivy | GCP-0004 | medium | — | — | Roles should not be assigned to default service accounts |
| trivy | GCP-0005 | medium | — | — | Users should not be granted service account access at the folder |
| trivy | GCP-0006 | medium | — | — | Roles should not be assigned to default service accounts |
| trivy | GCP-0008 | medium | — | — | Roles should not be assigned to default service accounts |
| trivy | GCP-0009 | medium | — | — | Users should not be granted service account access at the organi |
| trivy | GCP-0011 | medium | — | — | Users should not be granted service account access at the projec |
| trivy | GCP-0069 | low | — | — | Not Proper Email Account In Use |
| trivy | GCP-0079 | low | — | — | IAM Audit Not Properly Configured |
| checkov | CKV2_GCP_3 | — | encryption | google_service_account_key | Ensure that there are only GCP-managed service account keys for  |
| checkov | CKV_GCP_113 | — | iam | google_iam_policy | Ensure IAM policy should not define public access |
| checkov | CKV_GCP_115 | — | iam | google_organization_iam_member, google_o | Ensure basic roles are not used at organization level. |
| checkov | CKV_GCP_116 | — | iam | google_folder_iam_member, google_folder_ | Ensure basic roles are not used at folder level. |
| checkov | CKV_GCP_117 | — | iam | google_project_iam_member, google_projec | Ensure basic roles are not used at project level. |
| checkov | CKV_GCP_118 | — | iam | google_iam_workload_identity_pool_provid | Ensure IAM workload identity pool provider is restricted |
| checkov | CKV_GCP_125 | — | iam | google_iam_workload_identity_pool_provid | Ensure GCP GitHub Actions OIDC trust policy is configured secure |
| checkov | CKV_GCP_41 | — | iam | google_project_iam_binding, google_proje | Ensure that IAM users are not assigned the Service Account User  |
| checkov | CKV_GCP_42 | — | iam | google_project_iam_member | Ensure that Service Account has no Admin privileges |
| checkov | CKV_GCP_44 | — | iam | google_folder_iam_member, google_folder_ | Ensure no roles that enable to impersonate and manage all servic |
| checkov | CKV_GCP_45 | — | iam | google_organization_iam_member, google_o | Ensure no roles that enable to impersonate and manage all servic |
| checkov | CKV_GCP_46 | — | iam | google_project_iam_member, google_projec | Ensure Default Service account is not used at a project level |
| checkov | CKV_GCP_47 | — | iam | google_organization_iam_member, google_o | Ensure default service account is not used at an organization le |
| checkov | CKV_GCP_48 | — | iam | google_folder_iam_member, google_folder_ | Ensure Default Service account is not used at a folder level |
| checkov | CKV_GCP_49 | — | iam | google_project_iam_member, google_projec | Ensure roles do not impersonate or manage Service Accounts used  |

### kms — 1 trivy + 5 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | GCP-0065 | high | — | — | KMS keys should be rotated at least every 90 days |
| checkov | CKV2_GCP_6 | — | encryption | google_kms_crypto_key, google_kms_crypto | Ensure that Cloud KMS cryptokeys are not anonymously or publicly |
| checkov | CKV2_GCP_8 | — | encryption | google_kms_key_ring, google_kms_key_ring | Ensure that Cloud KMS Key Rings are not anonymously or publicly  |
| checkov | CKV_GCP_112 | — | iam | google_kms_crypto_key_iam_policy, google | Ensure KMS policy should not allow public access |
| checkov | CKV_GCP_43 | — | general security | google_kms_crypto_key | Ensure KMS encryption keys are rotated within a period of 90 day |
| checkov | CKV_GCP_82 | — | encryption | google_kms_crypto_key | Ensure KMS keys are protected from deletion |

### logging — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_GCP_4 | — | logging | google_logging_folder_sink, google_loggi | Ensure that retention policies on log buckets are configured usi |

### notebooks — 0 trivy + 6 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_GCP_21 | — | encryption | google_notebooks_instance | Ensure Vertex AI instance disks are encrypted with a Customer Ma |
| checkov | CKV2_GCP_35 | — | encryption | google_notebooks_runtime | Ensure Vertex AI runtime is encrypted with a Customer Managed Ke |
| checkov | CKV2_GCP_36 | — | networking | google_notebooks_runtime | Ensure Vertex AI runtime is private |
| checkov | CKV_GCP_126 | — | general security | google_notebooks_instance | Ensure Vertex AI Notebook instances are launched with Shielded V |
| checkov | CKV_GCP_127 | — | general security | google_notebooks_instance | Ensure Integrity Monitoring for Shielded Vertex AI Notebook Inst |
| checkov | CKV_GCP_89 | — | general security | google_notebooks_instance | Ensure Vertex AI instances are private |

### project — 0 trivy + 4 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_GCP_1 | — | networking | google_project_default_service_accounts | Ensure GKE clusters are not running using the Compute Engine def |
| checkov | CKV2_GCP_11 | — | general security | google_project_services | Ensure GCP GCR Container Vulnerability Scanning is enabled |
| checkov | CKV2_GCP_5 | — | logging | google_project, google_project_iam_audit | Ensure that Cloud Audit Logging is configured properly across al |
| checkov | CKV_GCP_27 | — | networking | google_project | Ensure that the default network does not exist in a project |

### pubsub — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_GCP_83 | — | encryption | google_pubsub_topic | Ensure PubSub Topics are encrypted with Customer Supplied Encryp |
| checkov | CKV_GCP_99 | — | general security | google_pubsub_topic_iam_member, google_p | Ensure that Pub/Sub Topics are not anonymously or publicly acces |

### redis — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_GCP_95 | — | general security | google_redis_instance | Ensure Memorystore for Redis has AUTH enabled |
| checkov | CKV_GCP_97 | — | general security | google_redis_instance | Ensure Memorystore for Redis uses intransit encryption |

### spanner — 0 trivy + 3 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_GCP_119 | — | general security | google_spanner_database | Ensure Spanner Database has deletion protection enabled |
| checkov | CKV_GCP_120 | — | general security | google_spanner_database | Ensure Spanner Database has drop protection enabled |
| checkov | CKV_GCP_93 | — | encryption | google_spanner_database | Ensure Spanner Database is encrypted with Customer Supplied Encr |

### sql — 13 trivy + 26 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | GCP-0015 | high | — | — | SSL connections to a SQL database instance should be enforced. |
| trivy | GCP-0017 | high | — | — | Ensure that Cloud SQL Database Instances are not publicly expose |
| trivy | GCP-0026 | high | — | — | Disable local_infile setting in MySQL |
| trivy | GCP-0014 | medium | — | — | Temporary file logging should be enabled for all temporary files |
| trivy | GCP-0016 | medium | — | — | Ensure that logging of connections is enabled. |
| trivy | GCP-0019 | medium | — | — | Cross-database ownership chaining should be disabled |
| trivy | GCP-0020 | medium | — | — | Ensure that logging of lock waits is enabled. |
| trivy | GCP-0022 | medium | — | — | Ensure that logging of disconnections is enabled. |
| trivy | GCP-0023 | medium | — | — | Contained database authentication should be disabled |
| trivy | GCP-0024 | medium | — | — | Enable automated backups to recover from data-loss |
| trivy | GCP-0025 | medium | — | — | Ensure that logging of checkpoints is enabled. |
| trivy | GCP-0018 | low | — | — | Ensure that Postgres errors are logged |
| trivy | GCP-0021 | low | — | — | Ensure that logging of long statements is disabled. |
| checkov | CKV2_GCP_13 | — | logging | google_sql_database_instance | Ensure PostgreSQL database flag 'log_duration' is set to 'on' |
| checkov | CKV2_GCP_14 | — | logging | google_sql_database_instance | Ensure PostgreSQL database flag 'log_executor_stats' is set to ' |
| checkov | CKV2_GCP_15 | — | logging | google_sql_database_instance | Ensure PostgreSQL database flag 'log_parser_stats' is set to 'of |
| checkov | CKV2_GCP_16 | — | logging | google_sql_database_instance | Ensure PostgreSQL database flag 'log_planner_stats' is set to 'o |
| checkov | CKV2_GCP_17 | — | logging | google_sql_database_instance | Ensure PostgreSQL database flag 'log_statement_stats' is set to  |
| checkov | CKV2_GCP_20 | — | backup and recovery | google_sql_database_instance | Ensure MySQL DB instance has point-in-time recovery backup confi |
| checkov | CKV2_GCP_7 | — | iam | google_sql_database_instance, google_sql | Ensure that a MySQL database instance does not allow anyone to c |
| checkov | CKV_GCP_108 | — | logging | google_sql_database_instance | Ensure hostnames are logged for GCP PostgreSQL databases |
| checkov | CKV_GCP_109 | — | logging | google_sql_database_instance | Ensure the GCP PostgreSQL database log levels are set to ERROR o |
| checkov | CKV_GCP_11 | — | networking | google_sql_database_instance | Ensure that Cloud SQL database Instances are not open to the wor |
| checkov | CKV_GCP_110 | — | logging | google_sql_database_instance | Ensure pgAudit is enabled for your GCP PostgreSQL database |
| checkov | CKV_GCP_111 | — | logging | google_sql_database_instance | Ensure GCP PostgreSQL logs SQL statements |
| checkov | CKV_GCP_14 | — | backup and recovery | google_sql_database_instance | Ensure all Cloud SQL database instance have backup configuration |
| checkov | CKV_GCP_50 | — | general security | google_sql_database_instance | Ensure MySQL database 'local_infile' flag is set to 'off' |
| checkov | CKV_GCP_51 | — | logging | google_sql_database_instance | Ensure PostgreSQL database 'log_checkpoints' flag is set to 'on' |
| checkov | CKV_GCP_52 | — | logging | google_sql_database_instance | Ensure PostgreSQL database 'log_connections' flag is set to 'on' |
| checkov | CKV_GCP_53 | — | logging | google_sql_database_instance | Ensure PostgreSQL database 'log_disconnections' flag is set to ' |
| checkov | CKV_GCP_54 | — | logging | google_sql_database_instance | Ensure PostgreSQL database 'log_lock_waits' flag is set to 'on' |
| checkov | CKV_GCP_55 | — | logging | google_sql_database_instance | Ensure PostgreSQL database 'log_min_messages' flag is set to a v |
| checkov | CKV_GCP_56 | — | logging | google_sql_database_instance | Ensure PostgreSQL database 'log_temp_files flag is set to '0' |
| checkov | CKV_GCP_57 | — | logging | google_sql_database_instance | Ensure PostgreSQL database 'log_min_duration_statement' flag is  |
| checkov | CKV_GCP_58 | — | general security | google_sql_database_instance | Ensure SQL database 'cross db ownership chaining' flag is set to |
| checkov | CKV_GCP_59 | — | general security | google_sql_database_instance | Ensure SQL database 'contained database authentication' flag is  |
| checkov | CKV_GCP_6 | — | networking | google_sql_database_instance | Ensure all Cloud SQL database instance requires all incoming con |
| checkov | CKV_GCP_60 | — | networking | google_sql_database_instance | Ensure Cloud SQL database does not have public IP |
| checkov | CKV_GCP_79 | — | general security | google_sql_database_instance | Ensure SQL database is using latest Major version |

### storage — 5 trivy + 6 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | GCP-0001 | high | — | — | Ensure that Cloud Storage bucket is not anonymously or publicly  |
| trivy | GCP-0002 | medium | — | — | Ensure that Cloud Storage buckets have uniform bucket-level acce |
| trivy | GCP-0077 | medium | — | — | Cloud Storage Bucket Logging Not Enabled |
| trivy | GCP-0078 | medium | — | — | Cloud Storage Bucket Versioning Disabled |
| trivy | GCP-0066 | low | — | — | Cloud Storage buckets should be encrypted with a customer-manage |
| checkov | CKV_GCP_114 | — | general security | google_storage_bucket | Ensure public access prevention is enforced on Cloud Storage buc |
| checkov | CKV_GCP_28 | — | general security | google_storage_bucket_iam_member, google | Ensure that Cloud Storage bucket is not anonymously or publicly  |
| checkov | CKV_GCP_29 | — | general security | google_storage_bucket | Ensure that Cloud Storage buckets have uniform bucket-level acce |
| checkov | CKV_GCP_62 | — | logging | google_storage_bucket | Bucket should log access |
| checkov | CKV_GCP_63 | — | logging | google_storage_bucket | Bucket should not log to itself |
| checkov | CKV_GCP_78 | — | logging | google_storage_bucket | Ensure Cloud storage has versioning enabled |

### tpu — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_GCP_32 | — | networking | google_tpu_v2_vm | Ensure TPU v2 is private |

### vertex — 0 trivy + 7 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_GCP_24 | — | encryption | google_vertex_ai_endpoint | Ensure Vertex AI endpoint uses a Customer Managed Key (CMK) |
| checkov | CKV2_GCP_25 | — | encryption | google_vertex_ai_featurestore | Ensure Vertex AI featurestore uses a Customer Managed Key (CMK) |
| checkov | CKV2_GCP_26 | — | encryption | google_vertex_ai_tensorboard | Ensure Vertex AI tensorboard uses a Customer Managed Key (CMK) |
| checkov | CKV2_GCP_33 | — | networking | google_vertex_ai_endpoint | Ensure Vertex AI endpoint is private |
| checkov | CKV2_GCP_34 | — | networking | google_vertex_ai_index_endpoint | Ensure Vertex AI index endpoint is private |
| checkov | CKV_GCP_92 | — | encryption | google_vertex_ai_dataset | Ensure Vertex AI datasets uses a CMK (Customer Managed Key) |
| checkov | CKV_GCP_96 | — | encryption | google_vertex_ai_metadata_store | Ensure Vertex AI Metadata Store uses a CMK (Customer Managed Key |

### workbench — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_GCP_27 | — | encryption | google_workbench_instance | Ensure Vertex AI workbench instance disks are encrypted with a C |
| checkov | CKV2_GCP_28 | — | general security | google_workbench_instance | Ensure Vertex AI workbench instances are private |

