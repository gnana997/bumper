# Merged ORACLE catalog — Trivy + Checkov (porting worklist)

27 checks grouped by **service**, so a Trivy check and the Checkov check(s) for the same intent sit together — port ONE bumper rule per intent, citing both ids in provenance. Trivy supplies severity; Checkov (OSS) does not (assign at port time). The `resource` column is the Terraform type to write the rule against.

### (unmapped) — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_OCI_1 | — | secrets | — | Ensure no hard coded OCI private key in provider |

### compute — 1 trivy + 0 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | OCI-0001 | critical | — | — | Compute instance requests an IP reservation from a public pool |

### containerengine — 0 trivy + 3 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_OCI_3 | — | networking | oci_containerengine_cluster | Ensure Kubernetes engine cluster is configured with NSG(s) |
| checkov | CKV2_OCI_5 | — | encryption | oci_containerengine_node_pool | Ensure Kubernetes Engine Cluster boot volume is configured with  |
| checkov | CKV2_OCI_6 | — | general security | oci_containerengine_cluster | Ensure Kubernetes Engine Cluster pod security policy is enforced |

### core — 0 trivy + 9 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_OCI_2 | — | networking | oci_core_network_security_group_security | Ensure NSG does not allow all traffic on RDP port (3389) |
| checkov | CKV_OCI_16 | — | general security | oci_core_security_list | Ensure VCN has an inbound security list |
| checkov | CKV_OCI_17 | — | networking | oci_core_security_list | Ensure VCN inbound security lists are stateless |
| checkov | CKV_OCI_2 | — | general security | oci_core_volume | Ensure OCI Block Storage Block Volume has backup enabled |
| checkov | CKV_OCI_21 | — | networking | oci_core_network_security_group_security | Ensure security group has stateless ingress security rules |
| checkov | CKV_OCI_3 | — | general security | oci_core_volume | OCI Block Storage Block Volumes are not encrypted with a Custome |
| checkov | CKV_OCI_4 | — | encryption | oci_core_instance | Ensure OCI Compute Instance boot volume has in-transit data encr |
| checkov | CKV_OCI_5 | — | general security | oci_core_instance | Ensure OCI Compute Instance has Legacy MetaData service endpoint |
| checkov | CKV_OCI_6 | — | logging | oci_core_instance | Ensure OCI Compute Instance has monitoring enabled |

### datacatalog — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_OCI_23 | — | networking | oci_datacatalog_catalog | Ensure OCI Data Catalog is configured without overly permissive  |

### file — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_OCI_4 | — | general security | oci_file_storage_export | Ensure File Storage File System access is restricted to root use |
| checkov | CKV_OCI_15 | — | encryption | oci_file_storage_file_system | Ensure OCI File System is Encrypted with a customer Managed Key |

### identity — 0 trivy + 6 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_OCI_1 | — | iam | oci_identity_group, oci_identity_user, o | Ensure administrator users are not associated with API keys |
| checkov | CKV_OCI_11 | — | general security | oci_identity_authentication_policy | OCI IAM password policy - must contain lower case |
| checkov | CKV_OCI_12 | — | general security | oci_identity_authentication_policy | OCI IAM password policy - must contain Numeric characters |
| checkov | CKV_OCI_13 | — | general security | oci_identity_authentication_policy | OCI IAM password policy - must contain Special characters |
| checkov | CKV_OCI_14 | — | general security | oci_identity_authentication_policy | OCI IAM password policy - must contain Uppercase characters |
| checkov | CKV_OCI_18 | — | iam | oci_identity_authentication_policy | OCI IAM password policy for local (non-federated) users has a mi |

### objectstorage — 0 trivy + 4 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_OCI_10 | — | general security | oci_objectstorage_bucket | Ensure OCI Object Storage is not Public |
| checkov | CKV_OCI_7 | — | logging | oci_objectstorage_bucket | Ensure OCI Object Storage bucket can emit object events |
| checkov | CKV_OCI_8 | — | general security | oci_objectstorage_bucket | Ensure OCI Object Storage has versioning enabled |
| checkov | CKV_OCI_9 | — | encryption | oci_objectstorage_bucket | Ensure OCI Object Storage is encrypted with Customer Managed Key |

