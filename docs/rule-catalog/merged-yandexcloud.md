# Merged YANDEXCLOUD catalog — Trivy + Checkov (porting worklist)

24 checks grouped by **service**, so a Trivy check and the Checkov check(s) for the same intent sit together — port ONE bumper rule per intent, citing both ids in provenance. Trivy supplies severity; Checkov (OSS) does not (assign at port time). The `resource` column is the Terraform type to write the rule against.

### compute — 0 trivy + 5 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_YC_11 | — | networking | yandex_compute_instance | Ensure security group is assigned to network interface. |
| checkov | CKV_YC_18 | — | networking | yandex_compute_instance_group | Ensure compute instance group does not have public IP. |
| checkov | CKV_YC_2 | — | networking | yandex_compute_instance | Ensure compute instance does not have public IP. |
| checkov | CKV_YC_22 | — | networking | yandex_compute_instance_group | Ensure compute instance group has security group assigned. |
| checkov | CKV_YC_4 | — | general security | yandex_compute_instance | Ensure compute instance does not have serial console enabled. |

### kms — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_YC_9 | — | encryption | yandex_kms_symmetric_key | Ensure KMS symmetric key is rotated. |

### kubernetes — 0 trivy + 8 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_YC_10 | — | encryption | yandex_kubernetes_cluster | Ensure etcd database is encrypted with KMS key. |
| checkov | CKV_YC_14 | — | networking | yandex_kubernetes_cluster | Ensure security group is assigned to Kubernetes cluster. |
| checkov | CKV_YC_15 | — | networking | yandex_kubernetes_node_group | Ensure security group is assigned to Kubernetes node group. |
| checkov | CKV_YC_16 | — | networking | yandex_kubernetes_cluster | Ensure network policy is assigned to Kubernetes cluster. |
| checkov | CKV_YC_5 | — | networking | yandex_kubernetes_cluster | Ensure Kubernetes cluster does not have public IP address. |
| checkov | CKV_YC_6 | — | networking | yandex_kubernetes_node_group | Ensure Kubernetes cluster node group does not have public IP add |
| checkov | CKV_YC_7 | — | general security | yandex_kubernetes_cluster | Ensure Kubernetes cluster auto-upgrade is enabled. |
| checkov | CKV_YC_8 | — | general security | yandex_kubernetes_node_group | Ensure Kubernetes node group auto-upgrade is enabled. |

### mdb — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_YC_1 | — | networking | yandex_mdb_postgresql_cluster, yandex_md | Ensure security group is assigned to database cluster. |
| checkov | CKV_YC_12 | — | networking | yandex_mdb_postgresql_cluster, yandex_md | Ensure public IP is not assigned to database cluster. |

### organizationmanager — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_YC_21 | — | iam | yandex_organizationmanager_organization_ | Ensure organization member does not have elevated access. |

### resourcemanager — 0 trivy + 3 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_YC_13 | — | iam | yandex_resourcemanager_cloud_iam_binding | Ensure cloud member does not have elevated access. |
| checkov | CKV_YC_23 | — | iam | yandex_resourcemanager_folder_iam_bindin | Ensure folder member does not have elevated access. |
| checkov | CKV_YC_24 | — | iam | yandex_resourcemanager_folder_iam_bindin | Ensure passport account is not used for assignment. Use service  |

### storage — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_YC_17 | — | general security | yandex_storage_bucket | Ensure storage bucket does not have public access permissions. |
| checkov | CKV_YC_3 | — | encryption | yandex_storage_bucket | Ensure storage bucket is encrypted. |

### vpc — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_YC_19 | — | general security | yandex_vpc_security_group | Ensure security group does not contain allow-all rules. |
| checkov | CKV_YC_20 | — | general security | yandex_vpc_security_group_rule | Ensure security group rule is not allow-all. |

