# Merged TENCENTCLOUD catalog — Trivy + Checkov (porting worklist)

14 checks grouped by **service**, so a Trivy check and the Checkov check(s) for the same intent sit together — port ONE bumper rule per intent, citing both ids in provenance. Trivy supplies severity; Checkov (OSS) does not (assign at port time). The `resource` column is the Terraform type to write the rule against.

### cbs — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_TC_1 | — | encryption | tencentcloud_cbs_storage | Ensure Tencent Cloud CBS is encrypted |

### clb — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_TC_11 | — | logging | tencentcloud_clb_instance | Ensure Tencent Cloud CLB has a logging ID and topic |
| checkov | CKV_TC_12 | — | networking | tencentcloud_clb_listener | Ensure Tencent Cloud CLBs use modern, encrypted protocols |

### instance — 0 trivy + 5 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_TC_13 | — | general security | tencentcloud_instance | Ensure Tencent Cloud CVM user data does not contain sensitive in |
| checkov | CKV_TC_2 | — | networking | tencentcloud_instance | Ensure Tencent Cloud CVM instance does not allocate a public IP |
| checkov | CKV_TC_3 | — | logging | tencentcloud_instance | Ensure Tencent Cloud CVM monitor service is enabled |
| checkov | CKV_TC_4 | — | networking | tencentcloud_instance | Ensure Tencent Cloud CVM instances do not use the default securi |
| checkov | CKV_TC_5 | — | networking | tencentcloud_instance | Ensure Tencent Cloud CVM instances do not use the default VPC |

### kubernetes — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_TC_6 | — | logging | tencentcloud_kubernetes_cluster | Ensure Tencent Cloud TKE clusters enable log agent |
| checkov | CKV_TC_7 | — | networking | tencentcloud_kubernetes_cluster | Ensure Tencent Cloud TKE cluster is not assigned a public IP add |

### mysql — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_TC_10 | — | networking | tencentcloud_mysql_instance | Ensure Tencent Cloud MySQL instances intranet ports are not set  |
| checkov | CKV_TC_9 | — | networking | tencentcloud_mysql_instance | Ensure Tencent Cloud mysql instances do not enable access from p |

### security — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_TC_8 | — | networking | tencentcloud_security_group_rule_set | Ensure Tencent Cloud VPC security group rules do not accept all  |

### vpc — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_TC_14 | — | networking | tencentcloud_vpc_flow_log_config | Ensure Tencent Cloud VPC flow logs are enabled |

