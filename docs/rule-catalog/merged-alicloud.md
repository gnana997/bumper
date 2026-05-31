# Merged ALICLOUD catalog — Trivy + Checkov (porting worklist)

36 checks grouped by **service**, so a Trivy check and the Checkov check(s) for the same intent sit together — port ONE bumper rule per intent, citing both ids in provenance. Trivy supplies severity; Checkov (OSS) does not (assign at port time). The `resource` column is the Terraform type to write the rule against.

### actiontrail — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_ALI_4 | — | logging | alicloud_actiontrail_trail | Ensure Action Trail Logging for all regions |
| checkov | CKV_ALI_5 | — | logging | alicloud_actiontrail_trail | Ensure Action Trail Logging for all events |

### alb — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_ALI_29 | — | networking | alicloud_alb_acl_entry_attachment | Alibaba ALB ACL does not restrict Access |

### api — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_ALI_21 | — | networking | alicloud_api_gateway_api | Ensure API Gateway API Protocol HTTPS |

### cs — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_ALI_26 | — | kubernetes | alicloud_cs_kubernetes | Ensure Kubernetes installs plugin Terway or Flannel to support s |
| checkov | CKV_ALI_31 | — | kubernetes | alicloud_cs_kubernetes_node_pool | Ensure K8s nodepools are set to auto repair |

### db — 0 trivy + 5 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_ALI_20 | — | networking | alicloud_db_instance | Ensure RDS instance uses SSL |
| checkov | CKV_ALI_22 | — | logging | alicloud_db_instance | Ensure Transparent Data Encryption is Enabled on instance |
| checkov | CKV_ALI_25 | — | logging | alicloud_db_instance | Ensure RDS Instance SQL Collector Retention Period should be gre |
| checkov | CKV_ALI_30 | — | general security | alicloud_db_instance | Ensure RDS instance auto upgrades for minor versions |
| checkov | CKV_ALI_9 | — | encryption | alicloud_db_instance | Ensure database instance is not public |

### disk — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_ALI_7 | — | encryption | alicloud_disk | Ensure disk is encrypted |
| checkov | CKV_ALI_8 | — | encryption | alicloud_disk | Ensure Disk is encrypted with Customer Master Key |

### ecs — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_ALI_32 | — | encryption | alicloud_ecs_launch_template | Ensure launch template data disks are encrypted |

### kms — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_ALI_27 | — | encryption | alicloud_kms_key | Ensure KMS Key Rotation is enabled |
| checkov | CKV_ALI_28 | — | encryption | alicloud_kms_key | Ensure KMS Keys are enabled |

### log — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_ALI_38 | — | logging | alicloud_log_audit | Ensure log audit is enabled for RDS |

### mongodb — 0 trivy + 4 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_ALI_41 | — | networking | alicloud_mongodb_instance | Ensure MongoDB is deployed inside a VPC |
| checkov | CKV_ALI_42 | — | networking | alicloud_mongodb_instance | Ensure Mongodb instance uses SSL |
| checkov | CKV_ALI_43 | — | networking | alicloud_mongodb_instance | Ensure MongoDB instance is not public |
| checkov | CKV_ALI_44 | — | encryption | alicloud_mongodb_instance | Ensure MongoDB has Transparent Data Encryption Enabled |

### oss — 0 trivy + 5 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_ALI_1 | — | general security | alicloud_oss_bucket, alicloud_oss_bucket | Alibaba Cloud OSS bucket accessible to public |
| checkov | CKV_ALI_10 | — | general security | alicloud_oss_bucket | Ensure OSS bucket has versioning enabled |
| checkov | CKV_ALI_11 | — | general security | alicloud_oss_bucket | Ensure OSS bucket has transfer Acceleration enabled |
| checkov | CKV_ALI_12 | — | logging | alicloud_oss_bucket | Ensure the OSS bucket has access logging enabled |
| checkov | CKV_ALI_6 | — | encryption | alicloud_oss_bucket | Ensure OSS bucket is encrypted with Customer Master Key |

### ram — 0 trivy + 9 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_ALI_13 | — | iam | alicloud_ram_account_password_policy | Ensure RAM password policy requires minimum length of 14 or grea |
| checkov | CKV_ALI_14 | — | iam | alicloud_ram_account_password_policy | Ensure RAM password policy requires at least one number |
| checkov | CKV_ALI_15 | — | iam | alicloud_ram_account_password_policy | Ensure RAM password policy requires at least one symbol |
| checkov | CKV_ALI_16 | — | iam | alicloud_ram_account_password_policy | Ensure RAM password policy expires passwords within 90 days or l |
| checkov | CKV_ALI_17 | — | iam | alicloud_ram_account_password_policy | Ensure RAM password policy requires at least one lowercase lette |
| checkov | CKV_ALI_18 | — | iam | alicloud_ram_account_password_policy | Ensure RAM password policy prevents password reuse |
| checkov | CKV_ALI_19 | — | iam | alicloud_ram_account_password_policy | Ensure RAM password policy requires at least one uppercase lette |
| checkov | CKV_ALI_23 | — | iam | alicloud_ram_account_password_policy | Ensure Ram Account Password Policy Max Login Attempts not > 5 |
| checkov | CKV_ALI_24 | — | iam | alicloud_ram_security_preference | Ensure RAM enforces MFA |

### slb — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_ALI_33 | — | networking | alicloud_slb_tls_cipher_policy | Alibaba Cloud Cypher Policy are secure |

