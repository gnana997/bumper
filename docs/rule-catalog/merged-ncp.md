# Merged NCP catalog — Trivy + Checkov (porting worklist)

19 checks grouped by **service**, so a Trivy check and the Checkov check(s) for the same intent sit together — port ONE bumper rule per intent, citing both ids in provenance. Trivy supplies severity; Checkov (OSS) does not (assign at port time). The `resource` column is the Terraform type to write the rule against.

### (unmapped) — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_NCP_17 | — | secrets | — | Ensure no hard coded NCP access key and secret key exists in pro |

### access — 0 trivy + 3 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_NCP_2 | — | networking | ncloud_access_control_group, ncloud_acce | Ensure every access control groups rule has a description |
| checkov | CKV_NCP_26 | — | networking | ncloud_access_control_group | Ensure Access Control Group has Access Control Group Rule attach |
| checkov | CKV_NCP_3 | — | networking | ncloud_access_control_group_rule | Ensure no security group rules allow outbound traffic to 0.0.0.0 |

### auto — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_NCP_18 | — | networking | ncloud_auto_scaling_group, ncloud_lb_tar | Ensure that auto Scaling groups that are associated with a load  |

### launch — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_NCP_7 | — | encryption | ncloud_launch_configuration | Ensure Basic Block storage is encrypted. |

### lb — 0 trivy + 5 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_NCP_1 | — | general security | ncloud_lb_target_group | Ensure HTTP HTTPS Target group defines Healthcheck |
| checkov | CKV_NCP_13 | — | networking | ncloud_lb_listener | Ensure LB Listener uses only secure protocols |
| checkov | CKV_NCP_15 | — | general security | ncloud_lb_target_group | Ensure Load Balancer Target Group is not using HTTP |
| checkov | CKV_NCP_16 | — | networking | ncloud_lb | Ensure Load Balancer isn't exposed to the internet |
| checkov | CKV_NCP_24 | — | general security | ncloud_lb_listener | Ensure Load Balancer Listener Using HTTPS |

### nas — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_NCP_14 | — | encryption | ncloud_nas_volume | Ensure NAS is securely encrypted |

### network — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_NCP_12 | — | networking | ncloud_network_acl_rule | An inbound Network ACL rule should not allow ALL ports. |

### nks — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_NCP_19 | — | kubernetes | ncloud_nks_cluster | Ensure Naver Kubernetes Service public endpoint disabled |
| checkov | CKV_NCP_22 | — | kubernetes | ncloud_nks_cluster | Ensure NKS control plane logging enabled for all log types |

### public — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_NCP_23 | — | networking | ncloud_public_ip | Ensure Server instance should not have public IP. |

### route — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_NCP_20 | — | networking | ncloud_route | Ensure Routing Table associated with Web tier subnet have the de |
| checkov | CKV_NCP_22 | — | networking | ncloud_route_table, ncloud_subnet | Ensure a route table for the public subnets is created. |

### server — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_NCP_6 | — | encryption | ncloud_server | Ensure Server instance is encrypted. |

