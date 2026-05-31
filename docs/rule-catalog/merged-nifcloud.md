# Merged NIFCLOUD catalog — Trivy + Checkov (porting worklist)

21 checks grouped by **service**, so a Trivy check and the Checkov check(s) for the same intent sit together — port ONE bumper rule per intent, citing both ids in provenance. Trivy supplies severity; Checkov (OSS) does not (assign at port time). The `resource` column is the Terraform type to write the rule against.

### computing — 5 trivy + 0 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | NIF-0001 | critical | — | — | A security group rule should not allow unrestricted ingress from |
| trivy | NIF-0004 | critical | — | — | Missing security group for instance. |
| trivy | NIF-0002 | low | — | — | Missing description for security group. |
| trivy | NIF-0003 | low | — | — | Missing description for security group rule. |
| trivy | NIF-0005 | low | — | — | The instance has common private network |

### dns — 1 trivy + 0 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | NIF-0007 | critical | — | — | Delete verified record |

### nas — 3 trivy + 0 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | NIF-0014 | critical | — | — | A security group rule should not allow unrestricted ingress from |
| trivy | NIF-0013 | low | — | — | The nas instance has common private network |
| trivy | NIF-0015 | low | — | — | Missing description for nas security group. |

### network — 6 trivy + 0 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | NIF-0016 | critical | — | — | Missing security group for router. |
| trivy | NIF-0018 | critical | — | — | Missing security group for vpnGateway. |
| trivy | NIF-0020 | critical | — | — | An outdated SSL policy is in use by a load balancer. |
| trivy | NIF-0021 | critical | — | — | Use of plain HTTP. |
| trivy | NIF-0017 | low | — | — | The router has common private network |
| trivy | NIF-0019 | low | — | — | The elb has common private network |

### rdb — 5 trivy + 0 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | NIF-0008 | critical | — | — | A database resource is marked as publicly accessible. |
| trivy | NIF-0011 | critical | — | — | A security group rule should not allow unrestricted ingress traf |
| trivy | NIF-0009 | medium | — | — | RDB instance should have backup retention longer than 1 day |
| trivy | NIF-0010 | low | — | — | The db instance has common private network |
| trivy | NIF-0012 | low | — | — | Missing description for db security group. |

### ssl_certificate — 1 trivy + 0 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | NIF-0006 | low | — | — | Delete expired SSL certificates |

