# Merged DIGITALOCEAN catalog — Trivy + Checkov (porting worklist)

13 checks grouped by **service**, so a Trivy check and the Checkov check(s) for the same intent sit together — port ONE bumper rule per intent, citing both ids in provenance. Trivy supplies severity; Checkov (OSS) does not (assign at port time). The `resource` column is the Terraform type to write the rule against.

### compute — 6 trivy + 0 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | DIG-0001 | critical | — | — | A firewall rule should not allow unrestricted ingress from any I |
| trivy | DIG-0002 | critical | — | — | The load balancer forwarding rule is using an insecure protocol  |
| trivy | DIG-0003 | critical | — | — | A firewall rule should not allow unrestricted egress to any IP a |
| trivy | DIG-0008 | critical | — | — | Kubernetes clusters should be auto-upgraded to ensure that they  |
| trivy | DIG-0004 | high | — | — | SSH Keys are the preferred way to connect to your droplet, no ke |
| trivy | DIG-0005 | medium | — | — | The Kubernetes cluster does not enable surge upgrades |

### droplet — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_DIO_2 | — | general security | digitalocean_droplet | Ensure the droplet specifies an SSH key |

### firewall — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_DIO_4 | — | networking | digitalocean_firewall | Ensure the firewall ingress is not wide open |

### spaces — 3 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | DIG-0006 | critical | — | — | Spaces bucket or bucket object has public read acl set |
| trivy | DIG-0007 | medium | — | — | Spaces buckets should have versioning enabled |
| trivy | DIG-0009 | medium | — | — | Force destroy is enabled on Spaces bucket which is dangerous |
| checkov | CKV_DIO_1 | — | backup and recovery | digitalocean_spaces_bucket | Ensure the Spaces bucket has versioning enabled |
| checkov | CKV_DIO_3 | — | general security | digitalocean_spaces_bucket | Ensure the Spaces bucket is private |

