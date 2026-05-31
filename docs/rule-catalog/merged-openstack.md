# Merged OPENSTACK catalog — Trivy + Checkov (porting worklist)

8 checks grouped by **service**, so a Trivy check and the Checkov check(s) for the same intent sit together — port ONE bumper rule per intent, citing both ids in provenance. Trivy supplies severity; Checkov (OSS) does not (assign at port time). The `resource` column is the Terraform type to write the rule against.

### (unmapped) — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_OPENSTACK_1 | — | secrets | — | Ensure no hard coded OpenStack password, token, or application_c |

### compute — 2 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | OPNSTK-0001 | medium | — | — | No plaintext password for compute instance |
| trivy | OPNSTK-0002 | medium | — | — | A firewall rule allows traffic from/to the public internet |
| checkov | CKV_OPENSTACK_4 | — | secrets | openstack_compute_instance_v2 | Ensure that instance does not use basic credentials |

### fw — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_OPENSTACK_5 | — | networking | openstack_fw_rule_v1 | Ensure firewall rule set a destination IP |

### networking — 3 trivy + 0 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | OPNSTK-0003 | medium | — | — | A security group rule allows ingress traffic from multiple publi |
| trivy | OPNSTK-0004 | medium | — | — | A security group rule allows egress traffic to multiple public a |
| trivy | OPNSTK-0005 | medium | — | — | Missing description for security group. |

