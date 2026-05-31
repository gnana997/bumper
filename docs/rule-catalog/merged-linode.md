# Merged LINODE catalog — Trivy + Checkov (porting worklist)

6 checks grouped by **service**, so a Trivy check and the Checkov check(s) for the same intent sit together — port ONE bumper rule per intent, citing both ids in provenance. Trivy supplies severity; Checkov (OSS) does not (assign at port time). The `resource` column is the Terraform type to write the rule against.

### (unmapped) — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_LIN_1 | — | secrets | — | Ensure no hard coded Linode tokens exist in provider |

### firewall — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_LIN_5 | — | general security | linode_firewall | Ensure Inbound Firewall Policy is not set to ACCEPT |
| checkov | CKV_LIN_6 | — | general security | linode_firewall | Ensure Outbound Firewall Policy is not set to ACCEPT |

### instance — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_LIN_2 | — | general security | linode_instance | Ensure SSH key set in authorized_keys |

### user — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_LIN_3 | — | general security | linode_user | Ensure email is set |
| checkov | CKV_LIN_4 | — | general security | linode_user | Ensure username is set |

