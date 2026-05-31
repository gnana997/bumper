# Merged CLOUDSTACK catalog — Trivy + Checkov (porting worklist)

1 checks grouped by **service**, so a Trivy check and the Checkov check(s) for the same intent sit together — port ONE bumper rule per intent, citing both ids in provenance. Trivy supplies severity; Checkov (OSS) does not (assign at port time). The `resource` column is the Terraform type to write the rule against.

### compute — 1 trivy + 0 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | CLDSTK-0001 | high | — | — | No sensitive data stored in user_data |

