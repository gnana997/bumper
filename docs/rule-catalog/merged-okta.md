# Merged OKTA catalog — Trivy + Checkov (porting worklist)

1 checks grouped by **service**, so a Trivy check and the Checkov check(s) for the same intent sit together — port ONE bumper rule per intent, citing both ids in provenance. Trivy supplies severity; Checkov (OSS) does not (assign at port time). The `resource` column is the Terraform type to write the rule against.

### app — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_OKTA_1 | — | iam | okta_app_signon_policy_rule | Ensure 2FA is enabled for an Okta application signon policy rule |

