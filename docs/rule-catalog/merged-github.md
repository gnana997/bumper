# Merged GITHUB catalog — Trivy + Checkov (porting worklist)

11 checks grouped by **service**, so a Trivy check and the Checkov check(s) for the same intent sit together — port ONE bumper rule per intent, citing both ids in provenance. Trivy supplies severity; Checkov (OSS) does not (assign at port time). The `resource` column is the Terraform type to write the rule against.

### actions — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_GIT_4 | — | encryption | github_actions_environment_secret, githu | Ensure GitHub Actions secrets are encrypted |

### branch — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_GIT_5 | — | general security | github_branch_protection_v3, github_bran | GitHub pull requests should require at least 2 approvals |
| checkov | CKV_GIT_6 | — | general security | github_branch_protection_v3, github_bran | Ensure GitHub branch protection rules requires signed commits |

### branchprotections — 1 trivy + 0 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | GIT-0004 | high | — | — | GitHub branch protection does not require signed commits. |

### environmentsecrets — 1 trivy + 0 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | GIT-0002 | high | — | — | Ensure plaintext value is not used for GitHub Action Environment |

### repositories — 2 trivy + 0 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | GIT-0001 | critical | — | — | GitHub repository shouldn't be public. |
| trivy | GIT-0003 | high | — | — | GitHub repository has vulnerability alerts disabled. |

### repository — 0 trivy + 4 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_GIT_1 | — | general security | github_repository | Ensure each Repository has branch protection associated |
| checkov | CKV_GIT_1 | — | general security | github_repository | Ensure GitHub repository is Private |
| checkov | CKV_GIT_2 | — | general security | github_repository_webhook | Ensure GitHub repository webhooks are using HTTPS |
| checkov | CKV_GIT_3 | — | general security | github_repository | Ensure GitHub repository has vulnerability alerts enabled |

