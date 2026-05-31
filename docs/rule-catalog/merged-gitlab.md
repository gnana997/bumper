# Merged GITLAB catalog — Trivy + Checkov (porting worklist)

4 checks grouped by **service**, so a Trivy check and the Checkov check(s) for the same intent sit together — port ONE bumper rule per intent, citing both ids in provenance. Trivy supplies severity; Checkov (OSS) does not (assign at port time). The `resource` column is the Terraform type to write the rule against.

### branch — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_GLB_2 | — | general security | gitlab_branch_protection | Ensure GitLab branch protection rules does not allow force pushe |

### project — 0 trivy + 3 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_GLB_1 | — | general security | gitlab_project | Ensure at least two approving reviews are required to merge a Gi |
| checkov | CKV_GLB_3 | — | secrets | gitlab_project | Ensure GitLab prevent secrets is enabled |
| checkov | CKV_GLB_4 | — | general security | gitlab_project | Ensure GitLab commits are signed |

