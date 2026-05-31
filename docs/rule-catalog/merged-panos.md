# Merged PANOS catalog — Trivy + Checkov (porting worklist)

15 checks grouped by **service**, so a Trivy check and the Checkov check(s) for the same intent sit together — port ONE bumper rule per intent, citing both ids in provenance. Trivy supplies severity; Checkov (OSS) does not (assign at port time). The `resource` column is the Terraform type to write the rule against.

### (unmapped) — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_PAN_1 | — | secrets | — | Ensure no hard coded PAN-OS credentials exist in provider |

### ipsec — 0 trivy + 3 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_PAN_11 | — | networking | panos_ipsec_crypto_profile, panos_panora | Ensure IPsec profiles do not specify use of insecure encryption  |
| checkov | CKV_PAN_12 | — | networking | panos_ipsec_crypto_profile, panos_panora | Ensure IPsec profiles do not specify use of insecure authenticat |
| checkov | CKV_PAN_13 | — | networking | panos_ipsec_crypto_profile, panos_panora | Ensure IPsec profiles do not specify use of insecure protocols |

### management — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_PAN_2 | — | networking | panos_management_profile | Ensure plain-text management HTTP is not enabled for an Interfac |
| checkov | CKV_PAN_3 | — | networking | panos_management_profile | Ensure plain-text management Telnet is not enabled for an Interf |

### security — 0 trivy + 7 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_PAN_10 | — | networking | panos_security_policy, panos_security_ru | Ensure logging at session end is enabled within security policie |
| checkov | CKV_PAN_4 | — | networking | panos_security_policy, panos_security_ru | Ensure DSRI is not enabled within security policies |
| checkov | CKV_PAN_5 | — | networking | panos_security_policy, panos_security_ru | Ensure security rules do not have 'applications' set to 'any'  |
| checkov | CKV_PAN_6 | — | networking | panos_security_policy, panos_security_ru | Ensure security rules do not have 'services' set to 'any'  |
| checkov | CKV_PAN_7 | — | networking | panos_security_policy, panos_security_ru | Ensure security rules do not have 'source_addresses' and 'destin |
| checkov | CKV_PAN_8 | — | networking | panos_security_policy, panos_security_ru | Ensure description is populated within security policies |
| checkov | CKV_PAN_9 | — | networking | panos_security_policy, panos_security_ru | Ensure a Log Forwarding Profile is selected for each security po |

### zone — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_PAN_14 | — | networking | panos_zone, panos_zone_entry, panos_pano | Ensure a Zone Protection Profile is defined within Security Zone |
| checkov | CKV_PAN_15 | — | networking | panos_zone, panos_panorama_zone | Ensure an Include ACL is defined for a Zone when User-ID is enab |

