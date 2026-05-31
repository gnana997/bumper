# Merged KUBERNETES catalog — Trivy + Checkov (porting worklist)

43 checks grouped by **service**, so a Trivy check and the Checkov check(s) for the same intent sit together — port ONE bumper rule per intent, citing both ids in provenance. Trivy supplies severity; Checkov (OSS) does not (assign at port time). The `resource` column is the Terraform type to write the rule against.

### kubernetes — 0 trivy + 41 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_K8S_1 | — | general security | kubernetes_pod_security_policy | Do not admit containers wishing to share the host process ID nam |
| checkov | CKV_K8S_10 | — | general security | kubernetes_pod, kubernetes_pod_v1, kuber | CPU requests should be set |
| checkov | CKV_K8S_11 | — | general security | kubernetes_pod, kubernetes_pod_v1, kuber | CPU Limits should be set |
| checkov | CKV_K8S_12 | — | general security | kubernetes_pod, kubernetes_pod_v1, kuber | Memory Limits should be set |
| checkov | CKV_K8S_13 | — | general security | kubernetes_pod, kubernetes_pod_v1, kuber | Memory requests should be set |
| checkov | CKV_K8S_14 | — | general security | kubernetes_pod, kubernetes_pod_v1, kuber | Image Tag should be fixed - not latest or blank |
| checkov | CKV_K8S_15 | — | general security | kubernetes_pod, kubernetes_pod_v1, kuber | Image Pull Policy should be Always |
| checkov | CKV_K8S_159 | — | general security | kubernetes_pod, kubernetes_pod_v1, kuber | Do not admit privileged containers |
| checkov | CKV_K8S_16 | — | general security | kubernetes_pod, kubernetes_pod_v1, kuber | Do not admit privileged containers |
| checkov | CKV_K8S_17 | — | general security | kubernetes_pod, kubernetes_pod_v1, kuber | Do not admit containers wishing to share the host process ID nam |
| checkov | CKV_K8S_18 | — | general security | kubernetes_pod, kubernetes_pod_v1, kuber | Do not admit containers wishing to share the host IPC namespace |
| checkov | CKV_K8S_19 | — | networking | kubernetes_pod, kubernetes_pod_v1, kuber | Do not admit containers wishing to share the host network namesp |
| checkov | CKV_K8S_2 | — | general security | kubernetes_pod_security_policy | Do not admit privileged containers |
| checkov | CKV_K8S_20 | — | general security | kubernetes_pod, kubernetes_pod_v1, kuber | Containers should not run with allowPrivilegeEscalation |
| checkov | CKV_K8S_21 | — | general security | kubernetes_pod, kubernetes_pod_v1, kuber | The default namespace should not be used |
| checkov | CKV_K8S_22 | — | general security | kubernetes_pod, kubernetes_pod_v1, kuber | Use read-only filesystem for containers where possible |
| checkov | CKV_K8S_24 | — | general security | kubernetes_pod_security_policy | Do not allow containers with added capability |
| checkov | CKV_K8S_25 | — | general security | kubernetes_pod, kubernetes_pod_v1, kuber | Minimize the admission of containers with added capability |
| checkov | CKV_K8S_26 | — | general security | kubernetes_pod, kubernetes_pod_v1, kuber | Do not specify hostPort unless absolutely necessary |
| checkov | CKV_K8S_27 | — | networking | kubernetes_pod, kubernetes_pod_v1, kuber | Do not expose the docker daemon socket to containers |
| checkov | CKV_K8S_28 | — | general security | kubernetes_pod, kubernetes_pod_v1, kuber | Minimize the admission of containers with the NET_RAW capability |
| checkov | CKV_K8S_29 | — | general security | kubernetes_pod, kubernetes_pod_v1, kuber | Apply security context to your pods, deployments and daemon_sets |
| checkov | CKV_K8S_3 | — | general security | kubernetes_pod_security_policy | Do not admit containers wishing to share the host IPC namespace |
| checkov | CKV_K8S_30 | — | general security | kubernetes_pod, kubernetes_pod_v1, kuber | Apply security context to your pods and containers |
| checkov | CKV_K8S_32 | — | general security | kubernetes_pod_security_policy | Ensure default seccomp profile set to docker/default or runtime/ |
| checkov | CKV_K8S_34 | — | general security | kubernetes_pod, kubernetes_pod_v1, kuber | Ensure that Tiller (Helm v2) is not deployed |
| checkov | CKV_K8S_35 | — | general security | kubernetes_pod, kubernetes_pod_v1, kuber | Prefer using secrets as files over secrets as environment variab |
| checkov | CKV_K8S_36 | — | general security | kubernetes_pod_security_policy | Minimise the admission of containers with capabilities assigned |
| checkov | CKV_K8S_37 | — | general security | kubernetes_pod, kubernetes_pod_v1, kuber | Minimise the admission of containers with capabilities assigned |
| checkov | CKV_K8S_39 | — | general security | kubernetes_pod, kubernetes_pod_v1, kuber | Do not use the CAP_SYS_ADMIN linux capability |
| checkov | CKV_K8S_4 | — | networking | kubernetes_pod_security_policy | Do not admit containers wishing to share the host network namesp |
| checkov | CKV_K8S_41 | — | general security | kubernetes_service_account, kubernetes_s | Ensure that default service accounts are not actively used |
| checkov | CKV_K8S_42 | — | general security | kubernetes_role_binding, kubernetes_role | Ensure that default service accounts are not actively used |
| checkov | CKV_K8S_43 | — | general security | kubernetes_pod, kubernetes_pod_v1, kuber | Image should use digest |
| checkov | CKV_K8S_44 | — | general security | kubernetes_service, kubernetes_service_v | Ensure that the Tiller Service (Helm v2) is deleted |
| checkov | CKV_K8S_49 | — | iam | kubernetes_role, kubernetes_role_v1, kub | Minimize wildcard use in Roles and ClusterRoles |
| checkov | CKV_K8S_5 | — | general security | kubernetes_pod_security_policy | Containers should not run with allowPrivilegeEscalation |
| checkov | CKV_K8S_6 | — | general security | kubernetes_pod_security_policy | Do not admit root containers |
| checkov | CKV_K8S_7 | — | general security | kubernetes_pod_security_policy | Do not admit containers with the NET_RAW capability |
| checkov | CKV_K8S_8 | — | general security | kubernetes_pod, kubernetes_pod_v1, kuber | Liveness Probe Should be Configured |
| checkov | CKV_K8S_9 | — | general security | kubernetes_pod, kubernetes_pod_v1, kuber | Readiness Probe Should be Configured |

### network — 2 trivy + 0 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | KUBE-0001 | high | — | — | A network policy should not allow unrestricted ingress from any  |
| trivy | KUBE-0002 | high | — | — | A network policy should not allow unrestricted egress to any IP  |

