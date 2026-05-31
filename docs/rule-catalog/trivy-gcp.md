# Trivy GCP check catalog (porting worklist)

75 checks harvested from trivy-checks (Apache-2.0). Logic is hand-ported to bumper's plan-JSON + CEL model.

| id | service | severity | cis | title |
|---|---|---|---|---|
| GCP-0046 | bigquery | critical | - | BigQuery datasets should only be accessible within the organisation |
| GCP-0027 | compute | critical | - | A firewall rule should not allow unrestricted ingress from any IP address. |
| GCP-0035 | compute | critical | - | A firewall rule should not allow unrestricted egress to any IP address. |
| GCP-0037 | compute | critical | - | The encryption key used to encrypt a compute disk has been specified in plaintex |
| GCP-0039 | compute | critical | - | SSL policies should enforce secure versions of TLS |
| GCP-0044 | compute | critical | - | Instances should not use the default service account |
| GCP-0031 | compute | high | - | Instances should not have public IP addresses |
| GCP-0043 | compute | high | - | Instances should not have IP forwarding enabled |
| GCP-0070 | compute | high | - | RDP Access Is Not Restricted |
| GCP-0048 | gke | high | - | Legacy metadata endpoints enabled. |
| GCP-0053 | gke | high | - | GKE Control Plane should not be publicly accessible |
| GCP-0055 | gke | high | - | Shielded GKE nodes not enabled. |
| GCP-0057 | gke | high | - | Node metadata value disables metadata concealment. |
| GCP-0061 | gke | high | - | Master authorized networks should be configured on GKE clusters |
| GCP-0062 | gke | high | - | Legacy ABAC permissions are enabled. |
| GCP-0064 | gke | high | - | Legacy client authentication methods utilized. |
| GCP-0007 | iam | high | - | Service accounts should not have roles assigned with excessive privileges |
| GCP-0010 | iam | high | - | Default network should not be created at project level |
| GCP-0068 | iam | high | - | A configuration for an external workload identity pool provider should have cond |
| GCP-0065 | kms | high | - | KMS keys should be rotated at least every 90 days |
| GCP-0015 | sql | high | - | SSL connections to a SQL database instance should be enforced. |
| GCP-0017 | sql | high | - | Ensure that Cloud SQL Database Instances are not publicly exposed |
| GCP-0026 | sql | high | - | Disable local_infile setting in MySQL |
| GCP-0001 | storage | high | - | Ensure that Cloud Storage bucket is not anonymously or publicly accessible. |
| GCP-0030 | compute | medium | - | Disable project-wide SSH keys for all instances |
| GCP-0032 | compute | medium | - | Disable serial port connectivity for all instances |
| GCP-0036 | compute | medium | - | Instances should not override the project setting for OS Login |
| GCP-0041 | compute | medium | - | Instances should have Shielded VM VTPM enabled |
| GCP-0042 | compute | medium | - | OS Login should be enabled at project level |
| GCP-0045 | compute | medium | - | Instances should have Shielded VM integrity monitoring enabled |
| GCP-0067 | compute | medium | - | Instances should have Shielded VM secure boot enabled |
| GCP-0071 | compute | medium | - | SSH Access Is Not Restricted |
| GCP-0072 | compute | medium | - | Google Compute Network Using Firewall Rule that Allows All Ports |
| GCP-0073 | compute | medium | - | Disable Default Firewall Rules |
| GCP-0076 | compute | medium | - | Google Compute Subnetwork Logging Disabled |
| GCP-0012 | dns | medium | - | Zone signing should not use RSA SHA1 |
| GCP-0013 | dns | medium | - | Cloud DNS should use DNSSEC |
| GCP-0050 | gke | medium | - | Checks for service account defined for GKE nodes |
| GCP-0056 | gke | medium | - | Network Policy should be enabled on GKE clusters |
| GCP-0059 | gke | medium | - | Clusters should be set to private |
| GCP-0003 | iam | medium | - | IAM granted directly to user. |
| GCP-0004 | iam | medium | - | Roles should not be assigned to default service accounts |
| GCP-0005 | iam | medium | - | Users should not be granted service account access at the folder level |
| GCP-0006 | iam | medium | - | Roles should not be assigned to default service accounts |
| GCP-0008 | iam | medium | - | Roles should not be assigned to default service accounts |
| GCP-0009 | iam | medium | - | Users should not be granted service account access at the organization level |
| GCP-0011 | iam | medium | - | Users should not be granted service account access at the project level |
| GCP-0014 | sql | medium | - | Temporary file logging should be enabled for all temporary files. |
| GCP-0016 | sql | medium | - | Ensure that logging of connections is enabled. |
| GCP-0019 | sql | medium | - | Cross-database ownership chaining should be disabled |
| GCP-0020 | sql | medium | - | Ensure that logging of lock waits is enabled. |
| GCP-0022 | sql | medium | - | Ensure that logging of disconnections is enabled. |
| GCP-0023 | sql | medium | - | Contained database authentication should be disabled |
| GCP-0024 | sql | medium | - | Enable automated backups to recover from data-loss |
| GCP-0025 | sql | medium | - | Ensure that logging of checkpoints is enabled. |
| GCP-0002 | storage | medium | - | Ensure that Cloud Storage buckets have uniform bucket-level access enabled |
| GCP-0077 | storage | medium | - | Cloud Storage Bucket Logging Not Enabled |
| GCP-0078 | storage | medium | - | Cloud Storage Bucket Versioning Disabled |
| GCP-0029 | compute | low | - | VPC flow logs should be enabled for all subnetworks |
| GCP-0033 | compute | low | - | VM disks should be encrypted with Customer Supplied Encryption Keys |
| GCP-0034 | compute | low | - | Disks should be encrypted with customer managed encryption keys |
| GCP-0074 | compute | low | - | Google Compute Network Using Firewall Rule that Allows Large Port Range |
| GCP-0075 | compute | low | - | Google Compute Subnetwork with Private Google Access Disabled |
| GCP-0049 | gke | low | - | Clusters should have IP aliasing enabled |
| GCP-0051 | gke | low | - | Clusters should be configured with Labels |
| GCP-0052 | gke | low | - | Stackdriver Monitoring should be enabled |
| GCP-0054 | gke | low | - | Ensure Container-Optimized OS (cos) is used for Kubernetes Engine Clusters Node  |
| GCP-0058 | gke | low | - | Kubernetes should have 'Automatic upgrade' enabled |
| GCP-0060 | gke | low | - | Stackdriver Logging should be enabled |
| GCP-0063 | gke | low | - | Kubernetes should have 'Automatic repair' enabled |
| GCP-0069 | iam | low | - | Not Proper Email Account In Use |
| GCP-0079 | iam | low | - | IAM Audit Not Properly Configured |
| GCP-0018 | sql | low | - | Ensure that Postgres errors are logged |
| GCP-0021 | sql | low | - | Ensure that logging of long statements is disabled. |
| GCP-0066 | storage | low | - | Cloud Storage buckets should be encrypted with a customer-managed key. |
