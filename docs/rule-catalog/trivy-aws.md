# Trivy AWS check catalog (porting worklist)

175 checks harvested from trivy-checks (Apache-2.0). Logic is hand-ported to bumper's plan-JSON + CEL model.

| id | service | severity | cis | title |
|---|---|---|---|---|
| AWS-0012 | cloudfront | critical | - | CloudFront distribution allows unencrypted (HTTP) communications. |
| AWS-0161 | cloudtrail | critical | 1.2,1.4 | The S3 Bucket backing Cloudtrail should be private |
| AWS-0029 | ec2 | critical | - | User data for EC2 instances must not contain sensitive AWS keys |
| AWS-0102 | ec2 | critical | - | An Network ACL rule allows ALL ports. |
| AWS-0104 | ec2 | critical | - | A security group rule should not allow unrestricted egress to any IP address. |
| AWS-0129 | ec2 | critical | - | User data for EC2 instances must not contain sensitive AWS keys |
| AWS-0036 | ecs | critical | - | Task definition defines sensitive environment variable(s). |
| AWS-0040 | eks | critical | - | EKS Clusters should have the public access disabled |
| AWS-0041 | eks | critical | - | EKS cluster should not have open CIDR range for public access |
| AWS-0046 | elasticsearch | critical | - | Elasticsearch doesn't enforce HTTPS traffic. |
| AWS-0047 | elb | critical | - | An outdated SSL policy is in use by a load balancer. |
| AWS-0054 | elb | critical | - | Use of plain HTTP. |
| AWS-0141 | iam | critical | 1.2,1.4 | The root user has complete access to all services and resources in an AWS accoun |
| AWS-0142 | iam | critical | 1.2,1.4 | The "root" account has unrestricted access to all resources in the AWS account.  |
| AWS-0067 | lambda | critical | - | Ensure that lambda function permission has a source arn specified |
| AWS-0085 | redshift | critical | - | AWS Classic resource usage. |
| AWS-0134 | ssm | critical | - | Secrets should not be exfiltrated using Terraform HTTP data blocks |
| AWS-0005 | apigateway | high | - | API Gateway domain name uses outdated SSL/TLS protocols. |
| AWS-0006 | athena | high | - | Athena databases and workgroup configurations are created unencrypted at rest by |
| AWS-0007 | athena | high | - | Athena workgroups should enforce configuration to prevent client disabling encry |
| AWS-0011 | cloudfront | high | - | CloudFront distribution does not have a WAF in front. |
| AWS-0013 | cloudfront | high | - | CloudFront distribution uses outdated SSL/TLS protocols. |
| AWS-0015 | cloudtrail | high | - | CloudTrail should use Customer managed keys to encrypt the logs |
| AWS-0016 | cloudtrail | high | - | Cloudtrail log validation should be enabled to prevent tampering of log data |
| AWS-0018 | codebuild | high | - | CodeBuild Project artifacts encryption should not be disabled |
| AWS-0019 | config | high | - | Config configuration aggregator should be using all regions for source |
| AWS-0021 | documentdb | high | - | DocumentDB storage must be encrypted |
| AWS-0023 | dynamodb | high | - | DAX Cluster should always encrypt data at rest |
| AWS-0008 | ec2 | high | - | Launch configuration with unencrypted block device. |
| AWS-0009 | ec2 | high | - | Launch configuration should not have a public IP address. |
| AWS-0026 | ec2 | high | - | EBS volumes must be encrypted |
| AWS-0028 | ec2 | high | - | aws_instance should activate session tokens for Instance Metadata Service. |
| AWS-0101 | ec2 | high | - | AWS best practice to not use the default VPC for workflows |
| AWS-0107 | ec2 | high | 1.2 | Security groups should not allow unrestricted ingress to SSH or RDP from any IP  |
| AWS-0122 | ec2 | high | - | Ensure all data stored in the launch configuration EBS is securely encrypted |
| AWS-0130 | ec2 | high | - | aws_instance should activate session tokens for Instance Metadata Service. |
| AWS-0131 | ec2 | high | - | Instance with unencrypted block device. |
| AWS-0164 | ec2 | high | - | Instances in a subnet should not receive a public IP address by default. |
| AWS-0030 | ecr | high | - | ECR repository has image scans disabled. |
| AWS-0031 | ecr | high | - | ECR images tags shouldn't be mutable. |
| AWS-0032 | ecr | high | - | ECR repository policy must block public access |
| AWS-0035 | ecs | high | - | ECS Task Definitions with EFS volumes should use in-transit encryption |
| AWS-0037 | efs | high | - | EFS Encryption has not been enabled |
| AWS-0039 | eks | high | - | EKS should have the encryption of secrets enabled |
| AWS-0045 | elasticache | high | - | Elasticache Replication Group stores unencrypted data at-rest. |
| AWS-0051 | elasticache | high | - | Elasticache Replication Group uses unencrypted traffic. |
| AWS-0043 | elasticsearch | high | - | Elasticsearch domain uses plaintext traffic for node to node communication. |
| AWS-0048 | elasticsearch | high | - | Elasticsearch domain isn't encrypted at rest. |
| AWS-0126 | elasticsearch | high | - | Elasticsearch domain endpoint is using outdated TLS policy. |
| AWS-0052 | elb | high | - | Load balancers should drop invalid headers |
| AWS-0053 | elb | high | - | Load balancer is exposed to the internet. |
| AWS-0137 | emr | high | - | Enable at-rest encryption for EMR clusters. |
| AWS-0138 | emr | high | - | Enable in-transit encryption for EMR clusters. |
| AWS-0139 | emr | high | - | Enable local-disk encryption for EMR clusters. |
| AWS-0057 | iam | high | 1.4 | IAM policy should avoid use of wildcards and instead apply the principle of leas |
| AWS-0345 | iam | high | - | Disallow unrestricted S3 IAM Policies |
| AWS-0346 | iam | high | - | Reduce unnecessary unauthorized access or information disclosure of S3 buckets. |
| AWS-0064 | kinesis | high | - | Kinesis stream is unencrypted. |
| AWS-0072 | mq | high | - | Ensure MQ Broker is not publicly exposed |
| AWS-0073 | msk | high | - | A MSK cluster allows unencrypted data in transit. |
| AWS-0179 | msk | high | - | A MSK cluster allows unencrypted data at rest. |
| AWS-0076 | neptune | high | - | Neptune storage must be encrypted at rest |
| AWS-0128 | neptune | high | - | Neptune encryption should use Customer Managed Keys |
| AWS-0079 | rds | high | - | There is no encryption specified or encryption is disabled on the RDS Cluster. |
| AWS-0080 | rds | high | - | RDS encryption has not been enabled at a DB Instance level. |
| AWS-0180 | rds | high | - | RDS Publicly Accessible |
| AWS-0084 | redshift | high | - | Redshift clusters should use at rest encryption |
| AWS-0127 | redshift | high | - | Redshift cluster should be deployed into a specific VPC |
| AWS-0086 | s3 | high | - | S3 Access block should block public ACL |
| AWS-0087 | s3 | high | - | S3 Access block should block public policy |
| AWS-0088 | s3 | high | - | Unencrypted S3 bucket. |
| AWS-0091 | s3 | high | - | S3 Access Block should Ignore Public ACL |
| AWS-0092 | s3 | high | - | S3 Buckets not publicly accessible through ACL. |
| AWS-0093 | s3 | high | - | S3 Access block should restrict public bucket to limit access |
| AWS-0132 | s3 | high | - | S3 encryption should use Customer Managed Keys |
| AWS-0112 | sam | high | - | SAM API domain name uses outdated SSL/TLS protocols. |
| AWS-0114 | sam | high | - | Function policies should avoid use of wildcards and instead apply the principle  |
| AWS-0120 | sam | high | - | State machine policies should avoid use of wildcards and instead apply the princ |
| AWS-0121 | sam | high | - | SAM Simple table must have server side encryption enabled. |
| AWS-0095 | sns | high | - | Unencrypted SNS topic. |
| AWS-0136 | sns | high | - | SNS topic not encrypted with CMK. |
| AWS-0096 | sqs | high | - | Unencrypted SQS queue. |
| AWS-0097 | sqs | high | - | AWS SQS policy document has wildcard action statement. |
| AWS-0135 | sqs | high | - | SQS queue should be encrypted with a CMK. |
| AWS-0109 | workspaces | high | - | Root and user volumes on Workspaces should be encrypted |
| AWS-0001 | apigateway | medium | - | API Gateway stages for V1 and V2 should have access logging enabled |
| AWS-0002 | apigateway | medium | - | API Gateway must have cache enabled |
| AWS-0010 | cloudfront | medium | - | Cloudfront distribution should have Access Logging configured |
| AWS-0014 | cloudtrail | medium | 1.2 | Cloudtrail should be enabled in all regions regardless of where your AWS resourc |
| AWS-0020 | documentdb | medium | - | DocumentDB logs export should be enabled |
| AWS-0024 | dynamodb | medium | - | Point in time recovery should be enabled to protect DynamoDB table |
| AWS-0105 | ec2 | medium | 1.4 | Network ACLs should not allow unrestricted ingress to SSH or RDP from any IP add |
| AWS-0178 | ec2 | medium | - | VPC Flow Logs is a feature that enables you to capture information about the IP  |
| AWS-0038 | eks | medium | - | EKS Clusters should have cluster control plane logging turned on |
| AWS-0050 | elasticache | medium | - | Redis cluster should have backup retention turned on |
| AWS-0042 | elasticsearch | medium | - | Domain logging should be enabled for Elastic Search domains |
| AWS-0056 | iam | medium | 1.2,1.4 | IAM Password policy should prevent password reuse. |
| AWS-0058 | iam | medium | 1.2 | IAM Password policy should have requirement for at least one lowercase character |
| AWS-0059 | iam | medium | 1.2 | IAM Password policy should have requirement for at least one number in the passw |
| AWS-0060 | iam | medium | 1.2 | IAM Password policy should have requirement for at least one symbol in the passw |
| AWS-0061 | iam | medium | 1.2 | IAM Password policy should have requirement for at least one uppercase character |
| AWS-0062 | iam | medium | 1.2 | IAM Password policy should have expiry less than or equal to 90 days. |
| AWS-0063 | iam | medium | 1.2,1.4 | IAM Password policy should have minimum password length of 14 or more characters |
| AWS-0123 | iam | medium | - | IAM groups should have MFA enforcement activated. |
| AWS-0144 | iam | medium | 1.2 | Credentials which are no longer used should be disabled. |
| AWS-0145 | iam | medium | 1.2,1.4 | IAM Users should have MFA enforcement activated. |
| AWS-0165 | iam | medium | 1.4 | The "root" account has unrestricted access to all resources in the AWS account.  |
| AWS-0342 | iam | medium | - | IAM Pass Role Filtering |
| AWS-0065 | kms | medium | - | A KMS key is not configured to auto-rotate. |
| AWS-0070 | mq | medium | - | MQ Broker should have audit logging enabled |
| AWS-0074 | msk | medium | - | Ensure MSK Cluster logging is enabled |
| AWS-0075 | neptune | medium | - | Neptune logs export should be enabled |
| AWS-0077 | rds | medium | - | RDS Cluster and RDS instance should have backup retention longer than default 1  |
| AWS-0176 | rds | medium | - | RDS IAM Database Authentication Disabled |
| AWS-0177 | rds | medium | - | RDS Deletion Protection Disabled |
| AWS-0343 | rds | medium | - | RDS Cluster Deletion Protection Disabled |
| AWS-0090 | s3 | medium | - | S3 Data should be versioned |
| AWS-0320 | s3 | medium | - | S3 DNS Compliant Bucket Names |
| AWS-0110 | sam | medium | - | SAM API must have data cache enabled |
| AWS-0113 | sam | medium | - | SAM API stages for V1 and V2 should have access logging enabled |
| AWS-0116 | sam | medium | - | SAM HTTP API stages for V1 and V2 should have access logging enabled |
| AWS-0175 | accessanalyzer | low | 1.4 | Enable IAM Access analyzer for IAM policies about all resources in each region. |
| AWS-0344 | ami | low | - | AWS AMI data source should specify owners |
| AWS-0003 | apigateway | low | - | API Gateway must have X-Ray tracing enabled |
| AWS-0004 | apigateway | low | - | No unauthorized access to API Gateway methods |
| AWS-0190 | apigateway | low | - | Ensure that response caching is enabled for your Amazon API Gateway REST APIs. |
| AWS-0162 | cloudtrail | low | 1.2,1.4 | CloudTrail logs should be stored in S3 and also sent to CloudWatch Logs |
| AWS-0163 | cloudtrail | low | 1.2,1.4 | You should enable bucket access logging on the CloudTrail S3 bucket. |
| AWS-0017 | cloudwatch | low | - | CloudWatch log groups should be encrypted using CMK |
| AWS-0147 | cloudwatch | low | 1.2,1.4 | Ensure a log metric filter and alarm exist for unauthorized API calls |
| AWS-0148 | cloudwatch | low | 1.2,1.4 | Ensure a log metric filter and alarm exist for AWS Management Console sign-in wi |
| AWS-0149 | cloudwatch | low | 1.2,1.4 | Ensure a log metric filter and alarm exist for usage of root user |
| AWS-0150 | cloudwatch | low | 1.2,1.4 | Ensure a log metric filter and alarm exist for IAM policy changes |
| AWS-0151 | cloudwatch | low | 1.2,1.4 | Ensure a log metric filter and alarm exist for CloudTrail configuration changes |
| AWS-0152 | cloudwatch | low | 1.2,1.4 | Ensure a log metric filter and alarm exist for AWS Management Console authentica |
| AWS-0153 | cloudwatch | low | 1.2,1.4 | Ensure a log metric filter and alarm exist for disabling or scheduled deletion o |
| AWS-0154 | cloudwatch | low | 1.2,1.4 | Ensure a log metric filter and alarm exist for S3 bucket policy changes |
| AWS-0155 | cloudwatch | low | 1.2,1.4 | Ensure a log metric filter and alarm exist for AWS Config configuration changes |
| AWS-0156 | cloudwatch | low | 1.2,1.4 | Ensure a log metric filter and alarm exist for security group changes |
| AWS-0157 | cloudwatch | low | 1.2,1.4 | Ensure a log metric filter and alarm exist for changes to Network Access Control |
| AWS-0158 | cloudwatch | low | 1.2,1.4 | Ensure a log metric filter and alarm exist for changes to network gateways |
| AWS-0159 | cloudwatch | low | 1.2,1.4 | Ensure a log metric filter and alarm exist for route table changes |
| AWS-0160 | cloudwatch | low | 1.2,1.4 | Ensure a log metric filter and alarm exist for VPC changes |
| AWS-0174 | cloudwatch | low | 1.4 | Ensure a log metric filter and alarm exist for organisation changes |
| AWS-0022 | documentdb | low | - | DocumentDB encryption should use Customer Managed Keys |
| AWS-0025 | dynamodb | low | - | DynamoDB tables should use at rest encryption with a Customer Managed Key |
| AWS-0027 | ec2 | low | - | EBS volume encryption should use Customer Managed Keys |
| AWS-0099 | ec2 | low | - | Missing description for security group. |
| AWS-0124 | ec2 | low | - | Missing description for security group rule. |
| AWS-0173 | ec2 | low | 1.4 | Default security group should restrict all traffic |
| AWS-0033 | ecr | low | - | ECR Repository should use customer managed keys to allow more control |
| AWS-0034 | ecs | low | - | ECS clusters should have container insights enabled |
| AWS-0049 | elasticache | low | - | Missing description for security group/security group rule. |
| AWS-0140 | iam | low | 1.2,1.4 | The "root" account has unrestricted access to all resources in the AWS account.  |
| AWS-0143 | iam | low | 1.2,1.4 | IAM policies should not be granted directly to users. |
| AWS-0146 | iam | low | 1.2,1.4 | Access keys should be rotated at least every 90 days |
| AWS-0166 | iam | low | 1.4 | Disabling or removing unnecessary credentials will reduce the window of opportun |
| AWS-0167 | iam | low | 1.4 | No user should have more than one active access key. |
| AWS-0168 | iam | low | 1.4 | Delete expired TLS certificates |
| AWS-0169 | iam | low | 1.4 | Missing IAM Role to allow authorized users to manage incidents with AWS Support. |
| AWS-0066 | lambda | low | - | Lambda functions should have X-Ray tracing enabled |
| AWS-0071 | mq | low | - | MQ Broker should have general logging enabled |
| AWS-0078 | rds | low | - | Performance Insights encryption should use Customer Managed Keys |
| AWS-0133 | rds | low | - | Enable Performance Insights to detect potential problems |
| AWS-0083 | redshift | low | - | Missing description for security group/security group rule. |
| AWS-0089 | s3 | low | - | S3 Bucket Logging |
| AWS-0094 | s3 | low | - | S3 buckets should each define an aws_s3_bucket_public_access_block |
| AWS-0170 | s3 | low | 1.4 | Buckets should have MFA deletion protection enabled. |
| AWS-0171 | s3 | low | 1.4 | S3 object-level API operations such as GetObject, DeleteObject, and PutObject ar |
| AWS-0172 | s3 | low | 1.4 | S3 object-level API operations such as GetObject, DeleteObject, and PutObject ar |
| AWS-0111 | sam | low | - | SAM API must have X-Ray tracing enabled |
| AWS-0117 | sam | low | - | SAM State machine must have X-Ray tracing enabled |
| AWS-0119 | sam | low | - | SAM State machine must have logging enabled |
| AWS-0125 | sam | low | - | SAM Function must have X-Ray tracing enabled |
| AWS-0098 | ssm | low | - | Secrets Manager should use customer managed keys |
