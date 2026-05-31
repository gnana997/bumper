# Merged AWS catalog — Trivy + Checkov (porting worklist)

620 checks grouped by **service**, so a Trivy check and the Checkov check(s) for the same intent sit together — port ONE bumper rule per intent, citing both ids in provenance. Trivy supplies severity; Checkov (OSS) does not (assign at port time). The `resource` column is the Terraform type to write the rule against.

### (unmapped) — 0 trivy + 13 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_107 | — | — | — | Ensure IAM policies does not allow credentials exposure |
| checkov | CKV_AWS_108 | — | — | — | Ensure IAM policies does not allow data exfiltration |
| checkov | CKV_AWS_109 | — | — | — | Ensure IAM policies does not allow permissions management / reso |
| checkov | CKV_AWS_110 | — | — | — | Ensure IAM policies does not allow privilege escalation |
| checkov | CKV_AWS_111 | — | — | — | Ensure IAM policies does not allow write access without constrai |
| checkov | CKV_AWS_286 | — | — | — | Ensure IAM policies does not allow privilege escalation |
| checkov | CKV_AWS_287 | — | — | — | Ensure IAM policies does not allow credentials exposure |
| checkov | CKV_AWS_288 | — | — | — | Ensure IAM policies does not allow data exfiltration |
| checkov | CKV_AWS_289 | — | — | — | Ensure IAM policies does not allow permissions management / reso |
| checkov | CKV_AWS_290 | — | — | — | Ensure IAM policies does not allow write access without constrai |
| checkov | CKV_AWS_355 | — | — | — | Ensure no IAM policies documents allow "*" as a statement's reso |
| checkov | CKV_AWS_356 | — | — | — | Ensure no IAM policies documents allow "*" as a statement's reso |
| checkov | CKV_AWS_41 | — | secrets | — | Ensure no hard coded AWS access key and secret key exists in pro |

### accessanalyzer — 1 trivy + 0 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0175 | low | — | — | Enable IAM Access analyzer for IAM policies about all resources  |

### acm — 0 trivy + 3 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_AWS_71 | — | networking | aws_acm_certificate | Ensure AWS ACM Certificate domain name does not include wildcard |
| checkov | CKV_AWS_233 | — | networking | aws_acm_certificate | Ensure Create before destroy for ACM certificates |
| checkov | CKV_AWS_234 | — | logging | aws_acm_certificate | Verify logging preference for ACM certificates |

### ami — 1 trivy + 0 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0344 | low | — | — | AWS AMI data source should specify owners |

### apigateway — 6 trivy + 17 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0005 | high | — | — | API Gateway domain name uses outdated SSL/TLS protocols. |
| trivy | AWS-0001 | medium | — | — | API Gateway stages for V1 and V2 should have access logging enab |
| trivy | AWS-0002 | medium | — | — | API Gateway must have cache enabled |
| trivy | AWS-0003 | low | — | — | API Gateway must have X-Ray tracing enabled |
| trivy | AWS-0004 | low | — | — | No unauthorized access to API Gateway methods |
| trivy | AWS-0190 | low | — | — | Ensure that response caching is enabled for your Amazon API Gate |
| checkov | CKV2_AWS_29 | — | networking | aws_api_gateway_rest_api, aws_api_gatewa | Ensure public API gateway are protected by WAF |
| checkov | CKV2_AWS_4 | — | logging | aws_api_gateway_method_settings, aws_api | Ensure API Gateway stage have logging level defined as appropria |
| checkov | CKV2_AWS_51 | — | general security | aws_api_gateway_stage, aws_apigatewayv2_ | Ensure AWS API Gateway endpoints uses client certificate authent |
| checkov | CKV2_AWS_53 | — | general security | aws_api_gateway_method | Ensure AWS API gateway request is validated |
| checkov | CKV2_AWS_70 | — | networking | aws_api_gateway_method | Ensure API gateway method has authorization or API key set |
| checkov | CKV2_AWS_77 | — | networking | aws_api_gateway_stage, aws_apigatewayv2_ | Ensure AWS API Gateway Rest API attached WAFv2 WebACL is configu |
| checkov | CKV_AWS_120 | — | backup and recovery | aws_api_gateway_stage | Ensure API Gateway caching is enabled |
| checkov | CKV_AWS_206 | — | general security | aws_api_gateway_domain_name | Ensure API Gateway Domain uses a modern security Policy |
| checkov | CKV_AWS_217 | — | backup and recovery | aws_api_gateway_deployment | Ensure Create before destroy for API deployments |
| checkov | CKV_AWS_225 | — | backup and recovery | aws_api_gateway_method_settings | Ensure API Gateway method setting caching is enabled |
| checkov | CKV_AWS_237 | — | general security | aws_api_gateway_rest_api | Ensure Create before destroy for API Gateway |
| checkov | CKV_AWS_276 | — | logging | aws_api_gateway_method_settings | Ensure Data Trace is not enabled in API Gateway Method Settings |
| checkov | CKV_AWS_308 | — | encryption | aws_api_gateway_method_settings | Ensure API Gateway method setting caching is set to encrypted |
| checkov | CKV_AWS_309 | — | iam | aws_apigatewayv2_route | Ensure API GatewayV2 routes specify an authorization type |
| checkov | CKV_AWS_59 | — | general security | aws_api_gateway_method | Ensure there is no open access to back-end resources through API |
| checkov | CKV_AWS_73 | — | logging | aws_api_gateway_stage | Ensure API Gateway has X-Ray Tracing enabled |
| checkov | CKV_AWS_76 | — | logging | aws_api_gateway_stage, aws_apigatewayv2_ | Ensure API Gateway has Access Logging enabled |

### appautoscaling — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_AWS_16 | — | general security | aws_appautoscaling_target, aws_dynamodb_ | Ensure that Auto Scaling is enabled on your DynamoDB tables |

### appflow — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_263 | — | encryption | aws_appflow_flow | Ensure AppFlow flow uses CMK |
| checkov | CKV_AWS_264 | — | encryption | aws_appflow_connector_profile | Ensure AppFlow connector profile uses CMK |

### appsync — 0 trivy + 6 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_AWS_33 | — | application security | aws_appsync_graphql_api | Ensure AppSync is protected by WAF |
| checkov | CKV2_AWS_78 | — | networking | aws_appsync_graphql_api, aws_wafv2_web_a | Ensure AWS AppSync attached WAFv2 WebACL is configured with AMR  |
| checkov | CKV_AWS_193 | — | logging | aws_appsync_graphql_api | Ensure AppSync has Logging enabled |
| checkov | CKV_AWS_194 | — | logging | aws_appsync_graphql_api | Ensure AppSync has Field-Level logs enabled |
| checkov | CKV_AWS_214 | — | encryption | aws_appsync_api_cache | Ensure AppSync API Cache is encrypted at rest |
| checkov | CKV_AWS_215 | — | encryption | aws_appsync_api_cache | Ensure AppSync API Cache is encrypted in transit |

### athena — 2 trivy + 3 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0006 | high | — | — | Athena databases and workgroup configurations are created unencr |
| trivy | AWS-0007 | high | — | — | Athena workgroups should enforce configuration to prevent client |
| checkov | CKV_AWS_159 | — | encryption | aws_athena_workgroup | Ensure that Athena Workgroup is encrypted |
| checkov | CKV_AWS_77 | — | encryption | aws_athena_database | Ensure Athena Database is encrypted at rest (default is unencryp |
| checkov | CKV_AWS_82 | — | general security | aws_athena_workgroup | Ensure Athena Workgroup should enforce configuration to prevent  |

### backup — 0 trivy + 3 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_AWS_18 | — | backup and recovery | aws_backup_selection | Ensure that Elastic File System (Amazon EFS) file systems are ad |
| checkov | CKV2_AWS_9 | — | backup and recovery | aws_backup_selection | Ensure that EBS are added in the backup plans of AWS Backup |
| checkov | CKV_AWS_166 | — | encryption | aws_backup_vault | Ensure Backup Vault is encrypted at rest using KMS CMK |

### batch — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_210 | — | general security | aws_batch_job_definition | Batch job does not define a privileged container |

### bedrockagent — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_373 | — | encryption | aws_bedrockagent_agent | Ensure Bedrock Agent is encrypted with a CMK |
| checkov | CKV_AWS_383 | — | ai and ml | aws_bedrockagent_agent | Ensure AWS Bedrock agent is associated with Bedrock guardrails |

### cloudformation — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_124 | — | logging | aws_cloudformation_stack | Ensure that CloudFormation stacks are sending event notification |

### cloudfront — 4 trivy + 15 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0012 | critical | — | — | CloudFront distribution allows unencrypted (HTTP) communications |
| trivy | AWS-0011 | high | — | — | CloudFront distribution does not have a WAF in front. |
| trivy | AWS-0013 | high | — | — | CloudFront distribution uses outdated SSL/TLS protocols. |
| trivy | AWS-0010 | medium | — | — | Cloudfront distribution should have Access Logging configured |
| checkov | CKV2_AWS_32 | — | networking | aws_cloudfront_distribution | Ensure CloudFront distribution has a response headers policy att |
| checkov | CKV2_AWS_42 | — | networking | aws_cloudfront_distribution | Ensure AWS CloudFront distribution uses custom SSL certificate |
| checkov | CKV2_AWS_46 | — | iam | aws_cloudfront_distribution | Ensure AWS CloudFront Distribution with S3 have Origin Access se |
| checkov | CKV2_AWS_47 | — | application security | aws_cloudfront_distribution, aws_wafv2_w | Ensure AWS CloudFront attached WAFv2 WebACL is configured with A |
| checkov | CKV2_AWS_54 | — | networking | aws_cloudfront_distribution | Ensure AWS CloudFront distribution is using secure SSL protocols |
| checkov | CKV2_AWS_72 | — | networking | aws_cloudfront_distribution | Ensure AWS CloudFront origin protocol policy enforces HTTPS-only |
| checkov | CKV_AWS_174 | — | encryption | aws_cloudfront_distribution | Verify CloudFront Distribution Viewer Certificate is using TLS v |
| checkov | CKV_AWS_216 | — | general security | aws_cloudfront_distribution | Ensure CloudFront distribution is enabled |
| checkov | CKV_AWS_259 | — | general security | aws_cloudfront_response_headers_policy | Ensure CloudFront response header policy enforces Strict Transpo |
| checkov | CKV_AWS_305 | — | general security | aws_cloudfront_distribution | Ensure CloudFront distribution has a default root object configu |
| checkov | CKV_AWS_310 | — | general security | aws_cloudfront_distribution | Ensure CloudFront distributions should have origin failover conf |
| checkov | CKV_AWS_34 | — | encryption | aws_cloudfront_distribution | Ensure CloudFront distribution ViewerProtocolPolicy is set to HT |
| checkov | CKV_AWS_374 | — | networking | aws_cloudfront_distribution | Ensure AWS CloudFront web distribution has geo restriction enabl |
| checkov | CKV_AWS_68 | — | application security | aws_cloudfront_distribution | CloudFront Distribution should have WAF enabled |
| checkov | CKV_AWS_86 | — | logging | aws_cloudfront_distribution | Ensure CloudFront distribution has Access Logging enabled |

### cloudsearch — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_218 | — | general security | aws_cloudsearch_domain | Ensure that CloudSearch is using latest TLS |
| checkov | CKV_AWS_220 | — | general security | aws_cloudsearch_domain | Ensure that CloudSearch is using https |

### cloudtrail — 6 trivy + 7 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0161 | critical | — | — | The S3 Bucket backing Cloudtrail should be private |
| trivy | AWS-0015 | high | — | — | CloudTrail should use Customer managed keys to encrypt the logs |
| trivy | AWS-0016 | high | — | — | Cloudtrail log validation should be enabled to prevent tampering |
| trivy | AWS-0014 | medium | — | — | Cloudtrail should be enabled in all regions regardless of where  |
| trivy | AWS-0162 | low | — | — | CloudTrail logs should be stored in S3 and also sent to CloudWat |
| trivy | AWS-0163 | low | — | — | You should enable bucket access logging on the CloudTrail S3 buc |
| checkov | CKV2_AWS_10 | — | logging | aws_cloudtrail | Ensure CloudTrail trails are integrated with CloudWatch Logs |
| checkov | CKV_AWS_251 | — | logging | aws_cloudtrail | Ensure CloudTrail logging is enabled |
| checkov | CKV_AWS_252 | — | logging | aws_cloudtrail | Ensure CloudTrail defines an SNS Topic |
| checkov | CKV_AWS_294 | — | encryption | aws_cloudtrail_event_data_store | Ensure CloudTrail Event Data Store uses CMK |
| checkov | CKV_AWS_35 | — | logging | aws_cloudtrail | Ensure CloudTrail logs are encrypted at rest using KMS CMKs |
| checkov | CKV_AWS_36 | — | logging | aws_cloudtrail | Ensure CloudTrail log file validation is enabled |
| checkov | CKV_AWS_67 | — | logging | aws_cloudtrail | Ensure CloudTrail is enabled in all Regions |

### cloudwatch — 16 trivy + 4 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0017 | low | — | — | CloudWatch log groups should be encrypted using CMK |
| trivy | AWS-0147 | low | — | — | Ensure a log metric filter and alarm exist for unauthorized API  |
| trivy | AWS-0148 | low | — | — | Ensure a log metric filter and alarm exist for AWS Management Co |
| trivy | AWS-0149 | low | — | — | Ensure a log metric filter and alarm exist for usage of root use |
| trivy | AWS-0150 | low | — | — | Ensure a log metric filter and alarm exist for IAM policy change |
| trivy | AWS-0151 | low | — | — | Ensure a log metric filter and alarm exist for CloudTrail config |
| trivy | AWS-0152 | low | — | — | Ensure a log metric filter and alarm exist for AWS Management Co |
| trivy | AWS-0153 | low | — | — | Ensure a log metric filter and alarm exist for disabling or sche |
| trivy | AWS-0154 | low | — | — | Ensure a log metric filter and alarm exist for S3 bucket policy  |
| trivy | AWS-0155 | low | — | — | Ensure a log metric filter and alarm exist for AWS Config config |
| trivy | AWS-0156 | low | — | — | Ensure a log metric filter and alarm exist for security group ch |
| trivy | AWS-0157 | low | — | — | Ensure a log metric filter and alarm exist for changes to Networ |
| trivy | AWS-0158 | low | — | — | Ensure a log metric filter and alarm exist for changes to networ |
| trivy | AWS-0159 | low | — | — | Ensure a log metric filter and alarm exist for route table chang |
| trivy | AWS-0160 | low | — | — | Ensure a log metric filter and alarm exist for VPC changes |
| trivy | AWS-0174 | low | — | — | Ensure a log metric filter and alarm exist for organisation chan |
| checkov | CKV_AWS_158 | — | encryption | aws_cloudwatch_log_group | Ensure that CloudWatch Log Group is encrypted by KMS |
| checkov | CKV_AWS_319 | — | general security | aws_cloudwatch_metric_alarm | Ensure that CloudWatch alarm actions are enabled |
| checkov | CKV_AWS_338 | — | logging | aws_cloudwatch_log_group | Ensure CloudWatch log groups retains logs for at least 1 year |
| checkov | CKV_AWS_66 | — | logging | aws_cloudwatch_log_group | Ensure that CloudWatch Log Group specifies retention days |

### codeartifact — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_221 | — | encryption | aws_codeartifact_domain | Ensure CodeArtifact Domain is encrypted by KMS using a customer  |

### codebuild — 1 trivy + 5 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0018 | high | — | — | CodeBuild Project artifacts encryption should not be disabled |
| checkov | CKV_AWS_147 | — | encryption | aws_codebuild_project | Ensure that CodeBuild projects are encrypted using CMK |
| checkov | CKV_AWS_311 | — | encryption | aws_codebuild_project | Ensure that CodeBuild S3 logs are encrypted |
| checkov | CKV_AWS_314 | — | logging | aws_codebuild_project | Ensure CodeBuild project environments have a logging configurati |
| checkov | CKV_AWS_316 | — | general security | aws_codebuild_project | Ensure CodeBuild project environments do not have privileged mod |
| checkov | CKV_AWS_78 | — | encryption | aws_codebuild_project | Ensure that CodeBuild Project encryption is not disabled |

### codecommit — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_AWS_37 | — | general security | aws_codecommit_repository | Ensure CodeCommit associates an approval rule |
| checkov | CKV_AWS_257 | — | general security | aws_codecommit_approval_rule_template | Ensure CodeCommit branch changes have at least 2 approvals |

### codegurureviewer — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_381 | — | encryption | aws_codegurureviewer_repository_associat | Make sure that aws_codegurureviewer_repository_association has a |

### codepipeline — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_219 | — | encryption | aws_codepipeline | Ensure CodePipeline Artifact store is using a KMS CMK |

### cognito — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_366 | — | iam | aws_cognito_identity_pool | Ensure AWS Cognito identity pool does not allow unauthenticated  |

### comprehend — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_267 | — | encryption | aws_comprehend_entity_recognizer | Ensure that Comprehend Entity Recognizer's model is encrypted by |
| checkov | CKV_AWS_268 | — | encryption | aws_comprehend_entity_recognizer | Ensure that Comprehend Entity Recognizer's volume is encrypted b |

### config — 1 trivy + 3 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0019 | high | — | — | Config configuration aggregator should be using all regions for  |
| checkov | CKV2_AWS_45 | — | logging | aws_config_configuration_recorder, aws_c | Ensure AWS Config recorder is enabled to record all supported re |
| checkov | CKV2_AWS_48 | — | logging | aws_config_configuration_recorder | Ensure AWS Config must record all possible resources |
| checkov | CKV_AWS_121 | — | logging | aws_config_configuration_aggregator | Ensure AWS Config is enabled in all regions |

### connect — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_269 | — | encryption | aws_connect_instance_storage_config | Ensure Connect Instance Kinesis Video Stream Storage Config uses |
| checkov | CKV_AWS_270 | — | encryption | aws_connect_instance_storage_config | Ensure Connect Instance S3 Storage Config uses CMK |

### datasync — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_295 | — | secrets | aws_datasync_location_object_storage | Ensure DataSync Location Object Storage doesn't expose secrets |

### dax — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_239 | — | encryption | aws_dax_cluster | Ensure DAX cluster endpoint is using TLS |
| checkov | CKV_AWS_47 | — | encryption | aws_dax_cluster | Ensure DAX is encrypted at rest (default is unencrypted) |

### dlm — 0 trivy + 4 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_253 | — | backup and recovery | aws_dlm_lifecycle_policy | Ensure DLM cross region events are encrypted |
| checkov | CKV_AWS_254 | — | backup and recovery | aws_dlm_lifecycle_policy | Ensure DLM cross region events are encrypted with Customer Manag |
| checkov | CKV_AWS_255 | — | backup and recovery | aws_dlm_lifecycle_policy | Ensure DLM cross region schedules are encrypted |
| checkov | CKV_AWS_256 | — | backup and recovery | aws_dlm_lifecycle_policy | Ensure DLM cross region schedules are encrypted using a Customer |

### dms — 0 trivy + 6 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_AWS_49 | — | networking | aws_dms_endpoint | Ensure AWS Database Migration Service endpoints have SSL configu |
| checkov | CKV_AWS_212 | — | encryption | aws_dms_replication_instance | Ensure DMS replication instance is encrypted by KMS using a cust |
| checkov | CKV_AWS_222 | — | encryption | aws_dms_replication_instance | Ensure DMS replication instance gets all minor upgrade automatic |
| checkov | CKV_AWS_296 | — | encryption | aws_dms_endpoint | Ensure DMS endpoint uses Customer Managed Key (CMK) |
| checkov | CKV_AWS_298 | — | encryption | aws_dms_s3_endpoint | Ensure DMS S3 uses Customer Managed Key (CMK) |
| checkov | CKV_AWS_89 | — | networking | aws_dms_replication_instance | DMS replication instance should not be publicly accessible |

### docdb — 0 trivy + 7 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_104 | — | logging | aws_docdb_cluster_parameter_group | Ensure DocumentDB has audit logs enabled |
| checkov | CKV_AWS_182 | — | encryption | aws_docdb_cluster | Ensure DocumentDB is encrypted by KMS using a customer managed K |
| checkov | CKV_AWS_292 | — | encryption | aws_docdb_global_cluster | Ensure DocumentDB Global Cluster is encrypted at rest (default i |
| checkov | CKV_AWS_360 | — | backup and recovery | aws_docdb_cluster | Ensure DocumentDB has an adequate backup retention period |
| checkov | CKV_AWS_74 | — | encryption | aws_docdb_cluster | Ensure DocumentDB is encrypted at rest (default is unencrypted) |
| checkov | CKV_AWS_85 | — | logging | aws_docdb_cluster | Ensure DocumentDB Logging is enabled |
| checkov | CKV_AWS_90 | — | encryption | aws_docdb_cluster_parameter_group | Ensure DocumentDB TLS is not disabled |

### documentdb — 3 trivy + 0 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0021 | high | — | — | DocumentDB storage must be encrypted |
| trivy | AWS-0020 | medium | — | — | DocumentDB logs export should be enabled |
| trivy | AWS-0022 | low | — | — | DocumentDB encryption should use Customer Managed Keys |

### dynamodb — 3 trivy + 4 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0023 | high | — | — | DAX Cluster should always encrypt data at rest |
| trivy | AWS-0024 | medium | — | — | Point in time recovery should be enabled to protect DynamoDB tab |
| trivy | AWS-0025 | low | — | — | DynamoDB tables should use at rest encryption with a Customer Ma |
| checkov | CKV_AWS_119 | — | encryption | aws_dynamodb_table | Ensure DynamoDB Tables are encrypted using a KMS Customer Manage |
| checkov | CKV_AWS_165 | — | backup and recovery | aws_dynamodb_global_table | Ensure DynamoDB point in time recovery (backup) is enabled for g |
| checkov | CKV_AWS_271 | — | encryption | aws_dynamodb_table_replica | Ensure DynamoDB table replica KMS encryption uses CMK |
| checkov | CKV_AWS_28 | — | backup and recovery | aws_dynamodb_table | Ensure DynamoDB point in time recovery (backup) is enabled |

### ec2 — 20 trivy + 35 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0029 | critical | — | — | User data for EC2 instances must not contain sensitive AWS keys |
| trivy | AWS-0102 | critical | — | — | An Network ACL rule allows ALL ports. |
| trivy | AWS-0104 | critical | — | — | A security group rule should not allow unrestricted egress to an |
| trivy | AWS-0129 | critical | — | — | User data for EC2 instances must not contain sensitive AWS keys |
| trivy | AWS-0008 | high | — | — | Launch configuration with unencrypted block device. |
| trivy | AWS-0009 | high | — | — | Launch configuration should not have a public IP address. |
| trivy | AWS-0026 | high | — | — | EBS volumes must be encrypted |
| trivy | AWS-0028 | high | — | — | aws_instance should activate session tokens for Instance Metadat |
| trivy | AWS-0101 | high | — | — | AWS best practice to not use the default VPC for workflows |
| trivy | AWS-0107 | high | — | — | Security groups should not allow unrestricted ingress to SSH or  |
| trivy | AWS-0122 | high | — | — | Ensure all data stored in the launch configuration EBS is secure |
| trivy | AWS-0130 | high | — | — | aws_instance should activate session tokens for Instance Metadat |
| trivy | AWS-0131 | high | — | — | Instance with unencrypted block device. |
| trivy | AWS-0164 | high | — | — | Instances in a subnet should not receive a public IP address by  |
| trivy | AWS-0105 | medium | — | — | Network ACLs should not allow unrestricted ingress to SSH or RDP |
| trivy | AWS-0178 | medium | — | — | VPC Flow Logs is a feature that enables you to capture informati |
| trivy | AWS-0027 | low | — | — | EBS volume encryption should use Customer Managed Keys |
| trivy | AWS-0099 | low | — | — | Missing description for security group. |
| trivy | AWS-0124 | low | — | — | Missing description for security group rule. |
| trivy | AWS-0173 | low | — | — | Default security group should restrict all traffic |
| checkov | CKV2_AWS_1 | — | networking | aws_network_acl, aws_subnet | Ensure that all NACL are attached to subnets |
| checkov | CKV2_AWS_11 | — | logging | aws_vpc | Ensure VPC flow logging is enabled in all VPCs |
| checkov | CKV2_AWS_12 | — | logging | aws_default_security_group, aws_vpc | Ensure the default security group of every VPC restricts all tra |
| checkov | CKV2_AWS_15 | — | networking | aws_autoscaling_group, aws_elb, aws_lb_t | Ensure that auto Scaling groups that are associated with a load  |
| checkov | CKV2_AWS_19 | — | networking | aws_eip, aws_eip_association | Ensure that all EIP addresses allocated to a VPC are attached to |
| checkov | CKV2_AWS_2 | — | encryption | aws_ebs_volume, aws_volume_attachment | Ensure that only encrypted EBS volumes are attached to EC2 insta |
| checkov | CKV2_AWS_35 | — | networking | aws_route, aws_route_table | AWS NAT Gateways should be utilized for the default route |
| checkov | CKV2_AWS_41 | — | iam | aws_instance | Ensure an IAM role is attached to EC2 instance |
| checkov | CKV2_AWS_44 | — | networking | aws_route, aws_route_table | Ensure AWS route table with VPC peering does not contain routes  |
| checkov | CKV2_AWS_5 | — | networking | aws_security_group | Ensure that Security Groups are attached to another resource |
| checkov | CKV_AWS_106 | — | encryption | aws_ebs_encryption_by_default | Ensure EBS default encryption is enabled |
| checkov | CKV_AWS_123 | — | networking | aws_vpc_endpoint_service | Ensure that VPC Endpoint Service is configured for Manual Accept |
| checkov | CKV_AWS_126 | — | logging | aws_instance | Ensure that detailed monitoring is enabled for EC2 instances |
| checkov | CKV_AWS_130 | — | networking | aws_subnet | Ensure VPC subnets do not assign public IP by default |
| checkov | CKV_AWS_135 | — | general security | aws_instance | Ensure that EC2 is EBS optimized |
| checkov | CKV_AWS_148 | — | networking | aws_default_vpc | Ensure no default VPC is planned to be provisioned |
| checkov | CKV_AWS_153 | — | encryption | aws_autoscaling_group | Autoscaling groups should supply tags to launch configurations |
| checkov | CKV_AWS_183 | — | encryption | aws_ebs_snapshot_copy | Ensure EBS Snapshot Copy is encrypted by KMS using a customer ma |
| checkov | CKV_AWS_189 | — | encryption | aws_ebs_volume | Ensure EBS Volume is encrypted by KMS using a customer managed K |
| checkov | CKV_AWS_204 | — | encryption | aws_ami | Ensure AMIs are encrypted using KMS CMKs |
| checkov | CKV_AWS_205 | — | general security | aws_ami_launch_permission | Ensure to Limit AMI launch Permissions |
| checkov | CKV_AWS_23 | — | networking | aws_security_group, aws_security_group_r | Ensure every security group and rule has a description |
| checkov | CKV_AWS_235 | — | encryption | aws_ami_copy | Ensure that copied AMIs are encrypted |
| checkov | CKV_AWS_236 | — | encryption | aws_ami_copy | Ensure AMI copying uses a CMK |
| checkov | CKV_AWS_3 | — | encryption | aws_ebs_volume | Ensure all data stored in the EBS is securely encrypted |
| checkov | CKV_AWS_315 | — | general security | aws_autoscaling_group | Ensure EC2 Auto Scaling groups use EC2 launch templates |
| checkov | CKV_AWS_331 | — | general security | aws_ec2_transit_gateway | Ensure Transit Gateways do not automatically accept VPC attachme |
| checkov | CKV_AWS_341 | — | general security | aws_launch_configuration, aws_launch_tem | Ensure Launch template should not have a metadata response hop l |
| checkov | CKV_AWS_352 | — | networking | aws_network_acl_rule | Ensure NACL ingress does not allow all Ports |
| checkov | CKV_AWS_386 | — | supply chain | aws_ami | Reduce potential for WhoAMI cloud image name confusion attack |
| checkov | CKV_AWS_389 | — | networking | aws_launch_configuration | Ensure AWS Auto Scaling group launch configuration doesn't have  |
| checkov | CKV_AWS_46 | — | secrets | aws_instance, aws_launch_template, aws_l | Ensure no hard-coded secrets exist in EC2 user data |
| checkov | CKV_AWS_79 | — | general security | aws_instance, aws_launch_template, aws_l | Ensure Instance Metadata Service Version 1 is not enabled |
| checkov | CKV_AWS_8 | — | encryption | aws_launch_configuration, aws_instance | Ensure all data stored in the Launch configuration or instance E |
| checkov | CKV_AWS_88 | — | networking | aws_instance, aws_launch_template | EC2 instance should not have public IP. |

### ecr — 4 trivy + 4 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0030 | high | — | — | ECR repository has image scans disabled. |
| trivy | AWS-0031 | high | — | — | ECR images tags shouldn't be mutable. |
| trivy | AWS-0032 | high | — | — | ECR repository policy must block public access |
| trivy | AWS-0033 | low | — | — | ECR Repository should use customer managed keys to allow more co |
| checkov | CKV_AWS_136 | — | encryption | aws_ecr_repository | Ensure that ECR repositories are encrypted using KMS |
| checkov | CKV_AWS_163 | — | general security | aws_ecr_repository | Ensure ECR image scanning on push is enabled |
| checkov | CKV_AWS_32 | — | iam | aws_ecr_repository_policy | Ensure ECR policy is not set to public |
| checkov | CKV_AWS_51 | — | general security | aws_ecr_repository | Ensure ECR Image Tags are immutable |

### ecs — 3 trivy + 10 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0036 | critical | — | — | Task definition defines sensitive environment variable(s). |
| trivy | AWS-0035 | high | — | — | ECS Task Definitions with EFS volumes should use in-transit encr |
| trivy | AWS-0034 | low | — | — | ECS clusters should have container insights enabled |
| checkov | CKV_AWS_223 | — | logging | aws_ecs_cluster | Ensure ECS Cluster enables logging of ECS Exec |
| checkov | CKV_AWS_224 | — | encryption | aws_ecs_cluster | Ensure ECS Cluster logging is enabled and client to container co |
| checkov | CKV_AWS_249 | — | iam | aws_ecs_task_definition | Ensure that the Execution Role ARN and the Task Role ARN are dif |
| checkov | CKV_AWS_332 | — | general security | aws_ecs_service | Ensure ECS Fargate services run on the latest Fargate platform v |
| checkov | CKV_AWS_333 | — | logging | aws_ecs_service | Ensure ECS services do not have public IP addresses assigned to  |
| checkov | CKV_AWS_334 | — | general security | aws_ecs_task_definition | Ensure ECS containers should run as non-privileged |
| checkov | CKV_AWS_335 | — | general security | aws_ecs_task_definition | Ensure ECS task definitions should not share the host's process  |
| checkov | CKV_AWS_336 | — | general security | aws_ecs_task_definition | Ensure ECS containers are limited to read-only access to root fi |
| checkov | CKV_AWS_65 | — | logging | aws_ecs_cluster | Ensure container insights are enabled on ECS cluster |
| checkov | CKV_AWS_97 | — | encryption | aws_ecs_task_definition | Ensure Encryption in transit is enabled for EFS volumes in ECS T |

### efs — 1 trivy + 4 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0037 | high | — | — | EFS Encryption has not been enabled |
| checkov | CKV_AWS_184 | — | encryption | aws_efs_file_system | Ensure resource is encrypted by KMS using a customer managed Key |
| checkov | CKV_AWS_329 | — | general security | aws_efs_access_point | EFS access points should enforce a root directory |
| checkov | CKV_AWS_330 | — | general security | aws_efs_access_point | EFS access points should enforce a user identity |
| checkov | CKV_AWS_42 | — | encryption | aws_efs_file_system | Ensure EFS is securely encrypted |

### eks — 4 trivy + 6 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0040 | critical | — | — | EKS Clusters should have the public access disabled |
| trivy | AWS-0041 | critical | — | — | EKS cluster should not have open CIDR range for public access |
| trivy | AWS-0039 | high | — | — | EKS should have the encryption of secrets enabled |
| trivy | AWS-0038 | medium | — | — | EKS Clusters should have cluster control plane logging turned on |
| checkov | CKV_AWS_100 | — | kubernetes | aws_eks_node_group | Ensure AWS EKS node group does not have implicit SSH access from |
| checkov | CKV_AWS_339 | — | kubernetes | aws_eks_cluster | Ensure EKS clusters run on a supported Kubernetes version |
| checkov | CKV_AWS_37 | — | kubernetes | aws_eks_cluster | Ensure Amazon EKS control plane logging is enabled for all log t |
| checkov | CKV_AWS_38 | — | kubernetes | aws_eks_cluster | Ensure Amazon EKS public endpoint not accessible to 0.0.0.0/0 |
| checkov | CKV_AWS_39 | — | kubernetes | aws_eks_cluster | Ensure Amazon EKS public endpoint disabled |
| checkov | CKV_AWS_58 | — | kubernetes | aws_eks_cluster | Ensure EKS Cluster has Secrets Encryption Enabled |

### elastic — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_312 | — | general security | aws_elastic_beanstalk_environment | Ensure Elastic Beanstalk environments have enhanced health repor |
| checkov | CKV_AWS_340 | — | general security | aws_elastic_beanstalk_environment | Ensure Elastic Beanstalk managed platform updates are enabled |

### elasticache — 4 trivy + 9 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0045 | high | — | — | Elasticache Replication Group stores unencrypted data at-rest. |
| trivy | AWS-0051 | high | — | — | Elasticache Replication Group uses unencrypted traffic. |
| trivy | AWS-0050 | medium | — | — | Redis cluster should have backup retention turned on |
| trivy | AWS-0049 | low | — | — | Missing description for security group/security group rule. |
| checkov | CKV2_AWS_50 | — | backup and recovery | aws_elasticache_replication_group | Ensure AWS ElastiCache Redis cluster with Multi-AZ Automatic Fai |
| checkov | CKV_AWS_134 | — | backup and recovery | aws_elasticache_cluster | Ensure that Amazon ElastiCache Redis clusters have automatic bac |
| checkov | CKV_AWS_191 | — | encryption | aws_elasticache_replication_group | Ensure ElastiCache replication group is encrypted by KMS using a |
| checkov | CKV_AWS_196 | — | networking | aws_elasticache_security_group | Ensure no aws_elasticache_security_group resources exist |
| checkov | CKV_AWS_29 | — | encryption | aws_elasticache_replication_group | Ensure all data stored in the ElastiCache Replication Group is s |
| checkov | CKV_AWS_30 | — | encryption | aws_elasticache_replication_group | Ensure all data stored in the ElastiCache Replication Group is s |
| checkov | CKV_AWS_31 | — | encryption | aws_elasticache_replication_group | Ensure all data stored in the ElastiCache Replication Group is s |
| checkov | CKV_AWS_322 | — | general security | aws_elasticache_cluster | Ensure ElastiCache for Redis cache clusters have auto minor vers |
| checkov | CKV_AWS_323 | — | networking | aws_elasticache_cluster | Ensure ElastiCache clusters do not use the default subnet group |

### elasticsearch — 5 trivy + 12 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0046 | critical | — | — | Elasticsearch doesn't enforce HTTPS traffic. |
| trivy | AWS-0043 | high | — | — | Elasticsearch domain uses plaintext traffic for node to node com |
| trivy | AWS-0048 | high | — | — | Elasticsearch domain isn't encrypted at rest. |
| trivy | AWS-0126 | high | — | — | Elasticsearch domain endpoint is using outdated TLS policy. |
| trivy | AWS-0042 | medium | — | — | Domain logging should be enabled for Elastic Search domains |
| checkov | CKV2_AWS_52 | — | iam | aws_elasticsearch_domain, aws_opensearch | Ensure AWS ElasticSearch/OpenSearch Fine-grained access control  |
| checkov | CKV2_AWS_59 | — | general security | aws_elasticsearch_domain, aws_opensearch | Ensure ElasticSearch/OpenSearch has dedicated master node enable |
| checkov | CKV_AWS_137 | — | networking | aws_elasticsearch_domain, aws_opensearch | Ensure that Elasticsearch is configured inside a VPC |
| checkov | CKV_AWS_228 | — | encryption | aws_elasticsearch_domain, aws_opensearch | Verify Elasticsearch domain is using an up to date TLS policy |
| checkov | CKV_AWS_247 | — | encryption | aws_elasticsearch_domain, aws_opensearch | Ensure all data stored in the Elasticsearch is encrypted with a  |
| checkov | CKV_AWS_248 | — | networking | aws_elasticsearch_domain, aws_opensearch | Ensure that Elasticsearch is not using the default Security Grou |
| checkov | CKV_AWS_317 | — | logging | aws_elasticsearch_domain, aws_opensearch | Ensure Elasticsearch Domain Audit Logging is enabled |
| checkov | CKV_AWS_318 | — | general security | aws_elasticsearch_domain, aws_opensearch | Ensure Elasticsearch domains are configured with at least three  |
| checkov | CKV_AWS_5 | — | encryption | aws_elasticsearch_domain, aws_opensearch | Ensure all data stored in the Elasticsearch is securely encrypte |
| checkov | CKV_AWS_6 | — | encryption | aws_elasticsearch_domain, aws_opensearch | Ensure all Elasticsearch has node-to-node encryption enabled |
| checkov | CKV_AWS_83 | — | general security | aws_elasticsearch_domain, aws_opensearch | Ensure Elasticsearch Domain enforces HTTPS |
| checkov | CKV_AWS_84 | — | logging | aws_elasticsearch_domain, aws_opensearch | Ensure Elasticsearch Domain Logging is enabled |

### elb — 4 trivy + 17 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0047 | critical | — | — | An outdated SSL policy is in use by a load balancer. |
| trivy | AWS-0054 | critical | — | — | Use of plain HTTP. |
| trivy | AWS-0052 | high | — | — | Load balancers should drop invalid headers |
| trivy | AWS-0053 | high | — | — | Load balancer is exposed to the internet. |
| checkov | CKV2_AWS_20 | — | networking | aws_alb, aws_alb_listener, aws_lb, aws_l | Ensure that ALB redirects HTTP requests into HTTPS ones |
| checkov | CKV2_AWS_28 | — | networking | aws_alb, aws_lb | Ensure public facing ALB are protected by WAF |
| checkov | CKV2_AWS_74 | — | networking | aws_alb_listener, aws_lb_listener | Ensure AWS Load Balancers use strong ciphers |
| checkov | CKV2_AWS_76 | — | networking | aws_alb, aws_lb, aws_wafv2_web_acl | Ensure AWS ALB attached WAFv2 WebACL is configured with AMR for  |
| checkov | CKV_AWS_103 | — | networking | aws_alb_listener, aws_lb, aws_lb_listene | Ensure that load balancer is using at least TLS 1.2 |
| checkov | CKV_AWS_127 | — | general security | aws_elb | Ensure that Elastic Load Balancer(s) uses SSL certificates provi |
| checkov | CKV_AWS_131 | — | networking | aws_lb, aws_alb | Ensure that ALB drops HTTP headers |
| checkov | CKV_AWS_138 | — | networking | aws_elb | Ensure that ELB is cross-zone-load-balancing enabled |
| checkov | CKV_AWS_150 | — | general security | aws_lb, aws_alb | Ensure that Load Balancer has deletion protection enabled |
| checkov | CKV_AWS_152 | — | networking | aws_lb, aws_alb | Ensure that Load Balancer (Network/Gateway) has cross-zone load  |
| checkov | CKV_AWS_2 | — | encryption | aws_lb_listener, aws_alb_listener | Ensure ALB protocol is HTTPS |
| checkov | CKV_AWS_261 | — | general security | aws_lb_target_group, aws_alb_target_grou | Ensure HTTP HTTPS Target group defines Healthcheck |
| checkov | CKV_AWS_328 | — | networking | aws_lb, aws_alb, aws_elb | Ensure that ALB is configured with defensive or strictest desync |
| checkov | CKV_AWS_376 | — | networking | aws_elb | Ensure AWS Elastic Load Balancer listener uses TLS/SSL |
| checkov | CKV_AWS_378 | — | networking | aws_alb_listener, aws_alb_target_group,  | Ensure AWS Load Balancer doesn't use HTTP protocol |
| checkov | CKV_AWS_91 | — | logging | aws_lb, aws_alb | Ensure the ELBv2 (Application/Network) has access logging enable |
| checkov | CKV_AWS_92 | — | logging | aws_elb | Ensure the ELB has access logging enabled |

### emr — 3 trivy + 8 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0137 | high | — | — | Enable at-rest encryption for EMR clusters. |
| trivy | AWS-0138 | high | — | — | Enable in-transit encryption for EMR clusters. |
| trivy | AWS-0139 | high | — | — | Enable local-disk encryption for EMR clusters. |
| checkov | CKV2_AWS_55 | — | encryption | aws_emr_cluster | Ensure AWS EMR cluster is configured with security configuration |
| checkov | CKV2_AWS_7 | — | networking | aws_emr_cluster, aws_security_group | Ensure that Amazon EMR clusters' security groups are not open to |
| checkov | CKV_AWS_114 | — | general security | aws_emr_cluster | Ensure that EMR clusters with Kerberos have Kerberos Realm set |
| checkov | CKV_AWS_171 | — | encryption | aws_emr_security_configuration | Ensure EMR Cluster security configuration encryption is using SS |
| checkov | CKV_AWS_349 | — | encryption | aws_emr_security_configuration | Ensure EMR Cluster security configuration encrypts local disks |
| checkov | CKV_AWS_350 | — | encryption | aws_emr_security_configuration | Ensure EMR Cluster security configuration encrypts EBS disks |
| checkov | CKV_AWS_351 | — | encryption | aws_emr_security_configuration | Ensure EMR Cluster security configuration encrypts InTransit |
| checkov | CKV_AWS_390 | — | networking | aws_emr_block_public_access_configuratio | Ensure AWS EMR block public access setting is enabled |

### fsx — 0 trivy + 4 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_178 | — | encryption | aws_fsx_ontap_file_system | Ensure fx ontap file system is encrypted by KMS using a customer |
| checkov | CKV_AWS_179 | — | encryption | aws_fsx_windows_file_system | Ensure FSX Windows filesystem is encrypted by KMS using a custom |
| checkov | CKV_AWS_190 | — | encryption | aws_fsx_lustre_file_system | Ensure lustre file systems is encrypted by KMS using a customer  |
| checkov | CKV_AWS_203 | — | encryption | aws_fsx_openzfs_file_system | Ensure resource is encrypted by KMS using a customer managed Key |

### glacier — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_167 | — | iam | aws_glacier_vault | Ensure Glacier Vault access policy is not public by only allowin |

### globalaccelerator — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_75 | — | logging | aws_globalaccelerator_accelerator | Ensure Global Accelerator accelerator has flow logs enabled |

### glue — 0 trivy + 3 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_195 | — | encryption | aws_glue_crawler, aws_glue_dev_endpoint, | Ensure Glue component has a security configuration associated |
| checkov | CKV_AWS_94 | — | encryption | aws_glue_data_catalog_encryption_setting | Ensure Glue Data Catalog Encryption is enabled |
| checkov | CKV_AWS_99 | — | encryption | aws_glue_security_configuration | Ensure Glue Security Configuration Encryption is enabled |

### guardduty — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_AWS_3 | — | general security | aws_guardduty_detector, aws_guardduty_or | Ensure GuardDuty is enabled to specific org/region |
| checkov | CKV_AWS_238 | — | general security | aws_guardduty_detector | Ensure that GuardDuty detector is enabled |

### iam — 24 trivy + 26 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0141 | critical | — | — | The root user has complete access to all services and resources  |
| trivy | AWS-0142 | critical | — | — | The "root" account has unrestricted access to all resources in t |
| trivy | AWS-0057 | high | — | — | IAM policy should avoid use of wildcards and instead apply the p |
| trivy | AWS-0345 | high | — | — | Disallow unrestricted S3 IAM Policies |
| trivy | AWS-0346 | high | — | — | Reduce unnecessary unauthorized access or information disclosure |
| trivy | AWS-0056 | medium | — | — | IAM Password policy should prevent password reuse. |
| trivy | AWS-0058 | medium | — | — | IAM Password policy should have requirement for at least one low |
| trivy | AWS-0059 | medium | — | — | IAM Password policy should have requirement for at least one num |
| trivy | AWS-0060 | medium | — | — | IAM Password policy should have requirement for at least one sym |
| trivy | AWS-0061 | medium | — | — | IAM Password policy should have requirement for at least one upp |
| trivy | AWS-0062 | medium | — | — | IAM Password policy should have expiry less than or equal to 90  |
| trivy | AWS-0063 | medium | — | — | IAM Password policy should have minimum password length of 14 or |
| trivy | AWS-0123 | medium | — | — | IAM groups should have MFA enforcement activated. |
| trivy | AWS-0144 | medium | — | — | Credentials which are no longer used should be disabled. |
| trivy | AWS-0145 | medium | — | — | IAM Users should have MFA enforcement activated. |
| trivy | AWS-0165 | medium | — | — | The "root" account has unrestricted access to all resources in t |
| trivy | AWS-0342 | medium | — | — | IAM Pass Role Filtering |
| trivy | AWS-0140 | low | — | — | The "root" account has unrestricted access to all resources in t |
| trivy | AWS-0143 | low | — | — | IAM policies should not be granted directly to users. |
| trivy | AWS-0146 | low | — | — | Access keys should be rotated at least every 90 days |
| trivy | AWS-0166 | low | — | — | Disabling or removing unnecessary credentials will reduce the wi |
| trivy | AWS-0167 | low | — | — | No user should have more than one active access key. |
| trivy | AWS-0168 | low | — | — | Delete expired TLS certificates |
| trivy | AWS-0169 | low | — | — | Missing IAM Role to allow authorized users to manage incidents w |
| checkov | CKV2_AWS_14 | — | iam | aws_iam_group, aws_iam_group_membership | Ensure that IAM groups includes at least one IAM user |
| checkov | CKV2_AWS_21 | — | iam | aws_iam_group_membership | Ensure that all IAM users are members of at least one IAM group. |
| checkov | CKV2_AWS_22 | — | iam | aws_iam_user | Ensure an IAM User does not have access to the console |
| checkov | CKV2_AWS_40 | — | iam | aws_iam_group_policy, aws_iam_policy, aw | Ensure AWS IAM policy does not allow full IAM privileges |
| checkov | CKV2_AWS_56 | — | iam | aws_iam_group_policy_attachment, aws_iam | Ensure AWS Managed IAMFullAccess IAM policy is not used. |
| checkov | CKV2_AWS_68 | — | networking | aws_iam_role, aws_sagemaker_notebook_ins | Ensure SageMaker notebook instance IAM policy is not overly perm |
| checkov | CKV_AWS_1 | — | iam | aws_iam_policy_document | Ensure IAM policies that allow full "*-*" administrative privile |
| checkov | CKV_AWS_10 | — | iam | aws_iam_account_password_policy | Ensure IAM password policy requires minimum length of 14 or grea |
| checkov | CKV_AWS_11 | — | iam | aws_iam_account_password_policy | Ensure IAM password policy requires at least one lowercase lette |
| checkov | CKV_AWS_12 | — | iam | aws_iam_account_password_policy | Ensure IAM password policy requires at least one number |
| checkov | CKV_AWS_13 | — | iam | aws_iam_account_password_policy | Ensure IAM password policy prevents password reuse |
| checkov | CKV_AWS_14 | — | iam | aws_iam_account_password_policy | Ensure IAM password policy requires at least one symbol |
| checkov | CKV_AWS_15 | — | iam | aws_iam_account_password_policy | Ensure IAM password policy requires at least one uppercase lette |
| checkov | CKV_AWS_273 | — | iam | aws_iam_user | Ensure access is controlled through SSO and not AWS IAM defined  |
| checkov | CKV_AWS_274 | — | iam | aws_iam_role, aws_iam_policy_attachment, | Disallow IAM roles, users, and groups from using the AWS Adminis |
| checkov | CKV_AWS_275 | — | iam | aws_iam_policy | Disallow policies from using the AWS AdministratorAccess policy |
| checkov | CKV_AWS_283 | — | iam | aws_iam_policy_document | Ensure no IAM policies documents allow ALL or any AWS principal  |
| checkov | CKV_AWS_348 | — | iam | aws_iam_access_key | Ensure IAM root user does not have Access keys |
| checkov | CKV_AWS_358 | — | iam | aws_iam_policy_document | Ensure AWS GitHub Actions OIDC authorization policies only allow |
| checkov | CKV_AWS_40 | — | iam | aws_iam_user_policy_attachment, aws_iam_ | Ensure IAM policies are attached only to groups or roles (Reduci |
| checkov | CKV_AWS_49 | — | iam | aws_iam_policy_document | Ensure no IAM policies documents allow "*" as a statement's acti |
| checkov | CKV_AWS_60 | — | iam | aws_iam_role | Ensure IAM role allows only specific services or principals to a |
| checkov | CKV_AWS_61 | — | iam | aws_iam_role | Ensure AWS IAM policy does not allow assume role permission acro |
| checkov | CKV_AWS_62 | — | iam | aws_iam_role_policy, aws_iam_user_policy | Ensure IAM policies that allow full "*-*" administrative privile |
| checkov | CKV_AWS_63 | — | iam | aws_iam_role_policy, aws_iam_user_policy | Ensure no IAM policies documents allow "*" as a statement's acti |
| checkov | CKV_AWS_9 | — | iam | aws_iam_account_password_policy | Ensure IAM password policy expires passwords within 90 days or l |

### imagebuilder — 0 trivy + 3 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_180 | — | encryption | aws_imagebuilder_component | Ensure Image Builder component is encrypted by KMS using a custo |
| checkov | CKV_AWS_199 | — | encryption | aws_imagebuilder_distribution_configurat | Ensure Image Builder Distribution Configuration encrypts AMI's u |
| checkov | CKV_AWS_200 | — | encryption | aws_imagebuilder_image_recipe | Ensure that Image Recipe EBS Disk are encrypted with CMK |

### kendra — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_262 | — | encryption | aws_kendra_index | Ensure Kendra index Server side encryption uses CMK |

### keyspaces — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_265 | — | encryption | aws_keyspaces_table | Ensure Keyspaces Table uses CMK |

### kinesis — 1 trivy + 5 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0064 | high | — | — | Kinesis stream is unencrypted. |
| checkov | CKV_AWS_177 | — | encryption | aws_kinesis_video_stream | Ensure Kinesis Video Stream is encrypted by KMS using a customer |
| checkov | CKV_AWS_185 | — | encryption | aws_kinesis_stream | Ensure Kinesis Stream is encrypted by KMS using a customer manag |
| checkov | CKV_AWS_240 | — | encryption | aws_kinesis_firehose_delivery_stream | Ensure Kinesis Firehose delivery stream is encrypted |
| checkov | CKV_AWS_241 | — | encryption | aws_kinesis_firehose_delivery_stream | Ensure that Kinesis Firehose Delivery Streams are encrypted with |
| checkov | CKV_AWS_43 | — | encryption | aws_kinesis_stream | Ensure Kinesis Stream is securely encrypted |

### kms — 1 trivy + 4 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0065 | medium | — | — | A KMS key is not configured to auto-rotate. |
| checkov | CKV2_AWS_64 | — | iam | aws_kms_key | Ensure KMS key Policy is defined |
| checkov | CKV_AWS_227 | — | encryption | aws_kms_key | Ensure KMS key is enabled |
| checkov | CKV_AWS_33 | — | encryption | aws_kms_key | Ensure KMS key policy does not contain wildcard (*) principal |
| checkov | CKV_AWS_7 | — | encryption | aws_kms_key | Ensure rotation for customer created CMKs is enabled |

### lambda — 2 trivy + 12 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0067 | critical | — | — | Ensure that lambda function permission has a source arn specifie |
| trivy | AWS-0066 | low | — | — | Lambda functions should have X-Ray tracing enabled |
| checkov | CKV2_AWS_75 | — | networking | aws_lambda_function, aws_lambda_function | Ensure no open CORS policy |
| checkov | CKV_AWS_115 | — | general security | aws_lambda_function | Ensure that AWS Lambda function is configured for function-level |
| checkov | CKV_AWS_116 | — | general security | aws_lambda_function | Ensure that AWS Lambda function is configured for a Dead Letter  |
| checkov | CKV_AWS_117 | — | general security | aws_lambda_function | Ensure that AWS Lambda function is configured inside a VPC |
| checkov | CKV_AWS_173 | — | encryption | aws_lambda_function | Check encryption settings for Lambda environmental variable |
| checkov | CKV_AWS_258 | — | general security | aws_lambda_function_url | Ensure that Lambda function URLs AuthType is not None |
| checkov | CKV_AWS_272 | — | supply chain | aws_lambda_function | Ensure AWS Lambda function is configured to validate code-signin |
| checkov | CKV_AWS_301 | — | general security | aws_lambda_permission | Ensure that AWS Lambda function is not publicly accessible |
| checkov | CKV_AWS_363 | — | general security | aws_lambda_function | Ensure Lambda Runtime is not deprecated |
| checkov | CKV_AWS_364 | — | iam | aws_lambda_permission | Ensure that AWS Lambda function permissions delegated to AWS ser |
| checkov | CKV_AWS_45 | — | secrets | aws_lambda_function | Ensure no hard-coded secrets exist in lambda environment |
| checkov | CKV_AWS_50 | — | logging | aws_lambda_function | X-Ray tracing is enabled for Lambda |

### load — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_213 | — | networking | aws_load_balancer_policy | Ensure ELB Policy uses only secure protocols |

### memorydb — 0 trivy + 3 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_201 | — | encryption | aws_memorydb_cluster | Ensure MemoryDB is encrypted at rest using KMS CMKs |
| checkov | CKV_AWS_202 | — | encryption | aws_memorydb_cluster | Ensure MemoryDB data is encrypted in transit |
| checkov | CKV_AWS_278 | — | encryption | aws_memorydb_snapshot | Ensure MemoryDB snapshot is encrypted by KMS using a customer ma |

### mq — 3 trivy + 6 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0072 | high | — | — | Ensure MQ Broker is not publicly exposed |
| trivy | AWS-0070 | medium | — | — | MQ Broker should have audit logging enabled |
| trivy | AWS-0071 | low | — | — | MQ Broker should have general logging enabled |
| checkov | CKV_AWS_197 | — | logging | aws_mq_broker | Ensure MQ Broker Audit logging is enabled |
| checkov | CKV_AWS_207 | — | general security | aws_mq_broker | Ensure MQ Broker minor version updates are enabled |
| checkov | CKV_AWS_208 | — | general security | aws_mq_broker, aws_mq_configuration | Ensure MQ Broker version is current |
| checkov | CKV_AWS_209 | — | encryption | aws_mq_broker | Ensure MQ broker encrypted by KMS using a customer managed Key ( |
| checkov | CKV_AWS_48 | — | logging | aws_mq_broker | Ensure MQ Broker logging is enabled |
| checkov | CKV_AWS_69 | — | networking | aws_mq_broker | Ensure MQ Broker is not publicly exposed |

### msk — 3 trivy + 3 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0073 | high | — | — | A MSK cluster allows unencrypted data in transit. |
| trivy | AWS-0179 | high | — | — | A MSK cluster allows unencrypted data at rest. |
| trivy | AWS-0074 | medium | — | — | Ensure MSK Cluster logging is enabled |
| checkov | CKV_AWS_291 | — | networking | aws_msk_cluster | Ensure MSK nodes are private |
| checkov | CKV_AWS_80 | — | logging | aws_msk_cluster | Ensure MSK Cluster logging is enabled |
| checkov | CKV_AWS_81 | — | encryption | aws_msk_cluster | Ensure MSK Cluster encryption in rest and transit is enabled |

### mwaa — 0 trivy + 4 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_AWS_66 | — | networking | aws_mwaa_environment | Ensure MWAA environment is not publicly accessible |
| checkov | CKV_AWS_242 | — | logging | aws_mwaa_environment | Ensure MWAA environment has scheduler logs enabled |
| checkov | CKV_AWS_243 | — | logging | aws_mwaa_environment | Ensure MWAA environment has worker logs enabled |
| checkov | CKV_AWS_244 | — | logging | aws_mwaa_environment | Ensure MWAA environment has webserver logs enabled |

### neptune — 3 trivy + 10 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0076 | high | — | — | Neptune storage must be encrypted at rest |
| trivy | AWS-0128 | high | — | — | Neptune encryption should use Customer Managed Keys |
| trivy | AWS-0075 | medium | — | — | Neptune logs export should be enabled |
| checkov | CKV2_AWS_58 | — | general security | aws_neptune_cluster | Ensure AWS Neptune cluster deletion protection is enabled |
| checkov | CKV_AWS_101 | — | logging | aws_neptune_cluster | Ensure Neptune logging is enabled |
| checkov | CKV_AWS_102 | — | general security | aws_neptune_cluster_instance | Ensure Neptune Cluster instance is not publicly available |
| checkov | CKV_AWS_279 | — | encryption | aws_neptune_cluster_snapshot | Ensure Neptune snapshot is securely encrypted |
| checkov | CKV_AWS_280 | — | encryption | aws_neptune_cluster_snapshot | Ensure Neptune snapshot is encrypted by KMS using a customer man |
| checkov | CKV_AWS_347 | — | encryption | aws_neptune_cluster | Ensure Neptune is encrypted by KMS using a customer managed Key  |
| checkov | CKV_AWS_359 | — | iam | aws_neptune_cluster | Neptune DB clusters should have IAM database authentication enab |
| checkov | CKV_AWS_361 | — | backup and recovery | aws_neptune_cluster | Ensure that Neptune DB cluster has automated backups enabled wit |
| checkov | CKV_AWS_362 | — | backup and recovery | aws_neptune_cluster | Neptune DB clusters should be configured to copy tags to snapsho |
| checkov | CKV_AWS_44 | — | encryption | aws_neptune_cluster | Ensure Neptune storage is securely encrypted |

### networkfirewall — 0 trivy + 4 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_AWS_63 | — | logging | aws_networkfirewall_firewall | Ensure Network firewall has logging configuration defined |
| checkov | CKV_AWS_344 | — | general security | aws_networkfirewall_firewall | Ensure that Network firewalls have deletion protection enabled |
| checkov | CKV_AWS_345 | — | encryption | aws_networkfirewall_firewall, aws_networ | Ensure that Network firewall encryption is via a CMK |
| checkov | CKV_AWS_346 | — | encryption | aws_networkfirewall_firewall_policy | Ensure Network Firewall Policy defines an encryption configurati |

### qldb — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_170 | — | iam | aws_qldb_ledger | Ensure QLDB ledger permissions mode is set to STANDARD |
| checkov | CKV_AWS_172 | — | general security | aws_qldb_ledger | Ensure QLDB ledger has deletion protection enabled |

### rds — 9 trivy + 34 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0079 | high | — | — | There is no encryption specified or encryption is disabled on th |
| trivy | AWS-0080 | high | — | — | RDS encryption has not been enabled at a DB Instance level. |
| trivy | AWS-0180 | high | — | — | RDS Publicly Accessible |
| trivy | AWS-0077 | medium | — | — | RDS Cluster and RDS instance should have backup retention longer |
| trivy | AWS-0176 | medium | — | — | RDS IAM Database Authentication Disabled |
| trivy | AWS-0177 | medium | — | — | RDS Deletion Protection Disabled |
| trivy | AWS-0343 | medium | — | — | RDS Cluster Deletion Protection Disabled |
| trivy | AWS-0078 | low | — | — | Performance Insights encryption should use Customer Managed Keys |
| trivy | AWS-0133 | low | — | — | Enable Performance Insights to detect potential problems |
| checkov | CKV2_AWS_27 | — | logging | aws_rds_cluster, aws_rds_cluster_paramet | Ensure Postgres RDS as aws_rds_cluster has Query Logging enabled |
| checkov | CKV2_AWS_30 | — | logging | aws_db_instance, aws_db_parameter_group | Ensure Postgres RDS as aws_db_instance has Query Logging enabled |
| checkov | CKV2_AWS_60 | — | general security | aws_db_instance | Ensure RDS instance with copy tags to snapshots is enabled |
| checkov | CKV2_AWS_69 | — | networking | aws_db_instance, aws_db_parameter_group | Ensure AWS RDS database instance configured with encryption in t |
| checkov | CKV2_AWS_8 | — | backup and recovery | aws_rds_cluster | Ensure that RDS clusters has backup plan of AWS Backup |
| checkov | CKV_AWS_118 | — | logging | aws_db_instance, aws_rds_cluster_instanc | Ensure that enhanced monitoring is enabled for Amazon RDS instan |
| checkov | CKV_AWS_129 | — | logging | aws_db_instance | Ensure that respective logs of Amazon Relational Database Servic |
| checkov | CKV_AWS_133 | — | backup and recovery | aws_rds_cluster, aws_db_instance | Ensure that RDS instances has backup policy |
| checkov | CKV_AWS_139 | — | general security | aws_rds_cluster | Ensure that RDS clusters have deletion protection enabled |
| checkov | CKV_AWS_140 | — | encryption | aws_rds_global_cluster | Ensure that RDS global clusters are encrypted |
| checkov | CKV_AWS_146 | — | encryption | aws_db_cluster_snapshot | Ensure that RDS database cluster snapshot is encrypted |
| checkov | CKV_AWS_157 | — | backup and recovery | aws_db_instance | Ensure that RDS instances have Multi-AZ enabled |
| checkov | CKV_AWS_16 | — | encryption | aws_db_instance | Ensure all data stored in the RDS is securely encrypted at rest |
| checkov | CKV_AWS_161 | — | iam | aws_db_instance | Ensure RDS database has IAM authentication enabled |
| checkov | CKV_AWS_162 | — | iam | aws_rds_cluster | Ensure RDS cluster has IAM authentication enabled |
| checkov | CKV_AWS_17 | — | networking | aws_db_instance, aws_rds_cluster_instanc | Ensure all data stored in RDS is not publicly accessible |
| checkov | CKV_AWS_198 | — | networking | aws_db_security_group | Ensure no aws_db_security_group resources exist |
| checkov | CKV_AWS_211 | — | general security | aws_db_instance | Ensure RDS uses a modern CaCert |
| checkov | CKV_AWS_226 | — | encryption | aws_db_instance, aws_rds_cluster_instanc | Ensure DB instance gets all minor upgrades automatically |
| checkov | CKV_AWS_245 | — | encryption | aws_db_instance_automated_backups_replic | Ensure replicated backups are encrypted at rest using KMS CMKs |
| checkov | CKV_AWS_246 | — | encryption | aws_rds_cluster_activity_stream | Ensure RDS Cluster activity streams are encrypted using KMS CMKs |
| checkov | CKV_AWS_250 | — | general security | aws_rds_cluster, aws_db_instance | Ensure that RDS PostgreSQL instances use a non vulnerable versio |
| checkov | CKV_AWS_266 | — | encryption | aws_db_snapshot_copy | Ensure DB Snapshot copy uses CMK |
| checkov | CKV_AWS_293 | — | general security | aws_db_instance | Ensure that AWS database instances have deletion protection enab |
| checkov | CKV_AWS_302 | — | general security | aws_db_snapshot | Ensure DB Snapshots are not Public |
| checkov | CKV_AWS_313 | — | general security | aws_rds_cluster | Ensure RDS cluster configured to copy tags to snapshots |
| checkov | CKV_AWS_324 | — | logging | aws_rds_cluster | Ensure that RDS Cluster log capture is enabled |
| checkov | CKV_AWS_325 | — | logging | aws_rds_cluster | Ensure that RDS Cluster audit logging is enabled for MySQL engin |
| checkov | CKV_AWS_326 | — | general security | aws_rds_cluster | Ensure that RDS Aurora Clusters have backtracking enabled |
| checkov | CKV_AWS_327 | — | encryption | aws_rds_cluster | Ensure RDS Clusters are encrypted using KMS CMKs |
| checkov | CKV_AWS_353 | — | logging | aws_rds_cluster_instance, aws_db_instanc | Ensure that RDS instances have performance insights enabled |
| checkov | CKV_AWS_354 | — | encryption | aws_rds_cluster_instance, aws_db_instanc | Ensure RDS Performance Insights are encrypted using KMS CMKs |
| checkov | CKV_AWS_388 | — | general security | aws_db_instance | Ensure AWS Aurora PostgreSQL is not exposed to local file read v |
| checkov | CKV_AWS_96 | — | encryption | aws_rds_cluster | Ensure all data stored in Aurora is securely encrypted at rest |

### redshift — 4 trivy + 12 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0085 | critical | — | — | AWS Classic resource usage. |
| trivy | AWS-0084 | high | — | — | Redshift clusters should use at rest encryption |
| trivy | AWS-0127 | high | — | — | Redshift cluster should be deployed into a specific VPC |
| trivy | AWS-0083 | low | — | — | Missing description for security group/security group rule. |
| checkov | CKV_AWS_105 | — | encryption | aws_redshift_parameter_group | Ensure Redshift uses SSL |
| checkov | CKV_AWS_141 | — | general security | aws_redshift_cluster | Ensured that Redshift cluster allowing version upgrade by defaul |
| checkov | CKV_AWS_142 | — | encryption | aws_redshift_cluster | Ensure that Redshift cluster is encrypted by KMS |
| checkov | CKV_AWS_154 | — | networking | aws_redshift_cluster | Ensure Redshift is not deployed outside of a VPC |
| checkov | CKV_AWS_281 | — | encryption | aws_redshift_snapshot_copy_grant | Ensure RedShift snapshot copy is encrypted by KMS using a custom |
| checkov | CKV_AWS_320 | — | general security | aws_redshift_cluster | Ensure Redshift clusters do not use the default database name |
| checkov | CKV_AWS_321 | — | general security | aws_redshift_cluster | Ensure Redshift clusters use enhanced VPC routing |
| checkov | CKV_AWS_343 | — | backup and recovery | aws_redshift_cluster | Ensure Amazon Redshift clusters should have automatic snapshots  |
| checkov | CKV_AWS_391 | — | networking | aws_redshift_cluster | Avoid AWS Redshift cluster with commonly used master username an |
| checkov | CKV_AWS_64 | — | encryption | aws_redshift_cluster | Ensure all data stored in the Redshift cluster is securely encry |
| checkov | CKV_AWS_71 | — | logging | aws_redshift_cluster | Ensure Redshift Cluster logging is enabled |
| checkov | CKV_AWS_87 | — | networking | aws_redshift_cluster | Redshift cluster should not be publicly accessible |

### redshiftserverless — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_282 | — | encryption | aws_redshiftserverless_namespace | Ensure that Redshift Serverless namespace is encrypted by KMS us |

### route53 — 0 trivy + 3 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_AWS_23 | — | networking | aws_route53_record | Route53 A Record has Attached Resource |
| checkov | CKV2_AWS_38 | — | networking | aws_route53_zone | Ensure Domain Name System Security Extensions (DNSSEC) signing i |
| checkov | CKV2_AWS_39 | — | logging | aws_route53_zone | Ensure Domain Name System (DNS) query logging is enabled for Ama |

### route53domains — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_377 | — | networking | aws_route53domains_registered_domain | Ensure Route 53 domains have transfer lock protection |

### s3 — 14 trivy + 25 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0086 | high | — | — | S3 Access block should block public ACL |
| trivy | AWS-0087 | high | — | — | S3 Access block should block public policy |
| trivy | AWS-0088 | high | — | — | Unencrypted S3 bucket. |
| trivy | AWS-0091 | high | — | — | S3 Access Block should Ignore Public ACL |
| trivy | AWS-0092 | high | — | — | S3 Buckets not publicly accessible through ACL. |
| trivy | AWS-0093 | high | — | — | S3 Access block should restrict public bucket to limit access |
| trivy | AWS-0132 | high | — | — | S3 encryption should use Customer Managed Keys |
| trivy | AWS-0090 | medium | — | — | S3 Data should be versioned |
| trivy | AWS-0320 | medium | — | — | S3 DNS Compliant Bucket Names |
| trivy | AWS-0089 | low | — | — | S3 Bucket Logging |
| trivy | AWS-0094 | low | — | — | S3 buckets should each define an aws_s3_bucket_public_access_blo |
| trivy | AWS-0170 | low | — | — | Buckets should have MFA deletion protection enabled. |
| trivy | AWS-0171 | low | — | — | S3 object-level API operations such as GetObject, DeleteObject,  |
| trivy | AWS-0172 | low | — | — | S3 object-level API operations such as GetObject, DeleteObject,  |
| checkov | CKV2_AWS_43 | — | iam | aws_s3_bucket_acl | Ensure S3 Bucket does not allow access to all Authenticated user |
| checkov | CKV2_AWS_6 | — | networking | aws_s3_bucket, aws_s3_bucket_public_acce | Ensure that S3 bucket has a Public Access block |
| checkov | CKV2_AWS_61 | — | logging | aws_s3_bucket | Ensure that an S3 bucket has a lifecycle configuration |
| checkov | CKV2_AWS_62 | — | logging | aws_s3_bucket | Ensure S3 buckets should have event notifications enabled |
| checkov | CKV2_AWS_65 | — | general security | aws_s3_bucket_ownership_controls | Ensure access control lists for S3 buckets are disabled |
| checkov | CKV_AWS_143 | — | general security | aws_s3_bucket | Ensure that S3 bucket has lock configuration enabled by default |
| checkov | CKV_AWS_144 | — | general security | aws_s3_bucket, aws_s3_bucket_replication | Ensure that S3 bucket has cross-region replication enabled |
| checkov | CKV_AWS_145 | — | encryption | aws_s3_bucket, aws_s3_bucket_server_side | Ensure that S3 buckets are encrypted with KMS by default |
| checkov | CKV_AWS_18 | — | logging | aws_s3_bucket | Ensure the S3 bucket has access logging enabled |
| checkov | CKV_AWS_181 | — | encryption | aws_s3_object_copy | Ensure S3 Object Copy is encrypted by KMS using a customer manag |
| checkov | CKV_AWS_186 | — | encryption | aws_s3_bucket_object | Ensure S3 bucket Object is encrypted by KMS using a customer man |
| checkov | CKV_AWS_19 | — | encryption | aws_s3_bucket, aws_s3_bucket_server_side | Ensure all data stored in the S3 bucket is securely encrypted at |
| checkov | CKV_AWS_20 | — | general security | aws_s3_bucket, aws_s3_bucket_acl | S3 Bucket has an ACL defined which allows public READ access. |
| checkov | CKV_AWS_21 | — | backup and recovery | aws_s3_bucket, aws_s3_bucket_versioning | Ensure all data stored in the S3 bucket have versioning enabled |
| checkov | CKV_AWS_300 | — | general security | aws_s3_bucket_lifecycle_configuration | Ensure S3 lifecycle configuration sets period for aborting faile |
| checkov | CKV_AWS_375 | — | networking | aws_s3_bucket_acl | Ensure AWS S3 bucket does not have global view ACL permissions e |
| checkov | CKV_AWS_379 | — | networking | aws_s3_bucket_acl | Ensure AWS S3 bucket is configured with secure data transport po |
| checkov | CKV_AWS_392 | — | networking | aws_s3_access_point | Ensure AWS S3 access point block public access setting is enable |
| checkov | CKV_AWS_53 | — | general security | aws_s3_bucket_public_access_block | Ensure S3 bucket has block public ACLS enabled |
| checkov | CKV_AWS_54 | — | general security | aws_s3_bucket_public_access_block | Ensure S3 bucket has block public policy enabled |
| checkov | CKV_AWS_55 | — | general security | aws_s3_bucket_public_access_block | Ensure S3 bucket has ignore public ACLs enabled |
| checkov | CKV_AWS_56 | — | general security | aws_s3_bucket_public_access_block | Ensure S3 bucket has 'restrict_public_buckets' enabled |
| checkov | CKV_AWS_57 | — | general security | aws_s3_bucket, aws_s3_bucket_acl | S3 Bucket has an ACL defined which allows public WRITE access. |
| checkov | CKV_AWS_70 | — | iam | aws_s3_bucket, aws_s3_bucket_policy | Ensure S3 bucket does not allow an action with any Principal |
| checkov | CKV_AWS_93 | — | iam | aws_s3_bucket, aws_s3_bucket_policy | Ensure S3 bucket policy does not lockout all but root user. (Pre |

### sagemaker — 0 trivy + 12 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_122 | — | networking | aws_sagemaker_notebook_instance | Ensure that direct internet access is disabled for an Amazon Sag |
| checkov | CKV_AWS_187 | — | encryption | aws_sagemaker_domain, aws_sagemaker_note | Ensure Sagemaker domain and notebook instance are encrypted by K |
| checkov | CKV_AWS_22 | — | encryption | aws_sagemaker_notebook_instance | Ensure SageMaker Notebook is encrypted at rest using KMS CMK |
| checkov | CKV_AWS_306 | — | networking | aws_sagemaker_notebook_instance | Ensure SageMaker notebook instances should be launched into a cu |
| checkov | CKV_AWS_307 | — | general security | aws_sagemaker_notebook_instance | Ensure SageMaker Users should not have root access to SageMaker  |
| checkov | CKV_AWS_367 | — | encryption | aws_sagemaker_data_quality_job_definitio | Ensure Amazon Sagemaker Data Quality Job uses KMS to encrypt mod |
| checkov | CKV_AWS_368 | — | encryption | aws_sagemaker_data_quality_job_definitio | Ensure Amazon Sagemaker Data Quality Job uses KMS to encrypt dat |
| checkov | CKV_AWS_369 | — | encryption | aws_sagemaker_data_quality_job_definitio | Ensure Amazon Sagemaker Data Quality Job encrypts all communicat |
| checkov | CKV_AWS_370 | — | networking | aws_sagemaker_model | Ensure Amazon SageMaker model uses network isolation |
| checkov | CKV_AWS_371 | — | encryption | aws_sagemaker_notebook_instance | Ensure Amazon SageMaker Notebook Instance only allows for IMDSv2 |
| checkov | CKV_AWS_372 | — | encryption | aws_sagemaker_flow_definition | Ensure Amazon SageMaker Flow Definition uses KMS for output conf |
| checkov | CKV_AWS_98 | — | encryption | aws_sagemaker_endpoint_configuration | Ensure all data stored in the Sagemaker Endpoint is securely enc |

### sam — 11 trivy + 0 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0112 | high | — | — | SAM API domain name uses outdated SSL/TLS protocols. |
| trivy | AWS-0114 | high | — | — | Function policies should avoid use of wildcards and instead appl |
| trivy | AWS-0120 | high | — | — | State machine policies should avoid use of wildcards and instead |
| trivy | AWS-0121 | high | — | — | SAM Simple table must have server side encryption enabled. |
| trivy | AWS-0110 | medium | — | — | SAM API must have data cache enabled |
| trivy | AWS-0113 | medium | — | — | SAM API stages for V1 and V2 should have access logging enabled |
| trivy | AWS-0116 | medium | — | — | SAM HTTP API stages for V1 and V2 should have access logging ena |
| trivy | AWS-0111 | low | — | — | SAM API must have X-Ray tracing enabled |
| trivy | AWS-0117 | low | — | — | SAM State machine must have X-Ray tracing enabled |
| trivy | AWS-0119 | low | — | — | SAM State machine must have logging enabled |
| trivy | AWS-0125 | low | — | — | SAM Function must have X-Ray tracing enabled |

### scheduler — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_297 | — | encryption | aws_scheduler_schedule | Ensure EventBridge Scheduler Schedule uses Customer Managed Key  |

### ses — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_365 | — | networking | aws_ses_configuration_set | Ensure SES Configuration Set enforces TLS usage |

### sfn — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_284 | — | logging | aws_sfn_state_machine | Ensure State Machine has X-Ray tracing enabled |
| checkov | CKV_AWS_285 | — | logging | aws_sfn_state_machine | Ensure State Machine has execution history logging enabled |

### sns — 2 trivy + 3 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0095 | high | — | — | Unencrypted SNS topic. |
| trivy | AWS-0136 | high | — | — | SNS topic not encrypted with CMK. |
| checkov | CKV_AWS_169 | — | iam | aws_sns_topic_policy | Ensure SNS topic policy is not public by only allowing specific  |
| checkov | CKV_AWS_26 | — | encryption | aws_sns_topic | Ensure all data stored in the SNS topic is encrypted |
| checkov | CKV_AWS_385 | — | iam | aws_sns_topic_policy | Ensure AWS SNS topic policies do not allow cross-account access |

### sqs — 3 trivy + 5 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0096 | high | — | — | Unencrypted SQS queue. |
| trivy | AWS-0097 | high | — | — | AWS SQS policy document has wildcard action statement. |
| trivy | AWS-0135 | high | — | — | SQS queue should be encrypted with a CMK. |
| checkov | CKV2_AWS_73 | — | encryption | aws_sqs_queue | Ensure AWS SQS uses CMK not AWS default keys for encryption |
| checkov | CKV_AWS_168 | — | iam | aws_sqs_queue_policy, aws_sqs_queue | Ensure SQS queue policy is not public by only allowing specific  |
| checkov | CKV_AWS_27 | — | encryption | aws_sqs_queue | Ensure all data stored in the SQS queue is encrypted |
| checkov | CKV_AWS_387 | — | general security | aws_sqs_queue_policy | Ensure SQS policy does not allow public access through wildcards |
| checkov | CKV_AWS_72 | — | general security | aws_sqs_queue_policy | Ensure SQS policy does not allow ALL (*) actions. |

### ssm — 2 trivy + 9 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0134 | critical | — | — | Secrets should not be exfiltrated using Terraform HTTP data bloc |
| checkov | CKV2_AWS_34 | medium | encryption | aws_ssm_parameter | AWS SSM Parameter should be Encrypted |
| trivy | AWS-0098 | low | — | — | Secrets Manager should use customer managed keys |
| checkov | CKV2_AWS_36 | — | supply chain | aws_ssm_parameter, data.http | Ensure terraform is not sending SSM secrets to untrusted domains |
| checkov | CKV2_AWS_57 | — | general security | aws_secretsmanager_secret | Ensure Secrets Manager secrets should have automatic rotation en |
| checkov | CKV_AWS_112 | — | encryption | aws_ssm_document | Ensure Session Manager data is encrypted in transit |
| checkov | CKV_AWS_113 | — | encryption,logging | aws_ssm_document | Ensure Session Manager logs are enabled and encrypted |
| checkov | CKV_AWS_149 | — | encryption | aws_secretsmanager_secret | Ensure that Secrets Manager secret is encrypted using KMS CMK |
| checkov | CKV_AWS_303 | — | general security | aws_ssm_document | Ensure SSM documents are not Public |
| checkov | CKV_AWS_304 | — | general security | aws_secretsmanager_secret_rotation | Ensure Secrets Manager secrets should be rotated within 90 days |
| checkov | CKV_AWS_337 | — | encryption | aws_ssm_parameter | Ensure SSM parameters are using KMS CMK |

### timestreamwrite — 0 trivy + 1 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_160 | — | encryption | aws_timestreamwrite_database | Ensure that Timestream database is encrypted with KMS CMK |

### transfer — 0 trivy + 3 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_164 | — | general security | aws_transfer_server | Ensure Transfer Server is not exposed publicly. |
| checkov | CKV_AWS_357 | — | encryption | aws_transfer_server | Ensure Transfer Server allows only secure protocols |
| checkov | CKV_AWS_380 | — | networking | aws_transfer_server | Ensure AWS Transfer Server uses latest Security Policy |

### waf — 0 trivy + 3 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV_AWS_175 | — | application security | aws_waf_web_acl, aws_wafregional_web_acl | Ensure WAF has associated rules |
| checkov | CKV_AWS_176 | — | logging | aws_waf_web_acl, aws_wafregional_web_acl | Ensure Logging is enabled for WAF Web Access Control Lists |
| checkov | CKV_AWS_342 | — | application security | aws_waf_web_acl, aws_wafregional_web_acl | Ensure WAF rule has any actions |

### wafv2 — 0 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| checkov | CKV2_AWS_31 | — | logging | aws_wafv2_web_acl | Ensure WAF2 has a Logging Configuration |
| checkov | CKV_AWS_192 | — | application security | aws_wafv2_web_acl | Ensure WAF prevents message lookup in Log4j2. See CVE-2021-44228 |

### workspaces — 1 trivy + 2 checkov

| tool | id | sev | category | resource | title |
|---|---|---|---|---|---|
| trivy | AWS-0109 | high | — | — | Root and user volumes on Workspaces should be encrypted |
| checkov | CKV_AWS_155 | — | encryption | aws_workspaces_workspace | Ensure that Workspace user volumes are encrypted |
| checkov | CKV_AWS_156 | — | encryption | aws_workspaces_workspace | Ensure that Workspace root volumes are encrypted |

