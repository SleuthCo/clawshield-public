---
framework: "AWS Security Services"
version: "1.0"
domain: "Cloud Security"
agent: "nimbus"
tags: ["aws", "security", "iam", "guardduty", "encryption", "compliance"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# AWS Security Services

AWS provides a comprehensive set of security services that address identity management, detection, infrastructure protection, data protection, and incident response. This document covers when to use each service, how they interrelate, and architecture patterns for defense in depth.

## IAM Policies and Identity Management

AWS Identity and Access Management (IAM) is the foundation of all AWS security. Every API call is authenticated and authorized through IAM.

### Policy Types and Evaluation Order

IAM policy evaluation follows a specific order. Understanding this is critical for debugging access issues:

1. **Service Control Policies (SCPs)**: Organization-level guardrails that set maximum permissions for member accounts. SCPs do not grant permissions; they restrict what identity-based and resource-based policies can grant.
2. **Resource-based policies**: Attached directly to resources (S3 bucket policies, KMS key policies, SQS queue policies). Can grant cross-account access.
3. **IAM permissions boundaries**: Set the maximum permissions an IAM entity (user or role) can have. Useful for delegating role creation safely.
4. **Identity-based policies**: Attached to IAM users, groups, or roles. These are the most common policy type.
5. **Session policies**: Passed as parameters when creating a temporary session (AssumeRole, federation).

### Policy Authoring Best Practices

- Use the least privilege principle: Start with no permissions and add only what is needed. Use IAM Access Analyzer to identify unused permissions and generate least-privilege policies.
- Avoid wildcards in actions: Instead of `s3:*`, use specific actions like `s3:GetObject`, `s3:PutObject`.
- Use conditions to restrict access: Require MFA (`aws:MultiFactorAuthPresent`), restrict by source IP (`aws:SourceIp`), enforce encryption (`s3:x-amz-server-side-encryption`), or limit to specific VPC endpoints (`aws:SourceVpce`).
- Tag-based access control (ABAC): Use resource tags and principal tags for scalable permissions. Example: Allow users to manage EC2 instances tagged with their department.

### Cross-Account Access Patterns

- **Assume Role**: Create a role in the target account with a trust policy allowing the source account. Use `sts:AssumeRole` from the source account. Preferred for programmatic cross-account access.
- **Resource-based policies**: Grant access directly on the resource (S3 buckets, KMS keys, SQS queues). Useful when you do not want the calling principal to give up their original permissions.
- **AWS Organizations**: Use delegated administrator and trusted access features for multi-account service management.

## Service Control Policies (SCPs)

SCPs are JSON policies attached to Organization root, OUs, or accounts that define the maximum permissions for all principals in the target scope.

### Common SCP Patterns

- **Deny Region Restriction**: Prevent use of non-approved regions while allowing global services (IAM, CloudFront, Route 53, Organizations, STS).
- **Deny Root Account Usage**: Prevent root user from performing any actions except those requiring root credentials.
- **Require Encryption**: Deny S3 PutObject without server-side encryption, deny creating unencrypted EBS volumes and RDS instances.
- **Prevent Leaving Organization**: Deny `organizations:LeaveOrganization` to prevent accounts from removing themselves.
- **Protect Security Services**: Deny disabling CloudTrail, GuardDuty, Config, or Security Hub. Deny modifying security-critical IAM roles.
- **Prevent VPC Changes**: Restrict modification of VPCs, subnets, route tables, and internet gateways in production accounts.

### SCP Design Strategy

- Use a deny-list approach (start with full access, deny dangerous actions) rather than an allow-list approach for most organizations. Allow-lists are more secure but harder to maintain.
- Apply SCPs at the OU level, not individual accounts, for manageability.
- Always test SCPs in a sandbox OU before applying to production.
- SCPs do not affect the management account. Critical security controls should be compensated in the management account through other mechanisms.

## Amazon GuardDuty

GuardDuty is a threat detection service that continuously monitors for malicious activity and unauthorized behavior using ML, anomaly detection, and integrated threat intelligence.

### Data Sources

- **CloudTrail Management Events**: Detects unusual API calls, unauthorized access attempts, and suspicious management activity.
- **CloudTrail S3 Data Events**: Detects suspicious data access patterns in S3 (credential exfiltration, unusual data access).
- **VPC Flow Logs**: Detects network-based threats like port scanning, communication with known malicious IPs, cryptocurrency mining traffic.
- **DNS Logs**: Detects DNS-based threats like communication with command-and-control servers.
- **EKS Audit Logs**: Detects suspicious activity in Kubernetes clusters.
- **RDS Login Activity**: Detects anomalous login behavior to RDS databases.
- **Lambda Network Activity**: Detects suspicious network activity from Lambda functions.
- **Runtime Monitoring**: Detects runtime threats on EC2, ECS, and EKS using a security agent.

### Architecture Pattern

Enable GuardDuty in every account via Organizations delegated administrator. Route findings to a central Security Hub. Use EventBridge rules to trigger automated remediation (Lambda functions for isolation, notification via SNS/PagerDuty, ticket creation in Jira/ServiceNow).

## AWS Security Hub

Security Hub provides a comprehensive view of security alerts and security posture across AWS accounts. It aggregates, organizes, and prioritizes findings from multiple AWS services and third-party tools.

### Security Standards

- **AWS Foundational Security Best Practices (FSBP)**: AWS-curated set of controls based on AWS best practices.
- **CIS AWS Foundations Benchmark**: Industry-standard benchmark from the Center for Internet Security.
- **PCI DSS**: Controls relevant to organizations handling payment card data.
- **NIST 800-53**: Controls mapped to the NIST Cybersecurity Framework.

### Integration Pattern

Security Hub acts as the central aggregation point. Configure cross-region aggregation to a single region. Use delegated administrator for Organizations-wide enablement. Integrate findings from GuardDuty, Inspector, Macie, Firewall Manager, IAM Access Analyzer, and third-party tools. Export findings to SIEM (Splunk, Sumo Logic, Elasticsearch) via EventBridge for advanced correlation and investigation.

## AWS Config

AWS Config provides a detailed view of the configuration of AWS resources and evaluates resource configurations against desired settings using Config Rules.

### Key Use Cases

- **Configuration History**: Track how a resource was configured at any point in time. Essential for compliance audits and forensic investigations.
- **Config Rules**: Evaluate resource compliance automatically. Use AWS managed rules (200+ available) or write custom rules using Lambda. Examples: ensure EBS volumes are encrypted, ensure S3 buckets are not public, ensure security groups do not allow unrestricted SSH.
- **Conformance Packs**: Deploy collections of Config rules as a single entity. AWS provides sample conformance packs for common compliance frameworks (CIS, HIPAA, PCI DSS, NIST).
- **Remediation**: Attach remediation actions (SSM Automation documents) to Config rules for automatic or manual remediation of non-compliant resources.
- **Aggregator**: Aggregate compliance data across multiple accounts and regions into a single view.

## AWS CloudTrail

CloudTrail records API calls and account activity across your AWS infrastructure. It is foundational for security auditing, governance, and compliance.

### Configuration Best Practices

- Create an organization trail that logs all accounts to a centralized S3 bucket in a dedicated logging account.
- Enable management events in all regions (default for organization trails).
- Enable data events for critical resources: S3 object-level logging for sensitive buckets, Lambda invocation logging, DynamoDB data events.
- Enable CloudTrail Insights to detect unusual API call patterns and error rates.
- Protect the log bucket with S3 Object Lock (WORM) for compliance. Enable MFA Delete on the bucket.
- Enable log file validation to detect tampering.
- Send logs to CloudWatch Logs for real-time metric filters and alarms.

## AWS KMS and Secrets Manager

### KMS (Key Management Service)

KMS provides centralized control over encryption keys. It integrates natively with most AWS services.

- **AWS Managed Keys**: Automatically created and managed by AWS services. No management overhead but limited control over key policies and rotation.
- **Customer Managed Keys (CMK)**: Full control over key policies, rotation, and lifecycle. Required for cross-account access, custom key policies, and regulatory compliance.
- **Custom Key Stores**: Use CloudHSM cluster as the backing store for KMS keys. Required when regulations mandate dedicated HSM.
- **Multi-Region Keys**: Replicate KMS keys across regions for disaster recovery and cross-region encryption scenarios.
- **Key Policy Best Practices**: Follow least privilege. Use grants for temporary access. Enable automatic key rotation (annual for symmetric keys). Use key aliases for abstraction.

### Secrets Manager

Secrets Manager stores, rotates, and retrieves database credentials, API keys, and other secrets.

- **Automatic Rotation**: Configure Lambda functions to rotate secrets automatically. AWS provides rotation functions for RDS, Redshift, and DocumentDB.
- **Cross-Account Access**: Use resource-based policies to share secrets across accounts.
- **Integration**: Applications retrieve secrets via API calls. Use the Secrets Manager caching client library to reduce API calls and latency.
- **Secrets Manager vs Parameter Store**: Use Secrets Manager for credentials that need automatic rotation. Use Parameter Store (SecureString) for configuration values and secrets that do not require rotation. Parameter Store is free for standard parameters.

## AWS WAF and Shield

### WAF (Web Application Firewall)

WAF protects web applications from common exploits. It integrates with CloudFront, ALB, API Gateway, and AppSync.

- **Managed Rule Groups**: AWS Managed Rules cover OWASP Top 10, known bad inputs, SQL injection, XSS, and bot control. AWS Marketplace provides vendor-managed rules (Fortinet, F5, Imperva).
- **Custom Rules**: Write rules to match specific request patterns. Use rate-based rules for DDoS and brute-force mitigation.
- **Bot Control**: Managed rule group that detects and manages bot traffic, including credential stuffing and content scraping.
- **Fraud Control**: Account Takeover Prevention (ATP) and Account Creation Fraud Prevention (ACFP) managed rule groups.

### Shield

- **Shield Standard**: Automatic, free DDoS protection for all AWS customers. Protects against most common layer 3/4 attacks.
- **Shield Advanced**: Enhanced DDoS protection with 24/7 access to the AWS DDoS Response Team (DRT), cost protection (credit for scaling charges during attack), advanced attack diagnostics, and WAF at no additional charge. Required for protecting EC2, ELB, CloudFront, Global Accelerator, and Route 53.

## Amazon Macie

Macie uses ML and pattern matching to discover and protect sensitive data stored in S3.

### Use Cases

- Discover PII (names, addresses, credit card numbers, SSNs) in S3 buckets
- Monitor S3 bucket security posture (public access, encryption, replication)
- Automate sensitive data discovery on a schedule
- Integration with Security Hub for centralized findings
- Custom data identifiers using regex for organization-specific sensitive data patterns

## Amazon Inspector

Inspector is an automated vulnerability management service that continuously scans EC2 instances, container images in ECR, and Lambda functions for software vulnerabilities and unintended network exposure.

### Capabilities

- **EC2 Scanning**: Uses the SSM Agent to scan for OS and application vulnerabilities (CVE-based). No separate agent required.
- **ECR Scanning**: Automatically scans container images pushed to ECR. Supports continuous scanning for new vulnerabilities in existing images.
- **Lambda Scanning**: Scans Lambda function code and dependencies for vulnerabilities.
- **Network Reachability**: Analyzes VPC configuration to identify unintended network exposure.
- **SBOM Export**: Export Software Bill of Materials for all scanned resources.

## Amazon Detective

Detective simplifies the process of investigating security findings. It automatically collects and analyzes data from CloudTrail, VPC Flow Logs, GuardDuty, and EKS Audit Logs to build a linked graph model.

### Investigation Workflow

1. Start from a GuardDuty finding, Security Hub finding, or a specific entity (IP address, IAM principal, EC2 instance)
2. Use the visual investigation graph to explore relationships and activity patterns
3. Examine timelines of API calls, network traffic, and resource interactions
4. Identify the scope and impact of a security event
5. Determine root cause and affected resources

## Security Architecture Patterns

### Multi-Account Security Architecture

```
Organization Management Account
  |-- Security OU
  |     |-- Security Tooling Account (delegated admin for GuardDuty, Security Hub, Config, Inspector, Macie)
  |     |-- Log Archive Account (centralized CloudTrail, Config logs, VPC Flow Logs)
  |-- Infrastructure OU
  |     |-- Network Account (Transit Gateway, DNS, shared networking)
  |-- Workload OU
  |     |-- Production OU (restricted SCPs, mandatory encryption)
  |     |-- Staging OU
  |     |-- Development OU (relaxed SCPs)
  |-- Sandbox OU (isolated experimentation)
```

### Defense in Depth Layers

1. **Perimeter**: CloudFront + WAF + Shield Advanced at the edge
2. **Network**: VPC with private subnets, NACLs, security groups, VPC endpoints for AWS services
3. **Identity**: IAM least privilege, MFA, short-lived credentials via roles, SCPs for guardrails
4. **Application**: Inspector for vulnerability scanning, Secrets Manager for credential management
5. **Data**: KMS encryption at rest, TLS in transit, Macie for data classification, S3 Block Public Access
6. **Detection**: GuardDuty for threat detection, CloudTrail for audit, Config for compliance, Security Hub for aggregation
7. **Response**: EventBridge automation, Lambda remediation, Detective for investigation, runbooks in Systems Manager
