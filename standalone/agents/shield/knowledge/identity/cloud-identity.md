---
framework: "Cloud Identity"
version: "1.0"
domain: "Cloud IAM"
agent: "sentinel"
tags: ["cloud-iam", "aws-iam", "azure-ad", "gcp-iam", "workload-identity", "federation"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Cloud Identity and Access Management

This document covers cloud IAM across major providers (AWS, Azure, GCP), service accounts, workload identity, federation, cross-account access, and least privilege automation.

## AWS IAM

**Core Concepts:**
- IAM Users: long-lived credentials (access key ID + secret access key, or console password)
- IAM Roles: temporary credentials assumed by users, services, or external identities
- IAM Policies: JSON documents defining permissions (effect, action, resource, condition)
- IAM Groups: collections of users sharing common policies
- Identity-based policies: attached to users, groups, or roles
- Resource-based policies: attached to resources (S3 buckets, SQS queues, KMS keys)

**Policy Evaluation Logic:**
1. By default, all requests are implicitly denied
2. Explicit allow in any applicable policy grants access
3. Explicit deny in any applicable policy overrides any allow
4. Service Control Policies (SCPs) set maximum permissions for organization
5. Permission boundaries set maximum permissions for individual roles/users
6. Session policies further constrain assumed role permissions

**AWS IAM Best Practices:**
- Never use the root account for daily operations; secure with MFA
- Use IAM roles instead of long-lived access keys wherever possible
- Implement least privilege: start with minimum permissions and expand as needed
- Use AWS Organizations with Service Control Policies for guardrails
- Enable CloudTrail in all regions for comprehensive API logging
- Implement permission boundaries to delegate admin capabilities safely
- Use IAM Access Analyzer to identify unused permissions and external access
- Rotate access keys every 90 days; prefer roles for programmatic access
- Use AWS SSO (IAM Identity Center) for centralized human access management
- Enable MFA for all human user accounts

**Key AWS IAM Services:**
- IAM Identity Center (SSO): centralized access management for AWS accounts and applications
- AWS Organizations: multi-account management with SCPs
- IAM Access Analyzer: identify resources shared externally and unused permissions
- AWS STS: Security Token Service for temporary credentials
- AWS Secrets Manager: rotate and manage secrets
- AWS KMS: key management for encryption
- AWS CloudTrail: API activity logging for audit and forensics

**Common AWS IAM Misconfigurations:**
- Wildcard (*) in Action or Resource fields granting excessive permissions
- S3 bucket policies allowing public access
- IAM roles with overly broad trust policies (Principal: "*")
- Long-lived access keys without rotation
- Missing condition keys on sensitive actions
- Lambda execution roles with administrative permissions
- Cross-account role trust without external ID condition

## Azure AD / Microsoft Entra ID

**Core Concepts:**
- Tenant: dedicated instance of Azure AD for an organization
- Users: human identities with authentication credentials
- Groups: security groups and Microsoft 365 groups for access management
- Service Principals: identity for applications and services
- Managed Identities: Azure-managed credentials for workloads (system-assigned, user-assigned)
- App Registrations: register applications for authentication integration
- Enterprise Applications: service principals representing external or internal apps

**Azure AD Role Types:**
- Built-in Roles: Global Administrator, Security Administrator, User Administrator, etc.
- Custom Roles: organization-defined roles with specific permissions
- Azure RBAC Roles: scoped to Azure resources (Owner, Contributor, Reader)
- Administrative Units: delegate management of specific user/group subsets

**Privileged Identity Management (PIM):**
- Just-in-time role activation for Azure AD and Azure resource roles
- Requires justification and optional approval for activation
- Time-limited access with configurable maximum duration
- Access reviews for recurring certification of role assignments
- Alerts for suspicious role activation patterns
- Audit history of all PIM operations

**Conditional Access Policies:**
- Signal-based access decisions combining identity, device, location, application, and risk
- Policy components: assignments (who, what, where) + access controls (grant, block, session)
- Common policies:
  - Require MFA for all users accessing cloud applications
  - Block legacy authentication protocols
  - Require compliant device for access to sensitive applications
  - Block access from unauthorized locations or countries
  - Require MFA for risky sign-ins (Identity Protection integration)
  - Restrict application access based on authentication context

**Azure AD Security Best Practices:**
- Enable Security Defaults or implement comprehensive Conditional Access policies
- Block legacy authentication protocols (basic auth, older Exchange protocols)
- Implement PIM for all privileged role assignments
- Use Managed Identities instead of service principal secrets
- Enable Azure AD Identity Protection for risk-based policies
- Implement emergency access (break-glass) accounts with monitoring
- Regular access reviews for all privileged role assignments
- Enable sign-in and audit log forwarding to SIEM

**Common Azure AD Attack Vectors:**
- Password spray against Azure AD authentication endpoints
- Consent phishing: tricking users into granting OAuth app permissions
- Token theft through AiTM phishing proxies
- Abuse of application permissions (Graph API, Exchange, SharePoint)
- Azure AD Connect exploitation (sync account compromise)
- Service principal secret or certificate theft
- Cross-tenant access exploitation

## GCP IAM

**Core Concepts:**
- Google Account: identity for human users
- Service Account: identity for workloads and applications
- IAM Policy: bindings associating members with roles at a resource level
- Roles: collections of permissions (basic, predefined, custom)
- Organization: root node of GCP resource hierarchy
- Folders: grouping mechanism within the organization
- Projects: fundamental organizational unit containing resources

**Role Types:**
- Basic Roles: Owner, Editor, Viewer (broad, avoid in production)
- Predefined Roles: granular, service-specific roles maintained by Google
- Custom Roles: organization-defined roles with specific permission selection

**GCP IAM Hierarchy:**
- Organization > Folder > Project > Resource
- Policies inherited downward; child cannot restrict parent grant
- Set organization-level policies for baseline access
- Use folders for business unit or environment segregation
- Apply most specific permissions at the project or resource level

**GCP IAM Best Practices:**
- Avoid Basic Roles (Owner, Editor) in production; use predefined roles
- Use Workload Identity Federation instead of service account keys
- Implement organization policies (constraints) for guardrails
- Enable VPC Service Controls for data exfiltration prevention
- Use IAM Recommender to right-size permissions
- Implement Workforce Identity Federation for human access (no GCP-native passwords)
- Enable Cloud Audit Logs for all services
- Restrict service account key creation through organization policy
- Implement Domain Restricted Sharing to prevent external collaboration

## Service Accounts and Workload Identity

**Service Account Risks:**
- Long-lived credentials prone to theft and misuse
- Often over-privileged due to lack of regular review
- Difficult to attribute actions to specific workloads
- Key files stored in insecure locations (code repos, env vars, config files)
- No MFA protection for non-interactive authentication

**Modern Workload Identity Approaches:**

**AWS:**
- IAM Roles for EC2: instance metadata provides temporary credentials
- IAM Roles for EKS (IRSA): Kubernetes service accounts mapped to IAM roles
- ECS Task Roles: task-level IAM role assignment
- Lambda Execution Roles: function-level IAM permissions
- IMDSv2: token-required metadata service preventing SSRF-based credential theft

**Azure:**
- System-Assigned Managed Identity: lifecycle tied to the resource
- User-Assigned Managed Identity: independent lifecycle, can be shared
- Workload Identity Federation: external tokens exchanged for Azure AD tokens
- Azure Arc: extend managed identity to on-premises and multi-cloud

**GCP:**
- Workload Identity Federation: exchange external tokens for GCP credentials
- GKE Workload Identity: map Kubernetes service accounts to GCP service accounts
- Attached Service Accounts: VM-level service account with metadata access
- Impersonation: delegate permissions through service account impersonation chain

**SPIFFE/SPIRE (Universal):**
- SPIFFE (Secure Production Identity Framework for Everyone): standard for workload identity
- SPIRE (SPIFFE Runtime Environment): implementation of the SPIFFE standard
- Platform-agnostic workload identity across hybrid and multi-cloud
- Short-lived X.509 certificates (SVIDs) for mutual authentication
- Automatic certificate rotation without application changes
- Eliminates need for static secrets in workload-to-workload communication

## Federation and Cross-Account Access

**Identity Federation Patterns:**

**SAML Federation:**
- Enterprise IdP (Okta, Ping, ADFS) federated with cloud provider
- Users authenticate against corporate directory
- Receive temporary cloud credentials based on SAML assertions
- Attribute mappings determine cloud roles and permissions

**OIDC Federation:**
- Modern alternative to SAML for web and mobile applications
- CI/CD providers (GitHub Actions, GitLab CI) authenticate to cloud without stored secrets
- Workload identity federation using OIDC tokens from external providers
- Short-lived tokens eliminate secret management burden

**AWS Cross-Account Access:**
- Cross-account IAM roles with trust policies
- AWS Organizations for centralized management of multiple accounts
- Resource-based policies for cross-account resource sharing (S3, KMS, SNS)
- AWS RAM (Resource Access Manager) for sharing resources across accounts
- External ID condition to prevent confused deputy attacks
- Transit account pattern for centralized networking

**Azure Cross-Tenant Access:**
- Azure Lighthouse: managed service provider access to customer tenants
- Cross-tenant access settings: inbound and outbound trust policies
- B2B collaboration: guest accounts in Azure AD
- Multi-tenant applications: single app registration serving multiple tenants

**GCP Cross-Project Access:**
- Shared VPC: central networking shared across projects
- Cross-project IAM bindings: grant access at organization or folder level
- Service account impersonation across projects
- Organization-level policies for centralized control

## Least Privilege Automation

**Permission Right-Sizing:**

**AWS:**
- IAM Access Analyzer: generates policies based on actual CloudTrail activity
- Access Advisor: shows last-used timestamp for each service
- Policy Simulator: test policy effects without applying
- Automated process: enable CloudTrail, wait 90 days, generate policy from activity

**Azure:**
- PIM access reviews: periodic certification of role assignments
- Azure AD Identity Governance: entitlement management with auto-expiry
- Azure Policy: enforce organizational standards and assess compliance
- Microsoft Entra Permissions Management: multi-cloud permission analytics

**GCP:**
- IAM Recommender: suggests permission reductions based on usage
- Policy Analyzer: determine effective permissions for identities
- Organization Policy Service: enforce constraints across the hierarchy
- Automated recommendations review and approval workflow

**Access Review Automation:**
- Schedule quarterly access reviews for all privileged access
- Monthly reviews for external/guest access
- Automated reminders and escalation for overdue reviews
- Auto-revocation of access not certified within review period
- Risk-based review frequency: higher risk triggers more frequent review
- Integration with HR systems for automatic lifecycle events

**Continuous Access Evaluation:**
- Real-time policy evaluation during active sessions
- Token revocation on risk signal changes (account compromise, location change)
- Device compliance changes trigger session re-evaluation
- Critical security events trigger immediate access revocation
- Integration between IdP, EDR, and access management for real-time signals
