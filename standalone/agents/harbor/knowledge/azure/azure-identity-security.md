---
framework: "Azure Identity and Security"
version: "1.0"
domain: "Cloud Security"
agent: "nimbus"
tags: ["azure", "entra-id", "security", "identity", "rbac", "sentinel", "defender"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Azure Identity and Security

Azure's security model is identity-centric, built on Microsoft Entra ID (formerly Azure AD) as the universal identity platform. This document covers identity management, access control, governance, and the security services ecosystem.

## Microsoft Entra ID (Azure AD)

Microsoft Entra ID is the cloud-based identity and access management service. It provides authentication and authorization for Azure resources, Microsoft 365, SaaS applications, and custom applications.

### Core Capabilities

- **Single Sign-On (SSO)**: Users authenticate once and access all connected applications. Supports SAML 2.0, OpenID Connect, OAuth 2.0, and WS-Federation protocols.
- **Multi-Factor Authentication (MFA)**: Requires a second form of verification. Should be enforced for all users, especially administrators. Security defaults enable MFA for all users at no additional cost.
- **Self-Service Password Reset (SSPR)**: Reduces helpdesk burden by allowing users to reset their own passwords with appropriate verification.
- **Application Proxy**: Publishes on-premises web applications externally without VPN. Provides SSO to legacy applications.
- **B2B Collaboration**: Invite external users (guests) to access your organization's resources with their own credentials. Manage with access reviews.
- **B2C**: Customer-facing identity management with customizable sign-up/sign-in experiences. Supports social identity providers (Google, Facebook, Apple).

### License Tiers

- **Free**: Basic identity management, SSO for up to 10 apps per user, security defaults
- **P1**: Conditional Access, dynamic groups, self-service group management, hybrid identity (Azure AD Connect)
- **P2**: Identity Protection (risk-based Conditional Access), Privileged Identity Management (PIM), access reviews
- **Governance**: Full identity governance lifecycle, entitlement management, lifecycle workflows

## Conditional Access

Conditional Access policies are the core of Azure's zero trust strategy. They evaluate signals and enforce access decisions in real time.

### Signal Types (Conditions)

- **User or Group Membership**: Target specific users, groups, or roles
- **IP Location Information**: Named locations, trusted IPs, country/region
- **Device Platform**: iOS, Android, Windows, macOS, Linux
- **Device State**: Compliant devices (via Intune), Hybrid Azure AD joined devices
- **Client Application**: Browser, mobile app, desktop client, legacy authentication
- **Sign-in Risk**: Real-time risk level (low, medium, high) from Identity Protection
- **User Risk**: Cumulative risk level based on user behavior patterns

### Access Controls (Grants and Sessions)

- **Block access**: Deny authentication entirely
- **Grant access with requirements**: Require MFA, require compliant device, require Hybrid Azure AD joined device, require approved client app, require app protection policy, require password change
- **Session controls**: Sign-in frequency (re-authentication interval), persistent browser session, Conditional Access App Control (proxy through Defender for Cloud Apps for real-time session monitoring)

### Common Policy Patterns

1. **Require MFA for all users**: Target all users, all cloud apps, grant access with MFA required. Exclude emergency access (break-glass) accounts.
2. **Block legacy authentication**: Target all users, all cloud apps, condition on "other clients" (legacy auth protocols), block access. Legacy authentication does not support MFA and is the most exploited attack vector.
3. **Require compliant devices for corporate apps**: Target all users, specific apps (Office 365, Azure Management), require device compliance.
4. **Risk-based MFA**: Target all users, all cloud apps, condition on medium or high sign-in risk, require MFA. Users with low-risk sign-ins pass through without additional friction.
5. **Block access from untrusted countries**: Target all users, all cloud apps, condition on locations outside of trusted countries, block access.

## Privileged Identity Management (PIM)

PIM provides just-in-time (JIT) privileged access to reduce the standing permissions attack surface. It requires Entra ID P2 licensing.

### Capabilities

- **Eligible Assignments**: Users are eligible for a role but must activate it when needed. Activation requires MFA, justification, and optional approval workflow. Assignments can be time-bound.
- **Active Assignments**: Users have the role permanently active. Should be minimized to emergency access accounts only.
- **Activation Settings**: Maximum activation duration (1-24 hours), require justification, require MFA, require approval, notification to administrators.
- **Access Reviews**: Periodic review of role assignments to ensure they are still necessary. Reviewers can be managers, self-review, or specific reviewers. Auto-apply results to remove access.

### PIM for Azure Resources

PIM extends beyond Entra ID directory roles to Azure RBAC roles (Owner, Contributor, Reader, custom roles) on management groups, subscriptions, resource groups, and individual resources. Eligible users activate Azure roles through PIM with the same approval and auditing capabilities.

### Best Practices

- Make Global Administrator, Security Administrator, and Privileged Role Administrator eligible-only, never permanently active
- Set maximum activation duration to 8 hours for most roles
- Require approval for high-privilege roles (Owner, User Access Administrator)
- Configure access reviews on a quarterly basis for all privileged roles
- Maintain at least two emergency access (break-glass) accounts with permanent Global Administrator assigned, excluded from Conditional Access, and stored securely

## Managed Identities

Managed identities eliminate the need for applications to manage credentials when accessing Azure resources.

### System-Assigned Managed Identity

- Created and tied to a specific Azure resource (VM, App Service, Function, AKS pod)
- Lifecycle tied to the resource: deleted when the resource is deleted
- One-to-one relationship: each resource has at most one system-assigned identity
- Use when the identity is only needed by a single resource

### User-Assigned Managed Identity

- Created as a standalone Azure resource in a resource group
- Independent lifecycle: persists after associated resources are deleted
- Can be assigned to multiple resources simultaneously
- Use when multiple resources need the same identity (e.g., multiple VMs accessing the same storage account)

### Common Usage Patterns

- Azure VM accessing Key Vault secrets without storing credentials
- Azure Function accessing Azure SQL Database with Entra authentication
- AKS pods accessing Azure resources using Workload Identity (federated identity credentials)
- App Service accessing Storage Account, Service Bus, or Event Hubs
- Azure Data Factory accessing data sources with managed identity authentication

### Workload Identity for Kubernetes (AKS)

AKS Workload Identity replaces the deprecated pod-managed identity (aad-pod-identity) and uses Kubernetes-native service account token projection with federated identity credentials:

1. Create a user-assigned managed identity
2. Create a Kubernetes service account annotated with the managed identity client ID
3. Establish a federated identity credential linking the managed identity to the Kubernetes service account
4. Pods using the service account can authenticate as the managed identity

## Azure RBAC

Azure Role-Based Access Control manages access to Azure resources. It is built into Azure Resource Manager and applies to the management plane (Azure operations).

### Core Concepts

- **Security Principal**: User, group, service principal, or managed identity requesting access
- **Role Definition**: Collection of permissions (actions, notActions, dataActions, notDataActions). Can be built-in or custom.
- **Scope**: The level at which access is granted: management group, subscription, resource group, or resource
- **Role Assignment**: Attaches a security principal to a role definition at a scope

### Key Built-in Roles

- **Owner**: Full access to all resources, including the right to delegate access via RBAC
- **Contributor**: Full access to all resources but cannot grant access to others
- **Reader**: View all resources but cannot make changes
- **User Access Administrator**: Manage user access to Azure resources (assign roles)
- **Network Contributor**, **Storage Account Contributor**, **SQL DB Contributor**: Service-specific contributor roles

### Best Practices

- Use built-in roles when possible; create custom roles only when needed
- Assign roles to groups, not individual users, for scalability
- Use the most restrictive scope possible (resource group over subscription)
- Implement PIM for eligible role assignments on sensitive scopes
- Regularly review role assignments with access reviews
- Deny assignments can explicitly deny specific actions and take precedence over role assignments

## Azure Policy

Azure Policy enforces organizational standards and assesses compliance at scale. Policies evaluate resource properties during creation and existing resources on a schedule.

### Policy Effects

- **Audit**: Log a warning in the activity log when a non-compliant resource is created or exists
- **Deny**: Prevent the creation of non-compliant resources
- **Modify**: Add, update, or remove properties or tags on a resource during creation or update
- **DeployIfNotExists**: Deploy a related resource if it does not exist (e.g., deploy diagnostic settings when a resource is created)
- **AuditIfNotExists**: Log a warning if a related resource does not exist
- **Disabled**: Turn off the policy evaluation
- **DenyAction**: Deny specific actions on resources (e.g., deny delete on production resources)

### Common Policies

- Require specific tags on resources (enforce cost center, environment, owner tags)
- Restrict allowed regions for resource deployment
- Restrict allowed VM SKUs to prevent oversized deployments
- Require encryption on storage accounts, SQL databases
- Deny public IP addresses on VMs in production subscriptions
- Deploy Azure Monitor diagnostic settings automatically on all supported resources

### Policy Initiatives

Group related policies into initiatives (policy sets). Azure provides built-in initiatives for compliance standards: CIS Microsoft Azure Foundations Benchmark, NIST SP 800-53, PCI DSS, ISO 27001, HIPAA HITRUST. Assign initiatives at management group or subscription scope for broad governance.

## Microsoft Defender for Cloud

Defender for Cloud is the Cloud Security Posture Management (CSPM) and Cloud Workload Protection Platform (CWPP) for Azure, AWS, and GCP.

### CSPM Capabilities

- **Secure Score**: Quantified security posture score with prioritized recommendations
- **Security Recommendations**: Actionable steps to improve security posture, mapped to MITRE ATT&CK
- **Regulatory Compliance Dashboard**: Continuous assessment against compliance standards
- **Cloud Security Graph**: Query relationships between cloud resources to identify attack paths
- **Attack Path Analysis**: Identifies exploitable paths from internet exposure to sensitive resources

### CWPP (Defender Plans)

- **Defender for Servers**: Vulnerability assessment (Qualys integrated), adaptive application controls, file integrity monitoring, just-in-time VM access, endpoint detection and response (EDR via Defender for Endpoint)
- **Defender for Containers**: Container image vulnerability scanning, runtime protection, Kubernetes admission control
- **Defender for Databases**: Threat protection for Azure SQL, MySQL, PostgreSQL, Cosmos DB, and SQL on VMs
- **Defender for Storage**: Detects malicious file uploads, suspicious access patterns, data exfiltration attempts
- **Defender for Key Vault**: Detects unusual and suspicious access to Key Vault
- **Defender for App Service**: Detects attacks targeting App Service applications
- **Defender for DNS**: Detects suspicious DNS activity

## Microsoft Sentinel

Sentinel is a cloud-native SIEM (Security Information and Event Management) and SOAR (Security Orchestration, Automation, and Response) solution built on Azure Monitor Log Analytics.

### Data Connectors

- Azure Activity Logs, Entra ID sign-in/audit logs, Defender for Cloud alerts
- Microsoft 365 (Exchange, SharePoint, Teams, Defender suite)
- AWS CloudTrail, GCP audit logs (multi-cloud monitoring)
- Syslog, Common Event Format (CEF), REST API for third-party sources
- Threat Intelligence feeds (STIX/TAXII)

### Key Capabilities

- **Analytics Rules**: Detect threats using scheduled queries (KQL), Microsoft security alerts, ML-based anomaly detection, and fusion (multi-stage attack detection correlating alerts across sources)
- **Hunting**: Proactive threat hunting using built-in and custom KQL queries. Use bookmarks to save interesting findings. Create livestream rules for real-time hunting.
- **Incidents**: Correlated alerts grouped into incidents for investigation. Assign to analysts, track status, add comments, and link to evidence.
- **Automation (Playbooks)**: Logic Apps-based automation for incident response. Auto-enrich incidents with threat intelligence, isolate compromised VMs, disable user accounts, send notifications, create ServiceNow tickets.
- **Workbooks**: Interactive dashboards for security monitoring and investigation. Built-in templates for common scenarios. Custom workbooks using KQL.
- **UEBA (User and Entity Behavior Analytics)**: Baseline normal behavior for users and entities. Detect anomalies that may indicate compromised accounts or insider threats.

## Azure Key Vault

Key Vault provides centralized secrets management, key management, and certificate management.

### Tiers

- **Standard**: Software-protected keys. Suitable for most scenarios.
- **Premium**: Includes HSM-protected keys (FIPS 140-2 Level 2). Required for regulatory compliance scenarios.
- **Managed HSM**: Dedicated, single-tenant HSM (FIPS 140-2 Level 3). For the most stringent compliance requirements.

### Best Practices

- Use separate Key Vaults for each application and environment (dev, staging, production)
- Enable soft delete and purge protection to prevent accidental or malicious key deletion
- Use managed identities for Key Vault access; avoid storing Key Vault credentials anywhere
- Enable diagnostic logging and alert on suspicious access patterns
- Use Azure RBAC for Key Vault data plane access (recommended over access policies for granular control)
- Enable private endpoints to restrict Key Vault access to specific virtual networks
- Implement key rotation policies and automate certificate renewal
