---
framework: "GCP Security"
version: "1.0"
domain: "Cloud Security"
agent: "nimbus"
tags: ["gcp", "security", "iam", "vpc-service-controls", "beyondcorp", "scc"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# GCP Security

Google Cloud security is built on a zero-trust architecture model, leveraging Google's BeyondCorp principles. This document covers IAM, organizational governance, network security, threat detection, and data protection.

## GCP IAM

GCP IAM provides fine-grained access control for Google Cloud resources. It follows an allow-by-default deny model where permissions are granted through IAM policies bound at various levels of the resource hierarchy.

### Core Concepts

- **Principal (Member)**: The identity making the request. Can be a Google Account (user), Service Account, Google Group, Google Workspace domain, Cloud Identity domain, or allUsers/allAuthenticatedUsers.
- **Role**: A collection of permissions. Permissions are expressed as `service.resource.verb` (e.g., `compute.instances.start`). Roles are granted to principals at a specific scope.
- **Policy (Binding)**: Associates one or more principals with a role at a resource hierarchy node. Policies are inherited downward.

### Role Types

- **Basic Roles**: Owner, Editor, Viewer. Extremely broad. Avoid in production. Owner includes permissions to manage IAM policies and billing. Editor grants read-write to most resources. These are legacy roles from before IAM existed.
- **Predefined Roles**: Curated by Google for specific services and use cases (e.g., `roles/compute.instanceAdmin.v1`, `roles/storage.objectViewer`). Hundreds of predefined roles available. Preferred over basic roles.
- **Custom Roles**: Define your own set of permissions. Use when predefined roles are too broad or too narrow. Can be defined at the organization or project level.

### IAM Best Practices

- Grant roles to groups, not individual users. Manage group membership in Google Workspace or Cloud Identity.
- Use the principle of least privilege. Start with the most restrictive role and expand only when justified.
- Use IAM Recommender to identify and remove excess permissions. It analyzes 90 days of usage and suggests more restrictive roles.
- Avoid basic roles (Owner, Editor, Viewer) in production. Use predefined or custom roles instead.
- Use IAM Conditions for context-based access (time-of-day, resource attributes, IP address).
- Implement organization-level IAM deny policies for hard guardrails that cannot be overridden by allow policies.

### Service Accounts

Service accounts are special accounts used by applications, VMs, and services to authenticate with GCP APIs.

- **Default Service Accounts**: Automatically created for certain services (Compute Engine default, App Engine default). Often have overly broad permissions (Editor role). Remove the default Editor role and assign specific roles.
- **User-Created Service Accounts**: Create purpose-specific service accounts with only the permissions needed. Name them descriptively (e.g., `data-pipeline-sa@project.iam.gserviceaccount.com`).
- **Service Account Keys**: JSON key files for authentication outside GCP. Avoid when possible. They are long-lived credentials that can be leaked. Rotate regularly. Use Workload Identity Federation instead.
- **Service Account Impersonation**: A principal assumes the identity of a service account using `iam.serviceAccountTokenCreator` role. Creates short-lived credentials. Audit trail shows both the original principal and the impersonated service account.

### Workload Identity Federation

Workload Identity Federation allows external identities (AWS IAM, Azure AD, OIDC providers, SAML providers) to access GCP resources without service account keys.

- Create a Workload Identity Pool and Provider in GCP
- Configure attribute mappings from the external identity to GCP
- Grant the external identity access to impersonate a GCP service account
- Use cases: CI/CD from GitHub Actions, GitLab CI, or Jenkins accessing GCP; AWS workloads accessing GCP resources; on-premises applications authenticating without key files

## Organization Policies

Organization Policies provide centralized, constraint-based governance across the GCP resource hierarchy. Unlike IAM (which controls who can do what), Organization Policies control what can be done regardless of who has permission.

### Key Organization Policy Constraints

- **Resource Location Restriction** (`gcp.resourceLocations`): Restrict which regions/zones resources can be created in. Critical for data residency compliance.
- **Disable Service Account Key Creation** (`iam.disableServiceAccountKeyCreation`): Prevent creation of user-managed service account keys. Forces use of Workload Identity, attached service accounts, or impersonation.
- **Restrict Shared VPC Host Projects** (`compute.restrictSharedVpcHostProjects`): Control which projects can be designated as Shared VPC host projects.
- **Restrict VPC Peering** (`compute.restrictVpcPeering`): Control which VPC networks can be peered.
- **Uniform Bucket-Level Access** (`storage.uniformBucketLevelAccess`): Require uniform (IAM-only) access control on Cloud Storage buckets. Prevents legacy ACLs.
- **Require OS Login** (`compute.requireOsLogin`): Enforce OS Login for SSH access to VMs. Integrates with IAM for SSH key management.
- **Restrict VM External IP** (`compute.vmExternalIpAccess`): Prevent VMs from having external IP addresses. Force outbound traffic through Cloud NAT.
- **Domain Restricted Sharing** (`iam.allowedPolicyMemberDomains`): Restrict which domains can be granted IAM roles. Prevents accidental sharing with external identities.
- **Disable Automatic IAM Grants** (`iam.automaticIamGrantsForDefaultServiceAccounts`): Prevent default service accounts from automatically receiving the Editor role.

### Custom Organization Policies

In addition to built-in constraints, custom organization policies can be created using CEL (Common Expression Language) to enforce constraints based on resource attributes. Example: require all Cloud SQL instances to have specific flags enabled, or require all GKE clusters to use a minimum version.

## VPC Service Controls

VPC Service Controls create a security perimeter around GCP resources to prevent data exfiltration and unauthorized access, even by users with IAM permissions.

### Core Concepts

- **Service Perimeter**: Defines a boundary around GCP projects and services. Resources inside the perimeter can communicate freely. Access from outside the perimeter is blocked by default.
- **Access Levels**: Define conditions under which external access is allowed (IP ranges, device security posture, identity attributes). Based on Access Context Manager.
- **Ingress/Egress Rules**: Fine-grained rules for specific directional access across the perimeter boundary. Define which identities can access which resources from/to where.
- **Perimeter Bridges**: Allow communication between two separate perimeters. Resources in bridged perimeters can access each other's services.

### Protected Services

VPC Service Controls can protect: BigQuery, Cloud Storage, Cloud SQL, Spanner, Bigtable, Dataproc, Dataflow, Pub/Sub, Cloud Functions, Artifact Registry, and many more. Check the supported services list as coverage expands.

### Architecture Pattern

1. Create an access policy at the organization level
2. Define access levels (corporate IP ranges, device trust levels)
3. Create a service perimeter containing production projects
4. Configure ingress rules for authorized access patterns (CI/CD pipelines, admin access with appropriate access levels)
5. Configure egress rules for authorized data flows (cross-project data sharing, external API calls)
6. Use dry-run mode first to validate the perimeter without blocking traffic. Review audit logs for violations before enforcing.

### Common Use Cases

- Prevent data exfiltration from BigQuery (block copying query results to projects outside the perimeter)
- Protect Cloud Storage buckets from unauthorized access even if a user has IAM permissions
- Restrict Cloud SQL access to only applications within the perimeter
- Segment production data from development environments at the network level

## Security Command Center

Security Command Center (SCC) is the centralized security and risk management platform for GCP. It provides asset inventory, vulnerability scanning, threat detection, and compliance monitoring.

### Tiers

- **Standard**: Free. Asset inventory, Security Health Analytics (basic misconfiguration scanning), Web Security Scanner (OWASP Top 10 for App Engine, GKE, Compute Engine web apps).
- **Premium**: Paid. Adds Event Threat Detection, Container Threat Detection, Virtual Machine Threat Detection, compliance monitoring (CIS, PCI DSS, NIST, ISO 27001), attack path simulation, and all Standard features with enhanced detectors.
- **Enterprise**: Extends Premium with multi-cloud support (AWS, Azure), AI-powered investigation (Gemini), case management, and integration with Google Security Operations (Chronicle).

### Key Capabilities

- **Security Health Analytics**: Automatically detects misconfigurations (public buckets, open firewall rules, disabled logging, unencrypted disks, overly permissive IAM). Provides actionable findings with remediation steps.
- **Event Threat Detection**: Analyzes Cloud Audit Logs and VPC Flow Logs to detect threats (suspicious admin activity, malware, cryptomining, data exfiltration, brute force SSH).
- **Container Threat Detection**: Monitors GKE cluster runtime behavior for threats (reverse shell, malicious binary execution, unexpected library loading).
- **Virtual Machine Threat Detection**: Scans VM memory for cryptocurrency mining malware without agents.
- **Attack Path Simulation**: Models attack paths from the internet to high-value resources. Identifies combinations of vulnerabilities and misconfigurations that could be exploited.

## Chronicle (Google Security Operations)

Chronicle is Google's cloud-native SIEM and SOAR platform, now integrated into Google Security Operations.

### Architecture

- Built on Google infrastructure with massive scale for log ingestion, retention, and search
- Default 12 months hot storage for all ingested data (no tiering or archiving needed for the retention period)
- Fixed-price ingestion model (not volume-based) eliminates the cost concern of ingesting more data
- YARA-L detection language for writing detection rules
- Curated detection rule packs from Google's Mandiant threat intelligence team

### Key Capabilities

- **Log Ingestion**: Ingest from GCP (Cloud Audit Logs, VPC Flow Logs, Cloud DNS, GKE), AWS (CloudTrail, GuardDuty, VPC Flow Logs), Azure (Activity Logs, Entra ID, Defender), and hundreds of third-party sources via parsers
- **UDM (Unified Data Model)**: Normalizes all ingested data into a common schema for cross-source correlation
- **Detection Engine**: Rules written in YARA-L 2.0. Supports single-event rules, multi-event correlation, and reference lists. Curated detections from Mandiant.
- **Investigation**: Timeline and graph-based investigation. Correlate indicators across all data sources. Integrate Mandiant threat intelligence for context enrichment.
- **SOAR (Playbooks)**: Visual playbook builder for automated response workflows. Enrich alerts, contain threats, notify teams, create tickets.

## BeyondCorp (Zero Trust)

BeyondCorp is Google's implementation of zero trust security, shifting access controls from the network perimeter to individual devices and users.

### BeyondCorp Enterprise

- **Identity-Aware Proxy (IAP)**: Verifies user identity and device security before granting access to applications. Replaces VPN for application access. Supports web applications (HTTP/HTTPS) and TCP forwarding (SSH, RDP). Integrates with Access Context Manager for device trust and context-aware access.
- **Access Context Manager**: Defines access levels based on device attributes (OS version, disk encryption, screen lock), IP address, user identity, and geographic location. Access levels are used by IAP, VPC Service Controls, and IAM Conditions.
- **Endpoint Verification**: Lightweight agent that collects device security posture information (OS version, encryption status, password status). Reports to Access Context Manager for policy enforcement.
- **BeyondCorp Enterprise Threat and Data Protection**: DLP for web traffic, malware protection, URL filtering, and real-time phishing protection in Chrome Enterprise.

### Zero Trust Architecture Pattern

1. Deploy Endpoint Verification to all corporate devices
2. Define access levels in Access Context Manager (trusted device = encrypted, up-to-date OS, corp-managed)
3. Place applications behind IAP with Entra ID (or Google Workspace) authentication
4. Configure context-aware access policies requiring trusted device + authenticated user + appropriate role
5. Eliminate VPN requirement. Users access applications directly via IAP from any network.
6. Apply VPC Service Controls for API-level data access protection

## Workload Identity for GKE

Workload Identity is the recommended way for GKE pods to access GCP services. It maps Kubernetes service accounts to IAM service accounts.

### Setup

1. Enable Workload Identity on the GKE cluster
2. Create a GCP IAM service account with the required roles
3. Create a Kubernetes service account in the application namespace
4. Bind the Kubernetes service account to the IAM service account with an IAM policy binding
5. Annotate the Kubernetes service account with the IAM service account email
6. Configure pods to use the Kubernetes service account

### Benefits

- No service account keys to manage or rotate
- Per-pod identity (different pods can have different GCP permissions)
- Audit trails show both the Kubernetes identity and the GCP identity
- Works with GKE Standard and Autopilot

## Binary Authorization

Binary Authorization ensures only trusted container images are deployed to GKE, Cloud Run, or Anthos clusters.

### How It Works

1. **Build**: CI/CD pipeline builds and pushes container image to Artifact Registry
2. **Attest**: An attestor (human or automated) verifies the image meets policy requirements and creates a signed attestation (using a KMS key or PGP key). Common attestations: vulnerability scan passed, code review approved, built by trusted CI/CD system.
3. **Deploy**: Binary Authorization admission controller on GKE checks the deploy-time policy. The policy specifies which attestors must have signed the image. Unsigned or improperly attested images are blocked.
4. **Break-glass**: Emergency mechanism to bypass Binary Authorization with audit logging. Should be rare and reviewed.

### Policy Patterns

- Require attestation from a vulnerability scanner (e.g., only deploy images with no critical CVEs)
- Require attestation from a CI/CD pipeline (only images built by the trusted pipeline)
- Require human approval attestation for production deployments
- Allow only images from specific Artifact Registry repositories
- Different policies per GKE cluster (stricter for production, relaxed for development)

## CMEK and CSEK

### Customer-Managed Encryption Keys (CMEK)

By default, GCP encrypts all data at rest with Google-managed keys. CMEK lets you control the encryption keys using Cloud KMS.

- Create keys in Cloud KMS (software-backed, HSM-backed, or external via EKM)
- Configure GCP services (Cloud Storage, BigQuery, Compute Engine, Cloud SQL, GKE, Spanner, etc.) to use your KMS keys
- You control key lifecycle: creation, rotation, disable, destroy
- Key access is governed by IAM: revoking access to the key immediately prevents data access
- Automatic key rotation supported (configurable interval)
- Dual-key encryption with Key Access Justifications (Enterprise tier): requires Google to provide justification before accessing your key, giving you ability to deny access

### Customer-Supplied Encryption Keys (CSEK)

CSEK lets you provide your own encryption keys directly. GCP uses them to encrypt data but does not store them.

- Supported only for Compute Engine persistent disks and Cloud Storage
- You supply the key with every API call that reads or writes encrypted data
- Google does not store the key. If you lose the key, the data is permanently unrecoverable.
- Use when regulatory requirements mandate that the cloud provider never stores encryption keys
- Operational complexity is high. CMEK with Cloud KMS or Cloud EKM is preferred for most scenarios.

### Cloud External Key Manager (EKM)

Cloud EKM allows you to use encryption keys stored in a third-party key management system (Thales, Fortanix, etc.) with GCP services.

- Keys never leave the external key manager
- GCP calls the external KMS for every encrypt/decrypt operation
- Provides ultimate key sovereignty at the cost of latency and availability dependency on the external system
- Key Access Justifications available with EKM to control and audit when Google accesses your externally managed keys
