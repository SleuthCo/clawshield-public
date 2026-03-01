---
framework: "Identity and Access Management"
version: "1.0"
domain: "Identity Security"
agent: "sentinel"
tags: ["iam", "rbac", "abac", "oauth", "oidc", "saml", "mfa", "pam", "identity-governance"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Identity and Access Management (IAM) Fundamentals

This document covers IAM architecture, access control models, authentication protocols, privileged access management, and identity governance.

## IAM Architecture Overview

**Core IAM Functions:**
- **Identification:** establishing who a subject claims to be (username, email, badge)
- **Authentication:** verifying the claimed identity (password, MFA, biometrics)
- **Authorization:** determining what the authenticated identity is permitted to do
- **Accountability:** tracking and auditing actions performed by the identity

**IAM Components:**
- Identity Provider (IdP): authoritative source of identity and authentication
- Directory Service: stores identity attributes and group memberships
- Access Management: enforces authentication and session management
- Authorization Service: evaluates access policies and makes decisions
- Identity Governance: manages identity lifecycle, access reviews, compliance
- Privileged Access Management: secures and monitors privileged access
- Federation Service: enables cross-domain identity trust

## Access Control Models

**RBAC (Role-Based Access Control):**
- Access determined by assigned organizational roles
- Users are assigned to roles; roles are granted permissions
- Simplifies administration: manage roles, not individual user permissions
- Hierarchical roles: senior roles inherit permissions from junior roles
- Constraints: Separation of Duties (SoD) prevents conflicting role assignments

*RBAC Architecture:*
- Role engineering: analyze job functions to define role sets
- Role mining: analyze existing access patterns to discover roles
- Role hierarchy: reduces redundancy through inheritance
- Static SoD: user cannot hold conflicting roles simultaneously
- Dynamic SoD: user cannot activate conflicting roles in same session

*RBAC Limitations:*
- Role explosion: large organizations may need thousands of roles
- Rigid: does not adapt to contextual factors (location, time, risk)
- Over-provisioning: roles may include more permissions than needed for specific tasks
- Maintenance burden: roles must evolve with organizational changes

**ABAC (Attribute-Based Access Control):**
- Access decisions based on attributes of subject, resource, action, and environment
- Fine-grained: policies evaluate arbitrary attribute combinations
- Dynamic: decisions adapt to changing context (location, device, time, risk level)
- Scalable: new attributes can be added without restructuring the model

*ABAC Attributes:*
- Subject attributes: role, department, clearance, certification, risk score
- Resource attributes: classification, owner, sensitivity, type
- Action attributes: read, write, delete, approve, execute
- Environment attributes: time-of-day, location, device posture, network, threat level

*ABAC Policy Example:*
```
PERMIT access WHERE
  subject.role = "doctor" AND
  resource.type = "medical_record" AND
  subject.department = resource.department AND
  environment.network = "hospital_internal" AND
  action = "read"
```

*ABAC Implementation:*
- XACML (eXtensible Access Control Markup Language): standard policy language
- OPA (Open Policy Agent): modern policy engine using Rego language
- AWS Cedar: Amazon's policy language for fine-grained authorization
- Google Zanzibar / SpiceDB: relationship-based authorization at scale

**ReBAC (Relationship-Based Access Control):**
- Access determined by the relationship between subject and resource
- Models authorization as a graph of entities and relationships
- Naturally handles hierarchical and shared access patterns
- Example: "user can edit document if they are the owner or a member of the sharing group"

*ReBAC Implementations:*
- Google Zanzibar: powers Google Drive, YouTube, and other Google services
- SpiceDB: open-source Zanzibar-inspired authorization system
- AuthZed: managed SpiceDB service
- OpenFGA: open-source fine-grained authorization by Auth0/Okta

*ReBAC Advantages:*
- Intuitive modeling of real-world relationships
- Efficient permission checking through graph traversal
- Handles complex sharing and delegation patterns naturally
- Scales to billions of relationships

## OAuth 2.0 and OpenID Connect

**OAuth 2.0 (Authorization Framework):**

*Grant Types:*
- **Authorization Code:** server-side applications, most secure for web apps
- **Authorization Code + PKCE:** single-page apps and mobile apps (recommended for all public clients)
- **Client Credentials:** service-to-service authentication (machine-to-machine)
- **Device Authorization:** IoT and limited-input devices
- **Refresh Token:** obtain new access tokens without re-authentication

*Deprecated/Discouraged Grants:*
- Implicit Grant: deprecated due to token exposure in URL fragment
- Resource Owner Password Credentials: discouraged for security reasons

*Token Types:*
- Access Token: short-lived (15-60 min), used for API authorization
- Refresh Token: longer-lived, used to obtain new access tokens
- ID Token (OIDC): contains identity claims about the authenticated user

*Security Best Practices:*
- Always use PKCE for public clients (SPA, mobile, CLI)
- Use short-lived access tokens (15-60 minutes)
- Implement refresh token rotation (single-use refresh tokens)
- Validate token signature, issuer, audience, and expiration
- Store tokens securely (not in localStorage for SPAs; use secure cookies or BFF pattern)
- Implement token revocation endpoint
- Use DPoP (Demonstrating Proof-of-Possession) for token binding

**OpenID Connect (OIDC):**
- Identity layer built on top of OAuth 2.0
- Provides standard way to authenticate users and obtain identity claims
- ID Token: JWT containing user identity information
- UserInfo endpoint: additional user profile claims
- Discovery: /.well-known/openid-configuration for automatic configuration
- Standard claims: sub, name, email, email_verified, picture, locale

## SAML 2.0

**Components:**
- Identity Provider (IdP): authenticates users and issues SAML assertions
- Service Provider (SP): consumes SAML assertions to grant access
- SAML Assertion: XML document containing authentication and attribute statements

**SAML Flows:**
- SP-Initiated: user accesses SP, redirected to IdP for authentication
- IdP-Initiated: user authenticates at IdP, selects SP to access

**SAML Security Considerations:**
- Validate XML signatures on all SAML assertions
- Protect against XML Signature Wrapping (XSW) attacks
- Enforce assertion time limits (NotBefore, NotOnOrAfter)
- Validate audience restriction matches the expected SP
- Use encrypted assertions for sensitive attributes
- Protect against replay by tracking assertion IDs
- Implement proper session management independent of SAML assertion lifetime

## Multi-Factor Authentication (MFA)

**Authentication Factor Categories:**
- Knowledge: something you know (password, PIN, security questions)
- Possession: something you have (hardware token, phone, smart card)
- Inherence: something you are (fingerprint, face, iris, voice)

**MFA Methods (ordered by security strength):**

1. **FIDO2/WebAuthn (Phishing-Resistant):**
   - Hardware security keys (YubiKey, Titan, SoloKeys)
   - Platform authenticators (Windows Hello, Touch ID, Face ID)
   - Cryptographic challenge-response bound to origin (domain)
   - Immune to phishing, real-time relay, and credential theft
   - NIST AAL3 compliant with hardware authenticators

2. **Certificate-Based (PIV/Smart Card):**
   - X.509 certificates on smart cards or virtual smart cards
   - Mutual TLS authentication
   - Strong binding between identity and credential
   - Common in government (PIV) and high-security environments

3. **App-Based Push with Number Matching:**
   - Push notification requiring user to enter number shown on screen
   - Resists MFA fatigue/push bombing attacks
   - Requires additional context (application, location) for informed approval
   - Microsoft Authenticator, Duo with number matching

4. **TOTP (Time-Based One-Time Password):**
   - Authenticator apps generating 6-digit codes (Google Authenticator, Authy)
   - Based on shared secret and current time
   - Susceptible to real-time phishing/AiTM attacks
   - NIST AAL2 compliant

5. **SMS/Voice OTP (Weakest MFA):**
   - One-time code sent via SMS text message or voice call
   - Vulnerable to SIM swapping, SS7 exploitation, social engineering
   - NIST deprecated for new deployments but still common
   - Better than no MFA, but should be replaced with stronger methods

**MFA Deployment Strategy:**
- Enforce phishing-resistant MFA (FIDO2) for all privileged accounts
- Require MFA for all remote access without exception
- Implement MFA for all cloud services and SaaS applications
- Enable MFA for VPN, email, and collaboration tools
- Provide self-service MFA enrollment with identity proofing
- Support multiple MFA methods for redundancy and accessibility
- Implement adaptive MFA that increases requirements based on risk

## Privileged Access Management (PAM)

**PAM Core Functions:**
- Credential vaulting: securely store and manage privileged credentials
- Session management: monitor, record, and control privileged sessions
- Just-in-time access: grant privileges only when needed, for limited duration
- Least privilege enforcement: provide minimum necessary access
- Audit and compliance: full audit trail of all privileged access

**PAM Architecture:**
- Privileged credential vault with encrypted storage and HSM backing
- Session proxy for monitored and recorded access to target systems
- Workflow engine for access request, approval, and time-limited grants
- Discovery engine for finding privileged accounts across the environment
- Threat analytics for detecting anomalous privileged behavior

**PAM Best Practices:**
- Eliminate standing privileged access: implement just-in-time (JIT) for all admin access
- Rotate privileged credentials automatically after each use
- Record all privileged sessions with searchable, tamper-evident storage
- Implement break-glass procedures for emergency access
- Require dual approval for highest-privilege access
- Monitor for privileged account creation outside PAM system
- Integrate PAM with SIEM for behavioral analytics on privileged users

## Identity Governance and Administration (IGA)

**Identity Lifecycle Management:**
- Joiner: automated account provisioning from HR systems
- Mover: automated role adjustment when employees change positions
- Leaver: automated deprovisioning upon termination (within 24 hours)
- Contractor and temporary worker lifecycle with auto-expiry

**Access Certification Campaigns:**
- Periodic review of all access entitlements by managers and owners
- Frequency: quarterly for privileged access, semi-annually for standard
- Risk-based campaigns: prioritize review of high-risk entitlements
- Automated revocation of uncertified access
- Track certification completion and remediation

**Segregation of Duties (SoD):**
- Define conflicting role and permission combinations
- Preventive: block assignment of conflicting roles
- Detective: identify existing SoD violations through reports
- Regular SoD violation reports to compliance and management
- Exception management with documented risk acceptance

**Directory Services:**
- Active Directory: on-premises identity and access management
- Azure AD / Microsoft Entra ID: cloud identity platform
- LDAP directories: lightweight directory access for application integration
- Cloud directories: AWS Directory Service, Google Cloud Identity
- Hybrid identity: synchronization between on-premises and cloud directories
- Directory hardening: protect against AD attacks (DCSync, Kerberoasting, NTDS extraction)
