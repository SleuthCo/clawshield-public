---
framework: "NIST SP 800-53 Rev 5"
version: "5.1"
domain: "Access Control"
agent: "sentinel"
tags: ["nist", "800-53", "access-control", "authorization", "least-privilege", "rbac"]
last_updated: "2025-06-01"
chunk_strategy: "control"
---

# NIST SP 800-53 Rev 5 — Access Control (AC) Family

The Access Control family provides safeguards for managing system access, enforcing authorization decisions, and ensuring that only authorized users, processes, and devices can interact with organizational information systems.

## AC-1: Policy and Procedures

**Control Description:** Organizations develop, document, and disseminate access control policy and procedures that address purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance. The policy must be consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines.

**Implementation Guidance:**
- Define access control policy at the organizational level with system-level applicability
- Establish review cadence: policy reviewed at least annually, procedures at least annually or upon significant changes
- Designate an official to manage the development, documentation, and dissemination
- Ensure policy addresses all controls in the AC family
- Procedures must be sufficient to implement the associated access control policies

**Assessment Criteria:**
- Policy document exists and has been reviewed within the last 12 months
- Procedures address each AC family control selected for implementation
- Designated roles and responsibilities are clearly defined
- Evidence of dissemination to relevant personnel exists

## AC-2: Account Management

**Control Description:** Organizations manage system accounts including identifying account types, establishing conditions for group and role membership, specifying authorized users, authorizing access, creating/enabling/modifying/disabling/removing accounts, and monitoring account usage.

**Account Types:**
- Individual user accounts (standard and privileged)
- Shared or group accounts (must be explicitly authorized with justification)
- Service accounts (non-interactive, machine-to-machine)
- System accounts (operating system level)
- Guest and anonymous accounts (disabled by default)
- Emergency accounts (time-limited, audited)
- Temporary accounts (automatically expired)

**Implementation Requirements:**
- Maintain inventory of all active accounts with assigned owners
- Implement automated account lifecycle management where feasible
- Review accounts at a minimum of every 90 days for compliance
- Disable inactive accounts after 30 days (or organization-defined period)
- Remove or disable accounts of terminated or transferred personnel within 24 hours
- Implement account lock-out after organization-defined number of failed attempts
- Notify account managers when accounts are no longer needed, users are terminated, or system usage changes

**Control Enhancements:**
- AC-2(1): Automated account management using identity governance tools
- AC-2(2): Automated removal/disabling of temporary and emergency accounts
- AC-2(3): Disable accounts not used within 35 days
- AC-2(4): Automated audit actions for account operations (creation, modification, enabling, disabling, removal)
- AC-2(5): Require log-out after organization-defined inactivity period
- AC-2(6): Dynamic privilege management — restrict privileges based on defined criteria
- AC-2(7): Privileged user accounts — role-based schemes aligned with mission needs
- AC-2(9): Restrict use of shared/group accounts with specific conditions
- AC-2(11): Usage conditions — enforce restrictions based on time-of-day, location, or device
- AC-2(12): Account monitoring for atypical usage patterns using behavioral analytics
- AC-2(13): Disable accounts of high-risk individuals immediately upon determination

## AC-3: Access Enforcement

**Control Description:** The system enforces approved authorizations for logical access to information and system resources in accordance with applicable access control policies.

**Enforcement Mechanisms:**
- Discretionary Access Control (DAC): Owner-controlled permissions on objects
- Mandatory Access Control (MAC): System-enforced labels and clearances
- Role-Based Access Control (RBAC): Access determined by assigned organizational roles
- Attribute-Based Access Control (ABAC): Access based on subject/object/environment attributes
- Rule-Based Access Control: Dynamic enforcement using conditional logic

**Implementation Considerations:**
- Access enforcement occurs at the application layer, middleware, operating system, and network layer
- Enforcement must cover all access vectors: UI, API, CLI, direct data access
- Deny-by-default: access is denied unless explicitly permitted
- Access decisions must be logged for audit and forensic purposes
- Enforcement must be consistent across all system components

**Control Enhancements:**
- AC-3(2): Dual authorization — require two authorized individuals for critical actions
- AC-3(4): Discretionary access control — identity-based, user-directed sharing
- AC-3(7): Role-based access control with inheritance hierarchies
- AC-3(8): Revocation of access authorizations — real-time propagation
- AC-3(9): Controlled release of information based on classification
- AC-3(11): Restrict access to specific data types based on organizational policy
- AC-3(13): Attribute-based access control using XACML or OPA policies
- AC-3(14): Individual access — users can only access their own data
- AC-3(15): Discretionary and mandatory access control with security label enforcement

## AC-4: Information Flow Enforcement

**Control Description:** The system enforces approved authorizations for controlling the flow of information within the system and between connected systems based on applicable policy.

**Flow Control Policies:**
- Content-based filtering (DLP rules, classification labels)
- Source and destination restrictions (network segmentation, VLAN policies)
- Metadata-based restrictions (sensitivity labels, handling caveats)
- Cross-domain solutions for information transfer between security domains
- Encryption requirements for data in transit between trust zones

**Implementation Approaches:**
- Network firewalls with stateful inspection and application-layer filtering
- Data Loss Prevention (DLP) systems at network, endpoint, and cloud layers
- Information rights management (IRM) and digital rights management (DRM)
- Content inspection proxies for email, web, and file transfer
- API gateways enforcing data classification policies
- Cross-domain guards for multi-level security environments

**Control Enhancements:**
- AC-4(1): Object security and privacy attributes guiding flow decisions
- AC-4(3): Dynamic information flow control adjusting to current risk
- AC-4(4): Flow control of encrypted information — inspection capabilities
- AC-4(6): Metadata enforcement alongside content inspection
- AC-4(8): Security and privacy policy filters on data transfers
- AC-4(12): Data type identifiers preventing unauthorized data exfiltration
- AC-4(17): Domain authentication before permitting flow
- AC-4(21): Physical or logical separation of information flows

## AC-5: Separation of Duties

**Control Description:** Organizations identify and document duties requiring separation and define system access authorizations to support separation of duties.

**Key Separation Areas:**
- System administration vs. audit/security administration
- Security testing vs. system development
- Configuration management vs. system programming
- Account management vs. audit review
- Software development vs. production deployment
- Approval authority vs. execution authority
- Purchasing vs. accounts payable vs. receiving

**Implementation Guidance:**
- Map business processes to identify conflicting duties
- Implement technical controls to enforce separation (RBAC, workflow systems)
- Where full separation is impractical, implement compensating controls
- Privileged access management (PAM) tools to enforce just-in-time access
- Audit conflicting role assignments on a periodic basis
- Automated compliance checking for Segregation of Duties (SoD) violations
- Document all exceptions with risk acceptance by appropriate authority

## AC-6: Least Privilege

**Control Description:** Organizations employ the principle of least privilege, allowing only authorized accesses for users and processes that are necessary to accomplish assigned organizational tasks.

**Implementation Principles:**
- Default deny: no access unless explicitly granted
- Time-bound access: privileges granted for specific duration only
- Task-based access: privileges scoped to the specific function being performed
- Need-to-know: information access limited to what is required for the role
- Regular access reviews: certify continued need at least quarterly

**Control Enhancements:**
- AC-6(1): Authorize access to security functions — restrict administrative actions to dedicated security roles
- AC-6(2): Non-privileged access for non-security functions — admins use unprivileged accounts for daily tasks
- AC-6(3): Network access to privileged commands — restrict execution to specific network segments
- AC-6(5): Privileged accounts — restrict privileged accounts to specific personnel with explicit authorization
- AC-6(7): Review of user privileges — review at least annually for appropriateness
- AC-6(9): Log use of privileged functions — audit all privilege escalation and administrative actions
- AC-6(10): Prohibit non-privileged users from executing privileged functions — technical enforcement

**Practical Implementation:**
- Implement tiered administration (Tier 0 for identity, Tier 1 for servers, Tier 2 for workstations)
- Use PAM solutions for checkout/checkin of privileged credentials
- Deploy jump servers or privileged access workstations (PAWs)
- Implement just-in-time (JIT) and just-enough-access (JEA) models
- Monitor privileged session activity with recording and anomaly detection
- Enforce MFA for all privileged access without exception

## AC-7: Unsuccessful Logon Attempts

**Control Description:** The system enforces a limit on consecutive invalid logon attempts within a specified time period and automatically locks the account or delays the next logon attempt when the maximum is exceeded.

**Recommended Parameters:**
- Maximum failed attempts: 3-5 within a 15-minute window
- Lockout duration: 30 minutes minimum, or until unlocked by administrator
- For privileged accounts: 3 attempts maximum, administrator unlock required

**Implementation Considerations:**
- Apply to all authentication interfaces (console, SSH, RDP, web, API)
- Implement progressive delays (exponential backoff) as an alternative to lockout
- Protect against account enumeration through consistent error messages
- Alert security operations on repeated lockout events (potential brute force)
- Consider IP-based rate limiting alongside account-based lockout
- Protect service accounts with different lockout mechanisms to prevent DoS

## AC-8: System Use Notification

**Control Description:** The system displays an approved system use notification before granting access, informing potential users that the system is monitored, recording of activities may occur, unauthorized use is prohibited, and use implies consent to monitoring.

**Banner Requirements:**
- Display before authentication (not after)
- Include legal notice of monitoring and recording
- State that unauthorized access is prohibited and subject to prosecution
- Note that use constitutes consent to monitoring
- Remain displayed until user explicitly acknowledges
- Applicable to interactive and non-interactive (API, CLI) access points

## AC-10: Concurrent Session Control

**Control Description:** The system limits the number of concurrent sessions for each user account to an organization-defined number.

**Guidance:**
- Define maximum concurrent sessions by account type (e.g., standard users: 3, privileged: 1)
- Enforce at both the application and infrastructure layers
- Implement session management to prevent session hijacking
- Consider geographic anomaly detection for concurrent sessions from different locations
- Privileged accounts should typically be limited to a single concurrent session

## AC-11: Device Lock

**Control Description:** The system prevents further access by initiating a device lock after an organization-defined time period of inactivity.

**Parameters:**
- Standard workstations: lock after 15 minutes of inactivity
- High-security environments: lock after 5 minutes
- Server consoles: lock after 10 minutes
- Require re-authentication to unlock
- Display a device lock screen that conceals previously visible information

## AC-12: Session Termination

**Control Description:** The system automatically terminates a user session after organization-defined conditions or trigger events.

**Termination Triggers:**
- Inactivity timeout (distinct from device lock): terminate after 30-60 minutes
- Session maximum duration: force re-authentication after 8-12 hours
- Privilege change: terminate session when access rights are modified
- Network change: terminate when device moves to untrusted network
- Security event: terminate when associated account is flagged

## AC-14: Permitted Actions Without Identification or Authentication

**Control Description:** Organizations identify specific user actions that can be performed without identification and authentication, consistent with organizational missions and business functions.

**Typically Permitted:**
- Access to public-facing web content
- Emergency service information
- System health check endpoints (limited)
- All other actions require identification and authentication

## AC-17: Remote Access

**Control Description:** Organizations establish and document usage restrictions, configuration/connection requirements, and implementation guidance for each type of remote access allowed. Organizations authorize each type of remote access prior to allowing connections.

**Remote Access Methods:**
- VPN (IPsec or SSL/TLS) with multi-factor authentication
- Virtual Desktop Infrastructure (VDI) with session controls
- SSH with key-based authentication and certificate authorities
- Cloud-based remote access (ZTNA, SDP)
- Remote desktop protocols with network-level authentication

**Security Requirements:**
- Encrypt all remote access sessions end-to-end
- Enforce MFA for all remote access without exception
- Implement device posture assessment before granting access
- Monitor and log all remote access sessions
- Restrict remote access to managed and compliant devices
- Implement split tunneling controls based on risk assessment
- Review remote access authorizations at least quarterly

**Control Enhancements:**
- AC-17(1): Automated monitoring and control of remote access sessions
- AC-17(2): Protection of confidentiality and integrity using encryption
- AC-17(3): Managed access control points — route through limited, monitored gateways
- AC-17(4): Privileged commands and access — restrict remote execution of privileged commands
- AC-17(6): Protection of mechanism information — protect remote access credentials and configurations

## AC-18: Wireless Access

**Control Description:** Organizations establish and enforce restrictions, configuration requirements, and authorization for wireless access to the system.

**Requirements:**
- WPA3-Enterprise for all organizational wireless networks
- 802.1X authentication with RADIUS/certificate-based auth
- Rogue access point detection and prevention
- Wireless IDS/IPS deployment and monitoring
- Guest wireless isolated from internal networks
- Disable wireless on devices where not required

## AC-19: Access Control for Mobile Devices

**Control Description:** Organizations establish and enforce configuration requirements, connection requirements, and implementation guidance for organization-controlled mobile devices, and authorize the connection of mobile devices to organizational systems.

**Mobile Device Management Requirements:**
- Enroll all mobile devices in MDM/UEM solution
- Enforce device encryption (full disk or file-based)
- Require screen lock with PIN/biometric of minimum complexity
- Implement remote wipe capability for lost or stolen devices
- Restrict application installation to approved sources
- Enforce OS version and security patch compliance
- Container-based separation of organizational and personal data

## AC-20: Use of External Systems

**Control Description:** Organizations establish terms and conditions for authorized individuals to access the system from external systems and for processing, storing, or transmitting organization-controlled information using external systems.

**Governance Requirements:**
- Document acceptable external systems and connections
- Verify security controls on external systems before authorizing connection
- Limit information accessible from external systems based on classification
- Monitor external system connections for anomalous activity
- Implement contractual obligations for third-party system security
- Review external system authorizations at least annually

## AC-21: Information Sharing

**Control Description:** Organizations facilitate information sharing by enabling authorized users to determine whether access authorizations assigned to a sharing partner match the access restrictions on the information.

**Sharing Controls:**
- Automated policy checking before information release
- Classification marking and handling requirements
- Data loss prevention controls at sharing boundaries
- Audit trail for all information sharing events
- Recipient authentication and authorization verification

## AC-22: Publicly Accessible Content

**Control Description:** Organizations designate individuals authorized to post information onto publicly accessible systems, train authorized individuals, review proposed content before posting, and review content on publicly accessible systems for nonpublic information.

**Review Process:**
- Content approval workflow before public posting
- Automated scanning for sensitive information (PII, credentials, classified)
- Regular review of publicly accessible content at least quarterly
- Incident response procedures for unauthorized public disclosure
- Version control and audit trail for public content changes

## AC-24: Access Control Decisions

**Control Description:** Organizations establish procedures to ensure that access control decisions are applied to each access request prior to access enforcement.

**Decision Architecture:**
- Policy Decision Points (PDP) evaluate access requests against policy
- Policy Enforcement Points (PEP) enforce decisions at access boundaries
- Policy Information Points (PIP) provide attribute data for decisions
- Policy Administration Points (PAP) manage and distribute policies
- Centralize policy management while distributing enforcement
- Cache decisions appropriately with TTL aligned to risk tolerance

## AC-25: Reference Monitor

**Control Description:** The system implements a reference monitor that is tamperproof, always invoked, and small enough to be subject to analysis and testing.

**Properties:**
- Complete mediation: every access request must pass through the monitor
- Tamper-proof: the monitor cannot be modified by unauthorized entities
- Verifiable: the monitor is small enough for comprehensive analysis
- Implementation typically at the OS kernel or hypervisor level
- Modern implementations include security kernels, microkernel architectures, and hardware-enforced isolation
