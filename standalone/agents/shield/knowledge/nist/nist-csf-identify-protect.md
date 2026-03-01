---
framework: "NIST Cybersecurity Framework"
version: "2.0"
domain: "Identify and Protect Functions"
agent: "sentinel"
tags: ["nist", "csf", "identify", "protect", "risk-management", "asset-management"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# NIST Cybersecurity Framework 2.0 — Identify and Protect Functions

The NIST CSF 2.0 provides a comprehensive taxonomy of cybersecurity outcomes organized into six functions: Govern, Identify, Protect, Detect, Respond, and Recover. This document covers the Identify and Protect functions in depth.

## CSF 2.0 Overview and Structure

The CSF 2.0 is organized into a hierarchical structure: Functions contain Categories, which contain Subcategories. Each subcategory maps to informative references from other standards (NIST 800-53, ISO 27001, CIS Controls). CSF 2.0 added the Govern function to emphasize organizational governance and elevated supply chain risk management.

**Key Changes from CSF 1.1 to 2.0:**
- Added the Govern function as the sixth core function
- Expanded applicability beyond critical infrastructure to all organizations
- Enhanced supply chain risk management guidance
- Added implementation examples for each subcategory
- Improved integration with enterprise risk management
- Updated informative references to current framework versions

## ID.AM: Asset Management

**Objective:** Identify and manage the data, personnel, devices, systems, and facilities that enable the organization to achieve business purposes.

**ID.AM-01: Inventories of hardware managed by the organization are maintained.**
- Maintain a Configuration Management Database (CMDB) or equivalent asset register
- Discover assets through automated scanning (network, cloud API, agent-based)
- Classify assets by criticality using Business Impact Analysis (BIA)
- Track asset lifecycle: procurement, deployment, maintenance, decommission
- Include cloud resources, virtual machines, containers, serverless functions
- Update inventory within 24 hours of provisioning or decommission

**ID.AM-02: Inventories of software, services, and systems managed by the organization are maintained.**
- Catalog all software: operating systems, applications, libraries, frameworks
- Include Software Bill of Materials (SBOM) for critical applications
- Track software versions and patch levels
- Identify unauthorized software through application whitelisting comparison
- Include SaaS applications discovered through CASB or network monitoring
- Map software to asset owners and business processes

**ID.AM-03: Representations of the organization's authorized network communication and internal and external data flows are maintained.**
- Maintain network architecture diagrams updated at least quarterly
- Document data flow diagrams (DFDs) for critical business processes
- Identify trust boundaries between security zones
- Map external connections: internet, partner, cloud, remote access
- Document API integrations and data exchanges
- Include both north-south and east-west traffic flows

**ID.AM-04: Inventories of services provided by suppliers are maintained.**
- Catalog all third-party services with criticality classification
- Document data shared with each supplier
- Track contractual security requirements and SLAs
- Monitor supplier security posture through questionnaires and continuous monitoring
- Maintain fourth-party (supplier's suppliers) visibility for critical services

**ID.AM-05: Assets are prioritized based on classification, criticality, and value to the organization.**
- Implement data classification scheme: Public, Internal, Confidential, Restricted
- Apply BIA results to prioritize systems by recovery objectives
- Map assets to business processes and revenue impact
- Use criticality ratings to guide security control selection
- Update prioritization annually or upon significant business changes

## ID.RA: Risk Assessment

**Objective:** Understand the cybersecurity risk to the organization, assets, and individuals.

**ID.RA-01: Vulnerabilities in assets are identified, validated, and recorded.**
- Conduct authenticated vulnerability scans at least weekly for critical systems
- Scan external-facing assets continuously
- Validate vulnerabilities to eliminate false positives
- Track vulnerabilities in a centralized vulnerability management platform
- Correlate vulnerabilities with threat intelligence for risk prioritization
- Include application-layer vulnerabilities from SAST, DAST, and SCA tools

**ID.RA-02: Cyber threat intelligence is received from information sharing forums and sources.**
- Subscribe to threat intelligence feeds (commercial, open source, government)
- Participate in ISACs relevant to your industry
- Consume and operationalize STIX/TAXII-formatted threat data
- Integrate threat intelligence with SIEM and endpoint detection tools
- Track threat actors targeting your industry and geography
- Contextualize intelligence with organizational relevance

**ID.RA-03: Internal and external threats to the organization are identified and recorded.**
- Maintain a threat register documenting relevant threat sources
- Categories: nation-state actors, cybercriminals, hacktivists, insiders, natural events
- Assess threat actor capability, intent, and targeting
- Map threats to organizational assets and vulnerabilities
- Update threat assessments at least quarterly

**ID.RA-04: Potential impacts and likelihoods of threats exploiting vulnerabilities are identified and recorded.**
- Use quantitative or semi-quantitative risk analysis methods
- Apply frameworks such as FAIR (Factor Analysis of Information Risk)
- Consider financial, operational, reputational, and regulatory impacts
- Factor in existing control effectiveness
- Document risk scenarios with probability and impact ratings

**ID.RA-05: Threats, vulnerabilities, likelihoods, and impacts are used to understand inherent risk and inform prioritization of risk response.**
- Produce risk heat maps showing inherent and residual risk
- Prioritize risks using organizational risk appetite and tolerance
- Develop risk treatment plans: accept, mitigate, transfer, avoid
- Report risk posture to senior leadership and board
- Track risk trending over time

**ID.RA-06: Risk responses are chosen, prioritized, planned, tracked, and communicated.**
- Document risk treatment decisions with responsible parties and timelines
- Track remediation to completion with evidence
- Escalate risks exceeding tolerance to appropriate authority
- Communicate residual risk to system owners and authorizing officials

## ID.IM: Improvement

**Objective:** Improvements to organizational cybersecurity risk management processes, procedures, and activities are identified across all CSF functions.

**ID.IM-01: Improvements are identified from evaluations.**
- Conduct annual security program assessments against CSF
- Perform gap analysis comparing current state to target profile
- Benchmark against industry peers and best practices
- Use assessment findings to prioritize improvement initiatives

**ID.IM-02: Improvements are identified from security tests and exercises.**
- Incorporate findings from penetration tests, red team exercises
- Use incident post-mortem findings for process improvements
- Track improvement actions to completion
- Measure improvement effectiveness through follow-up testing

**ID.IM-03: Improvements are identified from execution of operational processes and procedures.**
- Gather feedback from incident responders and security analysts
- Analyze SOC metrics for process optimization opportunities
- Review change management and configuration management effectiveness
- Identify automation opportunities for repetitive security tasks

## PR.AA: Identity Management, Authentication, and Access Control

**Objective:** Access to physical and logical assets is limited to authorized users, services, and hardware, and managed commensurate with the assessed risk.

**PR.AA-01: Identities and credentials for authorized users, services, and hardware are managed by the organization.**
- Implement centralized identity management (IdP) for all users
- Enforce unique identity for every person, service, and device
- Manage credential lifecycle: issuance, rotation, revocation
- Implement certificate-based identity for devices and services
- Prohibit shared accounts except where explicitly authorized with compensating controls
- Automated provisioning and deprovisioning tied to HR events

**PR.AA-02: Identities are proofed and bound to credentials based on the context of interactions.**
- Verify identity before issuing credentials (identity proofing)
- Use NIST SP 800-63 identity assurance levels (IAL1, IAL2, IAL3)
- Bind credentials to verified identity through secure enrollment
- Re-verify identity periodically for high-risk access

**PR.AA-03: Users, services, and hardware are authenticated.**
- Enforce multi-factor authentication for all interactive access
- Implement phishing-resistant MFA (FIDO2, PIV) for privileged accounts
- Authentication assurance levels: AAL1 (single factor), AAL2 (multi-factor), AAL3 (hardware crypto)
- Mutual authentication for service-to-service communication (mTLS)
- Implement adaptive authentication adjusting requirements based on risk signals
- Protect authentication systems from credential stuffing and brute force

**PR.AA-04: Identity assertions are protected, conveyed, and verified.**
- Use standards-based protocols: OAuth 2.0, OpenID Connect, SAML 2.0
- Protect tokens with appropriate expiration (short-lived access tokens)
- Implement token binding to prevent token theft and replay
- Validate assertions at each relying party
- Implement federation assertion level (FAL) appropriate to risk

**PR.AA-05: Access permissions, entitlements, and authorizations are defined and managed in accordance with the principles of least privilege and separation of duties.**
- Implement RBAC or ABAC models aligned with job functions
- Conduct access reviews at least quarterly for privileged access
- Implement just-in-time (JIT) access for administrative functions
- Enforce separation of duties through technical controls
- Automate access certification campaigns
- Remove standing privileges where possible

**PR.AA-06: Physical access to assets is managed, monitored, and enforced.**
- Implement physical access control systems (badge readers, biometrics)
- Log and monitor all physical access events
- Escort visitors in restricted areas
- Review physical access rights quarterly
- Integrate physical and logical access management

## PR.AT: Awareness and Training

**Objective:** The organization's personnel are provided cybersecurity awareness and training so that they can perform their cybersecurity-related tasks.

**PR.AT-01: Personnel are provided awareness and training so that they possess the knowledge and skills to perform general tasks with cybersecurity risks in mind.**
- Annual security awareness training for all employees
- Topics: phishing, social engineering, password hygiene, data handling, reporting
- Role-specific training for developers (secure coding), admins (hardening), executives (risk)
- Measure effectiveness through phishing simulations and assessments
- Track completion rates with 100% compliance target

**PR.AT-02: Individuals in specialized roles are provided awareness and training so that they possess the knowledge and skills to perform relevant tasks with cybersecurity risks in mind.**
- Developers: OWASP Top 10, secure coding practices, SAST/DAST usage
- System administrators: hardening, patch management, configuration management
- Incident responders: forensics, malware analysis, containment procedures
- Security architects: threat modeling, security design patterns
- Cloud engineers: cloud security, IAM, encryption, monitoring

## PR.DS: Data Security

**Objective:** Data is managed consistent with the organization's risk strategy to protect the confidentiality, integrity, and availability of information.

**PR.DS-01: The confidentiality of data-at-rest is protected.**
- Encrypt sensitive data at rest using AES-256 or equivalent
- Implement full-disk encryption on endpoints and servers
- Use database-level encryption (TDE) for structured data
- Manage encryption keys through dedicated KMS with HSM backing
- Implement key rotation policies (at least annually)
- Protect backup data with encryption equal to primary data

**PR.DS-02: The confidentiality of data-in-transit is protected.**
- Enforce TLS 1.3 (minimum TLS 1.2) for all data in transit
- Implement certificate pinning for critical mobile applications
- Use VPN or dedicated connections for sensitive data transfers
- Disable legacy protocols (SSLv3, TLS 1.0, TLS 1.1)
- Implement HSTS headers for web applications
- Use encrypted DNS (DoH or DoT) where feasible

**PR.DS-10: The confidentiality of data-in-use is protected.**
- Implement DLP controls at endpoint, network, and cloud layers
- Use confidential computing (SGX, SEV, TrustZone) for sensitive workloads
- Clear sensitive data from memory when no longer needed
- Protect against side-channel attacks on cryptographic operations
- Implement screen capture prevention for sensitive applications

**PR.DS-11: Backups of data are created, protected, maintained, and tested for restoration.**
- Follow 3-2-1 backup strategy: 3 copies, 2 media types, 1 offsite
- Encrypt backups and protect encryption keys separately
- Test backup restoration at least quarterly for critical systems
- Implement immutable backups to protect against ransomware
- Define and meet Recovery Point Objectives (RPO) and Recovery Time Objectives (RTO)

## PR.PS: Platform Security

**Objective:** The hardware, software, and services of physical and virtual platforms are managed consistent with the organization's risk strategy.

**PR.PS-01: Configuration management practices are established and applied.**
- Maintain security baselines for all platform types (CIS Benchmarks)
- Implement automated configuration management (Ansible, Chef, Puppet, Terraform)
- Detect and remediate configuration drift continuously
- Enforce infrastructure as code (IaC) with security policy as code
- Change management process for all configuration changes

**PR.PS-02: Software is maintained, replaced, and removed commensurate with risk.**
- Patch critical vulnerabilities within 48 hours
- Patch high vulnerabilities within 14 days
- Remove end-of-life software or implement compensating controls
- Monitor for zero-day vulnerabilities with expedited patching process
- Test patches in staging before production deployment

**PR.PS-03: Hardware is maintained, replaced, and removed commensurate with risk.**
- Track hardware lifecycle and plan for replacement before end-of-support
- Sanitize or destroy media before disposal (NIST SP 800-88)
- Maintain spare hardware for critical systems
- Monitor hardware for tampering or unauthorized modification

**PR.PS-04: Log records are generated and made available for continuous monitoring.**
- Centralize logs in SIEM with defined retention periods
- Log sources: authentication, authorization, system events, network, application
- Protect log integrity with tamper-evident mechanisms
- Synchronize clocks across all systems using NTP
- Retain logs for at least 12 months online, 7 years in archive

**PR.PS-05: Installation and execution of unauthorized software is prevented.**
- Implement application allowlisting on critical systems
- Use code signing for all internally developed software
- Block execution from user-writable directories
- Monitor for unauthorized software through endpoint detection
- Control software repositories and package sources

**PR.PS-06: Secure software development practices are integrated, and their performance is monitored.**
- Implement secure SDLC with security gates at each phase
- Conduct threat modeling during design phase
- Perform SAST, DAST, and SCA in CI/CD pipeline
- Require security review for all code changes to security-critical components
- Track and remediate security findings before release

## PR.IR: Technology Infrastructure Resilience

**Objective:** Security architectures are managed with the organization's risk strategy to protect asset confidentiality, integrity, and availability, and organizational resilience.

**PR.IR-01: Networks and environments are protected from unauthorized logical access and usage.**
- Implement network segmentation based on data classification and function
- Deploy firewalls between security zones with deny-by-default rules
- Implement micro-segmentation for east-west traffic control
- Use network access control (NAC) for device admission
- Monitor network traffic for anomalies with NDR tools

**PR.IR-02: The organization's technology assets are protected from environmental and physical threats.**
- Physical security controls for data centers and server rooms
- Environmental controls: HVAC, fire suppression, water detection
- Redundant power (UPS, generators) for critical infrastructure
- Geographic diversity for disaster resilience

**PR.IR-03: Mechanisms are implemented to achieve resilience requirements in normal and adverse situations.**
- High availability architectures for critical systems
- Load balancing and failover capabilities
- DDoS protection and mitigation services
- Capacity planning with headroom for surge conditions
- Chaos engineering to validate resilience assumptions

**PR.IR-04: Adequate resource capacity to ensure availability is maintained.**
- Monitor capacity utilization and trend against growth projections
- Implement auto-scaling for cloud workloads
- Maintain performance baselines for anomaly detection
- Plan for capacity needs during incident response surge
