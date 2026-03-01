---
framework: "MITRE ATT&CK"
version: "15.1"
domain: "Initial Access"
agent: "sentinel"
tags: ["mitre", "attck", "initial-access", "phishing", "exploitation", "supply-chain"]
last_updated: "2025-06-01"
chunk_strategy: "technique"
---

# MITRE ATT&CK — Initial Access (TA0001)

Initial Access consists of techniques adversaries use to gain an initial foothold within a network. Techniques include exploiting public-facing applications, spear phishing, and leveraging trusted relationships. Understanding these techniques is critical for perimeter defense and early detection.

## T1566: Phishing

**Technique Description:** Adversaries send messages to gain access to victim systems. All forms of phishing are electronically delivered social engineering. Messages may contain malicious attachments, links, or manipulate users into divulging credentials.

**Sub-techniques:**

**T1566.001: Spearphishing Attachment**
- Adversaries attach malicious files to emails tailored to specific targets
- Common file types: Office documents with macros (DOCM, XLSM), PDFs, compressed archives (ZIP, RAR, ISO, IMG), HTML smuggling payloads
- Modern variations use password-protected archives to bypass email scanning
- ISO/IMG files used to bypass Mark-of-the-Web (MOTW) protections
- OneNote files (.one) increasingly used as macro policies tighten

**T1566.002: Spearphishing Link**
- Messages contain URLs directing victims to malicious sites
- Credential harvesting pages mimicking legitimate services (O365, Google)
- Drive-by download sites exploiting browser or plugin vulnerabilities
- Adversary-in-the-middle (AiTM) phishing proxies to capture session tokens and bypass MFA
- QR code phishing (quishing) to evade URL scanning
- Use of legitimate services (Google Docs, SharePoint) to host malicious content

**T1566.003: Spearphishing via Service**
- Phishing through social media (LinkedIn, Twitter), messaging platforms (Slack, Teams, Discord)
- Exploits trust in platform-internal communications
- May bypass email security controls entirely

**T1566.004: Spearphishing Voice (Vishing)**
- Phone calls impersonating IT support, executives, or service providers
- Often combined with other techniques for multi-stage attacks
- AI-generated voice deepfakes increasing realism

**Detection Strategies:**
- Email security gateway with sandboxing for attachment detonation
- URL rewriting and time-of-click analysis
- DMARC, DKIM, SPF enforcement to reduce email spoofing
- User-reported phishing analysis and response automation
- Monitor for AiTM indicators: unusual token issuance patterns, impossible travel
- Browser isolation for untrusted URLs
- Behavioral analytics on email patterns (unusual senders, first-time contacts)

**Mitigations:**
- M1049: Antivirus/Antimalware — scan attachments and downloads
- M1031: Network Intrusion Prevention — inspect email traffic
- M1054: Software Configuration — disable macros by default via Group Policy
- M1017: User Training — phishing awareness with simulated exercises
- M1032: Multi-factor Authentication — phishing-resistant MFA (FIDO2)
- M1021: Restrict Web-Based Content — block high-risk file types at email gateway

## T1190: Exploit Public-Facing Application

**Technique Description:** Adversaries exploit vulnerabilities in internet-facing applications to gain initial access. This includes web applications, VPN gateways, email servers, firewalls, and other perimeter services.

**Common Targets:**
- Web applications: SQL injection, command injection, deserialization, SSRF
- VPN appliances: Pulse Secure/Ivanti, Fortinet, Citrix, Palo Alto GlobalProtect
- Email servers: Microsoft Exchange (ProxyLogon, ProxyShell, ProxyNotShell)
- Firewalls and security appliances: Fortinet FortiOS, SonicWall, Cisco ASA
- CMS platforms: WordPress, Drupal, Confluence, SharePoint
- File transfer solutions: MOVEit, GoAnywhere, Accellion FTA
- CI/CD systems: Jenkins, GitLab, Bamboo exposed to internet

**Exploitation Patterns:**
- Zero-day exploitation by nation-state actors targeting perimeter devices
- N-day exploitation by cybercriminals targeting unpatched systems
- Chaining multiple lower-severity vulnerabilities for full compromise
- Mass scanning and exploitation within hours of CVE publication

**Detection Strategies:**
- Web Application Firewall (WAF) with virtual patching capabilities
- Network IDS/IPS with signatures for known exploits
- Application-level logging of errors, exceptions, and unusual requests
- Monitor for web shell deployment in web server directories
- File integrity monitoring on web application directories
- Anomalous process execution from web server or application processes
- External attack surface management (EASM) for visibility

**Mitigations:**
- M1048: Application Isolation and Sandboxing
- M1030: Network Segmentation — isolate public-facing services from internal networks
- M1051: Update Software — prioritize patching internet-facing systems within 48 hours
- M1016: Vulnerability Scanning — continuous scanning of external attack surface
- M1050: Exploit Protection — deploy RASP and WAF
- Implement virtual patching while testing production patches

## T1133: External Remote Services

**Technique Description:** Adversaries leverage external-facing remote services to initially access and persist within a network. Services such as VPN, RDP, Citrix, and SSH can be abused with valid credentials.

**Targeted Services:**
- VPN services (SSL VPN, IPsec VPN) — most commonly targeted
- Remote Desktop Protocol (RDP) exposed to internet
- Remote Desktop Gateway / Remote Desktop Web Access
- Citrix Virtual Apps and Desktops (Citrix Gateway)
- SSH services exposed to internet
- Remote management tools: TeamViewer, AnyDesk, ConnectWise ScreenConnect
- Cloud-based remote access services

**Attack Methods:**
- Credential stuffing using leaked credential databases
- Brute force attacks against exposed authentication endpoints
- Exploiting known vulnerabilities in VPN appliances
- Using previously compromised credentials (from phishing or infostealers)
- Purchasing access from Initial Access Brokers (IABs) on dark web
- MFA bypass through push fatigue (MFA bombing), SIM swapping, or AiTM

**Detection Strategies:**
- Monitor for authentication from unusual geographic locations
- Detect impossible travel scenarios (login from distant locations in short time)
- Alert on successful authentication after multiple failures
- Monitor for off-hours remote access by non-standard users
- Correlate VPN authentication with endpoint agent check-in
- Detect use of anonymizing services (TOR, residential proxies) for authentication
- Track concurrent sessions from the same user in different locations

**Mitigations:**
- M1032: Multi-factor Authentication — enforce on all remote access
- M1035: Limit Access to Resource Over Network — restrict remote services to managed IPs
- M1030: Network Segmentation — place remote access in DMZ
- M1036: Account Use Policies — disable unused remote access accounts
- Implement Zero Trust Network Access (ZTNA) instead of traditional VPN
- Deploy device posture assessment before granting access
- Implement rate limiting and account lockout on remote access services

## T1195: Supply Chain Compromise

**Technique Description:** Adversaries manipulate products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromise.

**T1195.001: Compromise Software Dependencies and Development Tools**
- Trojanize open source packages in npm, PyPI, Maven, NuGet registries
- Dependency confusion / namespace hijacking attacks
- Compromise developer tools: IDEs, build tools, code signing infrastructure
- Inject malicious code into legitimate open source projects
- Typosquatting on popular package names

**T1195.002: Compromise Software Supply Chain**
- Compromise software vendor's build or update infrastructure
- Inject backdoors into legitimate software updates (SolarWinds Orion, Kaseya VSA)
- Compromise code signing certificates to sign malicious updates
- Modify source code in version control systems
- Compromise CI/CD pipelines to inject malicious code

**T1195.003: Compromise Hardware Supply Chain**
- Implant malicious firmware or hardware components during manufacturing
- Modify hardware during transit (interdiction)
- Counterfeit components with embedded backdoors
- BIOS/UEFI rootkit implantation

**Detection Strategies:**
- Verify software integrity using cryptographic hashes and signatures
- Monitor for unexpected software update behavior
- Implement Software Bill of Materials (SBOM) tracking
- Scan dependencies for known vulnerabilities and malicious indicators
- Monitor for network connections to unexpected destinations from updated software
- Behavioral analysis of updated software for anomalous activity
- Code review of critical dependencies

**Mitigations:**
- M1051: Update Software — keep dependencies current while verifying integrity
- M1016: Vulnerability Scanning — scan dependencies with SCA tools (Snyk, Dependabot)
- Implement supply chain security frameworks (SLSA, SSDF)
- Use dependency pinning with integrity verification (lock files, hash checking)
- Establish trusted package repositories and mirrors
- Vendor risk management program with security assessments
- Implement software attestation and provenance verification

## T1078: Valid Accounts

**Technique Description:** Adversaries obtain and abuse credentials of existing accounts to gain initial access, persistence, privilege escalation, or defense evasion.

**T1078.001: Default Accounts**
- Factory-default credentials on devices, applications, and services
- Default credentials in documentation or publicly known
- Unchanged SNMP community strings, database accounts, admin panels

**T1078.002: Domain Accounts**
- Compromised Active Directory credentials
- Stolen through Kerberoasting, credential dumping, phishing
- Purchased from credential brokers or harvested from data breaches

**T1078.003: Local Accounts**
- Local administrator accounts with shared or weak passwords
- Service accounts with static credentials
- Root accounts on Linux/Unix systems

**T1078.004: Cloud Accounts**
- Compromised cloud service credentials (AWS, Azure, GCP)
- Stolen API keys and access tokens
- OAuth token theft through consent phishing
- Exposed credentials in code repositories

**Detection Strategies:**
- User and Entity Behavior Analytics (UEBA) for anomalous account usage
- Monitor for credentials used from unusual locations, devices, or times
- Detect account usage from multiple geographic locations simultaneously
- Alert on dormant account activation
- Monitor cloud API activity for unusual patterns
- Correlate authentication events across identity providers

**Mitigations:**
- M1032: Multi-factor Authentication — enforce everywhere
- M1027: Password Policies — enforce complexity, length (14+ characters), rotation
- M1026: Privileged Account Management — PAM for all privileged access
- M1036: Account Use Policies — disable default accounts, review unused accounts
- Implement credential monitoring for leaked credentials (dark web monitoring)
- Deploy passwordless authentication where possible

## T1189: Drive-by Compromise

**Technique Description:** Adversaries gain access through a user visiting a website during normal browsing. The user's web browser or browser plugins are exploited, typically targeting known or zero-day vulnerabilities.

**Attack Vectors:**
- Compromised legitimate websites (watering hole attacks)
- Malvertising through advertising networks
- Exploit kits targeting browser and plugin vulnerabilities
- Browser-based cryptocurrency miners
- Drive-by download from typosquatted domains

**Detection Strategies:**
- Endpoint Detection and Response (EDR) monitoring browser child processes
- Network monitoring for exploit kit traffic patterns
- Proxy logs analysis for known malicious redirectors
- Browser isolation for high-risk browsing
- DNS monitoring for suspicious domain resolution

**Mitigations:**
- M1048: Application Isolation and Sandboxing — browser isolation
- M1051: Update Software — keep browsers and plugins current
- M1021: Restrict Web-Based Content — ad blockers, script blockers
- M1050: Exploit Protection — browser exploit mitigation features

## T1199: Trusted Relationship

**Technique Description:** Adversaries breach or leverage organizations that have access to intended victims. Access through trusted third-party relationships exploits the trust granted to the third party.

**Common Vectors:**
- Managed Service Provider (MSP) access to client environments
- IT vendor remote access for support and maintenance
- Cloud service provider administrative access
- Business partner VPN connections
- Contractors with privileged access to systems

**Detection Strategies:**
- Monitor third-party access sessions for unusual patterns
- Implement session recording for third-party remote access
- Alert on third-party access outside agreed maintenance windows
- Monitor for lateral movement originating from third-party access points
- Review third-party account activity logs regularly

**Mitigations:**
- M1030: Network Segmentation — restrict third-party access to specific systems
- M1032: Multi-factor Authentication — require MFA for all third-party access
- Implement just-in-time access for vendor connections
- Conduct regular security assessments of critical third parties
- Define and enforce least-privilege access for all third-party accounts
- Contractual security requirements with right-to-audit clauses

## T1091: Replication Through Removable Media

**Technique Description:** Adversaries move onto systems by copying malware to removable media and taking advantage of autorun features or tricking users into executing.

**Detection:**
- Monitor for USB device connections and file execution
- Endpoint DLP monitoring for removable media activity
- Block autorun and autoplay features via Group Policy

**Mitigations:**
- M1042: Disable or Remove Feature — disable autorun/autoplay
- M1034: Limit Hardware Installation — restrict USB device usage
- M1040: Behavior Prevention on Endpoint — block execution from removable media

## T1200: Hardware Additions

**Technique Description:** Adversaries introduce computer accessories, networking hardware, or other computing devices into a system to gain access. Examples include hardware keyloggers, rogue wireless access points, and USB network implants.

**Detection:**
- Network Access Control (NAC) detecting unauthorized devices
- Physical inspection of equipment
- Wireless scanning for rogue access points
- USB device monitoring and alerting on new device types

**Mitigations:**
- M1034: Limit Hardware Installation — enforce device whitelisting
- M1035: Limit Access to Resource Over Network — 802.1X port-based NAC
- Physical security controls and visitor management
- Endpoint protection preventing unauthorized device drivers
