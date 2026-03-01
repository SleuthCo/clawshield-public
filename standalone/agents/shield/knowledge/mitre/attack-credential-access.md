---
framework: "MITRE ATT&CK"
version: "15.1"
domain: "Credential Access"
agent: "sentinel"
tags: ["mitre", "attck", "credential-access", "password", "kerberos", "credential-dumping"]
last_updated: "2025-06-01"
chunk_strategy: "technique"
---

# MITRE ATT&CK — Credential Access (TA0006)

Credential Access consists of techniques for stealing credentials like account names and passwords. Techniques include keylogging, credential dumping, and Kerberos ticket manipulation. Obtaining valid credentials enables adversaries to access systems, evade detection, and create additional backdoor accounts.

## T1110: Brute Force

**Technique Description:** Adversaries use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.

**T1110.001: Password Guessing**
- Attempt common passwords against known usernames
- Leverage organizational password patterns (Company2024!, Season+Year)
- Use OSINT to identify likely passwords (pet names, sports teams, birthdays)
- Targeted at specific high-value accounts (executives, administrators)
- Low-and-slow approach to avoid account lockout

**T1110.002: Password Cracking**
- Offline cracking of obtained password hashes
- Tools: Hashcat, John the Ripper
- Attack methods: dictionary, rules-based, hybrid, mask attacks
- GPU-accelerated cracking achieving billions of hashes per second for MD5/NTLM
- Rainbow table attacks against unsalted hashes
- Common hash types targeted: NTLM, Kerberos TGS (Kerberoasting), NTLMv2, bcrypt

**T1110.003: Password Spraying**
- Attempt a small number of commonly used passwords against many accounts
- Designed to avoid account lockout thresholds
- Effective against organizations with weak password policies
- Often targets cloud services: Azure AD, O365, Okta
- Typical spray: 1-2 passwords per account per lockout window
- Commonly sprayed passwords: Season+Year, Company+Year, Welcome1

**T1110.004: Credential Stuffing**
- Use credentials from data breaches against other services
- Exploit password reuse across personal and corporate accounts
- Automated using tools like Sentry MBA, OpenBullet, custom scripts
- Massive scale: millions of credential pairs tested
- Target consumer-facing and enterprise authentication endpoints

**Detection Strategies:**
- Monitor for multiple failed authentication attempts from single source
- Detect authentication failures across multiple accounts from single IP (spraying)
- Alert on successful authentication following period of failures
- Monitor for high-volume authentication requests from unusual sources
- Implement UEBA to detect anomalous authentication patterns
- Track geographically dispersed authentication attempts
- Monitor for authentication attempts against disabled or locked accounts
- Detect use of known breach credential lists via threat intelligence

**Mitigations:**
- M1032: Multi-factor Authentication — prevents use of stolen passwords alone
- M1027: Password Policies — minimum 14 characters, complexity requirements
- M1036: Account Use Policies — lockout after 5 failed attempts in 15 minutes
- Implement password blocklists (known breached passwords, common patterns)
- Deploy CAPTCHA or progressive delays on authentication endpoints
- Monitor dark web for organizational credential exposure
- Enforce unique passwords through breach detection integration (Azure AD Password Protection, Have I Been Pwned API)

## T1003: OS Credential Dumping

**Technique Description:** Adversaries attempt to dump credentials to obtain account login and credential material, typically hashes or clear text passwords, from the operating system and software.

**T1003.001: LSASS Memory**
- Dump Local Security Authority Subsystem Service (lsass.exe) process memory
- Contains NTLM hashes, Kerberos tickets, cleartext passwords (if WDigest enabled)
- Tools: Mimikatz (sekurlsa::logonpasswords), ProcDump, comsvcs.dll MiniDump
- Direct memory access or creating a memory dump file for offline extraction
- Modern variants use direct syscalls to evade EDR API hooking
- LSASS Shtinkering and other advanced dump techniques

**T1003.002: Security Account Manager (SAM)**
- Extract password hashes from SAM database
- Located at %SystemRoot%\\System32\\config\\SAM (locked during normal operation)
- Access via registry: reg save HKLM\\SAM, HKLM\\SYSTEM
- Volume Shadow Copy provides access to locked SAM file
- Contains local account NTLM hashes

**T1003.003: NTDS**
- Extract Active Directory database (ntds.dit) containing all domain credentials
- Methods: ntdsutil, Volume Shadow Copy, DCSync (MS-DRSR replication)
- DCSync mimics domain controller replication to request password data
- Requires Domain Admin or specific replication permissions
- Contains NTLM hashes for all domain accounts

**T1003.004: LSA Secrets**
- Extract secrets stored in LSA from registry
- Contains service account passwords, cached domain credentials, DPAPI keys
- Registry location: HKLM\\SECURITY\\Policy\\Secrets
- Tools: Mimikatz (lsadump::secrets), secretsdump.py

**T1003.005: Cached Domain Credentials**
- Extract cached domain logon information (MSCACHE/DCC2 hashes)
- Stored for offline logon when domain controllers are unavailable
- Default: 10 most recent logons cached
- Slower to crack than NTLM (PBKDF2-based)
- Registry: HKLM\\SECURITY\\Cache

**T1003.006: DCSync**
- Abuse Active Directory replication protocol to request password hashes
- Mimics a domain controller requesting replication data
- Requires: Replicating Directory Changes All permission
- Tools: Mimikatz (lsadump::dcsync), secretsdump.py
- Can target specific accounts or dump entire domain

**T1003.007: Proc Filesystem (Linux)**
- Extract credentials from /proc filesystem
- Read process memory of running applications
- Target: ssh-agent, web servers, database clients with cached credentials
- /proc/[pid]/maps and /proc/[pid]/mem for memory access

**T1003.008: /etc/passwd and /etc/shadow**
- Extract password hashes from Linux password files
- /etc/shadow requires root access
- Offline cracking of extracted hashes (SHA-512 crypt, yescrypt)

**Detection Strategies:**
- Monitor access to lsass.exe process (Sysmon Event ID 10: ProcessAccess)
- Detect suspicious process access to LSASS with PROCESS_VM_READ
- Monitor for ntdsutil.exe, secretsdump.py, or similar tool execution
- Alert on Volume Shadow Copy creation (vssadmin, wmic shadowcopy)
- Detect DCSync: monitor for unusual directory replication requests (Event ID 4662)
- Monitor registry access to SAM, SECURITY, and SYSTEM hives
- Monitor for comsvcs.dll MiniDump calls
- EDR behavioral detection for credential dumping patterns
- Monitor for credential access tools in memory or on disk

**Mitigations:**
- M1040: Behavior Prevention on Endpoint — Credential Guard, LSASS protection (PPL)
- M1043: Credential Access Protection — Windows Credential Guard
- M1026: Privileged Account Management — reduce number of privileged accounts
- M1027: Password Policies — avoid WDigest authentication
- Enable LSA RunAsPPL to protect LSASS from memory access
- Disable caching of domain credentials where feasible
- Implement tiered administration to limit credential exposure
- Restrict DCSync permissions to actual domain controllers only
- Monitor and restrict access to ntds.dit and backup copies

## T1558: Steal or Forge Kerberos Tickets

**Technique Description:** Adversaries attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets to enable Pass the Ticket or to forge tickets for impersonation.

**T1558.001: Golden Ticket**
- Forge Ticket Granting Tickets (TGT) using the krbtgt account hash
- Provides unrestricted access to the entire domain
- Valid for the lifetime specified (attackers often set 10 years)
- Survives password resets of individual accounts
- Requires: krbtgt NTLM hash (obtained through DCSync or NTDS extraction)
- Remediation: reset krbtgt password twice (old password still valid for one cycle)

**T1558.002: Silver Ticket**
- Forge Ticket Granting Service (TGS) tickets for specific services
- Requires: service account NTLM hash
- Provides access to specific service without contacting domain controller
- Harder to detect than Golden Tickets (no TGT request in DC logs)
- Commonly targeted: CIFS (file shares), HTTP (web), MSSQL, LDAP

**T1558.003: Kerberoasting**
- Request TGS tickets for service accounts from the domain controller
- Crack the ticket offline to recover the service account password
- Any domain user can request tickets for SPNs
- Tools: Rubeus (kerberoast), GetUserSPNs.py (Impacket)
- Targets service accounts with SPNs registered
- Effective because many service accounts have weak passwords

**T1558.004: AS-REP Roasting**
- Target accounts with Kerberos pre-authentication disabled
- Request AS-REP for these accounts and crack offline
- Similar to Kerberoasting but targets a different Kerberos exchange
- Enabled by: DONT_REQUIRE_PREAUTH user account flag
- Tools: Rubeus (asreproast), GetNPUsers.py (Impacket)

**Detection Strategies:**
- Monitor for anomalous TGS ticket requests (Event ID 4769) targeting service accounts
- Detect encryption downgrade: RC4 ticket requests when AES is configured (Kerberoasting indicator)
- Alert on TGT usage without corresponding AS-REQ (Golden Ticket indicator)
- Monitor for TGS tickets with unusually long lifetimes
- Track AS-REP requests for accounts without pre-authentication
- Honeypot accounts with SPNs to detect Kerberoasting activity
- Monitor krbtgt account for password changes outside planned rotations
- UEBA for unusual service ticket request patterns

**Mitigations:**
- M1027: Password Policies — enforce 25+ character passwords for service accounts
- M1026: Privileged Account Management — use managed service accounts (gMSA) where possible
- M1041: Encrypt Sensitive Information — enforce AES encryption for Kerberos
- Enable Kerberos pre-authentication for all accounts
- Rotate krbtgt password every 180 days
- Minimize service accounts with SPNs
- Use Group Managed Service Accounts (gMSA) with automatic password rotation
- Implement Kerberos armoring (FAST) where supported

## T1552: Unsecured Credentials

**Technique Description:** Adversaries search compromised systems for insecurely stored credentials that can be used for lateral movement or privilege escalation.

**T1552.001: Credentials In Files**
- Search for passwords in configuration files, scripts, and documents
- Common locations: web.config, applicationSettings, .env files
- Infrastructure as Code: Terraform state files, Ansible playbooks
- Developer notes, README files, documentation
- Browser-saved passwords in profile directories
- Password managers database files
- Tools: LaZagne, SharpChrome, truffleHog

**T1552.002: Credentials in Registry**
- Windows registry stores credentials for services, VPN, Wi-Fi
- Autologon credentials: HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon
- VPN credentials in vendor-specific registry locations
- Putty stored sessions with credentials

**T1552.003: Bash History**
- Extract credentials from command history files
- .bash_history, .zsh_history may contain passwords passed as arguments
- MySQL, SSH, curl commands with inline credentials
- Environment variable exports containing secrets

**T1552.004: Private Keys**
- Steal SSH private keys from user directories (.ssh/id_rsa)
- Extract TLS/SSL private keys from web servers
- Cloud service account key files (GCP JSON keys, AWS credentials)
- Code signing certificates and private keys
- API keys stored in application configuration

**T1552.005: Cloud Instance Metadata API**
- Query cloud metadata services for credentials
- AWS: http://169.254.169.254/latest/meta-data/iam/security-credentials/
- Azure: http://169.254.169.254/metadata/identity/oauth2/token
- GCP: http://metadata.google.internal/computeMetadata/v1/
- SSRF vulnerabilities used to access metadata from external position
- Instance metadata provides temporary credentials for attached roles

**T1552.006: Group Policy Preferences**
- Extract passwords from Group Policy Preferences XML files
- SYSVOL: \\\\domain\\SYSVOL\\domain\\Policies\\\\Machine\\Preferences
- Passwords encrypted with a publicly known AES key (MS14-025)
- Tools: Get-GPPPassword (PowerSploit)

**T1552.007: Container API**
- Access Kubernetes secrets and ConfigMaps
- Docker environment variables containing credentials
- Container orchestration API access for secret extraction
- Service mesh credentials and certificates

**Detection Strategies:**
- Monitor file access to known credential storage locations
- Alert on registry queries to autologon and credential storage keys
- Detect bulk file searches for credential patterns (findstr, grep for "password")
- Monitor for metadata API access from unexpected instances or processes
- DLP controls scanning for credential patterns in files
- Monitor for access to SYSVOL Group Policy Preferences files
- Track Kubernetes secret access through audit logging
- Alert on unusual cloud metadata API access patterns

**Mitigations:**
- M1015: Active Directory Configuration — remove GPP passwords, enforce LAPS
- M1022: Restrict File and Directory Permissions on credential stores
- M1027: Password Policies — prohibit storing passwords in cleartext
- Implement secrets management solutions (HashiCorp Vault, AWS Secrets Manager)
- Use IMDSv2 (token-required) on AWS to prevent SSRF-based metadata access
- Encrypt credential files and protect with strong access controls
- Implement credential scanning in CI/CD pipelines (git-secrets, detect-secrets)
- Regular credential rotation and revocation

## T1556: Modify Authentication Process

**Technique Description:** Adversaries modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts.

**T1556.001: Domain Controller Authentication**
- Patch LSASS on domain controllers to capture credentials
- Skeleton Key: inject into LSASS to add a master password
- SSP (Security Support Provider) injection for credential capture
- DCShadow: register a rogue domain controller for persistence

**T1556.002: Password Filter DLL**
- Register malicious password filter DLL on domain controllers
- Captures plaintext passwords during password change operations
- DLL receives username and new password in cleartext
- Registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Notification Packages

**T1556.003: Pluggable Authentication Modules (PAM)**
- Modify PAM configuration on Linux to capture or bypass authentication
- Insert malicious PAM module to log credentials
- Modify pam_unix.so or add custom module accepting any password
- Common target: /etc/pam.d/sshd, /etc/pam.d/common-auth

**T1556.004: Network Device Authentication**
- Modify authentication on network devices (routers, switches, firewalls)
- Add backdoor accounts or modify authentication mechanisms
- Patch firmware to accept additional credentials
- Modify TACACS+ or RADIUS configurations

**T1556.005: Reversible Encryption**
- Enable reversible encryption storage of passwords in Active Directory
- Allows retrieval of cleartext passwords from domain controller
- Setting: "Store passwords using reversible encryption" in GPO

**T1556.006: Multi-Factor Authentication**
- Compromise MFA mechanisms to bypass authentication
- Register additional MFA devices to attacker-controlled phone
- Exploit MFA enrollment processes
- SIM swapping for SMS-based MFA
- Steal TOTP seeds from authentication servers

**T1556.007: Hybrid Identity**
- Compromise Azure AD Connect or similar identity synchronization
- Access the synchronization service account credentials
- Modify synchronization rules to maintain access
- Tools: AADInternals for Azure AD Connect exploitation

**T1556.008: Network Provider DLL**
- Register a malicious network provider DLL that captures credentials
- HKLM\\SYSTEM\\CurrentControlSet\\Control\\NetworkProvider\\Order
- Captures credentials during network logon operations
- Executes with SYSTEM privileges during authentication

**Detection Strategies:**
- File integrity monitoring on authentication libraries (LSASS DLLs, PAM modules)
- Monitor password filter DLL registration (registry changes)
- Alert on network provider DLL additions
- Monitor Azure AD Connect configuration changes
- Track MFA device registration events for anomalies
- Detect Skeleton Key by testing master passwords against domain accounts
- Monitor for DCShadow by detecting rogue DC registration in AD
- Audit PAM configuration file modifications on Linux systems

**Mitigations:**
- M1032: Multi-factor Authentication — phishing-resistant MFA (FIDO2)
- M1026: Privileged Account Management — restrict DC and identity system access
- M1022: Restrict File and Directory Permissions on authentication components
- M1028: Operating System Configuration — enable LSA protection (RunAsPPL)
- Implement Windows Credential Guard on domain controllers
- Monitor and alert on all authentication infrastructure changes
- Restrict who can modify PAM configuration and install PAM modules
- Regular integrity verification of authentication components

## T1539: Steal Web Session Cookie

**Technique Description:** Adversaries steal web session cookies to authenticate to web applications and services without needing credentials.

**Attack Methods:**
- Extract cookies from browser profile directories
- Intercept cookies through man-in-the-middle attacks
- Cross-site scripting (XSS) to exfiltrate cookies
- Malware cookie theft from browser process memory
- Adversary-in-the-middle (AiTM) phishing to capture session tokens
- Pass-the-cookie attacks using stolen session data

**Detection Strategies:**
- Monitor for browser credential file access by non-browser processes
- Detect session usage from unusual IPs or user agents
- Implement cookie binding to specific device characteristics
- Monitor for concurrent sessions with different IP addresses

**Mitigations:**
- M1032: Multi-factor Authentication with token binding
- M1054: Software Configuration — short session timeouts, HttpOnly/Secure/SameSite cookie flags
- Implement continuous session validation
- Deploy AiTM-resistant authentication (FIDO2, certificate-based)

## T1111: Multi-Factor Authentication Interception

**Technique Description:** Adversaries target MFA mechanisms to intercept or bypass additional authentication factors.

**Interception Methods:**
- Intercept SMS-based OTP via SIM swapping or SS7 exploitation
- Man-in-the-middle proxies capturing and replaying MFA tokens in real-time
- Malware intercepting TOTP codes from authenticator applications
- Social engineering users to provide MFA codes (vishing)
- MFA fatigue / push bombing — sending repeated push notifications

**Detection and Mitigation:**
- Implement phishing-resistant MFA (FIDO2/WebAuthn, certificate-based)
- Monitor for repeated MFA push denials followed by acceptance
- Implement number matching for push-based MFA
- Alert on MFA registration changes
- Detect unusual authentication patterns suggesting MFA bypass
