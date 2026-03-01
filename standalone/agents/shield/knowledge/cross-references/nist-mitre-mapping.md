---
framework: "NIST-MITRE Mapping"
version: "1.0"
domain: "Cross-Reference"
agent: "sentinel"
tags: ["nist", "mitre", "attck", "mapping", "control-coverage", "gap-analysis"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# NIST 800-53 to MITRE ATT&CK Mapping

This document maps NIST SP 800-53 Rev 5 security controls to MITRE ATT&CK techniques, enabling organizations to understand which controls mitigate which attack techniques, identify coverage gaps, and prioritize security investments based on the threat landscape.

## Mapping Methodology

**Purpose:** Connecting defensive controls (NIST 800-53) to offensive techniques (ATT&CK) provides a threat-informed approach to security control selection and prioritization. Organizations can evaluate whether their implemented controls adequately address the techniques used by relevant threat actors.

**Mapping Sources:**
- MITRE ATT&CK Mitigations: official mapping of mitigations to techniques
- NIST SP 800-53 to ATT&CK mapping maintained by MITRE Center for Threat-Informed Defense
- CISA Cross-Sector Cybersecurity Performance Goals (CPGs)
- Organizational threat intelligence on relevant threat actors and their techniques

**Mapping Relationship Types:**
- Direct Mitigation: control directly prevents or significantly reduces the technique
- Detection: control enables detection of the technique (does not prevent)
- Partial Mitigation: control reduces risk but does not fully prevent the technique
- Indirect Mitigation: control addresses a prerequisite or enabler of the technique

## Access Control Mappings

**AC-2 (Account Management) mitigates:**
- T1078 Valid Accounts — managing account lifecycle prevents abuse of dormant accounts
- T1136 Create Account — monitoring account creation detects unauthorized accounts
- T1098 Account Manipulation — tracking account changes detects privilege modifications
- T1078.001 Default Accounts — disabling default accounts removes initial access vector
- Coverage type: Direct Mitigation and Detection

**AC-3 (Access Enforcement) mitigates:**
- T1078 Valid Accounts — authorization prevents misuse of compromised credentials
- T1548 Abuse Elevation Control Mechanism — proper enforcement prevents privilege abuse
- T1068 Exploitation for Privilege Escalation — access controls limit exploit impact
- T1574 Hijack Execution Flow — file permissions prevent binary replacement
- Coverage type: Direct Mitigation

**AC-4 (Information Flow Enforcement) mitigates:**
- T1048 Exfiltration Over Alternative Protocol — flow controls restrict data movement
- T1041 Exfiltration Over C2 Channel — DLP detects data in outbound traffic
- T1567 Exfiltration Over Web Service — web filtering controls data uploads
- T1071 Application Layer Protocol — protocol-aware filtering detects misuse
- Coverage type: Direct Mitigation and Detection

**AC-5 (Separation of Duties) mitigates:**
- T1078 Valid Accounts — limits damage from single compromised account
- T1098 Account Manipulation — prevents single admin from unilateral privilege changes
- Coverage type: Partial Mitigation (limits blast radius)

**AC-6 (Least Privilege) mitigates:**
- T1068 Exploitation for Privilege Escalation — minimal privileges reduce escalation impact
- T1078 Valid Accounts — least privilege limits what compromised accounts can do
- T1548 Abuse Elevation Control Mechanism — minimal standing privileges reduce abuse opportunity
- T1098 Account Manipulation — restricted admin rights prevent unauthorized account changes
- T1543 Create or Modify System Process — restricted privileges prevent service installation
- Coverage type: Direct Mitigation

**AC-17 (Remote Access) mitigates:**
- T1133 External Remote Services — controls on remote access reduce unauthorized use
- T1021 Remote Services — monitoring and restriction of remote access protocols
- T1219 Remote Access Software — controlling remote access tool deployment
- Coverage type: Direct Mitigation

## Identification and Authentication Mappings

**IA-2 (Identification and Authentication) mitigates:**
- T1078 Valid Accounts — MFA makes stolen credentials insufficient for access
- T1110 Brute Force — authentication controls resist password guessing
- T1133 External Remote Services — authentication required for remote service access
- T1566 Phishing — MFA limits effectiveness of credential phishing
- Coverage type: Direct Mitigation

**IA-5 (Authenticator Management) mitigates:**
- T1110 Brute Force — strong password requirements resist cracking
- T1078 Valid Accounts — credential rotation limits window of credential abuse
- T1552 Unsecured Credentials — secure authenticator storage prevents credential theft
- Coverage type: Direct Mitigation

## Audit and Accountability Mappings

**AU-2 (Event Logging) enables detection of:**
- T1078 Valid Accounts — login event logging for anomaly detection
- T1059 Command and Script Interpreter — command execution logging
- T1053 Scheduled Task/Job — task creation event logging
- T1543 Create or Modify System Process — service installation logging
- T1098 Account Manipulation — account change event logging
- T1003 OS Credential Dumping — process access logging for LSASS
- Coverage type: Detection

**AU-6 (Audit Record Review) enables detection of:**
- All tactics — review of audit logs enables detection of any logged technique
- Effectiveness depends on review frequency, correlation capability, and analyst skill
- Automated review (SIEM) provides continuous detection capability
- Coverage type: Detection

## System and Communications Protection Mappings

**SC-7 (Boundary Protection) mitigates:**
- T1190 Exploit Public-Facing Application — firewall and WAF protect perimeter
- T1133 External Remote Services — network controls restrict remote access
- T1048 Exfiltration Over Alternative Protocol — egress filtering prevents data loss
- T1071 Application Layer Protocol — application-aware filtering detects C2
- T1090 Proxy — network controls detect and block proxy usage
- Coverage type: Direct Mitigation and Detection

**SC-8 (Transmission Confidentiality) mitigates:**
- T1557 Adversary-in-the-Middle — encryption prevents traffic interception
- T1040 Network Sniffing — encrypted traffic prevents credential capture
- Coverage type: Direct Mitigation

**SC-28 (Protection of Information at Rest) mitigates:**
- T1005 Data from Local System — encryption renders stolen data unusable
- T1039 Data from Network Shared Drive — encryption protects stored data
- T1003 OS Credential Dumping — encrypted credential stores resist dumping
- Coverage type: Partial Mitigation

## Configuration Management Mappings

**CM-2 (Baseline Configuration) mitigates:**
- T1546 Event Triggered Execution — baseline detects unauthorized persistence
- T1547 Boot or Logon Autostart Execution — baseline detects new autostart entries
- T1574 Hijack Execution Flow — baseline detects library modifications
- Coverage type: Detection

**CM-7 (Least Functionality) mitigates:**
- T1059 Command and Script Interpreter — disabling unnecessary scripting engines
- T1053 Scheduled Task/Job — disabling unnecessary scheduling tools
- T1569 System Services — disabling unnecessary services
- T1218 System Binary Proxy Execution — restricting LOLBin availability
- Coverage type: Direct Mitigation

## System and Information Integrity Mappings

**SI-3 (Malicious Code Protection) mitigates:**
- T1566.001 Spearphishing Attachment — scanning attachments for malware
- T1204.002 Malicious File — detecting malware execution
- T1059 Command and Script Interpreter — detecting malicious script execution
- T1105 Ingress Tool Transfer — detecting downloaded malware
- Coverage type: Direct Mitigation and Detection

**SI-4 (System Monitoring) enables detection of:**
- All techniques — comprehensive monitoring provides visibility across the attack lifecycle
- Effectiveness depends on monitoring scope, rule quality, and analyst capability
- Network, endpoint, and application monitoring provide layered detection
- Coverage type: Detection

## Coverage Analysis

**High-Coverage Control Families:**
- Access Control (AC): covers initial access, persistence, privilege escalation, lateral movement
- Identification and Authentication (IA): covers credential access, initial access
- Audit and Accountability (AU): provides detection capability across all tactics
- System and Information Integrity (SI): covers execution, defense evasion, exfiltration
- System and Communications Protection (SC): covers lateral movement, C2, exfiltration

**Common Coverage Gaps:**
- Insider threat techniques: difficult to prevent with technical controls alone
- Living-off-the-land techniques: legitimate tools used maliciously bypass many controls
- Zero-day exploitation: no signature-based detection for unknown vulnerabilities
- Supply chain compromise: difficult to detect with perimeter-focused controls
- Social engineering: requires user awareness training (AT family) as primary defense

## Prioritization Framework

**Threat-Informed Control Prioritization:**

1. Identify relevant threat actors targeting your industry and geography
2. Map their known TTPs from ATT&CK threat group profiles
3. Identify which NIST controls mitigate each TTP
4. Assess current implementation status of those controls
5. Prioritize control improvements that address the most relevant techniques
6. Implement layered controls: prevention + detection + response for each technique

**Risk-Based Prioritization Matrix:**
- Priority 1: Controls mitigating actively exploited techniques in your industry
- Priority 2: Controls covering the most frequently observed techniques (ATT&CK frequency data)
- Priority 3: Controls addressing techniques in your threat model with high impact
- Priority 4: Broad coverage controls that address multiple techniques simultaneously
- Priority 5: Controls for less common or emerging techniques

**Coverage Scoring:**
- For each ATT&CK technique relevant to your organization:
  - Prevention score (0-3): 0=none, 1=partial, 2=good, 3=strong
  - Detection score (0-3): same scale for detection capability
  - Response score (0-3): same scale for response/containment capability
- Aggregate scores identify weakest areas for investment
- Track score improvement over time as controls are implemented

## Continuous Mapping Maintenance

**Update Triggers:**
- New ATT&CK version release (quarterly)
- New NIST 800-53 updates
- Changes in organizational threat landscape
- Post-incident analysis revealing coverage gaps
- Red team or penetration test findings
- New technology adoption requiring updated mappings

**Automation:**
- Use MITRE ATT&CK Navigator for visual coverage mapping
- MITRE CTID (Center for Threat-Informed Defense) publishes mappings in machine-readable format
- Integrate mapping data with GRC platforms for automated control assessment
- Use threat intelligence to dynamically prioritize based on active campaigns
- Automate coverage scoring through integration with security tool configurations
