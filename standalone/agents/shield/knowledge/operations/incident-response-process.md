---
framework: "NIST SP 800-61r2"
version: "2.0"
domain: "Incident Response"
agent: "sentinel"
tags: ["incident-response", "nist-800-61", "playbooks", "forensics", "ir-lifecycle", "soc"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Incident Response Process — NIST SP 800-61r2

This document details the incident handling lifecycle as defined in NIST SP 800-61 Revision 2, including team structure, playbook design, communication protocols, and post-incident activities.

## Incident Response Lifecycle Overview

The NIST incident response lifecycle consists of four phases that form a continuous cycle: Preparation; Detection and Analysis; Containment, Eradication, and Recovery; and Post-Incident Activity. These phases are not strictly sequential; organizations may cycle between detection/analysis and containment multiple times during a single incident.

## Phase 1: Preparation

**Objective:** Establish the incident response capability before incidents occur. Preparation is the foundation that determines the effectiveness of all subsequent phases.

**IR Team Establishment:**
- Define IR team structure: centralized, distributed, or hybrid model
- Establish clear roles: IR manager, lead analyst, forensic analyst, communications lead
- Define escalation authority and decision-making matrix
- Secure executive sponsorship and authority for the IR team
- Establish 24/7 on-call rotation with contact procedures
- Cross-train team members to avoid single points of failure

**IR Toolkit and Infrastructure:**
- Forensic workstations with write-blockers and imaging tools
- Network analysis tools: packet capture, flow analysis, DNS logging
- Memory acquisition tools: WinPmem, AVML, LiME
- Disk imaging tools: FTK Imager, dc3dd, ewfacquire
- Malware analysis sandbox: isolated VM environment, Cuckoo/CAPE
- Secure communication channels: encrypted messaging, out-of-band phones
- Jump bag: portable forensic kit for on-site response
- Evidence storage: secure, access-controlled, tamper-evident

**Documentation and Procedures:**
- Incident response plan reviewed and approved by leadership
- Playbooks for common incident types (see Playbook section)
- Contact lists: internal teams, management, legal, PR, law enforcement
- Third-party contacts: MSSP, IR retainer firms, ISACs, CISA
- Evidence handling procedures and chain of custody forms
- Communication templates: internal notifications, customer notifications, regulatory reports

**Detection Infrastructure:**
- SIEM configured with detection rules and correlation logic
- EDR deployed on all endpoints with detection policies
- Network detection and response (NDR) for traffic analysis
- Email security with sandboxing and URL analysis
- Cloud security monitoring (CSPM, CWPP, CASB)
- Deception technology (honeypots, honeytokens) for early detection

## Phase 2: Detection and Analysis

**Detection Sources:**
- SIEM alerts from correlation rules and analytics
- EDR behavioral detections and alerts
- User reports of suspicious activity or phishing
- Threat intelligence feeds matching organizational indicators
- Network intrusion detection system alerts
- External notifications: CISA, ISACs, law enforcement, researchers
- Anomaly detection from UEBA and machine learning models
- Vulnerability scan results indicating active exploitation
- Dark web monitoring detecting organizational data exposure

**Incident Classification:**

**By Category:**
- Malware (ransomware, trojan, worm, cryptominer)
- Unauthorized access (account compromise, privilege escalation)
- Data breach (exfiltration, exposure, loss)
- Denial of service (DDoS, application DoS)
- Insider threat (malicious, negligent)
- Web application attack (injection, XSS, SSRF)
- Social engineering (phishing, vishing, BEC)
- Supply chain compromise

**By Severity:**
- SEV-1 (Critical): Active data breach, ransomware spreading, complete system compromise, significant business impact. Response: all-hands, 15-minute check-ins, executive briefing every 2 hours.
- SEV-2 (High): Confirmed intrusion with contained scope, significant data exposure risk, critical vulnerability actively exploited. Response: dedicated team, hourly updates.
- SEV-3 (Medium): Malware infection on single system, unauthorized access attempt, contained policy violation. Response: assigned analyst, 4-hour updates.
- SEV-4 (Low): Suspicious activity under investigation, failed attack, minor policy deviation. Response: standard workflow, daily updates.

**Analysis Techniques:**
- Timeline analysis: construct chronological sequence of events
- Log correlation: combine data from multiple sources for context
- Indicator of Compromise (IOC) matching: search for known malicious indicators
- Behavioral analysis: identify anomalous patterns in user and system behavior
- Malware analysis: static and dynamic analysis of suspicious files
- Memory forensics: analyze volatile data for evidence of compromise
- Network forensics: analyze packet captures and flow data
- Artifact analysis: examine browser history, registry, prefetch, amcache

**Scoping Questions:**
- What systems are affected? What is the blast radius?
- What data is at risk? What is the classification level?
- How did the attacker gain initial access?
- What is the current extent of lateral movement?
- Are any persistence mechanisms established?
- Is data being actively exfiltrated?
- What business processes are impacted?
- What is the estimated time of initial compromise?

## Phase 3: Containment, Eradication, and Recovery

**Containment Strategy Selection:**

**Short-Term Containment (immediate, within hours):**
- Network isolation of affected systems (quarantine VLAN, host firewall)
- Block malicious IPs, domains, and hashes at perimeter
- Disable compromised user accounts and revoke sessions
- Redirect DNS for C2 domains to sinkhole
- Implement enhanced monitoring on potentially affected systems
- Preserve evidence before making changes

**Long-Term Containment (days to weeks):**
- Apply temporary patches or mitigations
- Rebuild compromised systems from clean images if needed
- Implement additional network segmentation
- Deploy additional detection rules for the specific threat
- Rotate all credentials that may have been exposed
- Implement enhanced access controls on critical systems

**Evidence Preservation (critical during containment):**
- Capture memory dumps before system changes or shutdown
- Create forensic disk images of affected systems
- Collect relevant log files with chain of custody documentation
- Capture network traffic (PCAP) from affected segments
- Screenshot active sessions and running processes
- Document all containment actions with timestamps

**Eradication Activities:**
- Remove malware from all affected systems
- Delete unauthorized accounts created by the attacker
- Remove persistence mechanisms (scheduled tasks, services, registry keys)
- Patch exploited vulnerabilities
- Close backdoor access paths
- Reset all potentially compromised credentials
- Verify eradication through rescanning and monitoring
- Update detection signatures with incident-specific indicators

**Recovery Activities:**
- Restore systems from known-good backups or rebuild from scratch
- Validate system integrity before returning to production
- Restore data from clean backups with integrity verification
- Reconnect systems to the network in a controlled manner
- Implement enhanced monitoring for signs of re-compromise
- Gradually restore business operations with verification at each step
- Confirm with business owners that functionality is restored
- Monitor for at least 30 days post-recovery for recurrence

## Phase 4: Post-Incident Activity

**Lessons Learned Meeting:**
- Conduct within 5 business days of incident closure
- Include all participants: IR team, IT, business stakeholders, management
- Structured review: timeline, decisions made, what worked, what failed
- Non-blame culture: focus on process improvement, not individual fault
- Document findings and action items with owners and deadlines

**Key Questions for Review:**
- What happened and when? (detailed timeline)
- How was the incident detected? Could it have been detected sooner?
- Was the incident response plan followed? Were there deviations and why?
- What information was needed sooner? What data sources were lacking?
- Were containment actions effective and timely?
- What tools or capabilities were missing?
- What would we do differently next time?
- What new detection rules or process changes are needed?

**Post-Incident Deliverables:**
- Incident report documenting full timeline and response actions
- Root cause analysis identifying fundamental contributing factors
- Recommendations for security control improvements
- Updated detection rules based on incident indicators and TTPs
- Updated playbooks incorporating lessons learned
- Metrics: time-to-detect, time-to-contain, time-to-resolve, cost
- Threat intelligence: IOCs and TTPs shared with trusted partners

## IR Playbooks

**Playbook Structure:**
Each playbook should contain:
- Trigger conditions: what alerts or events activate this playbook
- Severity classification criteria
- Initial triage steps with decision points
- Investigation procedures with tool-specific commands
- Containment actions with approval requirements
- Eradication and recovery steps
- Communication requirements at each stage
- Escalation criteria and paths

**Ransomware Playbook (Key Steps):**
1. Isolate affected systems from the network immediately
2. Determine ransomware variant and scope of encryption
3. Preserve evidence (memory, disk, network) before any remediation
4. Assess backup integrity and availability
5. Engage legal counsel for notification and payment decisions
6. Notify law enforcement (FBI IC3) and CISA
7. Restore from backups after eradicating access and patching vulnerability
8. Reset all domain credentials if Active Directory was compromised
9. Implement enhanced monitoring for re-compromise attempts

**Business Email Compromise Playbook (Key Steps):**
1. Secure compromised email accounts (password reset, revoke sessions)
2. Search for mail forwarding rules and delegated access
3. Review sent items for fraudulent messages
4. Notify recipients of fraudulent emails
5. Check financial transactions initiated from compromised account
6. Report to FBI IC3 and financial institutions if funds transferred
7. Review and enhance email security controls

**Phishing Playbook (Key Steps):**
1. Extract and analyze all indicators from reported phishing email
2. Search email logs for all recipients of the same campaign
3. Check for credential submission on phishing pages
4. Reset credentials for users who submitted data
5. Block phishing URLs and sending domains
6. Remove phishing emails from all mailboxes
7. Notify and re-train affected users

## Communication Plans

**Internal Communication:**
- Incident commander provides regular updates to stakeholders
- Use predefined distribution lists by incident severity
- Encrypted channels for sensitive incident details
- War room (physical or virtual) for SEV-1 incidents
- Regular cadence: SEV-1 every 30 min, SEV-2 every 2 hours

**External Communication:**
- Legal counsel reviews all external communications before release
- PR/Communications team manages media inquiries
- Customer notification following breach notification laws
- Regulatory notification within required timeframes
- Law enforcement engagement through established contacts
- Coordinated disclosure for vulnerabilities discovered during incident

**Notification Timelines:**
- GDPR: 72 hours to supervisory authority
- HIPAA: 60 days to HHS (500+ individuals)
- SEC: 4 business days on Form 8-K for material incidents
- PCI DSS: immediately to acquirer and card brands
- State breach laws: 30-60 days depending on jurisdiction
- CIRCIA: 72 hours to CISA for significant incidents

## IR Team Structure

**Core Team Roles:**
- **Incident Commander:** Overall authority, decision-making, stakeholder communication
- **Lead Analyst:** Technical investigation lead, evidence coordination
- **Forensic Analyst:** Evidence collection, disk/memory/network forensics
- **Malware Analyst:** Malware reverse engineering and behavioral analysis
- **Threat Intel Analyst:** IOC research, threat actor profiling, intelligence sharing
- **Communications Lead:** Internal and external communications management

**Extended Team (Activated as Needed):**
- Legal counsel: regulatory compliance, evidence preservation, notification
- Public relations: media management, customer communication
- Human resources: insider threat cases, employee impact
- Business continuity: operational impact assessment, BCP activation
- Executive sponsor: resource authorization, strategic decisions
- External IR firm: augmented capacity for major incidents
