---
framework: "Security Monitoring"
version: "1.0"
domain: "Security Operations"
agent: "sentinel"
tags: ["siem", "detection-engineering", "sigma", "yara", "ioc", "threat-intelligence", "soc"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Security Monitoring

This document covers SIEM use cases, detection engineering practices, rule formats (Sigma, YARA), indicator management, threat intelligence integration, alert triage, and SOC operational metrics.

## SIEM Use Cases

**Authentication Monitoring:**
- Brute force detection: multiple failed logins from single source within time window
- Password spraying: few failed attempts across many accounts from single source
- Credential stuffing: high volume of authentication attempts with diverse credentials
- Impossible travel: successful logins from geographically distant locations in short timeframe
- Off-hours authentication: logins outside normal business hours for the user
- Dormant account activation: login to accounts inactive for 90+ days
- Concurrent sessions: same account active from multiple geographic locations
- MFA bypass: successful authentication without expected MFA challenge

**Privilege Escalation:**
- New local administrator creation on endpoints
- Addition to privileged groups (Domain Admins, Enterprise Admins)
- Unusual sudo or runas usage patterns
- Service account interactive login
- UAC bypass detection
- Token manipulation and impersonation
- Kerberos ticket anomalies (Golden/Silver ticket indicators)

**Data Exfiltration:**
- Unusual outbound data volume from endpoints or servers
- DNS tunneling: high volume of DNS queries to unusual domains with encoded data
- Large email attachments to external recipients
- Cloud storage uploads to personal accounts (shadow IT)
- USB mass storage device activity on sensitive systems
- Print activity for sensitive documents
- Encrypted traffic to unusual destinations without legitimate business purpose

**Lateral Movement:**
- PsExec and remote service creation across systems
- WMI remote execution (wmiprvse.exe spawning unusual processes)
- RDP connections between workstations (should not normally occur)
- Administrative share access (C$, ADMIN$) from non-administrative systems
- Pass-the-hash: NTLM authentication without preceding interactive logon
- Pass-the-ticket: Kerberos ticket usage from unexpected hosts
- SMB access patterns inconsistent with business workflows

**Malware and Execution:**
- Known malware hash detection from threat intelligence feeds
- Suspicious process execution chains (e.g., Office spawning PowerShell)
- Living-off-the-land binary (LOLBin) abuse: certutil, mshta, regsvr32, rundll32
- PowerShell encoded command execution
- WMI persistence creation
- Scheduled task creation with suspicious parameters
- DLL side-loading patterns

**Cloud-Specific Use Cases:**
- Root/global admin account usage
- Cloud resource creation in unexpected regions
- Security group modifications opening ports to 0.0.0.0/0
- S3 bucket policy changes to public access
- IAM role assumption from unusual principals
- Cloud function creation or modification
- Snapshot or image sharing to external accounts
- Cloud API calls from unexpected IP addresses

## Detection Engineering

**Detection Development Lifecycle:**

1. **Hypothesis Formation:** Based on threat intelligence, red team findings, or incident analysis, form a hypothesis about attacker behavior to detect
2. **Data Requirements:** Identify required log sources, fields, and enrichment data
3. **Rule Development:** Write detection logic in Sigma or platform-native format
4. **Testing:** Validate against historical data and synthetic attack simulations
5. **Tuning:** Reduce false positives through filtering and threshold adjustment
6. **Deployment:** Push to production SIEM with documentation and runbook
7. **Maintenance:** Regular review of rule effectiveness and false positive rates

**Detection Quality Metrics:**
- True Positive Rate: percentage of actual attacks detected
- False Positive Rate: percentage of alerts that are not actual attacks
- Detection Latency: time from attack action to alert generation
- Rule Coverage: percentage of ATT&CK techniques with detection rules
- Rule Efficacy: percentage of rules generating actionable alerts

**Detection Categories:**

**Signature-Based:**
- IOC matching: hashes, IPs, domains, URLs from threat intelligence
- Known exploit patterns: specific byte sequences or network signatures
- Advantages: low false positive rate for known threats
- Disadvantages: easily evaded by modification, zero coverage for novel threats

**Behavioral:**
- Anomaly detection: deviation from baseline behavior patterns
- Sequence detection: specific order of events indicating attack progression
- Statistical analysis: unusual volumes, frequencies, or patterns
- Advantages: can detect novel threats and living-off-the-land techniques
- Disadvantages: higher false positive rate, requires good baseline

**Heuristic:**
- Rule-based logic combining multiple indicators
- Weighted scoring: accumulate risk score from multiple signals
- Threshold-based: alert when aggregate score exceeds threshold
- Advantages: balances between precision and coverage
- Disadvantages: requires ongoing tuning as environment changes

## Sigma Rules

**Overview:** Sigma is an open standard for SIEM detection rules. Sigma rules are written in YAML and can be converted to queries for any SIEM platform (Splunk, Elastic, Microsoft Sentinel, QRadar).

**Sigma Rule Structure:**
```yaml
title: Suspicious PowerShell Encoded Command
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: production
description: Detects PowerShell execution with base64 encoded command
references:
    - https://attack.mitre.org/techniques/T1059/001/
author: Security Team
date: 2025/01/15
modified: 2025/05/01
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - '-enc'
            - '-EncodedCommand'
            - '-ec '
    filter:
        CommandLine|contains:
            - 'known_legitimate_encoded_script'
    condition: selection and not filter
falsepositives:
    - Legitimate administrative scripts using encoded commands
    - Software deployment tools
level: high
```

**Key Sigma Modifiers:**
- `|contains` — field contains the value as substring
- `|endswith` — field ends with the value
- `|startswith` — field starts with the value
- `|re` — regular expression match
- `|base64` — value is base64 encoded in the log
- `|all` — all values must be present (AND logic within a list)
- `|cidr` — match IP against CIDR range

**Sigma Conversion Tools:**
- sigma-cli: official conversion tool supporting 30+ SIEM backends
- sigmac (legacy): original converter
- pySigma: Python library for programmatic conversion
- Uncoder.IO: web-based converter for quick translation

**Sigma Rule Management:**
- Maintain a centralized repository of Sigma rules (Git-based)
- Version control all rule changes with review process
- Automated testing pipeline for rule validation
- Automated deployment to SIEM upon merge
- Track rule performance metrics (true positive, false positive rates)
- Regular review cadence: monthly for high-volume rules

## YARA Rules

**Overview:** YARA is a pattern matching tool designed for malware identification. YARA rules describe patterns (strings, byte sequences, conditions) that match malicious files or memory.

**YARA Rule Structure:**
```
rule Emotet_Payload {
    meta:
        description = "Detects Emotet malware payload"
        author = "Security Team"
        date = "2025-05-01"
        reference = "https://example.com/emotet-analysis"
        hash = "abc123def456..."
        severity = "high"

    strings:
        $s1 = "RunHTMLApplication" ascii
        $s2 = {6A 40 68 00 30 00 00 6A 14 8D 91}
        $s3 = /https?:\/\/[a-z0-9]+\.[a-z]{2,6}\/[a-z0-9]{8,}/
        $pdb = "C:\\Users\\dev\\emotet" nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        (2 of ($s*) or $pdb)
}
```

**YARA String Types:**
- Text strings: `"malware_string"` with modifiers (nocase, ascii, wide, fullword)
- Hex strings: `{6A 40 68 ?? 30}` with wildcards and jumps
- Regular expressions: `/pattern/` with modifiers

**YARA Deployment:**
- Endpoint scanning: integrate with EDR for real-time file scanning
- Email gateway: scan attachments against YARA rules
- Network: scan files extracted from network traffic
- Malware sandbox: classify samples in automated analysis
- Threat hunting: retroactive scanning of file repositories
- Memory scanning: detect fileless malware in process memory

## Indicator Management (IOC)

**Indicator Types (Diamond Model):**
- **Atomic:** individual indicators — IP addresses, domains, email addresses, hashes
- **Computed:** derived from data analysis — YARA rules, Sigma rules, regex patterns
- **Behavioral:** patterns of activity — TTPs, attack sequences, tradecraft

**IOC Lifecycle:**
1. **Collection:** gather from threat intel feeds, incident analysis, research
2. **Validation:** verify indicator accuracy and relevance
3. **Enrichment:** add context (malware family, actor attribution, confidence)
4. **Distribution:** push to detection tools (SIEM, EDR, firewall, proxy)
5. **Detection:** match indicators against real-time and historical data
6. **Expiration:** remove stale indicators (IPs: 30 days, domains: 90 days, hashes: 1 year)
7. **Review:** assess detection effectiveness and false positive rate

**Indicator Quality Assessment:**
- Confidence level: low, medium, high based on source reliability
- Timeliness: how recent is the indicator
- Relevance: does the indicator relate to threats targeting your sector
- Accuracy: has the indicator been validated as malicious
- Context: is sufficient context provided for effective use

**STIX/TAXII Standards:**
- STIX (Structured Threat Information eXpression): format for representing threat intelligence
- TAXII (Trusted Automated eXchange of Intelligence Information): transport protocol for sharing
- STIX objects: Indicator, Malware, Threat Actor, Campaign, Attack Pattern, Course of Action
- TAXII channels and collections for organized intelligence sharing

## Threat Intelligence Integration

**Intelligence Sources:**
- Commercial feeds: CrowdStrike, Mandiant, Recorded Future, Anomali
- Open source feeds: AlienVault OTX, Abuse.ch, MalwareBazaar, URLhaus
- Government: CISA advisories, US-CERT, FBI Flash alerts
- ISACs: sector-specific intelligence sharing communities
- Internal: indicators derived from your own incident investigations
- Dark web monitoring: credential exposure, data leaks, threat actor chatter

**Integration Architecture:**
- Threat Intelligence Platform (TIP): central management (MISP, OpenCTI, ThreatConnect)
- Automated feed ingestion and normalization
- Enrichment with internal context (asset criticality, vulnerability status)
- Distribution to SIEM for correlation with security events
- Distribution to EDR for endpoint matching
- Distribution to firewall/proxy for blocking
- Distribution to email gateway for phishing prevention
- Feedback loop: detection results improve intelligence quality

**Intelligence-Driven Detection:**
- Map threat actor TTPs to detection rules
- Prioritize detection development based on threat landscape
- Create detection rules from adversary behavior reports
- Validate detection coverage against known adversary playbooks
- Hunt proactively using threat intelligence hypotheses

## Alert Triage

**Triage Process:**
1. **Acknowledge:** take ownership of the alert within SLA (15 minutes for critical)
2. **Contextualize:** gather supporting data (asset info, user info, recent activity)
3. **Validate:** determine if the alert represents actual malicious activity
4. **Classify:** assign incident category and severity if true positive
5. **Escalate or Close:** escalate to Tier 2 or close as false positive with documentation

**Triage Decision Framework:**
- **True Positive:** confirmed malicious activity, escalate and initiate IR
- **Benign True Positive:** detection is accurate but activity is authorized/expected
- **False Positive:** detection triggered on non-malicious activity, tune rule
- **Insufficient Data:** unable to determine, escalate for deeper investigation

**Triage Enrichment Sources:**
- CMDB: asset owner, criticality, location, OS, applications
- Identity: user role, department, normal behavior pattern, risk score
- Threat Intelligence: indicator reputation, associated campaigns, actor attribution
- SIEM: correlated events, related alerts, historical activity
- Vulnerability data: known vulnerabilities on affected asset
- GeoIP: geographic context for source and destination IPs

## SOC Metrics

**Operational Metrics:**
- Total alert volume per day/week/month (trend analysis)
- Alert distribution by source, type, severity
- True positive rate by detection rule (target: >50% for high-fidelity rules)
- Mean Time to Acknowledge (MTTA): target <15 minutes for critical
- Mean Time to Triage: target <30 minutes for critical alerts
- Escalation rate: percentage of alerts requiring Tier 2 investigation
- Alert closure rate: percentage of alerts resolved per shift

**Effectiveness Metrics:**
- Mean Time to Detect (MTTD): measured from compromise to detection
- Mean Time to Respond (MTTR): measured from detection to containment
- Detection coverage: percentage of ATT&CK techniques with active detections
- Missed detections: incidents discovered by external parties, not internal SOC
- Threat hunt findings: threats discovered through proactive hunting

**Efficiency Metrics:**
- Analyst utilization: alert workload per analyst per shift
- Automation rate: percentage of alerts handled by automated playbooks
- Rule tuning effectiveness: false positive reduction over time
- Tool effectiveness: detection rate by security tool
- Training completion: certification and training hours per analyst

**Reporting Cadence:**
- Daily: shift handoff report with open incidents and pending actions
- Weekly: operational dashboard with alert trends and key metrics
- Monthly: management report with MTTD, MTTR, detection improvements
- Quarterly: executive summary with risk trends, investment recommendations
- Annual: program review with strategic planning and capability assessment
