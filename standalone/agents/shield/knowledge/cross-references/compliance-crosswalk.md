---
framework: "Compliance Crosswalk"
version: "1.0"
domain: "Governance, Risk, and Compliance"
agent: "sentinel"
tags: ["compliance", "crosswalk", "nist-csf", "iso-27001", "soc-2", "cis-controls", "pci-dss", "grc"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Compliance Framework Crosswalk

This document maps controls and requirements across major security and compliance frameworks: NIST CSF, ISO 27001, SOC 2, CIS Controls, and PCI DSS. Understanding these relationships enables efficient compliance management, evidence reuse, and comprehensive security coverage.

## Framework Overview

**NIST Cybersecurity Framework (CSF) 2.0:**
- Voluntary framework organized into six functions: Govern, Identify, Protect, Detect, Respond, Recover
- Applicable to all organizations regardless of size or sector
- Provides outcomes-based approach to cybersecurity risk management
- Widely used as a baseline for security program assessment
- Informative references map to other frameworks and standards

**ISO/IEC 27001:2022:**
- International standard for Information Security Management Systems (ISMS)
- Certifiable standard with third-party audit and certification
- Organized into management clauses (4-10) and Annex A controls (93 controls in 4 themes)
- Annex A themes: Organizational (37), People (8), Physical (14), Technological (34)
- Requires risk assessment as the basis for control selection
- Three-year certification cycle with annual surveillance audits

**SOC 2 (System and Organization Controls):**
- AICPA standard for service organization controls
- Five Trust Services Criteria: Security, Availability, Processing Integrity, Confidentiality, Privacy
- Type I: design of controls at a point in time
- Type II: operating effectiveness of controls over a period (typically 6-12 months)
- Common for SaaS providers, cloud services, and data processors
- Not a certification; results in an auditor's report with opinion

**CIS Controls v8:**
- Prioritized set of 18 security controls with implementation groups (IG1, IG2, IG3)
- IG1 (Essential Cyber Hygiene): 56 safeguards for all organizations
- IG2 (Foundational): additional 74 safeguards for organizations managing enterprise IT
- IG3 (Comprehensive): additional 23 safeguards for organizations with mature security
- Prescriptive and actionable with specific implementation guidance
- Regularly updated based on current threat landscape

**PCI DSS v4.0:**
- Mandatory standard for organizations handling payment card data
- 12 requirements organized into 6 goals
- Applies to all entities that store, process, or transmit cardholder data
- Validated through Self-Assessment Questionnaire (SAQ) or Qualified Security Assessor (QSA)
- Annual validation with quarterly vulnerability scanning (ASV)

## Access Control Crosswalk

**Area: User Access Management**

| Control Domain | NIST CSF | ISO 27001 | SOC 2 | CIS Controls | PCI DSS |
|---|---|---|---|---|---|
| Access policy | PR.AA-05 | A.5.15 | CC6.1 | CIS 6.1 | Req 7.1 |
| User provisioning | PR.AA-01 | A.5.16 | CC6.2 | CIS 6.2 | Req 7.2 |
| Privilege management | PR.AA-05 | A.8.2 | CC6.3 | CIS 5.4, 6.8 | Req 7.2.2 |
| Access review | PR.AA-05 | A.5.18 | CC6.2 | CIS 6.1 | Req 7.2.5 |
| Authentication | PR.AA-03 | A.8.5 | CC6.1 | CIS 6.3, 6.4, 6.5 | Req 8.3 |
| MFA | PR.AA-03 | A.8.5 | CC6.1 | CIS 6.3, 6.5 | Req 8.4 |
| Remote access | PR.AA-05 | A.8.1 | CC6.1 | CIS 6.7 | Req 8.4.2 |

**Key Mappings:**
- NIST CSF PR.AA corresponds directly to ISO 27001 Annex A.5 (Access Control) and A.8 (Technological)
- SOC 2 CC6 (Logical and Physical Access Controls) covers the breadth of access management
- CIS Control 6 (Access Control Management) provides prescriptive implementation
- PCI DSS Requirements 7 and 8 address access control and authentication specifically

## Data Protection Crosswalk

**Area: Data Encryption and Handling**

| Control Domain | NIST CSF | ISO 27001 | SOC 2 | CIS Controls | PCI DSS |
|---|---|---|---|---|---|
| Data classification | ID.AM-05 | A.5.12 | CC6.1 | CIS 3.7 | Req 9.4 |
| Encryption at rest | PR.DS-01 | A.8.24 | CC6.1, CC6.7 | CIS 3.11 | Req 3.5 |
| Encryption in transit | PR.DS-02 | A.8.24 | CC6.1, CC6.7 | CIS 3.10 | Req 4.1 |
| Key management | PR.DS-01 | A.8.24 | CC6.1 | CIS 3.11 | Req 3.6 |
| Data retention | ID.AM-05 | A.5.13 | CC6.5 | CIS 3.4 | Req 3.1 |
| Data disposal | PR.DS-01 | A.8.10 | CC6.5 | CIS 3.4 | Req 9.4.6 |
| DLP | PR.DS-01 | A.8.12 | CC6.7 | CIS 3.13 | Req 12.5 |

**Key Insights:**
- Encryption requirements are consistent across all frameworks
- PCI DSS is most prescriptive about encryption algorithms and key management
- ISO 27001 A.8.24 consolidates cryptographic controls under a single control
- CIS Control 3 (Data Protection) provides actionable implementation steps

## Incident Response Crosswalk

**Area: Security Incident Management**

| Control Domain | NIST CSF | ISO 27001 | SOC 2 | CIS Controls | PCI DSS |
|---|---|---|---|---|---|
| IR policy/plan | RS.MA-01 | A.5.24 | CC7.3, CC7.4 | CIS 17.1 | Req 12.10.1 |
| IR team | RS.MA-01 | A.5.24 | CC7.4 | CIS 17.1 | Req 12.10.1 |
| Incident detection | DE.CM-01 | A.8.15, A.8.16 | CC7.2 | CIS 17.2, 17.3 | Req 10.4, 12.10 |
| Incident analysis | RS.AN-03 | A.5.25 | CC7.3 | CIS 17.4 | Req 12.10.5 |
| Incident containment | RS.MI-01 | A.5.26 | CC7.3 | CIS 17.5 | Req 12.10.4 |
| Incident reporting | RS.CO-02 | A.5.26 | CC7.3 | CIS 17.2 | Req 12.10.6 |
| Lessons learned | RS.IM-01 | A.5.27 | CC7.5 | CIS 17.8 | Req 12.10.2 |
| IR testing | RS.IM-02 | A.5.24 | CC7.4 | CIS 17.6, 17.7 | Req 12.10.2 |

**Key Insights:**
- All frameworks require incident response capability; level of prescriptiveness varies
- NIST CSF Respond function maps comprehensively to ISO 27001 A.5.24-5.28
- PCI DSS 12.10 is highly specific about incident response requirements
- SOC 2 CC7 covers the full incident lifecycle from monitoring to improvement

## Vulnerability Management Crosswalk

**Area: Vulnerability and Patch Management**

| Control Domain | NIST CSF | ISO 27001 | SOC 2 | CIS Controls | PCI DSS |
|---|---|---|---|---|---|
| Vulnerability scanning | ID.RA-01 | A.8.8 | CC7.1 | CIS 7.1-7.6 | Req 11.3 |
| Patch management | PR.PS-02 | A.8.8, A.8.19 | CC7.1 | CIS 7.3, 7.4 | Req 6.3 |
| Penetration testing | ID.RA-01 | A.8.8 | CC4.1 | CIS 18.1-18.5 | Req 11.4 |
| Risk assessment | ID.RA-04 | Clause 6.1 | CC3.2 | CIS 7.5, 7.6 | Req 6.1 |
| Secure development | PR.PS-06 | A.8.25-8.31 | CC8.1 | CIS 16.1-16.14 | Req 6.2 |
| Change management | PR.PS-01 | A.8.32 | CC8.1 | CIS 2.4 | Req 6.5 |

**Key Insights:**
- PCI DSS has the most specific scanning and testing requirements (quarterly ASV, annual pentest)
- CIS Control 7 (Continuous Vulnerability Management) is the most prescriptive on process
- ISO 27001 A.8.8 consolidates vulnerability management under technical vulnerability management
- All frameworks require both identification (scanning) and remediation (patching)

## Logging and Monitoring Crosswalk

**Area: Security Monitoring and Audit**

| Control Domain | NIST CSF | ISO 27001 | SOC 2 | CIS Controls | PCI DSS |
|---|---|---|---|---|---|
| Audit logging | PR.PS-04 | A.8.15 | CC7.2 | CIS 8.2, 8.5 | Req 10.2 |
| Log protection | PR.PS-04 | A.8.15 | CC7.2 | CIS 8.9 | Req 10.3 |
| Log retention | PR.PS-04 | A.8.15 | CC7.2 | CIS 8.10 | Req 10.7 |
| Monitoring | DE.CM-01 | A.8.16 | CC7.2 | CIS 8.2, 8.11 | Req 10.4 |
| Time sync | PR.PS-04 | A.8.17 | CC7.2 | CIS 8.4 | Req 10.6 |
| Alert management | DE.AE-02 | A.8.16 | CC7.2 | CIS 8.11 | Req 10.4.1 |

**Key Insights:**
- PCI DSS Requirement 10 is the most detailed on specific log events and retention (12 months, 3 months readily available)
- CIS Control 8 (Audit Log Management) provides specific implementation steps
- All frameworks require centralized logging, integrity protection, and monitoring

## Common Control Sets

**Universal Controls (Required Across All Frameworks):**

1. **Asset Inventory:** know what you have before you can protect it
2. **Access Control:** authentication, authorization, least privilege
3. **Encryption:** data at rest and in transit
4. **Patch Management:** timely remediation of known vulnerabilities
5. **Logging and Monitoring:** audit trail and continuous monitoring
6. **Incident Response:** preparation, detection, response, recovery
7. **Risk Assessment:** identify and prioritize security risks
8. **Security Awareness:** training for all personnel
9. **Change Management:** controlled changes with security review
10. **Third-Party Risk:** vendor assessment and monitoring

**Framework-Specific Unique Requirements:**
- PCI DSS: quarterly ASV scanning, annual penetration testing, PAN storage restrictions, network segmentation testing
- ISO 27001: ISMS documentation, Statement of Applicability, management review, internal audit
- SOC 2: Trust Services Criteria mapping, description of system, complementary user entity controls
- CIS Controls: implementation group tiering, specific technical benchmarks
- NIST CSF: organizational profiles, tiers, governance function

## Audit Evidence Reuse

**Evidence Collection Strategy:**
Organizations subject to multiple compliance requirements can significantly reduce audit burden by mapping evidence to multiple frameworks simultaneously.

**Evidence Type Mapping:**

**Policy Documents:**
- Information Security Policy covers: ISO 27001 A.5.1, SOC 2 CC1.1, NIST CSF GV.PO, PCI DSS 12.1
- Access Control Policy covers: ISO 27001 A.5.15, SOC 2 CC6.1, NIST CSF PR.AA, PCI DSS 7.1
- Incident Response Plan covers: ISO 27001 A.5.24, SOC 2 CC7.3, NIST CSF RS.MA, PCI DSS 12.10

**Technical Evidence:**
- Vulnerability scan reports: satisfy ISO 27001 A.8.8, SOC 2 CC7.1, CIS 7, PCI DSS 11.3
- Access review records: satisfy ISO 27001 A.5.18, SOC 2 CC6.2, CIS 6.1, PCI DSS 7.2.5
- Log configuration screenshots: satisfy ISO 27001 A.8.15, SOC 2 CC7.2, CIS 8, PCI DSS 10.2
- Encryption configuration evidence: satisfy ISO 27001 A.8.24, SOC 2 CC6.7, CIS 3.10-3.11, PCI DSS 3.5-4.1
- MFA configuration evidence: satisfy ISO 27001 A.8.5, SOC 2 CC6.1, CIS 6.5, PCI DSS 8.4

**Process Evidence:**
- Change management tickets: satisfy ISO 27001 A.8.32, SOC 2 CC8.1, CIS 2.4, PCI DSS 6.5
- Incident response reports: satisfy ISO 27001 A.5.26, SOC 2 CC7.3, CIS 17, PCI DSS 12.10
- Risk assessment reports: satisfy ISO 27001 clause 6.1, SOC 2 CC3.2, NIST CSF ID.RA, PCI DSS 12.3.1
- Training completion records: satisfy ISO 27001 A.6.3, SOC 2 CC1.4, CIS 14, PCI DSS 12.6

## GRC Optimization

**Integrated Compliance Management:**

**Unified Control Framework (UCF):**
- Map all compliance requirements to a single set of organizational controls
- Each control satisfies requirements from multiple frameworks simultaneously
- Reduces duplication: implement once, comply many times
- Simplifies reporting: single control assessment satisfies multiple auditors
- Reduces control owner fatigue from repetitive audit requests

**GRC Platform Configuration:**
- Map compliance requirements to organizational controls in the GRC tool
- Link evidence artifacts to controls, not individual framework requirements
- Automate evidence collection from security tools (SIEM, vulnerability scanner, IAM)
- Generate framework-specific compliance reports from unified data
- Track control effectiveness metrics across all frameworks

**Continuous Compliance:**
- Shift from point-in-time audits to continuous monitoring
- Automated configuration compliance checking (CSPM, CIS benchmark scanning)
- Continuous control monitoring with real-time dashboards
- Automated evidence collection reducing manual audit preparation
- Exception management with automated expiry and review
- Risk-based audit scheduling focusing on highest-risk areas

**Compliance Program Maturity Model:**
- Level 1 (Reactive): respond to audit findings after the fact
- Level 2 (Managed): documented controls with periodic manual assessment
- Level 3 (Defined): unified control framework with mapped requirements
- Level 4 (Measured): continuous monitoring with metrics-driven improvement
- Level 5 (Optimized): automated compliance with predictive risk management

**Cost Optimization:**
- Reduce audit fatigue by presenting unified evidence packages
- Negotiate combined audits where possible (ISO 27001 + SOC 2 same auditor)
- Automate evidence collection to reduce manual preparation time
- Maintain always-audit-ready state to reduce sprint-based compliance efforts
- Leverage cloud provider compliance inheritance (shared responsibility model)
- Use GRC platforms to track evidence lifecycle and prevent expiration
