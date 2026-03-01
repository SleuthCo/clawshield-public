---
framework: "NIST SP 800-53 Rev 5"
version: "5.1"
domain: "Incident Response"
agent: "sentinel"
tags: ["nist", "800-53", "incident-response", "ir", "security-operations", "breach"]
last_updated: "2025-06-01"
chunk_strategy: "control"
---

# NIST SP 800-53 Rev 5 — Incident Response (IR) Family

The Incident Response family provides the organizational capability to prepare for, detect, analyze, contain, recover from, and conduct post-incident activities for cybersecurity incidents.

## IR-1: Policy and Procedures

**Control Description:** Organizations develop, document, and disseminate an incident response policy and associated procedures. The policy addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance.

**Policy Requirements:**
- Define what constitutes an incident versus an event
- Establish incident severity classification scheme (e.g., SEV-1 through SEV-4)
- Define roles and responsibilities for all incident response personnel
- Establish escalation procedures and thresholds
- Define communication requirements (internal, external, regulatory, law enforcement)
- Integrate with business continuity and disaster recovery plans
- Review and update policy at least annually or upon significant organizational changes

**Severity Classification Example:**
- SEV-1 (Critical): Active data breach, ransomware, complete system compromise
- SEV-2 (High): Confirmed intrusion, significant data exposure, critical vulnerability exploitation
- SEV-3 (Medium): Malware infection contained, unauthorized access attempt, policy violation
- SEV-4 (Low): Suspicious activity, failed attack, minor policy deviation

## IR-2: Incident Response Training

**Control Description:** Organizations provide incident response training to system users consistent with assigned roles and responsibilities within a defined time period of assuming a role, when required by system changes, and at a defined frequency thereafter.

**Training Requirements:**
- Initial training within 30 days of assignment to incident response role
- Annual refresher training for all IR team members
- Role-specific training: analysts, handlers, managers, communications
- Tabletop exercises at least quarterly involving cross-functional teams
- Technical training on tools: SIEM, EDR, forensics, malware analysis
- Legal and regulatory training: evidence handling, breach notification, privacy laws
- Training on current threat landscape and emerging attack techniques

**Training Topics:**
- Incident identification and classification
- Evidence preservation and chain of custody
- Containment strategies by incident type
- Communication protocols (internal and external)
- Forensic analysis techniques and tools
- Recovery procedures and validation
- Post-incident review and lessons learned processes
- Regulatory notification requirements (GDPR 72-hour rule, state breach laws)

## IR-3: Incident Response Testing

**Control Description:** Organizations test the incident response capability at a defined frequency using defined tests to determine effectiveness and document results.

**Testing Methods:**
- Tabletop exercises: scenario-based discussion walkthroughs (quarterly recommended)
- Functional exercises: simulated incidents with actual tool usage (semi-annually)
- Full-scale exercises: realistic multi-team simulations with live systems (annually)
- Red team/blue team exercises: adversary simulation with defensive response
- Purple team exercises: collaborative attack-defense exercises for control validation
- Chaos engineering: inject failures to test detection and response

**Test Scenarios to Cover:**
- Ransomware attack on critical systems
- Data exfiltration by insider threat
- Supply chain compromise (SolarWinds-style)
- Cloud account compromise and lateral movement
- DDoS against internet-facing services
- Business email compromise (BEC)
- Zero-day exploitation of public-facing application
- Physical security breach with cyber impact

**Control Enhancements:**
- IR-3(1): Automated testing using breach and attack simulation (BAS) tools
- IR-3(2): Coordination with related plans — ensure testing covers interdependencies with BCP, DR, COOP
- IR-3(3): Continuous improvement — update IR plans based on test results and lessons learned

## IR-4: Incident Handling

**Control Description:** Organizations implement an incident handling capability that includes preparation, detection and analysis, containment, eradication, recovery, and post-incident activity. Organizations coordinate incident handling activities with contingency planning activities.

**Preparation Phase:**
- Maintain incident response toolkit (forensic images, tools, documentation)
- Establish communication channels (out-of-band, encrypted)
- Pre-authorize containment actions for common incident types
- Establish relationships with law enforcement, CERT teams, ISACs
- Maintain current contact lists with 24/7 availability
- Deploy and configure detection systems (SIEM, EDR, NDR, UEBA)

**Detection and Analysis Phase:**
- Monitor security events from all sources continuously
- Correlate events across multiple data sources for context
- Classify and prioritize incidents based on impact and urgency
- Document all findings with timestamps and evidence
- Identify indicators of compromise (IOCs) and tactics, techniques, procedures (TTPs)
- Determine incident scope: affected systems, data, users, business processes

**Containment Phase:**
- Short-term containment: isolate affected systems, block malicious IPs/domains
- Evidence preservation: capture memory, disk images, network traffic before changes
- Long-term containment: apply temporary fixes, increase monitoring
- Decision framework: balance business impact against security risk
- Communication with stakeholders about containment actions and business impact

**Eradication Phase:**
- Remove malware, unauthorized accounts, backdoors
- Patch exploited vulnerabilities
- Reset compromised credentials
- Rebuild compromised systems from known-good images
- Verify eradication through scanning and monitoring
- Update detection signatures based on incident artifacts

**Recovery Phase:**
- Restore systems from clean backups or rebuild
- Validate system integrity before returning to production
- Implement enhanced monitoring for recurrence
- Gradually restore operations with verification at each step
- Confirm business process functionality
- Monitor for re-compromise indicators

**Post-Incident Activity:**
- Conduct lessons learned meeting within 5 business days
- Document root cause analysis and contributing factors
- Update incident response plans based on findings
- Identify control gaps and remediation actions
- Share threat intelligence with trusted partners and ISACs
- Calculate incident costs for organizational risk management

**Control Enhancements:**
- IR-4(1): Automated incident handling using SOAR platforms for playbook execution
- IR-4(2): Dynamic reconfiguration — automated response actions (quarantine, block, disable)
- IR-4(3): Continuity of operations — maintain essential functions during incident
- IR-4(4): Information correlation — cross-reference incidents for pattern detection
- IR-4(5): Automatic disabling of the system when specific attack indicators are detected
- IR-4(6): Insider threat response — specific procedures for insider threat incidents
- IR-4(7): Insider threat — intra-organization coordination with HR, legal, management
- IR-4(8): Correlation with external organizations — share incident data with ISACs, CISA
- IR-4(11): Integrated incident response team with defined roles from IT, security, legal, communications
- IR-4(13): Behavior analysis on collected data to identify lateral movement and persistence
- IR-4(14): Security operations center (SOC) operating 24/7 for incident detection and response

## IR-5: Incident Monitoring

**Control Description:** Organizations track and document incidents on an ongoing basis.

**Monitoring Requirements:**
- Maintain an incident tracking system with unique identifiers
- Record all incident details: timeline, actions taken, personnel involved
- Track incident metrics: time-to-detect, time-to-contain, time-to-resolve
- Monitor for recurring incident patterns indicating systemic issues
- Generate periodic reports for management on incident trends
- Retain incident records for at least three years (or as required by policy)

**Key Metrics:**
- Mean Time to Detect (MTTD): target less than 24 hours
- Mean Time to Respond (MTTR): target less than 4 hours for SEV-1
- Mean Time to Contain (MTTC): target less than 8 hours for SEV-1
- Mean Time to Recover: target less than 48 hours for critical systems
- Number of incidents by type, severity, and business unit
- False positive rate for detection systems
- Percentage of incidents detected internally vs. externally reported

**Control Enhancements:**
- IR-5(1): Automated tracking using case management and SOAR platforms

## IR-6: Incident Reporting

**Control Description:** Organizations require personnel to report suspected incidents to the organizational incident response capability within a defined time period. Organizations report incident information to defined authorities.

**Internal Reporting:**
- All employees must report suspected security incidents immediately
- Provide multiple reporting channels: email, phone, ticketing system, chat
- Protect reporters from retaliation for good-faith reporting
- Acknowledge receipt of reports within 1 hour during business hours
- Triage reported events within 4 hours

**External Reporting Requirements:**
- Report to CISA within 72 hours for significant incidents (per CIRCIA)
- GDPR: notify supervisory authority within 72 hours of awareness of personal data breach
- State breach notification laws: typically 30-60 days after discovery
- PCI DSS: notify payment brands and acquirer immediately upon suspected cardholder data breach
- HIPAA: notify HHS within 60 days for breaches affecting 500+ individuals
- SEC: material cybersecurity incidents reported on Form 8-K within 4 business days
- Report to law enforcement when criminal activity is suspected

**Control Enhancements:**
- IR-6(1): Automated reporting mechanisms integrated with incident management systems
- IR-6(2): Vulnerabilities related to incidents reported to relevant authorities
- IR-6(3): Supply chain coordination — notify supply chain partners of incidents that affect them

## IR-7: Incident Response Assistance

**Control Description:** Organizations provide an incident response support resource that is integral to the organizational incident response capability and offers advice and assistance to system users for handling and reporting incidents.

**Support Resources:**
- Internal Security Operations Center (SOC) with 24/7 coverage
- Incident response hotline with defined response times
- Knowledge base of common incidents and initial response procedures
- Automated guidance through chatbot or decision tree systems
- Retainer agreements with external incident response firms (e.g., CrowdStrike, Mandiant)

**Control Enhancements:**
- IR-7(1): Automation support for availability of information and support using online portals and automated systems
- IR-7(2): Coordination with external providers — maintain retainer agreements and define engagement procedures

## IR-8: Incident Response Plan

**Control Description:** Organizations develop an incident response plan that provides a roadmap for implementing the incident response capability, describes the structure and organization of the capability, provides a high-level approach for how the capability fits into the overall organization, and defines reportable incidents.

**Plan Contents:**
- Mission statement and objectives for the IR capability
- Organizational approach to incident response (centralized, distributed, hybrid)
- IR team structure, roles, responsibilities, and authority
- Communication plan covering internal and external notifications
- Incident classification and prioritization scheme
- Step-by-step procedures for each incident type
- Integration with other plans (BCP, DR, COOP, crisis communications)
- Metrics and success criteria for the IR program
- Plan maintenance and review schedule

**Plan Maintenance:**
- Review and update at least annually
- Update after every significant incident
- Update after organizational changes affecting IR capability
- Update when new systems, technologies, or threats emerge
- Distribute updates to all relevant personnel
- Test plan updates through exercises

**Control Enhancements:**
- IR-8(1): Develop IR plans for specific breach scenarios (ransomware, insider threat, cloud compromise)

## IR-9: Information Spillage Response

**Control Description:** Organizations respond to information spills by identifying the specific information involved, alerting affected personnel, reporting to appropriate authorities, and containing and recovering from the spill.

**Spillage Response Steps:**
1. Identify the information spilled and its classification level
2. Alert the information owner and privacy officer
3. Identify all systems, media, and personnel exposed to the spill
4. Contain the spill — isolate affected systems and media
5. Assess whether the spill constitutes a reportable breach
6. Sanitize or destroy affected media as appropriate
7. Retrain involved personnel on information handling
8. Document the spill and corrective actions taken

**Control Enhancements:**
- IR-9(1): Identify responsible personnel — determine who caused the spill
- IR-9(2): Training — provide remedial training to personnel involved
- IR-9(3): Post-spill operations — ensure operations continue during spill response
- IR-9(4): Exposure to unauthorized personnel — assess impact and take mitigating actions

## IR-10: Integrated Information Security Analysis Team

**Control Description:** Organizations establish an integrated team of forensic analysts, software engineers, network engineers, and real-time operations personnel to analyze cybersecurity events and recommend responses.

**Team Composition:**
- Digital forensics analysts with certified expertise (GCFE, EnCE, CFCE)
- Malware analysts and reverse engineers
- Network security engineers familiar with the organization's architecture
- System administrators for affected platforms
- Threat intelligence analysts
- Legal counsel for evidence handling and notification
- Communications/PR staff for external messaging
- Business unit representatives for impact assessment

**Operational Model:**
- Virtual team activated for significant incidents (SEV-1, SEV-2)
- Permanent core team supplemented by specialists as needed
- Defined activation criteria and communication channels
- Authority to access all relevant systems and data during incident
- Pre-authorized containment and response actions for speed
- After-action review responsibility for continuous improvement
