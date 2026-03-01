---
framework: "Incident & Breach Communications"
version: "1.0"
domain: "Crisis Communications"
agent: "pepper"
tags: ["incident-response", "breach-notification", "GDPR", "regulatory-notification", "customer-notification", "escalation"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Incident Communications

## Security Breach Notification Communications

### Breach Communication Principles

When a security breach occurs, communications must balance four often-competing imperatives: transparency (stakeholders deserve timely, honest information), legal compliance (regulatory notification requirements must be met), legal risk mitigation (statements must not create unnecessary liability), and operational security (communications must not compromise the ongoing investigation or remediation).

The communications function must work in close coordination with the CISO, legal counsel, privacy officers, and executive leadership. The communications professional is not the decision-maker on breach classification or notification obligations — those determinations are made by legal and security teams. The communications professional's role is to ensure that once notification decisions are made, the communications are clear, empathetic, compliant, and strategically sound.

### Breach Notification Communication Structure

An effective breach notification, whether to customers, regulators, or other stakeholders, should include:

**What happened:** A clear, factual description of the incident without unnecessary technical detail. "On [date], we discovered that an unauthorized party gained access to a database containing customer information" is preferable to overly technical descriptions of the attack vector.

**What information was involved:** Specific identification of the data categories affected. Be precise — customers need to know whether names, email addresses, passwords, financial data, Social Security numbers, or health information were compromised.

**What we are doing:** Actions the organization is taking to address the breach, protect affected individuals, and prevent future incidents. This should include both immediate remediation and longer-term security improvements.

**What you can do:** Clear, actionable guidance for affected individuals. This may include password changes, credit monitoring enrollment, fraud alert placement, and specific steps based on the type of data compromised.

**How to get more information:** Dedicated contact channels — typically a dedicated phone line, email address, and FAQ webpage established specifically for the incident.

### Customer Notification Best Practices

**Tone:** Empathetic, direct, and accountability-oriented. Avoid legalistic language, passive voice, and euphemisms. "We let you down" is more credible than "An incident occurred." However, balance emotional language with legal guidance — every word may be scrutinized in potential litigation.

**Timing:** Notify as soon as reasonably possible after confirming the breach and affected individuals, subject to law enforcement requests for delay and regulatory timing requirements. Delayed notification erodes trust exponentially.

**Channel:** Use direct notification channels — email, postal mail, or in-app notifications — depending on the affected population and regulatory requirements. Public website notices and press releases supplement but do not replace direct individual notification.

**Follow-up:** The initial notification should not be the last communication. Provide regular updates on the investigation, remediation progress, and any changes to the scope of affected data. Close the communication loop when the investigation concludes.

## GDPR Notification Requirements

### Supervisory Authority Notification (Article 33)

Under GDPR, the controller must notify the relevant supervisory authority within 72 hours of becoming aware of a personal data breach, unless the breach is unlikely to result in a risk to individual rights and freedoms.

**Required Content:** The nature of the breach, including categories and approximate number of data subjects and records affected. The name and contact details of the Data Protection Officer or other contact. The likely consequences of the breach. The measures taken or proposed to address the breach and mitigate potential adverse effects.

**Communications Implications:** The 72-hour timeline requires pre-drafted notification templates that can be rapidly customized. The communications team must be integrated into the incident response process from the start to ensure timely preparation of notification materials. If full information is not available within 72 hours, GDPR allows information to be provided in phases — but the initial notification must be made on time.

### Data Subject Notification (Article 34)

When a breach is likely to result in a high risk to individuals' rights and freedoms, the controller must notify affected data subjects without undue delay. The communication must use clear, plain language and include the same core elements as the supervisory authority notification, plus specific guidance on steps individuals can take to protect themselves.

**Exceptions:** Notification may not be required if the controller has implemented appropriate technical measures that render data unintelligible (such as encryption), the controller has taken subsequent measures that ensure the high risk is no longer likely to materialize, or individual notification would involve disproportionate effort (in which case a public communication is acceptable).

## Other Regulatory Notification Frameworks

### US State Breach Notification Laws

All 50 US states, plus DC, Guam, Puerto Rico, and the US Virgin Islands, have breach notification laws. Requirements vary by state in terms of definition of personal information, notification timeline (ranging from 30 to 90 days, with some requiring notification "as expeditiously as possible"), whether the state attorney general must be notified, whether credit monitoring must be offered, and specific content requirements for notification letters.

For organizations operating nationally, breach notifications must comply with the most stringent applicable state requirements. California (CCPA/CPRA), New York (SHIELD Act), and Illinois have particularly detailed requirements that often set the floor for national compliance.

### Sector-Specific Requirements

**Healthcare (HIPAA):** Covered entities must notify affected individuals within 60 days of discovering a breach of unsecured protected health information. Breaches affecting 500+ individuals must also be reported to HHS and prominent media outlets. The HHS breach portal ("Wall of Shame") makes all such breaches publicly searchable.

**Financial Services (GLBA/Interagency Guidance):** Financial institutions must notify primary federal regulators as soon as possible, and notify customers when the institution determines that misuse of information has occurred or is reasonably possible.

**SEC Registrants (SEC Cybersecurity Rules):** As of December 2023, public companies must disclose material cybersecurity incidents on Form 8-K within four business days of determining materiality. Annual reports must describe cybersecurity risk management and governance. Communications teams must prepare for rapid public disclosure of material incidents.

## Customer Notification Templates

### Template: Data Breach Notification (Email)

Subject Line: Important Security Notice from [Company Name]

Body Structure:
- Personal salutation
- Direct statement of what happened
- Specific information about what data was involved
- Assurance of immediate actions taken
- Concrete steps the customer can take
- Offer of protective services (credit monitoring, identity protection)
- Dedicated contact information
- Commitment to ongoing transparency
- Executive signature (CEO for Tier 1 incidents)

### Template: Service Outage Notification

Subject Line: [Service Name] Service Disruption — Update [Number]

Body Structure:
- Current status summary
- Timeline of events
- Root cause (if identified)
- Impact scope (which customers, services, and regions are affected)
- Current remediation actions
- Estimated time to resolution (if known)
- Customer workaround guidance
- Next update timing commitment
- Technical support contact

### Template: Regulatory Action Notification

When a regulatory action affects customers (enforcement actions, consent orders, compliance changes), communications should include a clear explanation of the regulatory action in plain language, specific impact on customer accounts, services, or rights, actions the company is taking in response, what customers need to do (if anything), timeline for changes, and contact information for questions.

## Internal Escalation Communications

### Escalation Communication Framework

**Level 1 — Team Notification:** The security or operations team managing the incident communicates within their team. Format: Incident ticket or Slack/Teams message. Content: Technical details, initial assessment, assigned responders.

**Level 2 — Cross-Functional Alert:** When the incident exceeds team-level management capacity or has potential external impact, escalate to cross-functional leadership. Format: Structured email or crisis channel notification. Content: Incident summary, current impact assessment, potential escalation risks, resources needed, and recommended actions.

**Level 3 — Executive Notification:** When the incident is confirmed as externally visible, involves regulated data, or exceeds defined thresholds. Format: Phone call or text to executive on-call, followed by written briefing. Content: Incident classification, current and potential impact, communications timeline, media monitoring status, and recommended external response.

**Level 4 — Board Notification:** For Tier 1 incidents that are material, involve regulatory exposure, or pose significant reputational risk. Format: Direct call from CEO or General Counsel to Board Chair, followed by written briefing to full board. Content: Incident facts, organizational response, potential legal and financial exposure, communications strategy, and timeline for next update.

### Escalation Communication Templates

Internal escalation communications should use a standardized format that enables rapid comprehension:

**INCIDENT CLASSIFICATION:** [Tier 1/2/3]
**INCIDENT SUMMARY:** [2-3 sentence description]
**CURRENT STATUS:** [Active/Contained/Resolved]
**IMPACT ASSESSMENT:** [Who/what is affected, quantified where possible]
**EXTERNAL VISIBILITY:** [None/Limited/Widespread]
**REGULATORY IMPLICATIONS:** [None/Potential/Confirmed]
**COMMUNICATIONS STATUS:** [No external comms yet/Holding statement issued/Full response issued]
**NEXT ACTIONS:** [Bulleted list with owners and timelines]
**NEXT UPDATE:** [Specific time for next communication]

### Incident Communication Coordination

Establish clear rules of engagement for incident communications: only designated communicators issue external statements. All employee inquiries are directed to a single internal contact point. Social media monitoring reports are centralized. Media inquiries are logged and triaged by the communications team. Customer-facing teams receive approved talking points within 2 hours of incident escalation.

The single biggest communications failure during incidents is fragmented messaging — different teams providing inconsistent or contradictory information to different audiences. Centralized communications coordination prevents this failure mode.

## Post-Incident Communication

### Transparency Report

After the incident is fully resolved and investigated, publish a transparency report that provides a detailed timeline, root cause analysis, remediation actions taken, and preventive measures implemented. Companies like Cloudflare, GitLab, and Atlassian have established excellent precedents for post-incident transparency reports that build long-term trust despite the negative short-term impact of the incident.

### Lessons Learned Communication

Share (appropriately) what the organization learned from the incident. This can be communicated internally (to drive cultural improvement), to customers (to rebuild confidence), and to the broader industry (to contribute to collective security improvement). The willingness to share lessons learned signals maturity and accountability.
