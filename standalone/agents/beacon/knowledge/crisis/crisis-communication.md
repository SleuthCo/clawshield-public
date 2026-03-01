---
framework: "Crisis Communications"
version: "1.0"
domain: "Crisis Management"
agent: "pepper"
tags: ["crisis", "incident-response", "disclosure", "media", "stakeholder", "communications"]
last_updated: "2025-02-01"
chunk_strategy: "heading"
---

# Crisis Communication Playbook

## The Crisis Communication Lifecycle

Every crisis follows a predictable communication arc: pre-crisis preparation, initial response (the golden hour), ongoing management, and post-crisis recovery. Failure at any stage compounds damage at subsequent stages.

**Pre-crisis**: Build holding statement templates. Identify spokespersons. Establish communication chains. Run tabletop exercises. Build media relationships before you need them.

**Golden hour**: Acknowledge the situation. Activate the communication team. Issue the holding statement. Control the narrative before speculation fills the vacuum.

**Ongoing management**: Regular updates on a published cadence. Transparent progress reporting. Stakeholder-specific messaging. Monitor sentiment and adjust.

**Recovery**: Publish post-incident analysis. Communicate lessons learned and remediation. Rebuild trust through demonstrated action, not just words.

## Security Incident Disclosure

Security incidents require a specific communication approach that balances transparency with operational security.

**What to communicate immediately**: That an incident has been detected. That investigation is underway. What actions affected users should take (password reset, session review, etc.). When the next update will come. Where to find ongoing updates.

**What NOT to communicate early**: Root cause (until confirmed). Scope (until verified). Attribution (until forensically established). Technical details that could aid further exploitation.

**Disclosure timeline template**: (1) T+0 to T+1 hour: Internal escalation, holding statement prepared. (2) T+1 to T+4 hours: Holding statement published, affected customers notified. (3) T+24 hours: First detailed update with confirmed scope. (4) T+72 hours: Comprehensive update with root cause and remediation plan. (5) T+30 days: Full post-incident report.

**Regulatory considerations**: GDPR requires notification within 72 hours. SEC requires material cybersecurity incident disclosure within 4 business days (via 8-K filing). State breach notification laws vary — some require notification within 30 days. FedRAMP requires notification within 1 hour for certain incident types.

## Holding Statement Templates

### Security Incident — Initial

"We are aware of [a security incident / unauthorized access / a vulnerability] affecting [scope]. Our security team is actively investigating and we are working to understand the full scope of impact. We are taking immediate steps to [contain the issue / protect affected users / secure our systems]. We will provide an update by [specific time]. If you believe you are affected, please [specific action]. For the latest information, visit [status page URL]."

### Service Outage

"We are currently experiencing [a disruption to / degraded performance of] [service name]. Our engineering team has been engaged and is working to restore full service. We understand the impact this has on your work and are treating this with the highest priority. We will provide updates every [30 minutes / 1 hour] until service is restored. Current status and updates: [status page URL]."

### Data Breach — Customer Notification

"We are writing to inform you of a security incident that may have affected your [account / data]. On [date], we discovered [brief factual description]. After investigation, we have determined that [specific data types] may have been accessed. We have [actions taken: reset passwords, revoked sessions, engaged forensic investigators]. We recommend you [specific customer actions]. We take the security of your data seriously and are [remediation steps]. If you have questions, please contact [specific channel]."

## Stakeholder-Specific Messaging

### Board of Directors

**Tone**: Measured, factual, forward-looking. No jargon. Frame in terms of business risk and fiduciary responsibility.

**Structure**: (1) What happened (one paragraph). (2) Business impact (quantified where possible). (3) What we've done so far. (4) What we're doing next. (5) What we need from the board (decisions, resources, guidance). (6) Timeline for resolution and next update.

**Never surprise the board**: If something might become public, brief the board before it does.

### Engineering Teams

**Tone**: Direct, technical, collaborative. Acknowledge the stress. Be honest about what you know and don't know.

**Key messages**: Here's what we know technically. Here's what we need you to do (and not do). Here's the communication plan — this is what we're telling customers, so align your support responses. Don't speculate publicly. Escalation path for new findings.

### Customers

**Tone**: Empathetic, clear, action-oriented. No blame, no minimization. Lead with what they need to do.

**Structure**: What happened (plain language). How it affects them specifically. What they should do right now. What you're doing to fix it and prevent recurrence. How to get help. When they'll hear from you again.

### Media

**Tone**: Professional, brief, factual. Stick to confirmed facts. Don't speculate.

**Rules**: Designate one spokesperson. Prepare for hostile questions. Bridge back to your key messages. "Here's what I can tell you..." is better than "No comment." Prepare for the question you don't want to answer — have a response ready.

### Regulators

**Tone**: Formal, thorough, compliant. Reference specific regulatory requirements being met.

**Content**: Timeline of events. Scope of impact (number of individuals, data types). Containment and remediation actions. Root cause (when known). Preventive measures. Point of contact for follow-up.

## Communication Anti-Patterns

**The non-apology apology**: "We're sorry you feel that way" or "We apologize for any inconvenience." These signal insincerity. If you're sorry, say what you're sorry for specifically.

**Blame shifting**: "A sophisticated nation-state actor..." when it was an unpatched server. Acknowledge your role before attributing to external factors.

**Over-lawyering**: When legal review strips every statement of meaning and empathy. The audience reads "we take security seriously" as "our lawyers wrote this." Balance legal protection with human communication.

**Information drip**: Releasing bad news in small increments over days. This extends the news cycle and looks like a coverup. Release what you know in structured updates rather than forced revelations.

**Silence**: The worst anti-pattern. Silence breeds speculation. If you have nothing new to say, say that: "Investigation is ongoing. No new information since our last update at [time]. Next update at [time]."

**Premature "all clear"**: Declaring the incident resolved before you're certain. If you have to retract, your credibility is severely damaged.

## Metrics for Crisis Communication Effectiveness

**Time to first public statement**: Target under 1 hour for major incidents. Under 4 hours for moderate incidents.

**Stakeholder coverage**: Percentage of affected stakeholders who received direct notification within the target timeframe.

**Message consistency**: Degree of alignment between messages to different stakeholders (no contradictions).

**Sentiment trajectory**: Social media and customer sentiment over time. Effective communication stabilizes sentiment within 48 hours.

**Inquiry volume**: Volume of inbound questions. Effective proactive communication reduces inbound volume. A spike in questions means your communication left gaps.

**Accuracy**: Percentage of public statements that proved accurate. Corrections needed erode credibility.
