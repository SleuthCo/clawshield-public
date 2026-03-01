---
framework: "Security Architecture"
version: "1.0"
domain: "Security Design Patterns"
agent: "sentinel"
tags: ["architecture", "defense-in-depth", "siem", "soc", "waf", "sdlc", "soar"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Security Architecture Patterns

This document covers foundational security architecture patterns including defense in depth, network design, monitoring infrastructure, and secure development practices.

## Defense in Depth

**Principle:** Multiple layers of security controls protect assets so that a failure in one layer does not result in a complete compromise. Each layer provides independent protection, and adversaries must defeat multiple defenses to reach critical assets.

**Layer Architecture:**

1. **Perimeter Layer:** Firewalls, IPS/IDS, DDoS protection, WAF, email gateway, DNS filtering
2. **Network Layer:** Segmentation, VLANs, ACLs, NDR, NTA, encrypted transit
3. **Host Layer:** OS hardening, endpoint protection (EDR), host firewall, patch management
4. **Application Layer:** Secure coding, input validation, authentication, authorization, RASP
5. **Data Layer:** Encryption at rest and in transit, DLP, classification, backup, access controls
6. **Identity Layer:** MFA, IAM, PAM, SSO, identity governance, behavioral analytics
7. **Policy Layer:** Security policies, standards, procedures, awareness training, governance

**Design Principles:**
- No single point of failure in security controls
- Defense mechanisms should be diverse (different vendors, technologies)
- Inner layers should not depend on outer layers being intact
- Each layer should log and alert independently
- Assume breach: design inner layers to contain compromised outer layers
- Balance security depth with operational complexity and user experience

## Network Segmentation

**Segmentation Tiers:**

**Tier 1 — Internet/External Zone:**
- Public-facing services and DMZ
- Heavily monitored and restricted
- Minimal services exposed with maximum protection

**Tier 2 — Presentation/Web Zone:**
- Web servers, reverse proxies, API gateways
- No direct database access
- Outbound connections restricted to specific application tier destinations

**Tier 3 — Application Zone:**
- Application servers, middleware, business logic
- Communicates with both presentation and data tiers
- Inter-application communication controlled by micro-segmentation

**Tier 4 — Data Zone:**
- Database servers, file servers, data warehouses
- Most restrictive access controls
- No direct internet access; limited to application tier connections
- Encryption for data at rest and all connections

**Tier 5 — Management Zone:**
- Security tools, monitoring systems, configuration management
- Privileged access workstations (PAWs)
- Jump servers / bastion hosts
- Out-of-band management network

**Implementation Technologies:**
- VLANs with inter-VLAN routing controlled by firewalls
- Software-defined networking (SDN) for dynamic segmentation
- Cloud VPCs, subnets, and security groups
- Service mesh for microservice communication control
- Zero Trust Network Access replacing flat VPN access

## DMZ Design Patterns

**Single DMZ Architecture:**
- One firewall with three zones: external, DMZ, internal
- DMZ hosts public-facing services (web servers, mail relay, DNS)
- Internal zone accessible only from DMZ application layer
- Suitable for small to medium deployments

**Dual Firewall DMZ:**
- External firewall between internet and DMZ
- Internal firewall between DMZ and internal network
- Different firewall vendors for defense diversity
- More secure: compromise of one firewall does not grant internal access
- Recommended for high-security environments

**Multi-Tier DMZ:**
- Separate DMZ zones for different service types
- Web DMZ, Application DMZ, Database DMZ each with own controls
- Strict traffic flow rules between tiers
- Maximum isolation for high-value assets

**Cloud DMZ Equivalent:**
- Public subnets for internet-facing load balancers
- Private subnets for application servers
- Isolated subnets for databases with no internet route
- Transit gateway or peering for inter-VPC communication
- Network ACLs and security groups as virtual firewalls

## WAF Architecture and Placement

**Deployment Models:**

**Inline (Reverse Proxy):**
- WAF sits in the traffic path between client and web server
- Can inspect, modify, and block requests in real time
- Adds latency but provides maximum protection
- Most common deployment for critical applications

**Out-of-Band (Monitoring):**
- WAF receives a copy of traffic via port mirroring or TAP
- Detection only; cannot block requests
- No latency impact; suitable for initial deployment and tuning
- Used for assessment before switching to inline blocking

**Cloud-Based WAF:**
- WAF-as-a-Service (Cloudflare, AWS WAF, Azure Front Door)
- DNS-based traffic routing through WAF infrastructure
- DDoS protection included
- Lower management overhead with limited customization
- Effective for protecting cloud-hosted applications

**WAF Rule Categories:**
- OWASP Core Rule Set (CRS): baseline protection against common attacks
- Custom rules: application-specific logic and business rules
- Rate limiting rules: throttling by IP, session, or API key
- Bot management rules: challenge suspicious automation
- Virtual patching rules: temporary mitigation for unpatched vulnerabilities
- Geo-blocking: restrict access by geographic region

**WAF Operational Best Practices:**
- Deploy in detection mode first; analyze false positives for 2-4 weeks
- Tune rules to reduce false positives before enabling blocking
- Integrate WAF logs with SIEM for correlation
- Automate rule updates from vendor feeds
- Test WAF bypass techniques regularly (encoding, fragmentation)
- Maintain exception lists with documented justification and review dates

## SIEM Architecture

**Core Components:**
- **Log Collection:** agents, syslog, API integrations, cloud connectors
- **Normalization:** parsing and normalizing diverse log formats to common schema
- **Correlation Engine:** rules and analytics detecting patterns across data sources
- **Storage:** high-performance index for recent data, cold storage for retention
- **Dashboard/Visualization:** real-time operational dashboards and investigation views
- **Case Management:** incident tracking and workflow integration

**Data Sources (Priority Order):**
1. Authentication systems (AD, LDAP, IdP, MFA)
2. Endpoint detection and response (EDR)
3. Firewalls and network security devices
4. Cloud audit logs (CloudTrail, Azure Activity Log, GCP Audit)
5. Email security gateways
6. Web application firewalls and web proxies
7. DNS query logs
8. Database audit logs
9. Application logs (security-relevant events)
10. Vulnerability scan results and asset inventory

**Architecture Patterns:**

**Centralized SIEM:**
- Single SIEM instance collecting from all sources
- Simple management but potential scalability limitations
- Suitable for single-site or small multi-site deployments

**Distributed Collection, Centralized Analysis:**
- Log collectors/forwarders at each location
- Filtering and normalization at the edge
- Centralized correlation and analysis engine
- Reduces bandwidth and improves scalability

**Federated SIEM:**
- Regional SIEM instances with local correlation
- Centralized meta-SIEM for cross-region correlation
- Required for large, geographically distributed enterprises
- Addresses data residency and sovereignty requirements

**Cloud-Native SIEM:**
- SaaS SIEM platform (Microsoft Sentinel, Google Chronicle, Splunk Cloud)
- Elastic scaling for data volume fluctuations
- Native cloud service integrations
- Reduced infrastructure management overhead

## SOC Design

**SOC Tiers:**

**Tier 1 — Alert Triage (L1 Analyst):**
- Monitor alerts from SIEM, EDR, and other detection tools
- Initial triage: classify alerts as true positive, false positive, or needs escalation
- Execute standard operating procedures (SOPs) for common alert types
- Document findings and escalate to Tier 2 when needed
- Target: triage alert within 15 minutes of generation

**Tier 2 — Investigation (L2 Analyst):**
- Deep investigation of escalated alerts
- Correlate data across multiple sources
- Determine incident scope, impact, and root cause
- Initiate containment actions per playbooks
- Conduct forensic analysis and malware triage
- Target: initial investigation within 1 hour of escalation

**Tier 3 — Advanced Analysis (L3 Analyst / Threat Hunter):**
- Proactive threat hunting based on intelligence and hypotheses
- Advanced forensics and malware reverse engineering
- Development of new detection rules and analytics
- Incident response leadership for complex incidents
- Red/Purple team coordination
- Threat intelligence analysis and operationalization

**SOC Manager:**
- Operational management of SOC staff and processes
- Metrics reporting and continuous improvement
- Stakeholder communication and escalation management
- Resource planning and shift scheduling
- Process optimization and tool evaluation

**SOC Metrics:**
- Mean Time to Detect (MTTD): time from incident occurrence to detection
- Mean Time to Acknowledge (MTTA): time from alert to analyst acknowledgment
- Mean Time to Respond (MTTR): time from detection to containment
- Alert volume by source, type, and severity
- True positive rate by detection rule
- Escalation rate from Tier 1 to Tier 2
- Analyst workload and utilization
- Threat hunting campaigns completed and findings

## Security Data Lake

**Architecture:**
- Centralized repository for all security-relevant data at scale
- Schema-on-read: store raw data and apply structure during analysis
- Separation of hot (recent, indexed), warm (weeks, searchable), and cold (months/years, archived) tiers
- Support for structured (logs), semi-structured (JSON), and unstructured (PCAP) data

**Use Cases:**
- Long-term threat hunting across historical data
- Machine learning training data for anomaly detection models
- Compliance log retention (7+ years for some regulations)
- Forensic investigation requiring extensive historical context
- Security analytics and trend analysis

**Technology Stack:**
- Storage: S3, Azure Data Lake, Google Cloud Storage with lifecycle policies
- Processing: Apache Spark, Databricks, Snowflake
- Schema: OCSF (Open Cybersecurity Schema Framework) for normalization
- Query: SQL-based analytics with columnar storage optimization
- Integration: feed SIEM for real-time, data lake for deep analysis

## SOAR Integration

**SOAR (Security Orchestration, Automation, and Response) Architecture:**

**Orchestration:**
- Connect and coordinate disparate security tools via APIs
- Unified workflow spanning SIEM, EDR, firewall, email, identity, ticketing
- Eliminate manual tool-switching and data gathering
- Standard integrations for 200+ security tools

**Automation:**
- Automated playbooks for repetitive response tasks
- Phishing triage: extract indicators, check reputation, quarantine, notify
- Malware response: isolate endpoint, collect forensics, block indicators
- Account compromise: disable account, revoke sessions, notify user
- Vulnerability response: validate, prioritize, assign, track remediation
- Reduce mean response time from hours to minutes

**Response:**
- Case management with full audit trail
- Evidence collection and chain of custody documentation
- Stakeholder notification and communication management
- Post-incident review automation
- Metrics collection and reporting

**Playbook Design Principles:**
- Start with the most frequent, highest-volume alert types
- Begin with semi-automated (analyst approval required)
- Advance to fully automated as confidence in playbook accuracy increases
- Include error handling and exception paths
- Version control playbooks like code
- Test playbooks regularly with simulated incidents

## Secure SDLC Toolchain

**Phase 1 — Requirements:**
- Security requirements derived from threat model and compliance mandates
- Abuse cases and negative requirements alongside functional requirements
- Privacy requirements (data minimization, consent, retention)
- Security acceptance criteria for each user story

**Phase 2 — Design:**
- Threat modeling (STRIDE, PASTA) for every significant design change
- Security architecture review by security champions or architects
- Cryptographic design review for data protection
- Authentication and authorization model review

**Phase 3 — Implementation:**
- IDE security plugins: real-time vulnerability feedback during coding
- Pre-commit hooks: secrets detection (git-secrets, detect-secrets, gitleaks)
- Secure coding standards enforcement (ESLint security rules, Semgrep)
- Peer code review with security-focused reviewers

**Phase 4 — Verification:**
- SAST: static analysis (SonarQube, Checkmarx, Semgrep, CodeQL)
- SCA: dependency scanning (Snyk, Dependabot, OWASP Dependency-Check)
- DAST: dynamic testing (Burp Suite, OWASP ZAP, Nuclei)
- Container scanning: image vulnerabilities (Trivy, Grype)
- IaC scanning: infrastructure misconfigurations (Checkov, tfsec, KICS)
- API security testing: specification validation and fuzzing

**Phase 5 — Release:**
- Security gate: no critical or high vulnerabilities without exception approval
- Signed artifacts with provenance attestation (SLSA)
- Automated deployment to hardened infrastructure
- Runtime protection: RASP, WAF virtual patching

**Phase 6 — Operations:**
- Continuous monitoring and detection
- Vulnerability management with SLA tracking
- Incident response with application context
- Regular penetration testing (annual minimum, quarterly recommended)
- Bug bounty program for continuous external testing

**Phase 7 — Decommission:**
- Data sanitization and secure deletion
- Credential and certificate revocation
- DNS and certificate cleanup
- Documentation update and archive
