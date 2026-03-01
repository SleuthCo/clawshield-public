---
framework: "STRIDE"
version: "1.0"
domain: "Threat Modeling"
agent: "sentinel"
tags: ["stride", "threat-modeling", "dfd", "trust-boundaries", "risk-rating", "threat-trees"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# STRIDE Threat Modeling Methodology

STRIDE is a threat classification model developed by Microsoft for identifying security threats. It provides a systematic approach to identifying threats against software systems by categorizing threats into six types. Combined with data flow diagrams and trust boundaries, STRIDE enables comprehensive threat analysis.

## STRIDE Threat Categories

**S — Spoofing Identity:**
Pretending to be something or someone other than yourself. Spoofing threats violate the property of authentication.

- User spoofing: using stolen credentials to impersonate legitimate users
- Service spoofing: a malicious service impersonating a legitimate one
- IP spoofing: forging source IP addresses in network packets
- Email spoofing: sending emails with forged sender addresses
- DNS spoofing: providing false DNS responses to redirect traffic
- Certificate spoofing: using fraudulent TLS certificates

*Mitigations:* Strong authentication (MFA), mutual TLS, certificate pinning, DNSSEC, DMARC/DKIM/SPF, signed tokens

**T — Tampering with Data:**
Modifying data or code without authorization. Tampering threats violate the property of integrity.

- Man-in-the-middle attacks modifying data in transit
- SQL injection modifying database records
- Unauthorized file system modifications
- Configuration tampering (registry, config files)
- Memory corruption attacks modifying process state
- Log tampering to cover attacker tracks
- Supply chain tampering: modifying software during build or distribution

*Mitigations:* Digital signatures, message authentication codes (HMAC), TLS, input validation, file integrity monitoring, code signing, tamper-evident logging

**R — Repudiation:**
Performing an action that cannot be attributed or proven. Repudiation threats violate the property of non-repudiation.

- Denying having performed a transaction
- Claiming an action was unauthorized
- Insufficient logging enabling deniability
- Log deletion or modification preventing attribution
- Shared account usage preventing individual attribution
- Timestamp manipulation

*Mitigations:* Comprehensive audit logging, tamper-evident log storage, digital signatures on transactions, centralized log aggregation (SIEM), unique user identification, timestamp synchronization (NTP)

**I — Information Disclosure:**
Exposing information to unauthorized entities. Information disclosure threats violate the property of confidentiality.

- Data breaches exposing sensitive data
- Error messages revealing internal system details
- Side-channel attacks leaking information (timing, cache)
- Directory traversal accessing unauthorized files
- Network sniffing capturing unencrypted data
- Metadata leakage in documents and images
- Memory disclosure vulnerabilities (Heartbleed-style)
- Unauthorized access to backup data

*Mitigations:* Encryption (at rest and in transit), access control, data classification, DLP, generic error messages, secure configuration, data masking, memory protection

**D — Denial of Service:**
Denying or degrading service to legitimate users. DoS threats violate the property of availability.

- Volumetric DDoS attacks overwhelming bandwidth
- Application-layer DoS exploiting expensive operations
- Resource exhaustion (CPU, memory, disk, connections)
- Algorithmic complexity attacks (hash collision, regex backtracking)
- Lock-out attacks causing account lockout for legitimate users
- Data corruption causing system failures
- Dependency disruption (upstream service unavailability)

*Mitigations:* Rate limiting, input validation, resource quotas, auto-scaling, DDoS protection services, circuit breakers, graceful degradation, redundancy, capacity planning

**E — Elevation of Privilege:**
Gaining capabilities beyond what was authorized. Elevation of privilege threats violate the property of authorization.

- Exploiting vulnerabilities to gain administrative access
- Privilege escalation through kernel exploits
- Insecure deserialization leading to code execution
- SQL injection executing as database admin
- Container escape gaining host access
- Misconfigured IAM policies granting excessive permissions
- Token manipulation elevating authorization claims
- Vertical privilege escalation (user to admin)
- Horizontal privilege escalation (user A accessing user B's data)

*Mitigations:* Least privilege, input validation, sandboxing, secure configuration, RBAC/ABAC, process isolation, security boundaries, regular privilege reviews

## Data Flow Diagrams (DFD)

**Purpose:** DFDs provide a visual representation of how data flows through a system, identifying processes, data stores, external entities, and data flows. They are the foundation for STRIDE threat analysis.

**DFD Elements:**

**External Entity (Rectangle):**
- Represents actors outside the system boundary
- Users, external services, third-party APIs, other systems
- Source or destination of data but not under the system's control
- Examples: end user, payment gateway, email service, partner API

**Process (Circle/Rounded Rectangle):**
- Represents a function that transforms or processes data
- Web server, application logic, API endpoint, background service
- Where most threats manifest — each process should be analyzed
- Examples: authentication service, order processing, data validation

**Data Store (Parallel Lines):**
- Represents persistent storage of data
- Databases, file systems, caches, message queues, configuration stores
- Key targets for information disclosure and tampering threats
- Examples: user database, session store, file upload storage

**Data Flow (Arrow):**
- Represents movement of data between elements
- Label with the type of data being transferred
- Identify protocol and encryption status
- Examples: HTTPS request, database query, message queue event, file read

**DFD Levels:**
- **Level 0 (Context Diagram):** System as a single process with external entities
- **Level 1 (High-Level):** Major subsystems and their interactions
- **Level 2 (Detailed):** Internal processes within each subsystem
- Go as deep as necessary to identify meaningful threats
- Focus detail on security-critical components

## Trust Boundaries

**Definition:** Trust boundaries define areas where the level of trust changes. Data crossing a trust boundary requires validation and may require authentication, authorization, or transformation.

**Common Trust Boundaries:**
- Internet to DMZ (untrusted to semi-trusted)
- DMZ to internal network (semi-trusted to trusted)
- Client to server (untrusted to trusted)
- User input to application processing
- Between different security zones or VLANs
- Between different organizational units or tenants
- Between different privilege levels (user space to kernel)
- Between different cloud accounts or subscriptions
- Between your code and third-party libraries
- Between application and operating system

**Trust Boundary Analysis:**
- Draw trust boundaries on DFDs as dashed lines
- Every data flow crossing a trust boundary is a potential attack vector
- Identify what validation occurs at each crossing
- Higher-trust zones should validate data from lower-trust zones
- Trust boundaries are prime locations for security controls
- Each crossing point should have explicit authentication, authorization, and input validation

## Applying STRIDE to DFD Elements

**Threat-Element Mapping:**

| Element | S | T | R | I | D | E |
|---------|---|---|---|---|---|---|
| External Entity | X | | | | | |
| Process | X | X | X | X | X | X |
| Data Store | | X | ? | X | X | |
| Data Flow | | X | | X | X | |

- External Entities can be spoofed
- Processes are vulnerable to all STRIDE categories
- Data Stores can be tampered with, may have repudiation issues, can disclose information, and can be denied access to
- Data Flows can be tampered with, can disclose information, and can be disrupted

**Analysis Process:**
1. For each element in the DFD, consider applicable STRIDE categories
2. For each applicable category, identify specific threats
3. Evaluate each threat for likelihood and impact
4. Determine existing mitigations and residual risk
5. Prioritize threats requiring additional controls
6. Document findings in a threat model report

## Threat Trees

**Definition:** Threat trees (attack trees) are hierarchical diagrams showing the different ways an attacker could achieve a specific goal. The root node represents the attacker's goal, and leaf nodes represent the atomic steps to achieve it.

**Construction Process:**
1. Define the root goal (e.g., "Steal user credentials")
2. Identify high-level attack paths (OR nodes: any path achieves the goal)
3. Decompose each path into required steps (AND nodes: all steps needed)
4. Continue decomposition until reaching atomic attack steps
5. Annotate with likelihood, cost, and difficulty for each leaf
6. Calculate aggregate risk for each path

**Example Threat Tree — Steal User Credentials:**
```
Root: Steal User Credentials [OR]
├── Phishing Attack [AND]
│   ├── Craft convincing phishing email
│   ├── User clicks link
│   └── User enters credentials on fake page
├── Credential Stuffing [AND]
│   ├── Obtain leaked credential database
│   ├── Identify target application
│   └── Automate login attempts
├── Intercept Credentials in Transit [AND]
│   ├── Position for man-in-the-middle
│   └── Downgrade or break TLS
├── Compromise Credential Store [AND]
│   ├── Gain access to database server
│   ├── Extract password hashes
│   └── Crack password hashes offline
└── Social Engineering [AND]
    ├── Identify target with access
    ├── Build pretext and trust
    └── Convince target to reveal credentials
```

**Annotations:**
- Probability: estimated likelihood of each leaf node
- Cost: resources required by the attacker
- Difficulty: technical skill level required
- Detectability: likelihood the attack is detected
- Impact: consequence if the attack succeeds

## Risk Rating

**DREAD Model (Microsoft legacy, useful for relative ranking):**
- **D**amage Potential: how severe is the damage? (0-10)
- **R**eproducibility: how easy to reproduce the attack? (0-10)
- **E**xploitability: how easy to launch the attack? (0-10)
- **A**ffected Users: how many users are impacted? (0-10)
- **D**iscoverability: how easy to discover the vulnerability? (0-10)
- Risk = (D + R + E + A + D) / 5

**CVSS-Based Risk Rating:**
- Use CVSS Base Score for vulnerability severity
- Adjust with Temporal Score for current exploit availability
- Apply Environmental Score for organizational context
- CVSS 3.1 scale: Low (0.1-3.9), Medium (4.0-6.9), High (7.0-8.9), Critical (9.0-10.0)

**Risk Matrix Approach:**
- Likelihood scale: Very Low, Low, Medium, High, Very High
- Impact scale: Negligible, Minor, Moderate, Major, Critical
- Risk = Likelihood x Impact
- Plot on a 5x5 matrix with color coding for risk levels
- Red (Critical/High): immediate remediation required
- Yellow (Medium): remediation planned within defined timeframe
- Green (Low): accept or remediate opportunistically

**Factors Influencing Likelihood:**
- Attacker skill level required
- Access level needed (network, authenticated, physical)
- Availability of exploit tools or public exploits
- Attractiveness of target (data value, publicity)
- Effectiveness of existing controls

**Factors Influencing Impact:**
- Confidentiality: data sensitivity and volume
- Integrity: criticality of data or system accuracy
- Availability: business process dependency
- Financial: direct costs, fines, legal exposure
- Reputational: customer trust, brand impact
- Regulatory: compliance violations, mandatory reporting

## Conducting a STRIDE Threat Model Session

**Step 1 — Scope Definition (30 minutes):**
- Define system boundaries and components in scope
- Identify assets requiring protection
- Define security objectives and compliance requirements
- Identify external dependencies and interfaces

**Step 2 — Data Flow Diagram (60 minutes):**
- Create or review DFD at appropriate level
- Mark trust boundaries
- Label data flows with data types and protocols
- Validate DFD with development team

**Step 3 — Threat Identification (90 minutes):**
- Walk through each DFD element systematically
- Apply STRIDE categories to each element
- Document specific threats with attack scenarios
- Use threat library for known attack patterns
- Consider attacker motivations and capabilities

**Step 4 — Risk Assessment (45 minutes):**
- Rate each threat for likelihood and impact
- Identify existing mitigations
- Calculate residual risk
- Prioritize threats requiring action

**Step 5 — Mitigation Planning (45 minutes):**
- Define security controls for high-priority threats
- Map controls to development backlog items
- Assign ownership and timelines
- Document accepted risks with justification

**Step 6 — Documentation and Review (30 minutes):**
- Compile threat model document
- Review with stakeholders
- Schedule periodic review (at least annually or on significant changes)
- Track mitigation implementation to completion
