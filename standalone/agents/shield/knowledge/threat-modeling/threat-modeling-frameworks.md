---
framework: "Threat Modeling Frameworks"
version: "1.0"
domain: "Threat Modeling"
agent: "sentinel"
tags: ["pasta", "linddun", "vast", "attack-trees", "kill-chain", "cloud-threats", "ai-threats"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Threat Modeling Frameworks

This document covers advanced threat modeling methodologies beyond STRIDE, including risk-centric, privacy-focused, and domain-specific approaches for cloud, AI/ML, and automated tooling.

## PASTA (Process for Attack Simulation and Threat Analysis)

**Overview:** PASTA is a seven-stage, risk-centric threat modeling methodology that aligns technical risk with business objectives. It emphasizes attacker-centric analysis and quantitative risk assessment.

**Stage 1 — Define Objectives:**
- Identify business objectives and security requirements
- Determine regulatory and compliance constraints
- Define risk appetite and tolerance levels
- Establish scope and boundaries of the analysis
- Align threat model outputs with business risk management

**Stage 2 — Define Technical Scope:**
- Inventory technical components: applications, infrastructure, data stores
- Document technology stack and dependencies
- Map network architecture and data flows
- Identify external interfaces and third-party integrations
- Create or validate architecture diagrams

**Stage 3 — Application Decomposition:**
- Decompose the application into functional components
- Create data flow diagrams with trust boundaries
- Identify entry points and data input mechanisms
- Map user roles and privilege levels
- Document authentication and authorization mechanisms
- Identify assets requiring protection

**Stage 4 — Threat Analysis:**
- Analyze current threat landscape relevant to the application
- Review threat intelligence for applicable threat actors
- Map threat actors to their capabilities, motivations, and targets
- Identify relevant attack patterns from ATT&CK and CAPEC
- Assess historical incidents in the same industry or technology stack
- Document applicable threat scenarios

**Stage 5 — Vulnerability Analysis:**
- Identify known vulnerabilities in the technology stack
- Correlate CVEs with deployed components
- Review application security testing results (SAST, DAST, pentest)
- Identify design weaknesses and logic flaws
- Map vulnerabilities to identified threats
- Assess exploitability of each vulnerability

**Stage 6 — Attack Modeling:**
- Build attack trees for high-priority threat scenarios
- Simulate attack paths through the application
- Assess probability and impact of successful attacks
- Identify the most likely and most damaging attack paths
- Model multi-step attack sequences (kill chains)
- Consider attacker return on investment for each path

**Stage 7 — Risk and Impact Analysis:**
- Quantify risk using organizational risk framework
- Calculate residual risk after existing controls
- Prioritize mitigations based on risk reduction potential
- Map mitigations to specific countermeasures
- Produce actionable recommendations with business context
- Track risk reduction over time through iterative assessments

**PASTA Advantages:**
- Business-risk-centric rather than purely technical
- Attacker-centric perspective provides realistic threat assessment
- Integrates threat intelligence and vulnerability data
- Produces quantifiable risk metrics for executive reporting
- Suitable for complex, multi-tier applications

## LINDDUN (Privacy Threat Modeling)

**Overview:** LINDDUN is a privacy-focused threat modeling framework that systematically identifies and mitigates privacy threats throughout the system lifecycle. It is complementary to security-focused frameworks like STRIDE.

**LINDDUN Threat Categories:**

**L — Linkability:**
- Ability to link two or more items of interest (data records, actions, identities)
- Example: linking browsing behavior across sessions to build user profiles
- Mitigation: data aggregation, pseudonymization, mix networks, unlinkable credentials

**I — Identifiability:**
- Ability to identify a subject from a set of subjects within the system
- Example: identifying a user from anonymized data through quasi-identifiers
- Mitigation: anonymization (k-anonymity, l-diversity, t-closeness), differential privacy

**N — Non-Repudiation (Privacy Context):**
- Inability to deny having performed an action (may violate privacy when undesired)
- Example: non-deniable proof of purchasing sensitive items
- Mitigation: deniable encryption, plausible deniability mechanisms, anonymous credentials

**D — Detectability:**
- Ability to detect that an item of interest exists
- Example: detecting that a user has a medical record in a system (even without accessing it)
- Mitigation: steganography, dummy traffic, broadcast protocols, hiding data existence

**D — Disclosure of Information:**
- Unauthorized access to personal information
- Example: data breach exposing personal data, inference from aggregated data
- Mitigation: access control, encryption, data minimization, purpose limitation

**U — Unawareness:**
- Users are not aware of data collection, processing, or sharing
- Example: hidden tracking, undisclosed data sharing with third parties
- Mitigation: transparency, privacy notices, consent management, data subject rights

**N — Non-Compliance:**
- Failure to comply with privacy legislation, regulation, or policy
- Example: violating GDPR data minimization principle, exceeding retention periods
- Mitigation: privacy by design, Data Protection Impact Assessment (DPIA), governance

**LINDDUN Process:**
1. Model the system using DFDs
2. Map LINDDUN threats to DFD elements
3. Identify relevant privacy threats using threat trees
4. Assess threat severity considering regulatory context
5. Select privacy-enhancing technologies (PETs) as mitigations
6. Document privacy decisions and residual risks

## VAST (Visual, Agile, and Simple Threat)

**Overview:** VAST is designed to scale threat modeling across the enterprise, providing different views for different stakeholders. It distinguishes between application threat models and operational threat models.

**Application Threat Model (Developer-Focused):**
- Based on process flow diagrams aligned with Agile development
- Identifies threats in application design and implementation
- Maps directly to user stories and development sprints
- Automated threat identification from architecture patterns
- Produces developer-actionable security requirements

**Operational Threat Model (Infrastructure-Focused):**
- Based on data flow diagrams of the operational environment
- Identifies infrastructure, network, and deployment threats
- Maps to operational controls and configuration requirements
- Considers the full deployment pipeline and runtime environment
- Produces operations-actionable security controls

**VAST Principles:**
- Scalability: designed for enterprise-wide adoption with hundreds of teams
- Automation: leverage tooling to reduce manual effort
- Integration: embed in existing development and operations workflows
- Actionability: produce specific, implementable security requirements
- Repeatability: consistent methodology across all teams and applications
- Executive reporting: aggregated risk views for leadership

## Attack Trees

**Formalization:**
Attack trees provide a formal, methodical way of describing the security of systems based on varying attacks. They are hierarchical diagrams showing the different ways an attacker could achieve specific goals.

**Node Types:**
- **OR nodes:** any child path achieves the parent goal (alternatives)
- **AND nodes:** all child paths must succeed to achieve the parent (requirements)
- **SAND nodes:** sequential AND — children must succeed in order

**Quantitative Analysis:**
- Assign values to leaf nodes: cost, time, probability, skill level, detectability
- Propagate values upward: OR takes minimum (easiest path), AND takes sum
- Identify minimum cost paths (cheapest for attacker)
- Identify maximum probability paths (most likely)
- Compare attack cost against asset value for risk prioritization

**Attack Tree Best Practices:**
- Start with attacker goals derived from threat intelligence
- Decompose to actionable, atomic attack steps at leaf level
- Validate with red team or penetration test findings
- Update trees as new attack techniques are discovered
- Use trees to prioritize defensive investments based on critical paths
- Visualize trees for communication with non-technical stakeholders

## Kill Chain Analysis

**Lockheed Martin Cyber Kill Chain:**

1. **Reconnaissance:** Research, identification, and selection of targets (OSINT, scanning)
2. **Weaponization:** Coupling exploit with backdoor into deliverable payload
3. **Delivery:** Transmission of weapon to target (email, web, USB)
4. **Exploitation:** Triggering the exploit to execute attacker's code
5. **Installation:** Installing backdoor or persistent access mechanism
6. **Command and Control (C2):** Establishing communication channel for remote control
7. **Actions on Objectives:** Achieving attacker's goal (exfiltration, destruction, encryption)

**Defensive Application:**
- Map defensive controls to each kill chain stage
- Identify detection opportunities at each stage
- Understand that disrupting any stage disrupts the entire attack
- Measure detection and prevention capability at each stage
- Prioritize controls that detect/prevent early stages (left of kill chain)

**Unified Kill Chain:**
Extends the Lockheed Martin model with additional phases:
- Initial Foothold phase (reconnaissance through exploitation)
- Network Propagation phase (lateral movement, privilege escalation, credential access)
- Actions on Objectives phase (data collection, exfiltration, impact)
- Maps directly to MITRE ATT&CK tactics for detailed technique coverage

## Threat Modeling for Cloud

**Cloud-Specific Threat Categories:**

**Identity and Access Threats:**
- Over-permissioned IAM roles and policies
- Credential theft from metadata services
- Cross-account and cross-tenant access abuse
- Federated identity trust exploitation
- Service account key exposure

**Configuration Threats:**
- Public storage buckets (S3, Blob, GCS)
- Overly permissive security groups and network ACLs
- Unencrypted data stores
- Logging and monitoring gaps
- Exposed management APIs and consoles

**Multi-Tenancy Threats:**
- Noisy neighbor resource exhaustion
- Side-channel attacks between tenants
- Data leakage through shared infrastructure
- Cross-tenant access via misconfigurations
- Shared resource poisoning

**Serverless and Container Threats:**
- Function injection and event data tampering
- Container escape and orchestration exploitation
- Insecure container images with known vulnerabilities
- Secrets in environment variables or container layers
- Supply chain attacks through base images

**Cloud Threat Modeling Process:**
1. Map cloud architecture including all services and data flows
2. Identify shared responsibility boundaries with cloud provider
3. Analyze IAM policies and trust relationships
4. Review network architecture and segmentation
5. Assess data storage and encryption configurations
6. Evaluate logging, monitoring, and alerting capabilities
7. Test for common cloud misconfigurations (ScoutSuite, Prowler)
8. Model cross-service attack paths
9. Assess blast radius of compromised identities or services

## Threat Modeling for AI/ML Systems

**AI-Specific Threat Categories:**

**Data Threats:**
- Training data poisoning: injecting malicious data to influence model behavior
- Data extraction: recovering training data from model queries
- Data supply chain: compromised data sources or labeling processes
- Privacy threats: model memorization of sensitive training data
- Bias injection: manipulating data to introduce discriminatory behavior

**Model Threats:**
- Model theft: extracting model weights through API queries (model extraction)
- Model evasion: crafting inputs that cause misclassification
- Model inversion: inferring sensitive attributes from model outputs
- Backdoor attacks: hidden triggers causing specific model behavior
- Adversarial examples: imperceptible perturbations causing incorrect outputs

**Infrastructure Threats:**
- ML pipeline compromise: injecting code into training pipelines
- Model serving exploitation: attacking inference endpoints
- GPU/TPU side-channel attacks: leaking data through shared compute
- Model registry poisoning: replacing legitimate models with compromised ones
- Experiment tracking manipulation: falsifying model evaluation results

**AI/ML Threat Modeling Process:**
1. Map the ML pipeline: data collection, preprocessing, training, validation, deployment, monitoring
2. Identify trust boundaries between pipeline stages
3. Analyze data provenance and integrity controls
4. Assess model access controls and authentication
5. Evaluate inference API security (rate limiting, input validation)
6. Model adversarial attack scenarios specific to the ML task
7. Assess supply chain risks for pre-trained models and datasets
8. Review monitoring for model drift and adversarial inputs
9. Evaluate feedback loop security (user feedback influencing future training)

## Automated Threat Modeling Tools

**Microsoft Threat Modeling Tool:**
- Free tool using DFD-based approach
- Auto-generates threats based on STRIDE and element types
- Template-based for common architectures (web, Azure, IoT)
- Produces threat report with suggested mitigations
- Suitable for teams new to threat modeling

**OWASP Threat Dragon:**
- Open-source threat modeling tool
- Web-based and desktop versions available
- DFD creation with automatic threat generation
- Integration with development workflows
- Supports both STRIDE and other threat libraries

**IriusRisk:**
- Commercial automated threat modeling platform
- Library of threat patterns and countermeasures
- Integration with CI/CD, Jira, Azure DevOps
- Risk quantification and compliance mapping
- Scales to enterprise with centralized threat model management

**Threagile:**
- Open-source, code-based threat modeling (YAML definitions)
- Automated risk identification from architecture descriptions
- Generates visual diagrams and risk reports
- Integrates into CI/CD pipelines
- Supports infrastructure-as-code approaches

**Best Practices for Tooling:**
- Tools support but do not replace human analysis
- Use tools for consistency and coverage tracking
- Integrate threat modeling into development lifecycle (shift left)
- Maintain threat model libraries specific to your technology stack
- Review and update tool-generated threats with domain expertise
- Export and track threats in existing issue management systems
