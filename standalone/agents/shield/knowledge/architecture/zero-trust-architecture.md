---
framework: "NIST SP 800-207"
version: "1.0"
domain: "Zero Trust Architecture"
agent: "sentinel"
tags: ["zero-trust", "zta", "nist-800-207", "micro-segmentation", "ztna", "sdp"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Zero Trust Architecture — NIST SP 800-207

Zero Trust is a security paradigm that eliminates implicit trust and continuously validates every stage of digital interaction. This document covers the principles, architecture patterns, and implementation strategies for Zero Trust.

## Zero Trust Principles

**Core Tenets of Zero Trust:**

1. **All data sources and computing services are considered resources.** A network may consist of multiple classes of devices. Small footprint devices (IoT), personal devices (BYOD), and cloud resources should all be treated as resources requiring protection.

2. **All communication is secured regardless of network location.** Network location alone does not imply trust. Access requests from within the enterprise network must meet the same security requirements as those from external networks. All communication must be encrypted and authenticated.

3. **Access to individual enterprise resources is granted on a per-session basis.** Trust in the requester is evaluated before access is granted. Access is granted with the minimum privileges needed to complete the task. Authentication and authorization to one resource does not automatically grant access to another.

4. **Access to resources is determined by dynamic policy.** Policy includes observable state of client identity, application, and the requesting asset. Behavioral attributes, environmental attributes, and risk levels are factored into access decisions.

5. **The enterprise monitors and measures the integrity and security posture of all owned and associated assets.** No asset is inherently trusted. Asset security posture is evaluated when evaluating resource requests. Continuous diagnostics and monitoring feed into policy decisions.

6. **All resource authentication and authorization are dynamic and strictly enforced before access is allowed.** This includes ongoing monitoring and re-authentication during established sessions. Constant cycle of obtaining access, scanning and assessing threats, adapting, and continually re-evaluating trust.

7. **The enterprise collects as much information as possible about the current state of assets, network infrastructure, and communications.** Data is used to improve security posture and policy creation. Continuous improvement based on collected data and intelligence.

## Zero Trust Architecture Components

**Policy Decision Point (PDP):**
- Evaluates access requests against defined policies
- Considers identity, device posture, context, and risk signals
- Returns allow/deny/conditional decisions
- Components: Policy Engine (PE) and Policy Administrator (PA)
- The Policy Engine is the brain of the ZTA, making the trust algorithm decisions
- The Policy Administrator establishes and shuts down communication paths

**Policy Enforcement Point (PEP):**
- Enables, monitors, and terminates connections between subjects and resources
- Gateway that enforces PDP decisions at the access boundary
- Deployed as close to the resource as possible
- Examples: reverse proxy, API gateway, micro-gateway, host-based firewall
- Must be tamper-resistant and highly available

**Policy Information Point (PIP):**
- Provides data inputs to the PDP for decision making
- Sources include: SIEM, threat intelligence, identity store, CMDB, compliance systems
- Feeds real-time context about users, devices, and environment
- May include external data sources (threat feeds, reputation services)

**Continuous Diagnostics and Mitigation (CDM):**
- Real-time assessment of asset security posture
- Device health, patch status, configuration compliance
- Provides ongoing trust evaluation data to PDP
- Feeds vulnerability and compliance data into access decisions

**Threat Intelligence:**
- External and internal threat data informing policy decisions
- Indicators of compromise integrated with access control decisions
- Behavioral analytics identifying anomalous access patterns
- Risk scoring based on current threat landscape

## Zero Trust Deployment Models

**Device Agent/Gateway-Based Model:**
- Each device runs a local agent that communicates with the PDP
- Agent provides device posture, user identity, and request context
- Gateway enforces PDP decisions at the network or application layer
- Best for: enterprises with managed device fleets
- Implementation: endpoint agents + reverse proxy or gateway

**Enclave-Based Model:**
- Resources grouped into enclaves with a gateway PEP at each boundary
- PDP evaluates requests at enclave boundaries
- Suitable for organizations with legacy systems that cannot host agents
- Gateway mediates all access into the enclave
- Best for: hybrid environments with legacy and modern systems

**Resource Portal-Based Model:**
- Central portal (PEP) acts as a proxy for all resource access
- No agent required on client device
- Portal handles authentication, authorization, and session management
- Best for: BYOD environments and third-party access scenarios
- Implementation: VDI, browser-based access portals, ZTNA services

## Micro-segmentation

**Definition:** Micro-segmentation divides the network into small, isolated segments to limit lateral movement and enforce granular access controls between workloads.

**Implementation Approaches:**
- Host-based firewalls with centrally managed policies (identity-aware)
- Software-defined networking (SDN) with programmable micro-segments
- Service mesh sidecar proxies (Istio, Linkerd) for service-to-service control
- Container network policies (Kubernetes NetworkPolicy, Calico, Cilium)
- Cloud-native security groups and network ACLs at the workload level

**Micro-segmentation Design Principles:**
- Segment by application tier, data sensitivity, and compliance scope
- Default deny: all east-west traffic blocked unless explicitly permitted
- Policy based on workload identity, not IP address
- Visibility first: map all communication flows before enforcing restrictions
- Implement in monitoring mode before enforcement to avoid disruption
- Automate policy generation from observed traffic patterns
- Test policies in staging environments before production enforcement

**Operational Considerations:**
- Maintain flow visibility dashboards for troubleshooting
- Integrate with change management for policy updates
- Automate exception handling with time-limited rules
- Regular review of micro-segmentation policies against current application architecture
- Performance testing to ensure segmentation does not introduce latency

## Identity-Centric Security

**Identity as the New Perimeter:**
- Every access request must be authenticated and authorized based on identity
- Identity encompasses user identity, device identity, and workload identity
- Strong identity verification replaces network-based trust
- Continuous identity validation throughout the session

**Identity Verification Components:**
- Multi-factor authentication: something you know, have, and are
- Phishing-resistant MFA: FIDO2/WebAuthn, hardware security keys
- Device identity: certificates, TPM-based attestation, MDM enrollment
- Workload identity: SPIFFE/SPIRE, managed identities, service accounts with short-lived credentials
- Continuous authentication: behavioral biometrics, session risk scoring

**Identity Governance in Zero Trust:**
- Just-in-time access provisioning: access granted only when needed
- Just-enough-access: minimum permissions for the specific task
- Automated access certification with risk-based review frequency
- Identity threat detection: impossible travel, anomalous behavior, credential abuse
- Federated identity across organizational boundaries with standards (SAML, OIDC)

## Continuous Verification

**Trust Algorithm:**
The PDP implements a trust algorithm that evaluates multiple factors for each access request:

- **Subject credentials and identity:** strength of authentication, identity assurance level
- **Device health and security posture:** patch level, EDR status, encryption, compliance
- **Request context:** time, location, network, resource sensitivity
- **Behavioral patterns:** deviation from normal usage, risk score
- **Threat intelligence:** known indicators matching request attributes
- **Resource sensitivity:** classification level, regulatory requirements

**Continuous Evaluation:**
- Re-evaluate trust throughout the session, not just at authentication
- Trigger re-authentication on risk signal changes (location change, anomalous behavior)
- Step-up authentication for sensitive operations during an active session
- Session termination on critical risk indicators
- Adaptive access controls that tighten or loosen based on real-time risk

## Software-Defined Perimeter (SDP)

**Architecture:**
- SDP Controller: authenticates and authorizes users before granting network access
- SDP Gateway: enforces access to protected resources
- SDP Client: initiates connections through the controller
- Resources are invisible to unauthorized users (dark cloud)

**Single Packet Authorization (SPA):**
- Network services are hidden behind closed ports
- Single cryptographic packet validates client before port opening
- Prevents port scanning and reconnaissance
- Provides first-packet authentication before TCP handshake

**SDP Benefits:**
- Resources are not discoverable on the network
- Mutual TLS between client and gateway
- Dynamic, per-user, per-session network access
- Reduce attack surface by hiding internal infrastructure
- Compatible with hybrid and multi-cloud deployments

## ZTNA Implementation Patterns

**ZTNA 1.0 (Basic):**
- Replaces VPN with identity-aware access
- Per-application access rather than network-level access
- User and device posture assessment at connection time
- Supports cloud-delivered or on-premises deployment

**ZTNA 2.0 (Advanced):**
- Continuous trust verification throughout the session
- Deep application-level inspection and DLP
- Consistent security for all applications (web, non-web, SaaS)
- Adaptive access controls responding to real-time risk
- Integration with SASE (Secure Access Service Edge) architecture

**Implementation Roadmap:**
1. **Phase 1 — Identify:** Catalog users, devices, applications, and data flows
2. **Phase 2 — Protect:** Implement strong identity verification and device posture assessment
3. **Phase 3 — Segment:** Deploy micro-segmentation for critical applications
4. **Phase 4 — Monitor:** Implement continuous monitoring and behavioral analytics
5. **Phase 5 — Automate:** Automate policy enforcement and incident response
6. **Phase 6 — Optimize:** Continuously improve based on data and evolving threats

**Migration Strategy:**
- Start with high-value, high-risk applications
- Run in parallel with existing VPN during transition
- Implement application-by-application migration
- Maintain backward compatibility during transition period
- Measure and report security improvements at each phase
- Train users on new access patterns before cutting over

## Zero Trust for Cloud Environments

**Cloud-Native Zero Trust:**
- Identity-based access replacing network perimeter (VPC is not a trust boundary)
- Service mesh for east-west traffic authentication and authorization
- Cloud IAM with least privilege and just-in-time access
- Workload identity federation eliminating long-lived credentials
- Policy-as-code for infrastructure and security configuration

**Multi-Cloud Zero Trust:**
- Consistent identity plane across cloud providers
- Unified policy management spanning AWS, Azure, GCP
- Cross-cloud workload identity using SPIFFE/SPIRE or cloud-native federation
- Centralized visibility and monitoring across all cloud environments
- Consistent micro-segmentation policies regardless of cloud provider
