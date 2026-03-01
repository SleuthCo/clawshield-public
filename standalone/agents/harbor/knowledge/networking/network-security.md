---
framework: "Network Security"
version: "1.0"
domain: "Security"
agent: "nimbus"
tags: ["networking", "security", "firewall", "waf", "tls", "ddos", "segmentation"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Network Security

Network security in the cloud implements defense in depth from the edge to the individual workload. This document covers security groups, firewalls, WAF configuration, DDoS mitigation, TLS management, and segmentation patterns.

## Security Groups vs NACLs (AWS)

### Security Groups

Security groups are stateful firewalls attached to ENIs (Elastic Network Interfaces). They operate at the instance/ENI level.

**Key Characteristics**:
- **Stateful**: If you allow inbound traffic on port 443, the response traffic is automatically allowed regardless of outbound rules.
- **Allow-only rules**: Security groups only support allow rules. Traffic not explicitly allowed is denied by default.
- **ENI-level**: Applied to individual ENIs (instances, load balancers, Lambda in VPC, RDS, etc.).
- **Self-referencing**: A security group can reference itself, allowing all members to communicate with each other. Common pattern for cluster communication.
- **Cross-group references**: An inbound rule can reference another security group as the source, allowing all instances in that group to access this group. This is the preferred pattern over IP-based rules for intra-VPC traffic.

**Best Practices**:
- Use descriptive names and tags. Include the application, environment, and purpose.
- Avoid overly permissive rules (0.0.0.0/0 on inbound). Restrict to specific source security groups or CIDR ranges.
- Use separate security groups per application tier (web, app, data). Chain them: web SG allows inbound from ALB SG, app SG allows from web SG, data SG allows from app SG.
- Regularly audit security groups for unused or overly permissive rules. Use VPC Reachability Analyzer and Security Hub.

### Network ACLs (NACLs)

NACLs are stateless firewalls applied at the subnet level. They provide an additional layer of defense.

**Key Characteristics**:
- **Stateless**: Inbound and outbound rules are evaluated independently. You must explicitly allow return traffic with ephemeral port rules.
- **Allow and deny rules**: Unlike security groups, NACLs support explicit deny rules.
- **Subnet-level**: Applied to all resources in the subnet.
- **Rule ordering**: Rules are evaluated in order by rule number (lowest first). First matching rule wins. Default rule at the end denies all.
- **Default NACL**: Allows all inbound and outbound traffic. Custom NACLs deny all traffic by default.

**When to Use NACLs**:
- Explicitly blocking known malicious IP ranges at the subnet level
- Implementing subnet-level deny rules that security groups cannot provide
- Meeting compliance requirements for defense-in-depth with multiple firewall layers
- NACLs are a coarse-grained supplementary control. Security groups should be the primary firewall mechanism.

### Azure and GCP Equivalents

- **Azure NSGs (Network Security Groups)**: Stateful, applied to subnets or NICs. Support allow and deny rules with priority ordering. Application Security Groups (ASGs) enable grouping VMs for rule targets without IP management.
- **GCP Firewall Rules**: VPC-level, stateful. Support allow and deny rules. Target by network tags, service accounts, or IP ranges. Firewall Policies provide hierarchical policy management across the organization.

## Cloud Firewall Services

### AWS Network Firewall

Managed stateful firewall for VPC traffic inspection. Deployed in a dedicated firewall subnet.

- **Stateful rules**: 5-tuple rules (source/dest IP, port, protocol), domain list filtering (allow/deny traffic to specific domains), Suricata-compatible IPS rules for deep packet inspection.
- **Stateless rules**: Basic packet filtering before stateful inspection. Use for high-volume simple rules.
- **TLS inspection**: Decrypt and inspect TLS-encrypted traffic with configurable certificate management.
- **Architecture**: Deploy in a dedicated firewall subnet. Route traffic through the firewall using VPC route tables. Integrate with Transit Gateway for centralized inspection of inter-VPC and internet-bound traffic.

### Azure Firewall

Managed stateful firewall for VNet traffic.

- **Standard**: L3-L7 filtering, threat intelligence, FQDN filtering, NAT. Deployed in a hub VNet.
- **Premium**: Adds TLS inspection, IDPS (signature-based intrusion detection), URL filtering, and web categories.
- **Azure Firewall Policy**: Hierarchical policies for multi-hub deployments. Base policy defines organization-wide rules; child policies add application-specific rules.
- **Forced Tunneling**: Route all internet-bound traffic through the firewall for centralized inspection and logging.

### GCP Cloud Firewall

- **VPC Firewall Rules**: Distributed, software-defined firewall applied to every VM. No deployment or management of firewall appliances.
- **Firewall Policies**: Hierarchical policies at organization, folder, or VPC level. Higher-level policies take precedence. Simplifies management at scale.
- **Cloud IDS**: Managed intrusion detection powered by Palo Alto Networks threat detection technology.

## WAF Rules and Patterns

### AWS WAF Rule Groups

- **AWS Managed Rules**: Core Rule Set (CRS) for OWASP Top 10, Known Bad Inputs, SQL injection, XSS, PHP/Linux exploits, and Anonymous IP list.
- **Bot Control**: Detect and manage bot traffic. Targeted protections for credential stuffing and account creation fraud.
- **Rate-Based Rules**: Block IPs exceeding a request threshold within a 5-minute window. Use for brute-force and DDoS mitigation. Rate limits can be scoped by IP, forwarded IP, or custom keys.
- **IP Set Rules**: Allow/block traffic from specific IP ranges. Use for allowlisting known partners or blocklisting known bad actors.
- **Geo-Match Rules**: Allow or block traffic based on country of origin.

### WAF Architecture Patterns

- Deploy WAF on the outermost layer (CloudFront for AWS, Front Door for Azure, Cloud Armor for GCP). Block malicious traffic before it reaches application infrastructure.
- Layer WAF rules: Managed rules for broad protection + custom rules for application-specific patterns + rate-based rules for volumetric attacks.
- Log all WAF decisions to S3 or Log Analytics for analysis. Use regex patterns to reduce false positives.
- Start in count/detection mode for new rules. Monitor false positives before switching to block mode.

### GCP Cloud Armor

- Pre-configured WAF rules for OWASP Top 10
- Custom rules using CEL (Common Expression Language)
- Adaptive Protection: ML-based L7 DDoS detection that automatically suggests rules
- Bot management
- Rate limiting per client IP
- Edge security policies applied at the global load balancer

## DDoS Mitigation

### Multi-Layer Defense

1. **Edge Layer**: CDN absorbs volumetric L3/L4 attacks. CloudFront, Front Door, and Cloud CDN automatically mitigate many attacks.
2. **Network Layer**: AWS Shield Standard (automatic, free), Azure DDoS Protection, GCP Cloud Armor. Protects against SYN floods, UDP reflection, and other L3/L4 attacks.
3. **Application Layer**: WAF rules block L7 attacks (HTTP floods, slowloris, application-specific exploits). Rate-based rules and bot control.
4. **Infrastructure**: Auto-scaling absorbs legitimate traffic surges. Avoid single points of failure.

### AWS Shield Advanced

- Enhanced DDoS protection for EC2, ELB, CloudFront, Global Accelerator, and Route 53
- 24/7 access to AWS DDoS Response Team (DRT) for manual mitigation during attacks
- Cost protection: Credits for scaling charges incurred during a DDoS attack
- Advanced attack diagnostics and near-real-time attack visibility
- Automatic application-layer DDoS mitigation (creates WAF rules automatically)
- WAF included at no additional charge

### Azure DDoS Protection

- **DDoS Network Protection**: Enhanced DDoS protection for VNet resources. Adaptive tuning, attack analytics, rapid response support.
- **DDoS IP Protection**: Per-IP DDoS protection for smaller deployments. Same protection capabilities at lower cost.

## TLS and mTLS

### TLS Best Practices

- **TLS 1.3**: Use TLS 1.3 wherever supported. It provides improved performance (1-RTT handshake, 0-RTT resumption) and stronger security (removed obsolete ciphers). Disable TLS 1.0 and 1.1.
- **TLS 1.2**: Minimum acceptable version for production. Configure strong cipher suites. Prefer ECDHE key exchange and AES-GCM encryption.
- **End-to-End Encryption**: Terminate TLS at the load balancer for simplicity, or re-encrypt from the load balancer to the application for complete encryption in transit.
- **HSTS**: Enable HTTP Strict Transport Security headers to prevent protocol downgrade attacks.
- **OCSP Stapling**: Enable to improve TLS handshake performance by including certificate status in the TLS handshake.

### Mutual TLS (mTLS)

mTLS requires both client and server to present certificates during the TLS handshake. Provides strong authentication for service-to-service communication.

**Implementation Approaches**:
- **Service Mesh**: Istio and Linkerd provide automatic mTLS between all meshed services. No application changes required. Certificates are automatically rotated.
- **API Gateway**: AWS API Gateway, Azure API Management, and GCP API Gateway support mTLS for client authentication.
- **Application-Level**: Application code manages client certificates. More control but higher operational burden.

## Certificate Management

### AWS Certificate Manager (ACM)

- **Public certificates**: Free SSL/TLS certificates for AWS services (ALB, CloudFront, API Gateway). Automatic renewal. Cannot export private keys; usable only with integrated AWS services.
- **Private CA**: Managed private certificate authority for internal services, IoT devices, and user certificates. Costs per CA and per certificate.
- **Import**: Import third-party certificates for use with AWS services. You manage renewal and distribution.

### Let's Encrypt

- Free, automated TLS certificates from a non-profit CA
- 90-day certificate lifetime with automated renewal via ACME protocol
- Tools: Certbot (standalone), cert-manager (Kubernetes), custom ACME clients
- Rate limits: 50 certificates per registered domain per week. Plan for large deployments.

### Kubernetes cert-manager

cert-manager automates certificate management in Kubernetes. It creates, renews, and distributes TLS certificates.

- **Issuers**: ACME (Let's Encrypt), self-signed, CA, Vault, AWS PCA, Venafi, and more
- **Certificate CRD**: Declare the desired certificate (domains, issuer, secret name). cert-manager handles creation and renewal.
- **Ingress Integration**: Annotate Ingress resources to automatically provision certificates for the ingress hosts.
- **CSI Driver**: Mount certificates directly into pods as volumes.

## Network Segmentation

### Macro-Segmentation

Separate workloads into different VPCs, VNets, or VPC networks based on trust boundaries, compliance requirements, and blast radius.

- **Environment Isolation**: Separate VPCs for production, staging, and development. Prevent accidental cross-environment access.
- **Compliance Boundaries**: Separate VPCs for PCI (cardholder data environment), HIPAA (ePHI), and general workloads. Apply stricter controls to regulated VPCs.
- **Team/Application Isolation**: Separate VPCs per team or application for blast radius reduction and independent management.

### Micro-Segmentation

Control traffic at the individual workload level, regardless of network location. Enforce least-privilege network access between services.

**Implementation Approaches**:
- **Security Groups / NSGs**: Fine-grained rules per workload or service. Reference other security groups for dynamic membership.
- **Kubernetes Network Policies**: Control pod-to-pod traffic. Deny by default, allow specific flows. See the container security document for details.
- **Service Mesh Policies**: Istio AuthorizationPolicy and Linkerd Server/ServerAuthorization provide identity-based (not IP-based) micro-segmentation.
- **Cloud-Native Firewalls**: GCP VPC Firewall with network tags, Azure NSGs with Application Security Groups.

### Zero Trust Networking Principles

- Never trust network location as a security boundary. An internal network is not inherently trustworthy.
- Authenticate and authorize every connection. Use mutual TLS for service-to-service communication.
- Encrypt all traffic, even within the private network. TLS everywhere.
- Segment access based on identity and context, not IP addresses.
- Continuously monitor and log all network access for anomaly detection.
- Implement least-privilege network access: services should only be able to reach the specific services they need.

## VPC Flow Logs and Network Monitoring

### AWS VPC Flow Logs

- Capture IP traffic information for network interfaces, subnets, or entire VPCs
- Publish to CloudWatch Logs, S3, or Kinesis Data Firehose
- Use for: security analysis (detect anomalous traffic patterns), troubleshooting connectivity issues, compliance auditing
- Custom log formats to capture specific fields (srcaddr, dstaddr, srcport, dstport, action, bytes, packets, tcp-flags)
- Traffic mirroring for full packet capture (specific instances, not VPC-wide)

### Azure Network Watcher

- NSG Flow Logs: Capture traffic information for NSGs. Traffic Analytics provides visual analysis.
- Connection Monitor: End-to-end connectivity monitoring between sources and destinations.
- IP Flow Verify: Test if a packet is allowed or denied to/from a VM.
- Next Hop: Determine the next hop for traffic from a VM.
- Packet Capture: Capture packets on VMs for deep analysis.

### GCP VPC Flow Logs

- Capture a sample (configurable rate) of network flows to/from VM instances
- Publish to Cloud Logging for analysis and export to BigQuery for queries
- Metadata annotations include VM name, zone, project, and VPC details
- Firewall Rules Logging: Log every firewall rule evaluation for compliance and debugging
- Packet Mirroring: Full packet capture for network appliances and IDS/IPS
