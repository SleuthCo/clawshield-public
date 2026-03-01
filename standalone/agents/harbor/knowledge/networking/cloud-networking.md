---
framework: "Cloud Networking"
version: "1.0"
domain: "Networking"
agent: "nimbus"
tags: ["networking", "vpc", "subnets", "transit-gateway", "vpn", "dns", "load-balancing", "cdn"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Cloud Networking

Cloud networking is foundational to every workload. This document covers VPC design, subnetting strategies, hybrid connectivity, private access patterns, DNS architecture, load balancing, and CDN patterns across AWS, Azure, and GCP.

## VPC Design Principles

### IP Address Planning

IP address planning is often the most consequential networking decision and the hardest to change after deployment.

- **Plan for the entire organization**: Allocate non-overlapping CIDR blocks across all VPCs, accounts, on-premises networks, and partner networks. Overlapping ranges prevent peering, VPN, and transit gateway connectivity.
- **Use large VPC CIDRs**: Start with /16 for production VPCs. IP addresses are free; running out of addresses requires painful re-architecting. It is far better to have unused addresses than to be constrained.
- **Reserve ranges**: Allocate non-overlapping blocks per region, per environment, per account. Document the allocation in a central IPAM system or spreadsheet.
- **RFC 1918 ranges**: Use 10.0.0.0/8, 172.16.0.0/12, or 192.168.0.0/16. The 10.0.0.0/8 block provides the most addresses and is most commonly used for cloud deployments.
- **Consider 100.64.0.0/10 (CGNAT range)**: Useful when RFC 1918 space is exhausted, but verify compatibility with your services and connectivity requirements.

### Subnet Strategy

- **Public subnets**: Resources with direct internet access (load balancers, NAT gateways, bastion hosts). Route table includes a route to an internet gateway. Minimize resources in public subnets.
- **Private subnets (application)**: Application workloads (EC2, ECS, EKS, Lambda in VPC). Route table includes a route to a NAT gateway for outbound internet access. No inbound internet access.
- **Private subnets (data)**: Databases, caches, and storage. No internet access at all (no NAT gateway route). Access only from application subnets.
- **Distribute across Availability Zones**: Create each subnet type in at least 2, preferably 3 AZs for high availability. Use equal-sized subnets per AZ.

### Subnet Sizing

For a /16 VPC with 3 AZs:
- Public subnets: /24 each (251 usable IPs per AZ, 753 total). Sufficient for load balancers and NAT gateways.
- Private application subnets: /20 each (4,091 usable IPs per AZ, 12,273 total). Large enough for container workloads.
- Private data subnets: /22 each (1,019 usable IPs per AZ, 3,057 total). Sufficient for databases and caches.
- Reserve remaining space for future growth, additional subnet tiers, or Kubernetes pod networking.

## Transit Gateway (AWS)

AWS Transit Gateway acts as a hub that connects VPCs, VPN connections, Direct Connect gateways, and transit gateway peering attachments.

### Architecture Patterns

- **Hub-and-Spoke**: Transit Gateway as the central hub. All VPCs (spokes) connect to the Transit Gateway. Route tables control which VPCs can communicate. Simplest model for most organizations.
- **Segmented Routing**: Use multiple route tables on the Transit Gateway to create network segments (production, non-production, shared services). VPCs in different segments cannot route to each other unless explicitly allowed.
- **Inter-Region**: Use Transit Gateway peering to connect Transit Gateways in different regions. Enables multi-region architectures with centralized routing.

### Best Practices

- Use separate Transit Gateway route tables for network segmentation
- Enable default route table association for simplicity, or use custom associations for fine-grained control
- Enable route propagation from VPN and Direct Connect attachments
- Use blackhole routes to explicitly block traffic between segments
- Monitor with VPC Flow Logs and Transit Gateway Flow Logs

## Hybrid Connectivity

### AWS Direct Connect

Dedicated physical connection from on-premises to AWS (1 Gbps, 10 Gbps, or 100 Gbps ports). Provides consistent network performance, reduced bandwidth costs, and private connectivity to all AWS services.

- **Dedicated Connections**: Physical port allocated at a Direct Connect location. Requires colocation or partner cross-connect. 1/10/100 Gbps.
- **Hosted Connections**: Sub-1G connections through a Direct Connect Partner. 50 Mbps to 10 Gbps.
- **Virtual Interfaces (VIFs)**: Public VIF (access AWS public services), Private VIF (access VPC resources), Transit VIF (access Transit Gateway).
- **Resilience**: Use two connections at different Direct Connect locations for high availability. Use Direct Connect SiteLink for site-to-site connectivity through AWS backbone.

### Azure ExpressRoute

Private connection from on-premises to Azure through a connectivity partner. Similar to Direct Connect.

- **Peering Types**: Azure Private Peering (access VNets), Microsoft Peering (access Microsoft 365 and Azure public services).
- **SKUs**: Local (same metro, unlimited egress), Standard (regional access), Premium (global access).
- **Global Reach**: Connect on-premises sites through ExpressRoute circuits and Azure backbone.
- **FastPath**: Bypass the ExpressRoute gateway for improved data path performance to VMs.

### GCP Cloud Interconnect

- **Dedicated Interconnect**: Physical connection from on-premises to Google's network. 10 Gbps or 100 Gbps.
- **Partner Interconnect**: Connection through a service provider. 50 Mbps to 50 Gbps.
- **Cross-Cloud Interconnect**: Direct connection between Google Cloud and another cloud provider (AWS, Azure, Oracle) through Google's network.

### VPN

VPN provides encrypted connectivity over the public internet. Lower cost than dedicated connections but with variable performance.

- **AWS Site-to-Site VPN**: IPsec VPN over the internet. Up to 1.25 Gbps per tunnel, 2 tunnels per VPN connection. Use with Transit Gateway for scalable VPN architectures. Accelerated VPN uses AWS Global Accelerator for improved performance.
- **Azure VPN Gateway**: IPsec VPN. VpnGw1-VpnGw5 SKUs with increasing throughput (up to 10 Gbps). Zone-redundant SKUs for availability.
- **GCP Cloud VPN**: HA VPN with two tunnels for 99.99% SLA. Classic VPN (single tunnel, 99.9% SLA, being deprecated).

## Private Connectivity to Cloud Services

### AWS PrivateLink and VPC Endpoints

- **Gateway Endpoints**: For S3 and DynamoDB. Free. Route table entry directs traffic to the service endpoint within the VPC.
- **Interface Endpoints (PrivateLink)**: For 100+ AWS services. Creates an ENI with a private IP in your subnet. Traffic stays on the AWS network, never traverses the internet. Per-endpoint and per-GB charges apply.
- **PrivateLink for Custom Services**: Expose your service behind a Network Load Balancer. Consumers create an interface endpoint to connect. Cross-account and cross-VPC service sharing without VPC peering.

### Azure Private Link

- **Private Endpoints**: Create a private IP for Azure PaaS services (Storage, SQL, Key Vault, etc.) in your VNet. Disable public access on the service. Traffic stays on the Microsoft backbone.
- **Private Link Service**: Expose your own service (behind a Standard Load Balancer) for private consumption by other VNets and subscriptions.

### GCP Private Service Connect

- **Consumer PSC Endpoints**: Create an internal IP for Google APIs or published services in your VPC. Traffic stays on Google's network.
- **Producer Services**: Publish services on a Service Attachment for consumers in other projects or organizations.

## DNS Architecture

### AWS Route 53

- **Public Hosted Zones**: Authoritative DNS for public domains. Anycast network for low-latency resolution worldwide.
- **Private Hosted Zones**: DNS resolution within VPCs. Associate with multiple VPCs across accounts.
- **Routing Policies**: Simple (round-robin), Weighted (A/B testing, gradual migration), Latency-based (route to nearest region), Failover (active-passive DR), Geolocation (country/continent-based), Geoproximity (distance-based with bias), Multivalue Answer (up to 8 healthy records).
- **Route 53 Resolver**: DNS resolution between VPCs and on-premises networks. Inbound endpoints for on-premises to resolve AWS private DNS. Outbound endpoints for VPC to resolve on-premises DNS. Resolver rules to forward queries for specific domains.
- **DNSSEC**: Enable DNSSEC signing for public hosted zones to protect against DNS spoofing.

### Azure DNS

- **Public DNS Zones**: Authoritative DNS for public domains. Anycast resolution.
- **Private DNS Zones**: DNS resolution within VNets. Auto-registration of VM records.
- **Azure DNS Private Resolver**: Enables conditional forwarding between Azure and on-premises DNS. Replaces DNS forwarder VMs. Inbound and outbound endpoints.

### GCP Cloud DNS

- **Public Zones**: Authoritative DNS. 100% SLA with anycast.
- **Private Zones**: Resolution within VPC networks. Cross-project sharing via DNS peering.
- **Cloud DNS Policies**: Inbound and outbound server policies for hybrid DNS resolution.

## Load Balancing Patterns

### AWS Elastic Load Balancing

- **Application Load Balancer (ALB)**: Layer 7 (HTTP/HTTPS). Path-based and host-based routing. WebSocket support. gRPC support. Integration with WAF, Cognito (authentication), and Lambda targets. Best for web applications and microservices.
- **Network Load Balancer (NLB)**: Layer 4 (TCP/UDP/TLS). Ultra-low latency. Static IP addresses. Preserves source IP. Best for non-HTTP workloads, extreme performance, and PrivateLink service endpoints.
- **Gateway Load Balancer (GWLB)**: Layer 3 (IP). Routes traffic through third-party virtual appliances (firewalls, IDS/IPS). Uses GENEVE encapsulation. Best for deploying network security appliances at scale.

### Azure Load Balancing

- **Azure Front Door**: Global Layer 7 load balancer with WAF, CDN, and DDoS protection. Anycast for global reach. Best for global web applications.
- **Azure Application Gateway**: Regional Layer 7 load balancer with WAF. Path-based routing, SSL termination, session affinity. Best for regional web applications.
- **Azure Load Balancer**: Layer 4. Standard SKU supports availability zones, outbound rules, and HA ports. Best for non-HTTP workloads.
- **Azure Traffic Manager**: DNS-based global traffic distribution. Supports priority, weighted, performance, geographic, and multivalue routing.

### GCP Cloud Load Balancing

- **External Application Load Balancer (Global)**: Global anycast Layer 7. URL map routing, Cloud CDN, Cloud Armor. Best for global web applications.
- **External Proxy Network Load Balancer (Global/Regional)**: Layer 4 TCP/SSL proxy. Global anycast option. Best for non-HTTP global services.
- **External Passthrough Network Load Balancer (Regional)**: Layer 4 passthrough. Preserves client IP. Best for UDP workloads or when client IP preservation is required.
- **Internal Application Load Balancer**: Layer 7 for internal services. Supports cross-region for multi-region internal traffic distribution.
- **Internal Passthrough Network Load Balancer**: Layer 4 for internal TCP/UDP services.

## Content Delivery Network (CDN)

### AWS CloudFront

- Global CDN with 400+ edge locations. Integrates with S3, ALB, EC2, Lambda@Edge, CloudFront Functions, and custom origins.
- **Cache Behaviors**: URL path patterns with different caching rules, origins, and settings per behavior.
- **Lambda@Edge**: Run Lambda functions at edge locations for request/response manipulation. Use cases: URL rewriting, authentication, A/B testing, dynamic content generation.
- **CloudFront Functions**: Lightweight functions at edge for simple request/response processing (header manipulation, URL redirects, cache key normalization). Lower latency and cost than Lambda@Edge.
- **Origin Shield**: Additional caching layer to reduce load on origins.

### Azure Front Door / Azure CDN

- Azure Front Door combines global load balancing, WAF, and CDN in a single service. Rules engine for request/response manipulation.
- Azure CDN (Standard from Microsoft, Verizon, Akamai): Traditional CDN for static content caching.

### GCP Cloud CDN

- Integrated with the External Application Load Balancer. Automatic cache fill from origin.
- Signed URLs and signed cookies for access-controlled content.
- Cache invalidation API for on-demand content refresh.
- Media CDN: Specialized CDN for video streaming workloads with high throughput and adaptive bitrate support.
