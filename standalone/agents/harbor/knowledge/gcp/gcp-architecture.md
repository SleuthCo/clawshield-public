---
framework: "GCP Architecture"
version: "1.0"
domain: "Cloud Architecture"
agent: "nimbus"
tags: ["gcp", "architecture", "vpc", "gke", "cloud-run", "bigquery", "spanner"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# GCP Architecture

Google Cloud Platform organizes resources in a hierarchical structure with distinct networking, compute, and data services. This document covers resource hierarchy, network design, compute patterns, and data platform architecture.

## Resource Hierarchy

GCP uses a hierarchical structure for organizing and governing resources. Understanding this hierarchy is essential because IAM policies and organization policies are inherited downward.

### Hierarchy Levels

1. **Organization**: Root node tied to a Google Workspace or Cloud Identity domain. All resources in the organization are children of this node. Organization-level IAM and Organization Policies apply to everything beneath.
2. **Folders**: Optional grouping mechanism under the Organization. Can be nested (up to 10 levels). Common structures: by environment (prod, staging, dev), by department (engineering, finance, marketing), or by application. Used to apply IAM and policies to groups of projects.
3. **Projects**: Fundamental organizing entity for GCP resources. All resources (VMs, databases, storage buckets) belong to exactly one project. Projects have a unique project ID (globally unique, immutable), project number (system-generated), and display name. Billing is tracked at the project level.
4. **Resources**: Individual GCP services and components within a project.

### Hierarchy Design Best Practices

- Use folders to mirror your organizational structure or application portfolio
- Apply IAM at the folder level for broad access patterns, refine at project level
- Create separate projects for different environments (prod, staging, dev) to enforce isolation
- Use a shared services project for centralized resources (DNS, logging, monitoring)
- Use a network host project for Shared VPC to centralize network management
- Implement a project factory (Terraform module or Cloud Foundation Toolkit) to standardize project creation with consistent settings, APIs, and baseline policies

## VPC Design

GCP VPCs are global resources that span all regions. Subnets are regional resources within a VPC. This global VPC model simplifies multi-region networking compared to other clouds.

### VPC Networking Fundamentals

- **Global VPC**: A single VPC can have subnets in any GCP region. Resources in different regions but the same VPC can communicate over Google's private backbone network without additional configuration.
- **Subnets**: Regional. Define IP ranges using CIDR notation. Each subnet maps to a single region but can have resources across all zones in that region.
- **IP Addressing**: Primary IP ranges for VM instances. Alias IP ranges for containers and multi-IP configurations. Secondary ranges for GKE pod and service IPs.
- **Firewall Rules**: Stateful, applied at the VPC level. Support target tags, target service accounts, source/destination IP ranges, and protocols/ports. Priority-based evaluation (0-65535, lower number = higher priority).
- **Routes**: System-generated default route to the internet gateway. Custom routes for VPN, interconnect, and custom next-hop targets. Policy-based routing for advanced scenarios.

### Shared VPC

Shared VPC allows a host project to share its VPC network with service projects. This centralizes network management while allowing project-level resource isolation.

- **Host Project**: Owns the VPC, subnets, firewall rules, VPN/Interconnect connections, and Cloud NAT. Managed by the network team.
- **Service Projects**: Attached to the host project. Resources in service projects use subnets from the host project VPC. Application teams manage their own resources but use centrally managed networking.
- **IAM Considerations**: Service project users need `compute.networkUser` role on specific subnets (not the entire host project) for least privilege.

### VPC Design Patterns

- **Hub-and-Spoke**: Central hub VPC connected to spoke VPCs via VPC peering. Hub hosts shared services (DNS, NVAs, jump hosts). Spokes host application workloads. Note: GCP VPC peering is non-transitive; use Network Connectivity Center or NVAs for spoke-to-spoke traffic through the hub.
- **Shared VPC (Recommended)**: Single VPC shared across projects. Simplest model. Centralized network management with delegated resource management. Preferred for most organizations.
- **Multi-VPC with Peering**: Separate VPCs for strong isolation. Use VPC peering for connectivity. Each VPC is independently managed. Use when teams need full network autonomy.

### Private Google Access

Resources without external IP addresses can access Google APIs and services through Private Google Access. Enable it on subnets where private instances need to reach services like Cloud Storage, BigQuery, or Artifact Registry. For enhanced security, use Private Service Connect to create private endpoints for Google APIs within your VPC.

## GKE Patterns

Google Kubernetes Engine is the managed Kubernetes service with deep GCP integration.

### Cluster Modes

- **Standard Mode**: Full control over node configuration and management. You manage node pools, OS images, machine types, and node auto-provisioning settings. Use when you need custom node configurations.
- **Autopilot Mode**: Google manages the nodes entirely. You only define pod specifications. Automatic scaling, security hardening, and resource optimization. Per-pod billing. Recommended for most workloads. Enforces security best practices by default (no privileged pods, no host network).

### Networking Modes

- **VPC-Native (Alias IP)**: Pods receive IP addresses from VPC secondary ranges. Required for Shared VPC, Private Google Access for pods, network policies, and most GKE features. Default and recommended.
- **Routes-Based (Legacy)**: Pods receive IPs from a GKE-managed range. Custom routes propagated to the VPC. Legacy mode with limitations.

### GKE Architecture Best Practices

- Use private clusters (nodes have only internal IP addresses, control plane has a private endpoint)
- Enable Workload Identity for pod-to-GCP-service authentication (maps Kubernetes service accounts to IAM service accounts)
- Use Gateway API (successor to Ingress) for traffic management and load balancing
- Enable Binary Authorization to enforce only trusted container images
- Use GKE Dataplane V2 (based on Cilium/eBPF) for enhanced networking, network policy enforcement, and observability
- Configure maintenance windows to control when automatic upgrades occur
- Use release channels (Rapid, Regular, Stable) to manage version upgrades. Stable is recommended for production.
- Implement pod disruption budgets (PDBs) to maintain availability during voluntary disruptions

### Multi-Cluster Patterns

- **Multi-Cluster Ingress (MCI)**: Single global load balancer routes traffic to pods across multiple GKE clusters in different regions. Provides geographic load balancing and failover.
- **Fleet Management**: Register clusters (GKE, on-premises, other clouds) as fleet members. Apply fleet-wide policies, manage team scopes, and use Config Sync for GitOps at fleet scale.
- **Anthos Service Mesh**: Managed Istio-based service mesh across fleet clusters. Provides mTLS, traffic management, and observability across clusters.

## Cloud Run

Cloud Run is a fully managed serverless container platform. Deploy any container that listens for HTTP requests or processes events.

### Key Characteristics

- Scale to zero and from zero (pay only when handling requests or events)
- Automatic scaling up to configurable maximum instances
- Per-request concurrency (default 80 concurrent requests per instance, configurable up to 1000)
- Built on Knative, runs on GKE internally
- Supports custom domains, VPC connectivity, and Cloud SQL connections
- Second-generation execution environment provides full Linux compatibility (file system access, all system calls)

### When to Use Cloud Run

- Stateless HTTP services (APIs, web applications, webhooks)
- Event-driven processing (Pub/Sub push, Eventarc triggers, Cloud Storage events)
- Scheduled jobs (Cloud Scheduler triggering Cloud Run jobs)
- Teams that want container portability without Kubernetes complexity
- Workloads with variable traffic patterns that benefit from scale-to-zero

### Cloud Run vs GKE vs Cloud Functions

- **Cloud Run**: Best for containerized HTTP services with variable traffic. No cluster management. Container-native (any language, any library).
- **GKE**: Best for complex microservice architectures needing full Kubernetes features, stateful workloads, GPU workloads, or custom networking.
- **Cloud Functions (2nd gen)**: Best for simple event-driven functions. Built on Cloud Run internally. Simpler developer experience for single-function workloads. Source-code deployment model.

## Cloud Functions

Cloud Functions 2nd generation is built on Cloud Run and Cloud Build, providing the same underlying infrastructure with a source-code-first developer experience.

### Triggers

- **HTTP**: Direct HTTP invocation with a unique URL
- **Eventarc**: Cloud Storage events, Pub/Sub messages, Firestore changes, Firebase events, Audit Log events (any GCP service), custom events
- **Pub/Sub**: Direct Pub/Sub topic trigger (legacy, use Eventarc for new functions)

### Key Differences (1st gen vs 2nd gen)

- 2nd gen supports longer timeouts (up to 60 minutes vs 9 minutes), larger instances (up to 32 GiB memory, 8 vCPUs), concurrency (up to 1000 per instance vs 1), traffic splitting, and minimum instances.

## BigQuery Architecture

BigQuery is a serverless, petabyte-scale data warehouse with built-in ML, geospatial analysis, and BI.

### Architecture Concepts

- **Slots**: Units of computational capacity for executing SQL queries. On-demand pricing allocates up to 2,000 slots per project (burstable). Editions pricing (Standard, Enterprise, Enterprise Plus) provides committed or autoscaled slot capacity.
- **Storage**: Columnar storage (Capacitor format) with automatic compression, encryption, and replication. Active storage (modified in last 90 days) billed at a higher rate than long-term storage.
- **Datasets**: Containers for tables, views, and functions. Regional (single region) or multi-regional (US, EU). Cannot span regions.
- **Reservations**: Dedicated slot capacity for predictable performance and cost. Assign reservations to projects or folders. Use autoscaling to handle bursts beyond baseline capacity.

### Design Patterns

- **Star Schema / Denormalization**: BigQuery performs best with denormalized (flat) or star schema data. Avoid excessive normalization that requires many JOINs. Use nested and repeated fields (STRUCT and ARRAY) instead of child tables.
- **Partitioning**: Partition tables by ingestion time, date/timestamp column, or integer range. Dramatically reduces query cost and improves performance by scanning only relevant partitions. Require partition filters in queries.
- **Clustering**: Order data within partitions by up to four columns. Improves filter and aggregation performance on clustered columns. Free to use; no additional storage cost.
- **Materialized Views**: Pre-computed views that BigQuery automatically maintains. Queries are transparently rewritten to use materialized views when beneficial. Useful for common aggregations.
- **BI Engine**: In-memory analysis service for sub-second query response. Reserve BI Engine capacity in a specific region. Automatically accelerates queries from connected BI tools (Looker, Data Studio, Tableau).

## Cloud Spanner

Spanner is a fully managed, globally distributed, strongly consistent relational database. It combines the benefits of relational structure with horizontal scalability.

### Architecture

- Spanner distributes data across splits (shards) automatically. Each split is replicated across zones (regional) or regions (multi-region). Paxos consensus protocol ensures strong consistency.
- Nodes provide compute capacity. Each node can handle approximately 10,000 reads/second or 2,000 writes/second (varies by workload and row size).
- Processing units (PUs) are fine-grained compute units (100 PUs = 1 node) for smaller workloads.

### Design Best Practices

- **Primary Key Design**: Avoid monotonically increasing keys (auto-increment, timestamps) as the primary key prefix. This creates hotspots. Use UUIDv4, bit-reversed sequential IDs, or application-meaningful keys that distribute writes evenly.
- **Interleaved Tables**: Parent-child table relationships where child rows are physically co-located with their parent row. Dramatically improves read performance for parent-child queries. Use for one-to-many relationships that are frequently queried together.
- **Secondary Indexes**: Use sparingly. Each index adds write overhead. Use storing clauses to create covering indexes that avoid reading the base table.
- **Multi-Region Configurations**: Choose between regional (3 zones in one region, lowest latency), dual-region (2 regions, read-write in primary, read-only in secondary), and multi-region (configurable read-write and read-only replicas across continents, 99.999% SLA).

## Multi-Region Design

### Global Load Balancing

GCP's Cloud Load Balancing is a global, anycast-based service. A single global IP address routes traffic to the nearest healthy backend across regions. Key load balancer types:

- **External Application Load Balancer (Global)**: HTTP/HTTPS traffic. URL map routing, SSL termination, Cloud CDN integration, Cloud Armor (WAF/DDoS) integration. Routes to GCE, GKE, Cloud Run, serverless NEGs.
- **External Proxy Network Load Balancer (Global)**: TCP/SSL traffic. For non-HTTP workloads needing global reach.
- **Internal Application Load Balancer (Regional/Cross-Region)**: Internal HTTP/HTTPS traffic between services.
- **External/Internal Passthrough Network Load Balancer (Regional)**: Layer 4, passthrough (preserves client IP). For UDP, TCP non-proxy, or protocol-preserving scenarios.

### Multi-Region Data Strategies

- **Cloud Spanner multi-region**: Strongly consistent across regions with 99.999% SLA
- **Cloud SQL cross-region read replicas**: Asynchronous replication for read scaling; manual failover for DR
- **Firestore multi-region**: Automatic multi-region replication within a multi-region location (nam5, eur3)
- **Cloud Storage dual-region and multi-region**: Automatic replication with turbo replication option (15-minute RPO) for dual-region
- **BigQuery cross-region dataset copies**: Use BigQuery Data Transfer Service or scheduled queries to replicate data between regions
- **Memorystore (Redis) cross-region replication**: Active-passive replication for cache failover
