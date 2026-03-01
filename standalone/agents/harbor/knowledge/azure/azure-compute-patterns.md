---
framework: "Azure Compute Patterns"
version: "1.0"
domain: "Cloud Compute"
agent: "nimbus"
tags: ["azure", "compute", "vms", "aks", "container-apps", "functions", "app-service"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Azure Compute Patterns

Azure provides a wide range of compute services from IaaS virtual machines to fully managed serverless platforms. Selecting the right service depends on the workload characteristics, team expertise, operational requirements, and cost constraints.

## Azure Virtual Machines

### VM Family Categories

- **General Purpose (B, D, DC)**: B-series for burstable workloads with variable CPU needs (development, small web servers). D-series (Dv5, Dav5, Dasv5) for balanced compute and memory suitable for most production workloads. DC-series for confidential computing with SGX enclaves.
- **Compute Optimized (F)**: Fv2-series for compute-intensive workloads: batch processing, gaming, scientific simulations, analytics. High CPU-to-memory ratio.
- **Memory Optimized (E, M, Mv2)**: E-series for in-memory databases, caching, analytics. M-series for very large in-memory workloads (SAP HANA). Mv2-series for the largest memory configurations (up to 11.4 TiB).
- **Storage Optimized (L)**: Lsv3-series with high throughput local NVMe storage for NoSQL databases (Cassandra, Couchbase), data warehousing, large transactional databases.
- **GPU (N)**: NC-series for CUDA compute workloads (ML training). ND-series for deep learning training (InfiniBand interconnect). NV-series for GPU-accelerated visualization and remote desktops.
- **HPC (H, HB, HC)**: High-performance computing with InfiniBand networking. HBv4 for memory-bandwidth-sensitive HPC. HCv1 for compute-intensive HPC.
- **Confidential (DC, EC)**: Hardware-based trusted execution environments for processing sensitive data. DCsv3 with Intel SGX. ECasv5 with AMD SEV-SNP.

### ARM-Based VMs (Ampere Altra)

Dpsv5 and Epsv5 series use Ampere Altra ARM processors, offering up to 50% better price-performance for Linux workloads compared to x86 equivalents. Suitable for web servers, application servers, microservices, small-to-medium databases, and CI/CD agents.

### VM Availability Options

- **Availability Sets**: Distribute VMs across fault domains (different racks) and update domains (rolling update isolation) within a single datacenter. Legacy approach. Provides 99.95% SLA.
- **Availability Zones**: Physically separate locations within an Azure region with independent power, cooling, and networking. Deploy VMs across zones for higher availability. Provides 99.99% SLA.
- **Virtual Machine Scale Sets (VMSS)**: Automatically create and manage a group of identical VMs. Supports auto-scaling, rolling upgrades, and both availability sets and availability zones. Flex orchestration mode is recommended for new deployments.

### Spot VMs

Azure Spot VMs use surplus capacity at up to 90% discount. Azure can evict Spot VMs when capacity is needed or the price exceeds your maximum.

- **Eviction Policies**: Stop/Deallocate (preserves the VM for restart when capacity returns) or Delete (removes the VM entirely).
- **Best Workloads**: Batch processing, CI/CD agents, dev/test environments, stateless web tiers, big data analytics, rendering.
- **VMSS Integration**: Mix regular and Spot VMs in a scale set. Set a maximum price or use -1 to pay up to the on-demand price.

## Azure Kubernetes Service (AKS)

AKS is the managed Kubernetes service. The control plane is free; you pay only for the worker nodes.

### Architecture Patterns

- **Single Cluster, Multi-Namespace**: Use for small to medium workloads. Isolate environments or teams with namespaces, network policies, and RBAC. Simplest operational model.
- **Multi-Cluster**: Use for strict isolation (compliance, blast radius), multi-region deployments, or very large workloads. Manage with Azure Fleet Manager or GitOps.
- **Hub-Spoke**: Central hub cluster for shared services (monitoring, ingress, service mesh) with spoke clusters for workloads. Connected via virtual network peering.

### Key Features

- **Node Pools**: Multiple node pools per cluster with different VM sizes, OS (Linux, Windows), and scaling configurations. Use system node pools for core components and user node pools for workloads. Use node taints and tolerations for workload placement.
- **Cluster Autoscaler**: Automatically adjusts the number of nodes in a node pool based on pending pod scheduling. Configure min/max node counts.
- **KEDA (Kubernetes Event-Driven Autoscaling)**: Scale pods based on event sources (Azure Service Bus queue depth, Kafka lag, HTTP requests, cron schedules). Integrated as an AKS add-on.
- **Azure CNI Overlay**: Pods get IPs from a private CIDR separate from the VNet, reducing IP address consumption. Recommended for large clusters.
- **Workload Identity**: Federated identity credentials linking Kubernetes service accounts to Entra ID managed identities for Azure resource access. Replaces pod-managed identity.
- **Azure Policy for AKS**: Enforce governance policies on Kubernetes resources using Azure Policy (backed by OPA Gatekeeper). Prevent privileged containers, enforce resource limits, restrict image registries.

### AKS Best Practices

- Use availability zones for node pools to survive zone failures
- Enable cluster autoscaler with appropriate min/max bounds
- Use managed identities (not service principals) for cluster identity
- Enable Defender for Containers for vulnerability scanning and runtime protection
- Use private clusters (API server not exposed to public internet) for production
- Implement network policies (Calico or Azure Network Policy) for pod-to-pod traffic control
- Use Azure Container Registry (ACR) with managed identity integration for image pulling

## Azure Container Apps

Container Apps is a fully managed serverless container platform built on Kubernetes (internally runs on AKS) and Dapr. It abstracts away the Kubernetes complexity.

### When to Use Container Apps

- Microservices that need HTTP ingress, service-to-service invocation, or event-driven processing
- Teams that want container-based hosting without Kubernetes operational overhead
- Applications that benefit from Dapr building blocks (state management, pub/sub, service invocation, secrets)
- Workloads with variable traffic that benefit from scale-to-zero
- Background processing jobs triggered by events (queue messages, schedule)

### Key Capabilities

- **Revisions**: Immutable snapshots of a container app version. Traffic splitting across revisions for blue/green and canary deployments.
- **Scaling Rules**: Scale based on HTTP traffic, TCP connections, CPU/memory utilization, and KEDA-supported event sources (Azure Queue, Service Bus, Kafka, custom metrics). Scale to zero when idle.
- **Dapr Integration**: Built-in Dapr sidecar for service invocation, state management, pub/sub messaging, input/output bindings, secrets management, and distributed tracing.
- **Managed Environment**: Container apps within the same environment share a virtual network and Log Analytics workspace. Provides service discovery via DNS-based naming.
- **Jobs**: Long-running or scheduled processing tasks. Supports manual trigger, schedule (cron), and event-driven trigger types.

### Container Apps vs AKS Decision

Use Container Apps when: you want minimal operational overhead, your workloads fit the supported patterns, you value scale-to-zero, and you do not need direct Kubernetes API access or custom operators.

Use AKS when: you need full Kubernetes control, require custom operators or CRDs, need Windows containers, have GPU workloads, need specialized networking (service mesh, custom CNI), or have an existing Kubernetes investment.

## Azure Functions

Azure Functions is the serverless compute service for event-driven workloads. Functions execute in response to triggers and can bind to input/output data sources.

### Hosting Plans

- **Consumption Plan**: Scale to zero, pay per execution (invocation count + execution time + memory). Cold start latency applies. Max 5-minute default timeout (configurable to 10 minutes). Best for sporadic, unpredictable workloads.
- **Flex Consumption Plan**: Newest plan. Combines scale-to-zero with always-ready instances and VNet integration. Supports per-function scaling and instance memory configuration. Addresses cold start without full Premium plan cost.
- **Premium Plan**: Pre-warmed instances eliminate cold starts. VNet integration for accessing private resources. Unlimited execution duration. Higher memory/CPU options. Min 1 instance (always warm). Best for latency-sensitive or VNet-connected workloads.
- **Dedicated (App Service) Plan**: Run on existing App Service Plan. No auto-scaling (use App Service scaling rules). Useful when you have spare App Service capacity or need deterministic pricing.
- **Container Apps Hosting**: Host Functions on Container Apps for container-based deployment with KEDA scaling. Useful for teams standardizing on Container Apps.

### Durable Functions

Durable Functions extends Azure Functions with stateful orchestration patterns:

- **Function Chaining**: Execute a sequence of functions in a specific order, passing output to the next function
- **Fan-Out/Fan-In**: Execute multiple functions in parallel and wait for all to complete
- **Async HTTP API**: Implement long-running operations with polling endpoints
- **Monitor**: Implement recurring processes with flexible intervals (polling a resource until a condition is met)
- **Human Interaction**: Approval workflows with timeout handling

### Best Practices

- Keep functions focused and small (single responsibility)
- Use dependency injection for testability and shared service instances (HttpClient, database connections)
- Implement idempotency since functions may be retried on failure
- Use managed identities for accessing Azure resources
- Configure appropriate retry policies per trigger type
- Monitor with Application Insights (auto-instrumented in Azure Functions)

## Azure App Service

App Service is the fully managed platform for hosting web applications, RESTful APIs, and mobile backends.

### Key Features

- **Deployment Slots**: Create staging slots for zero-downtime deployments. Swap slots to promote staging to production. Slot settings allow environment-specific configuration.
- **Auto-Scale**: Scale out/in based on metrics (CPU, memory, HTTP queue length) or schedules. Up to 30 instances on Premium plans, 100 on Isolated plans.
- **VNet Integration**: Connect App Service to a VNet for accessing private resources (databases, storage, on-premises via VPN/ExpressRoute). Regional VNet integration is the recommended approach.
- **Custom Domains and TLS**: Map custom domains. App Service Managed Certificates provide free TLS certificates. Use Azure Key Vault for bring-your-own certificates.
- **App Service Environment (ASE) v3**: Fully isolated, single-tenant deployment for compliance and high-scale requirements. Deploys into your VNet with private inbound and outbound addresses.

### App Service Plan Tiers

- **Free/Shared**: Development and testing only. Shared infrastructure, no SLA, limited features.
- **Basic**: Dedicated compute. Manual scaling up to 3 instances. No deployment slots, no auto-scale. Entry point for production-capable workloads.
- **Standard**: Auto-scale up to 10 instances, deployment slots, VNet integration, custom domains with SSL.
- **Premium (P1v3, P2v3, P3v3)**: Enhanced performance, up to 30 instances, more deployment slots, zone redundancy option.
- **Isolated (ASE v3)**: Single-tenant, fully isolated, VNet-deployed, up to 100 instances. For compliance-heavy workloads.

## Scaling Patterns Across Services

### Horizontal Scaling

- **VMSS**: Auto-scale based on metrics (CPU, memory, custom metrics), schedule, or predictive scaling. Multi-zone for availability.
- **AKS**: Horizontal Pod Autoscaler for pods, Cluster Autoscaler for nodes, KEDA for event-driven scaling.
- **Container Apps**: HTTP, TCP, and KEDA-based scaling with scale-to-zero capability.
- **Functions**: Automatic scaling per plan type. Consumption and Flex Consumption scale per function. Premium scales per plan instance.
- **App Service**: Metric-based and schedule-based auto-scale rules.

### Scale-to-Zero Economics

Scale-to-zero is a key cost optimization for intermittent workloads. Services supporting scale-to-zero: Azure Functions (Consumption, Flex Consumption), Container Apps, and AKS with virtual nodes (ACI). Evaluate cold start impact against cost savings for your latency requirements.

## Hybrid with Azure Arc

Azure Arc extends Azure management and services to any infrastructure (on-premises, edge, multi-cloud).

### Arc-Enabled Servers

- Install the Connected Machine agent on any server (Windows, Linux) running anywhere
- Apply Azure Policy for governance and compliance
- Use Azure Monitor and Log Analytics for centralized monitoring
- Enable Microsoft Defender for Cloud for threat protection
- Use Azure Automation for update management and configuration management

### Arc-Enabled Kubernetes

- Connect any CNCF-conformant Kubernetes cluster to Azure
- Apply Azure Policy for Kubernetes governance
- Deploy applications with GitOps (Flux v2) from Azure
- Use Container Insights for monitoring
- Enable Defender for Containers for security
- Run Azure Arc-enabled data services (SQL Managed Instance, PostgreSQL) on any Kubernetes cluster

### Arc-Enabled Application Services

Run Azure App Service, Functions, Logic Apps, API Management, and Event Grid on Arc-enabled Kubernetes clusters. Enables running Azure PaaS services on-premises or on other clouds with Azure management plane.

## Region Pairs and Multi-Region Design

Azure regions are paired for disaster recovery. Region pairs receive sequenced platform updates (never updated simultaneously) and some services provide automatic cross-region replication.

### Multi-Region Architecture Patterns

- **Active-Passive**: Primary region handles all traffic. Secondary region on standby with replicated data. Failover via Azure Front Door or Traffic Manager. Lower cost but non-zero RTO.
- **Active-Active**: Both regions handle traffic simultaneously. Azure Front Door routes users to the nearest region. Data is replicated bidirectionally. Near-zero RTO but higher cost and complexity (conflict resolution for data writes).
- **Data Replication**: Use geo-redundant storage (GRS/RA-GRS), Azure SQL active geo-replication, Cosmos DB multi-region writes, or Azure Cache for Redis geo-replication depending on the data tier.
