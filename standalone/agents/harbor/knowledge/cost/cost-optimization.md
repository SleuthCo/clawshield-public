---
framework: "Cost Optimization"
version: "1.0"
domain: "Cloud Financial Management"
agent: "nimbus"
tags: ["cost", "optimization", "reserved-instances", "savings-plans", "spot", "rightsizing"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Cost Optimization

Cloud cost optimization is an ongoing practice of reducing waste and improving price-performance. This document covers commitment discounts, spot/preemptible instances, rightsizing, auto-scaling for cost, storage optimization, data transfer strategies, serverless economics, and multi-cloud cost management.

## Reserved Instances and Savings Plans

### AWS Savings Plans

Savings Plans offer significant discounts (up to 72%) in exchange for a commitment to a consistent amount of compute usage (measured in dollars per hour) for 1 or 3 years.

**Types**:
- **Compute Savings Plans**: Most flexible. Apply to any EC2 instance family, size, AZ, region, OS, or tenancy. Also apply to Fargate and Lambda. Up to 66% savings. Recommended for most organizations.
- **EC2 Instance Savings Plans**: Locked to a specific instance family and region (but flexible on size, AZ, OS, tenancy). Up to 72% savings. Use when you are confident about the instance family and region.
- **SageMaker Savings Plans**: Apply to SageMaker ML instance usage. Same flexibility model as Compute Savings Plans.

**Purchase Strategy**:
- Analyze 30-60 days of steady-state usage to determine commitment level
- Start with Compute Savings Plans for flexibility. Add EC2 Instance Savings Plans for additional savings on predictable workloads.
- Purchase in layers: cover the minimum baseline with 3-year terms (deepest discount), cover the next tier with 1-year terms, leave the top tier for on-demand and Spot.
- Use AWS Cost Explorer Savings Plans recommendations as a starting point.
- Review and adjust quarterly. Purchase incrementally rather than all at once.

### AWS Reserved Instances (RIs)

RIs preceded Savings Plans and are still available. They offer discounts for committing to a specific instance type, region, OS, and tenancy.

- **Standard RIs**: Up to 72% discount. Locked to specific instance type, region, OS. Can be sold on the RI Marketplace if no longer needed.
- **Convertible RIs**: Up to 66% discount. Can be exchanged for different instance types, OSes, or tenancies. More flexible but smaller discount.
- RIs still exist for RDS, ElastiCache, Redshift, OpenSearch, and MemoryDB where Savings Plans do not apply. Purchase service-specific RIs for these.

### Azure Reservations

Azure Reservations provide discounts (up to 72% for 3-year) for committing to specific resource types.

- **Virtual Machine Reservations**: Instance family + region. Instance size flexibility within the family.
- **Azure Savings Plan for Compute**: Similar to AWS Compute Savings Plans. Applies to VMs, App Service, Container Instances, dedicated hosts, and Azure Functions Premium.
- **Service-Specific Reservations**: Available for SQL Database, Cosmos DB, Synapse, App Service, Blob Storage capacity, and more.
- **Azure Hybrid Benefit**: Use existing Windows Server and SQL Server licenses on Azure. Combine with reservations for maximum savings (up to 85%).

### GCP Committed Use Discounts (CUDs)

- **Resource-Based CUDs**: Commit to vCPU and memory amounts in a region for 1 or 3 years. Up to 57% (1-year) or 70% (3-year) discount. Apply to Compute Engine and GKE.
- **Spend-Based CUDs**: Commit to a minimum spend per hour for specific services (Cloud SQL, Cloud Run, VMware Engine). Up to 25% discount.
- **Flex CUDs**: Short-term (1-year) commitments at lower discounts. Cannot be cancelled but provide flexibility.

### Cross-Cloud Commitment Strategy

1. Analyze baseline utilization across all cloud providers
2. Cover the steady-state floor with 3-year commitments (highest discount)
3. Cover the next tier with 1-year commitments (balance of discount and flexibility)
4. Use Spot/Preemptible for fault-tolerant burst capacity
5. Leave the remaining variable capacity on-demand
6. Target commitment coverage of 60-80% of steady-state compute. Higher coverage risks over-commitment.

## Spot and Preemptible Instances

### AWS Spot Instances

Up to 90% discount by using spare EC2 capacity. AWS can reclaim instances with 2-minute notice.

**Best Practices**:
- Diversify across multiple instance types, families, and AZs to reduce interruption risk
- Use capacity-optimized allocation strategy (lowest interruption rate) rather than lowest-price
- Implement graceful shutdown: drain connections, checkpoint work, push state to external storage
- Use Spot in Auto Scaling Groups with mixed instances (On-Demand base + Spot burst)
- Monitor Spot interruption frequency by instance type using AWS Spot Advisor

**Ideal Workloads**: CI/CD agents, batch processing, data analytics (EMR), containerized microservices (ECS, EKS with Karpenter), dev/test environments, rendering, genomics processing.

### Azure Spot VMs

Up to 90% discount on surplus Azure capacity. Eviction when Azure needs the capacity or price exceeds your maximum.

- Eviction policy: Stop/Deallocate (restart later) or Delete
- Set maximum price (-1 for up to on-demand price, or specific amount)
- Use in VMSS for automatic Spot management
- Spot priority mix in VMSS: configure percentage of Spot vs regular VMs

### GCP Preemptible and Spot VMs

- **Spot VMs**: Replacement for preemptible VMs. Same discount (up to 91%). No maximum 24-hour runtime limit (unlike legacy preemptible VMs). Dynamic pricing model.
- **Preemptible VMs (Legacy)**: Maximum 24-hour runtime. Fixed discount. Being replaced by Spot VMs.
- Use with managed instance groups (MIGs) for automatic replacement

## Rightsizing

Rightsizing is the process of matching resource sizes to actual workload requirements. Studies consistently show that 30-40% of cloud resources are over-provisioned.

### Process

1. **Collect metrics**: CPU utilization, memory utilization, network throughput, disk I/O over 2-4 weeks
2. **Analyze utilization**: Identify resources consistently under-utilized (< 40% peak CPU, < 60% peak memory)
3. **Evaluate recommendations**: AWS Compute Optimizer, Azure Advisor, GCP Recommender provide specific instance type recommendations
4. **Implement changes**: Resize instances during maintenance windows. For stateless services, update the launch template and roll instances.
5. **Validate**: Monitor performance after rightsizing to ensure no degradation
6. **Repeat**: Rightsizing is continuous. Workloads change over time. Review monthly.

### Key Considerations

- Analyze peak utilization, not just averages. A server averaging 15% CPU but peaking at 80% should not be downsized by 85%.
- Consider memory requirements (CloudWatch Agent or node_exporter required for memory metrics)
- Account for growth projections and seasonal peaks
- Rightsize before purchasing commitments (RIs/SPs). Locking in discounts on oversized instances wastes money.
- Use burstable instances (T-series, B-series) for workloads with variable and generally low CPU usage

## Auto-Scaling for Cost

### Cost-Optimized Scaling

Auto-scaling is not just for availability; it is a cost optimization tool. Matching capacity to demand avoids paying for idle resources.

**Strategies**:
- **Time-Based Scaling**: Schedule capacity reductions during known low-traffic periods (nights, weekends). Effective for business-hour applications.
- **Target Tracking**: Set a target utilization (e.g., 60% CPU) and let the auto-scaler adjust capacity. Higher target = lower cost but less headroom. Lower target = higher cost but more headroom.
- **Predictive Scaling**: Use ML-based prediction (AWS Predictive Scaling, Azure Predictive Autoscale) to proactively scale before demand increases. Reduces latency impact of reactive scaling.
- **Scale-to-Zero**: For intermittent workloads, scale to zero instances when idle. Supported by Lambda, Cloud Functions, Azure Functions (Consumption), Cloud Run, Azure Container Apps, and Kubernetes with KEDA.

### Development Environment Cost Control

Non-production environments often account for 30-50% of cloud spend but generate no revenue.

- **Scheduled shutdown**: Stop dev/test instances outside business hours. Use AWS Instance Scheduler, Azure Automation, or GCP Cloud Scheduler with Cloud Functions.
- **Reduced redundancy**: Single-AZ, smaller instances, no multi-region for non-production.
- **Spot/Preemptible only**: Use Spot instances for all dev/test compute. Developers should design for interruption resilience.
- **Ephemeral environments**: Create environments on demand for PR review/testing and destroy them automatically after merge. Use Terraform/Pulumi with CI/CD automation.
- **Dev/Test pricing**: AWS, Azure, and GCP offer discounted pricing for development and test workloads. Azure Dev/Test pricing provides significant discounts on select services.

## Storage Tiering

### AWS S3 Storage Classes

| Class | Use Case | Retrieval | Durability | Relative Cost |
|-------|----------|-----------|------------|---------------|
| S3 Standard | Frequently accessed data | Immediate | 99.999999999% | $$$ |
| S3 Intelligent-Tiering | Unknown/changing access patterns | Immediate | 99.999999999% | $$-$$$ (auto) |
| S3 Standard-IA | Infrequently accessed (min 30 days) | Immediate | 99.999999999% | $$ |
| S3 One Zone-IA | Non-critical infrequent data | Immediate | 99.999999999% (1 AZ) | $ |
| S3 Glacier Instant | Archive with millisecond access | Milliseconds | 99.999999999% | $ |
| S3 Glacier Flexible | Archive accessed 1-2 times/year | Minutes-hours | 99.999999999% | ¢ |
| S3 Glacier Deep Archive | Long-term archive, rarely accessed | 12-48 hours | 99.999999999% | ¢¢ |

**S3 Intelligent-Tiering**: Automatically moves objects between access tiers based on usage patterns. No retrieval charges. Small monitoring fee per object. Recommended as the default for data with unpredictable access patterns.

### Lifecycle Policies

Automate storage tiering by creating lifecycle rules:
1. Move to Standard-IA after 30 days of no access
2. Move to Glacier Flexible after 90 days
3. Move to Glacier Deep Archive after 365 days
4. Delete after 7 years (compliance-dependent)

### Azure Blob Storage Tiers

- Hot (frequently accessed), Cool (30-day minimum, lower storage cost), Cold (90-day minimum), Archive (180-day minimum, hours to rehydrate)
- Lifecycle management policies automate tier transitions
- Azure Blob Inventory for usage analysis

### GCP Cloud Storage Classes

- Standard (frequently accessed), Nearline (30-day minimum), Coldline (90-day minimum), Archive (365-day minimum)
- Object Lifecycle Management for automated transitions
- Autoclass: Automatic tier management similar to S3 Intelligent-Tiering

## Data Transfer Optimization

Data transfer is often the most surprising and hardest-to-predict cloud cost component.

### Cost Reduction Strategies

- **VPC Endpoints / Private Link**: Eliminate data processing charges for traffic to AWS services. Gateway endpoints for S3 and DynamoDB are free.
- **Regional Placement**: Keep compute and storage in the same region to avoid cross-region transfer charges. Cross-region data transfer is 5-10x more expensive than same-region.
- **CDN**: Serve static content from CloudFront, Azure CDN, or Cloud CDN. CDN data transfer is significantly cheaper than origin data transfer.
- **Compression**: Compress data before transfer. gzip for text-based data, zstd for better compression ratios. Reduces both transfer cost and time.
- **Data Transfer Out Minimization**: Design APIs to return only required fields. Implement pagination. Use efficient serialization (Protocol Buffers, MessagePack over JSON).
- **NAT Gateway Costs**: NAT gateway data processing charges ($0.045/GB in AWS) add up for high-traffic workloads. Use VPC endpoints to bypass NAT gateway for AWS service traffic. Use S3 gateway endpoints (free) instead of routing S3 traffic through NAT gateway.
- **Same-AZ Communication**: For tightly coupled services, place them in the same AZ to avoid cross-AZ data transfer charges ($0.01/GB each way in AWS). Trade-off: reduced availability.

## Serverless Cost Models

### Lambda/Functions Pricing

Serverless functions are billed per invocation and per compute time (GB-seconds).

**Cost Optimization**:
- **Right-size memory**: Memory allocation determines CPU allocation. Use power tuning tools to find the optimal memory size that minimizes cost (or execution time). Over-provisioning memory wastes money; under-provisioning increases duration and can increase total cost.
- **Reduce duration**: Optimize code execution time. Cold start adds latency and cost. Use connection pooling, SDK client reuse, and lazy initialization.
- **Minimize invocations**: Batch events where possible (SQS batch size, Kinesis batch window). Deduplicate events before processing.
- **Architecture choices**: Use SQS batching over individual invocations. Use Step Functions for orchestration instead of Lambda-to-Lambda chaining.

### Container Serverless Pricing

- **Fargate**: Billed per vCPU-second and per GB-second. Approximately 20-30% more expensive than equivalent EC2 On-Demand. Cost savings come from eliminating over-provisioning (no idle EC2 capacity).
- **Cloud Run**: Billed per vCPU-second, per GB-second, and per request. Scale-to-zero means no cost when idle. Second-generation execution environment for better performance.
- **Azure Container Apps**: Consumption plan billed per vCPU-second and GB-second with scale-to-zero. Dedicated plan for predictable workloads.

### When Serverless Saves Money

Serverless is cost-effective when:
- Workload is intermittent or highly variable (benefits from scale-to-zero)
- Per-request cost is lower than the cost of idle capacity on traditional compute
- Operational cost savings (no patching, no capacity management) offset the per-unit price premium

Serverless becomes expensive when:
- Workload is sustained and predictable (always-running)
- High concurrency with sustained traffic (committed compute is cheaper)
- Functions are over-provisioned with memory

## Multi-Cloud Cost Management

### Challenges

- Different pricing models, billing formats, and discount structures across providers
- No native cross-cloud cost visibility from any single provider
- Different tagging implementations and limitations
- Different commitment discount mechanisms

### Multi-Cloud Cost Tools

- **CloudHealth (VMware)**: Multi-cloud cost management, governance, and optimization for AWS, Azure, GCP
- **Cloudability (Apptio)**: Multi-cloud cost visibility, allocation, and optimization
- **Spot by NetApp (Finout)**: Multi-cloud cost optimization and management
- **Kubecost**: Kubernetes-specific cost monitoring. Allocates costs to namespaces, deployments, and labels across any Kubernetes cluster regardless of cloud provider.
- **OpenCost**: CNCF project for Kubernetes cost monitoring. Open-source core of Kubecost. Vendor-neutral cost allocation for Kubernetes.
- **Infracost**: IaC cost estimation. Shows cost impact of Terraform changes before deployment. Multi-cloud support.

### Normalization

Normalize multi-cloud costs for comparison:
- Standardize on a common currency and exchange rate
- Map cloud-specific service names to generic categories (compute, storage, network, database)
- Normalize tagging across providers to a common schema
- Calculate per-unit costs (cost per vCPU-hour, cost per GB-month) for cross-provider comparison
- Account for discount differences when comparing (same workload may have different discount levels across providers)

### Multi-Cloud Cost Governance

- Establish a unified tagging standard that works across all providers
- Use a single FinOps tool for cross-cloud visibility and reporting
- Create consolidated dashboards showing total cloud spend across providers
- Track provider-specific optimization opportunities (each provider has unique discount mechanisms)
- Make provider selection decisions informed by total cost of ownership (TCO), not just list price
- Consider egress costs when designing multi-cloud architectures. Data transfer between clouds is expensive.

## Cost Optimization Checklist

### Quick Wins (Days)

- Delete unused resources (unattached EBS volumes, unused EIPs, idle load balancers)
- Stop or terminate unused instances (development environments left running)
- Remove old snapshots and AMIs beyond retention requirements
- Right-size obviously over-provisioned instances (< 10% average CPU)

### Medium-Term (Weeks)

- Purchase Savings Plans or Reserved Instances for steady-state workloads
- Implement auto-scaling for workloads with variable demand
- Configure S3 lifecycle policies for storage tiering
- Set up VPC endpoints for high-volume AWS service access
- Implement scheduled shutdown for non-production environments

### Ongoing (Continuous)

- Regular rightsizing reviews (monthly)
- Commitment discount portfolio management (quarterly)
- Anomaly detection and response
- Unit economics tracking
- Architecture reviews for cost optimization opportunities
- New service evaluation for better price-performance
