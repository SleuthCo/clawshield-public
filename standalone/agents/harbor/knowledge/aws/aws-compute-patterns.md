---
framework: "AWS Compute Patterns"
version: "1.0"
domain: "Cloud Compute"
agent: "nimbus"
tags: ["aws", "compute", "ec2", "ecs", "eks", "lambda", "fargate", "auto-scaling"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# AWS Compute Patterns

AWS offers a broad spectrum of compute services from bare-metal servers to fully managed serverless functions. Choosing the right compute service and configuration is foundational to cost, performance, and operational efficiency.

## EC2 Instance Selection

### Instance Family Categories

- **General Purpose (M, T, Mac)**: Balanced compute, memory, and networking. M-series (M7g, M7i) for production workloads needing consistent performance. T-series (T3, T3a, T4g) for burstable workloads with variable CPU needs (web servers, small databases, development environments).
- **Compute Optimized (C)**: High-performance processors for compute-intensive workloads. C7g (Graviton3) and C7i (Intel Sapphire Rapids) for batch processing, HPC, scientific modeling, gaming servers, video encoding, ML inference.
- **Memory Optimized (R, X, z)**: High memory-to-CPU ratio. R-series for in-memory caches (Redis, Memcached), real-time analytics, large databases. X-series for SAP HANA, very large in-memory databases. High Memory (u-) instances for up to 24 TiB of memory.
- **Storage Optimized (I, D, H)**: High sequential read/write access to large datasets on local storage. I-series for NoSQL databases (Cassandra, MongoDB), data warehousing. D-series for MapReduce, distributed file systems. H-series for large sequential I/O.
- **Accelerated Computing (P, G, Inf, Trn, DL, F, VT)**: GPU and custom hardware accelerators. P-series (P5, P4d) for ML training and HPC. G-series for graphics and ML inference. Inf-series (Inf2) for cost-effective ML inference on AWS Inferentia chips. Trn-series for ML training on AWS Trainium chips.
- **HPC Optimized (Hpc)**: Optimized for tightly coupled HPC workloads with high-bandwidth networking (EFA).

### Graviton Processors

AWS Graviton processors (ARM-based, custom-designed by AWS) deliver up to 40% better price-performance than comparable x86 instances.

- **Graviton3 (7g instances)**: 25% better compute performance than Graviton2, 2x floating-point performance, 2x cryptographic workload performance, 3x ML performance.
- **Graviton4 (8g instances)**: Latest generation with further improvements in performance and energy efficiency.
- **Adoption Strategy**: Most Linux-based workloads run without modification. Test application compatibility. Key considerations: ensure all dependencies (language runtimes, libraries, containers) have ARM64 builds. Java, Python, Node.js, Go, and .NET 6+ work well on Graviton.

### Instance Selection Decision Framework

1. **Start with Graviton**: Default to Graviton-based instances for Linux workloads. Fall back to Intel/AMD only if specific x86 requirements exist.
2. **Right-size first**: Use AWS Compute Optimizer to analyze utilization and get right-sizing recommendations. Many workloads are over-provisioned by 40-60%.
3. **Match the workload profile**: CPU-bound work to C-series, memory-bound to R-series, balanced to M-series.
4. **Consider burstable instances**: T-series instances accumulate CPU credits during low utilization and spend them during bursts. Cost-effective for workloads with variable CPU needs averaging below the baseline.
5. **Network performance matters**: Higher instance sizes provide higher network bandwidth. Use enhanced networking (ENA). For HPC, use Elastic Fabric Adapter (EFA) and placement groups.

## ECS vs EKS vs Fargate vs Lambda Decision Tree

### When to Use Each

**AWS Lambda**:
- Event-driven workloads, API backends with variable traffic
- Execution duration under 15 minutes
- Payload size under 6 MB (synchronous) or 256 KB (asynchronous)
- Memory requirement under 10 GB
- No specialized OS or runtime requirements
- Want zero server management and pay-per-invocation pricing
- Ideal for: API backends (with API Gateway), data processing (S3 events, Kinesis, DynamoDB Streams), scheduled tasks, IoT backends

**AWS Fargate (on ECS or EKS)**:
- Container workloads where you want no EC2 instance management
- Workloads that need to run for longer than 15 minutes
- Need more control over runtime environment than Lambda provides
- Want per-second billing without managing cluster capacity
- Acceptable performance (slight cold-start latency for new tasks)
- Ideal for: Microservices, batch processing, web applications, CI/CD workers

**Amazon ECS on EC2**:
- Need control over the underlying EC2 instances (GPU, custom AMIs, specific instance types)
- Predictable, steady-state workloads where Reserved Instances reduce cost
- Need to use Spot Instances for cost optimization with fault-tolerant workloads
- Need to run Windows containers (limited Fargate support)
- Workloads requiring high I/O to local instance storage
- Simpler orchestration model; team does not need Kubernetes expertise
- Ideal for: Long-running services, GPU workloads, Windows containers, cost-sensitive steady-state workloads

**Amazon EKS (with EC2 or Fargate)**:
- Kubernetes expertise exists in the team
- Multi-cloud or hybrid strategy requiring Kubernetes portability
- Need the rich Kubernetes ecosystem (Helm charts, operators, service mesh, GitOps tools)
- Complex microservice architectures requiring advanced scheduling, networking, and service discovery
- Workloads that benefit from Kubernetes-native tools (Istio, ArgoCD, Prometheus)
- Need multi-tenancy with namespace-level isolation
- Ideal for: Large microservice platforms, multi-cloud portability, teams with existing Kubernetes skills

### Comparison Matrix

| Factor | Lambda | Fargate | ECS on EC2 | EKS |
|--------|--------|---------|-----------|-----|
| Operational overhead | None | Low | Medium | High |
| Cold start | Yes (ms-sec) | Yes (sec) | No | No |
| Max duration | 15 min | Unlimited | Unlimited | Unlimited |
| Scaling speed | Fastest | Fast | Moderate | Moderate |
| Cost model | Per-invocation | Per-second | Per-instance | Per-instance + control plane |
| Kubernetes needed | No | Optional (EKS) | No | Yes |
| GPU support | No | No | Yes | Yes |
| Spot support | No | Fargate Spot | Yes | Yes |

## Auto-Scaling Patterns

### EC2 Auto Scaling

- **Target Tracking**: Set a target metric value (e.g., 50% average CPU utilization). ASG automatically adjusts capacity to maintain the target. Simplest approach for most workloads.
- **Step Scaling**: Define scaling adjustments for specific CloudWatch alarm thresholds. Provides more control than target tracking. Example: add 2 instances when CPU > 60%, add 4 instances when CPU > 80%.
- **Scheduled Scaling**: Scale based on predictable load patterns (increase capacity before known peak hours, decrease overnight). Combine with other scaling policies.
- **Predictive Scaling**: Uses ML to analyze historical load patterns and proactively scale capacity before demand increases. Effective for cyclical workloads. Best used alongside dynamic scaling policies.

### Best Practices for Auto Scaling

- Use multiple Availability Zones (minimum 2, preferably 3) for high availability. ASG automatically rebalances across AZs.
- Configure health checks: Use ELB health checks (not just EC2 status checks) to detect application-level failures.
- Set appropriate cooldown periods to prevent scaling thrashing. Default is 300 seconds.
- Use warm pools for instances that have long initialization times (JVM warm-up, large data loading). Pre-initialized instances join the ASG faster.
- Use instance refresh for rolling updates to launch template configurations.
- Configure mixed instances policy to use multiple instance types and purchase options (On-Demand + Spot) for cost optimization and capacity availability.

### ECS Service Auto Scaling

ECS uses Application Auto Scaling with three scaling policy types:
- **Target Tracking**: Track ECS service metrics (CPU utilization, memory utilization, ALB request count per target).
- **Step Scaling**: Scale based on CloudWatch alarms with stepped adjustments.
- **Scheduled Scaling**: Set desired count on a schedule.

For ECS on EC2, you need both service auto-scaling (task count) and cluster auto-scaling (EC2 instance count). ECS Cluster Auto Scaling uses a Capacity Provider that tracks the CapacityProviderReservation metric.

### Lambda Concurrency

- **Unreserved Concurrency**: Lambda functions share a regional concurrency pool (default 1,000, can be increased). Functions scale automatically up to this limit.
- **Reserved Concurrency**: Guarantees a set number of concurrent executions for a specific function. Other functions cannot consume this capacity. Also acts as a maximum concurrency limit.
- **Provisioned Concurrency**: Pre-initializes a specified number of execution environments to eliminate cold starts. Incurs cost even when not handling requests. Use for latency-sensitive workloads.

## Spot Instances

Spot Instances provide up to 90% cost savings compared to On-Demand pricing by using spare EC2 capacity. AWS can reclaim Spot Instances with a 2-minute interruption notice.

### Spot Best Practices

- **Diversify**: Use multiple instance types and sizes across multiple Availability Zones. The more diverse your fleet, the lower the interruption rate. Use capacity-optimized allocation strategy.
- **Handle Interruptions Gracefully**: Monitor the instance metadata service for interruption notices. Implement graceful shutdown (drain connections, checkpoint work, deregister from load balancer).
- **Use with Fault-Tolerant Workloads**: Batch processing, CI/CD, stateless web servers, big data (EMR), container workloads, test/dev environments.
- **Spot Fleet or EC2 Auto Scaling Mixed Instances Policy**: Automatically request capacity from the most available and cost-effective instance pools.
- **Spot Placement Score**: Use this API to find the best Region and AZ for Spot capacity before launching.

### Spot Architecture Patterns

- **Mixed Instances ASG**: Base capacity on On-Demand (or Reserved), burst capacity on Spot. Example: 30% On-Demand base with 70% Spot for cost optimization while ensuring minimum availability.
- **ECS Capacity Providers**: Mix Fargate and Fargate Spot, or EC2 On-Demand and EC2 Spot capacity providers with weighted strategies.
- **EKS with Karpenter**: Karpenter is an open-source Kubernetes node provisioner that automatically selects the right instance types and purchase options (On-Demand, Spot) based on pod requirements and availability.

## Hybrid Compute with AWS Outposts

AWS Outposts delivers AWS infrastructure and services to on-premises locations for a truly consistent hybrid experience.

### Outposts Rack

- Full AWS rack deployed in your data center
- Supports EC2, EBS, S3, ECS, EKS, RDS, ALB, and more
- Managed by AWS (patching, monitoring, maintenance)
- Connected to the parent AWS Region via a service link
- Use cases: Low-latency processing close to on-premises systems, local data processing with data residency requirements, migration stepping stone

### Outposts Server

- 1U or 2U form factor for edge locations with limited space
- Supports EC2, ECS, and SSM
- Use cases: Retail stores, factory floors, branch offices, remote locations

### Hybrid Decision Framework

- **AWS Outposts**: When you need AWS services and APIs on-premises with a consistent experience
- **AWS Local Zones**: When you need AWS compute closer to end users in a specific metro area for low-latency applications
- **AWS Wavelength**: When you need ultra-low-latency from 5G mobile networks
- **AWS Snow Family**: When you need compute at disconnected or austere edge locations (Snowcone, Snowball Edge)

## Compute Optimization Strategies

### Right-Sizing Process

1. Enable AWS Compute Optimizer for all accounts via Organizations
2. Review recommendations weekly for over-provisioned and under-provisioned instances
3. Analyze CloudWatch metrics: CPU utilization, memory utilization (requires CloudWatch Agent), network throughput, disk I/O
4. Consider peak usage patterns, not just averages. An instance averaging 10% CPU but peaking at 90% may be correctly sized.
5. Right-size first, then commit (Reserved Instances/Savings Plans) to lock in savings on the right-sized instances

### Cost-Performance Optimization

- Move to Graviton for 20-40% better price-performance on compatible workloads
- Use latest generation instances (M7g over M6g, C7g over C6g) for better performance per dollar
- Use AMD-based instances (M7a, C7a) for 10% savings over comparable Intel instances when x86 is required
- Evaluate Spot for interruptible workloads (typical 60-90% savings)
- Use Savings Plans for steady-state workloads (Compute Savings Plans are most flexible, EC2 Instance Savings Plans offer deeper discounts)
- Consolidate small instances into fewer larger instances to reduce per-instance overhead and licensing costs when applicable

### Serverless Optimization

- Use Lambda Power Tuning (open-source tool) to find the optimal memory configuration that minimizes cost or execution time
- Enable Lambda SnapStart for Java functions to reduce cold start from seconds to under 200ms
- Use Provisioned Concurrency selectively for latency-critical functions, not all functions
- Implement Lambda Layers for shared dependencies to reduce deployment package size
- Use Lambda Extensions for observability and security tooling without modifying application code
- Consider Step Functions for orchestrating multiple Lambda functions instead of chaining invocations, to improve error handling and reduce total execution time
