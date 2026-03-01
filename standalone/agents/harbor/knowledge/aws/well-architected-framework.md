---
framework: "AWS Well-Architected"
version: "2024"
domain: "Cloud Architecture"
agent: "nimbus"
tags: ["aws", "well-architected", "cloud", "architecture", "pillars", "best-practices"]
last_updated: "2025-02-01"
chunk_strategy: "heading"
---

# AWS Well-Architected Framework

The AWS Well-Architected Framework describes key concepts, design principles, and architectural best practices for designing and running workloads in the cloud. It consists of six pillars, each representing a fundamental area of architectural excellence.

## Pillar 1: Operational Excellence

The ability to support development and run workloads effectively, gain insight into their operations, and continuously improve supporting processes and procedures.

### Design Principles

**Perform operations as code**: Define your entire workload (infrastructure, application, configuration) as code. Apply the same engineering discipline to operations as to application code. Use CloudFormation, CDK, or Terraform.

**Make frequent, small, reversible changes**: Design workloads to allow components to be updated regularly. Small changes reduce blast radius. Reversible changes (feature flags, blue-green deployments) reduce risk.

**Refine operations procedures frequently**: As workloads evolve, update procedures. Conduct game days to validate. Automate what can be automated. Document what can't.

**Anticipate failure**: Perform pre-mortem exercises. Test failure scenarios. Understand blast radius. Design for graceful degradation.

**Learn from all operational failures**: Drive improvement through lessons learned. Share learnings across teams. Blameless post-incident reviews.

### Key Practices

**Observability**: Implement structured logging, distributed tracing, and metrics collection. Use CloudWatch, X-Ray, and OpenTelemetry. Define SLOs and SLIs for every critical service. Alert on symptoms (user impact), not just causes.

**Runbooks and playbooks**: Document operational procedures for common scenarios. Automate runbooks where possible (SSM Automation). Review and update quarterly.

**Deployment strategies**: Use CI/CD pipelines with automated testing gates. Implement canary deployments or rolling updates. Have rollback procedures tested and ready.

## Pillar 2: Security

The ability to protect data, systems, and assets to take advantage of cloud technologies to improve your security.

### Design Principles

**Implement a strong identity foundation**: Centralize identity management. Use least privilege. Eliminate long-term static credentials. Use IAM roles, not access keys. Implement MFA everywhere.

**Maintain traceability**: Monitor, alert on, and audit all actions and changes. Integrate log collection with systems to automatically investigate and take action. CloudTrail for API calls, VPC Flow Logs for network, GuardDuty for threat detection.

**Apply security at all layers**: Defense in depth — edge, VPC, subnet, load balancer, instance, OS, application. Don't rely on a single layer.

**Automate security best practices**: Automated security mechanisms improve ability to scale. Use Config Rules, Security Hub, automated remediation via Lambda.

**Protect data in transit and at rest**: Classify data by sensitivity. Use encryption, tokenization, and access control. TLS 1.2+ for transit. KMS-managed keys for storage. Use AWS Certificate Manager.

**Keep people away from data**: Reduce or eliminate direct access to production data. Use mechanisms to process data without direct access (SSM Session Manager instead of SSH, automated data pipelines instead of manual queries).

**Prepare for security events**: Incident response simulation (game days). Automated alerting and escalation. Forensic tooling pre-provisioned.

### IAM Best Practices

**No root account usage**: MFA on root. No access keys for root. Use Organizations SCPs to restrict root actions.

**Role-based access**: Prefer IAM Roles over users. Use OIDC federation for CI/CD (GitHub Actions OIDC, etc.). Session-based credentials with short TTLs.

**Permission boundaries**: Use permission boundaries to delegate administration safely. SCP guardrails at the org level. Resource-based policies for cross-account access.

**Least privilege iteration**: Start with broad permissions, use IAM Access Analyzer to identify unused permissions, then scope down progressively.

## Pillar 3: Reliability

The ability of a workload to perform its intended function correctly and consistently when it's expected to.

### Design Principles

**Automatically recover from failure**: Monitor key performance indicators and trigger automation when thresholds are breached. Auto Scaling, Route 53 health checks, ELB health checks.

**Test recovery procedures**: Test how your workload fails, and validate recovery procedures. Chaos engineering — use AWS Fault Injection Simulator.

**Scale horizontally**: Replace one large resource with multiple small resources to reduce the impact of a single failure. Distribute requests across multiple, smaller resources.

**Stop guessing capacity**: Monitor demand and automate. Use Auto Scaling with predictive scaling. Right-size regularly.

**Manage change through automation**: Changes to infrastructure should be made through automation. Avoid manual changes to production environments.

### Resilience Patterns

**Multi-AZ deployment**: Distribute across at least two Availability Zones. Use ALB for automatic failover. RDS Multi-AZ for database resilience.

**Circuit breaker**: Prevent cascading failures between services. Fail fast and return degraded responses rather than hanging indefinitely.

**Bulkhead isolation**: Isolate failures to prevent them from cascading. Separate thread pools, connection pools, and compute for different workloads.

**Retry with exponential backoff and jitter**: Implement retries with increasing delays and random jitter to prevent thundering herd problems. Use SDK built-in retry policies.

**Idempotency**: Design operations to be safely retried. Use idempotency keys for write operations. DynamoDB conditional writes, SQS deduplication.

## Pillar 4: Performance Efficiency

The ability to use computing resources efficiently to meet system requirements, and to maintain that efficiency as demand changes and technologies evolve.

### Compute Selection

**EC2**: Use when you need full control over the OS, specific instance types (GPU, high memory), or long-running processes. Use Spot for fault-tolerant workloads (up to 90% savings). Use Graviton instances for better price-performance.

**Lambda**: Use for event-driven, short-duration workloads. Scales to zero. Pay per invocation. Watch for cold start latency in synchronous paths. Use provisioned concurrency for latency-sensitive functions.

**Containers (ECS/EKS)**: Use when you need more control than Lambda but don't want to manage instances. Fargate for serverless containers. EKS for Kubernetes ecosystem compatibility.

### Database Selection

**DynamoDB**: Single-digit millisecond latency at any scale. Use for key-value and document workloads. Design access patterns first, then model data. Use single-table design for related entities.

**RDS/Aurora**: Relational workloads with complex queries and transactions. Aurora for MySQL/PostgreSQL with up to 5x performance improvement. Read replicas for read scaling.

**ElastiCache (Redis/Memcached)**: Caching layer for reducing database load. Session stores. Real-time leaderboards. Pub/sub messaging.

**Choosing**: If you need joins and transactions, use relational. If you need key-value at massive scale, use DynamoDB. If you need full-text search, use OpenSearch. If you need graph queries, use Neptune.

### Caching Strategies

**CDN (CloudFront)**: Cache static assets and API responses at the edge. Use cache invalidation judiciously — prefer versioned URLs.

**Application cache (ElastiCache)**: Cache expensive computations, database queries, and session data. Implement cache-aside pattern: check cache, if miss, query source, populate cache.

**Database cache**: Aurora read replicas, DynamoDB DAX for microsecond reads.

**Cache invalidation strategies**: TTL-based (simplest), event-driven invalidation (most accurate), write-through (consistent but slower writes).

## Pillar 5: Cost Optimization

The ability to run systems to deliver business value at the lowest price point.

### Key Strategies

**Right-sizing**: Use Compute Optimizer recommendations. Analyze actual utilization (target 40-70% for reserved capacity). Downsize oversized instances. Schedule non-production environments (shut down nights/weekends).

**Pricing models**: On-Demand for unpredictable/short workloads. Savings Plans for steady-state (up to 72% savings). Spot for fault-tolerant batch processing (up to 90% savings). Reserved capacity for databases and other stateful services.

**Architecture optimization**: Serverless for variable/unpredictable workloads. Graviton for 20-40% better price-performance. S3 Intelligent-Tiering for storage. Use S3 lifecycle policies to transition to cheaper tiers.

**FinOps practices**: Tag everything (at least: team, environment, project, cost-center). Use Cost Explorer and Budgets. Implement anomaly detection. Review monthly. Allocate costs to teams for accountability.

## Pillar 6: Sustainability

The ability to continually improve sustainability impacts by reducing energy consumption and increasing efficiency across all components of a workload.

### Principles

**Understand your impact**: Measure the carbon footprint of your workload using the AWS Customer Carbon Footprint Tool.

**Maximize utilization**: Higher utilization means less waste. Right-size resources. Use auto-scaling to match demand. Consolidate underutilized resources.

**Choose efficient technologies**: Managed services (let AWS optimize). Serverless (pay only for what you use). Graviton (more efficient per compute cycle). Regions powered by renewable energy.

**Reduce downstream impact**: Minimize data transfer. Compress data. Use efficient serialization formats. Cache aggressively.
