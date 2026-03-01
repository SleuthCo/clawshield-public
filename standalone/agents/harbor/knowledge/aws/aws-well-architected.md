---
framework: "AWS Well-Architected Framework"
version: "1.0"
domain: "Cloud Architecture"
agent: "nimbus"
tags: ["aws", "well-architected", "architecture", "best-practices", "pillars"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# AWS Well-Architected Framework

The AWS Well-Architected Framework provides architectural best practices across six pillars for designing and operating reliable, secure, efficient, cost-effective, and sustainable systems in the cloud. It was expanded from five to six pillars with the addition of Sustainability in late 2021.

## Pillar 1: Operational Excellence

Operational Excellence focuses on running and monitoring systems to deliver business value and continually improving processes and procedures.

### Design Principles

- Perform operations as code: Define your entire workload (applications, infrastructure) as code and trigger operations in response to events. Use CloudFormation, CDK, or Terraform for infrastructure, and AWS Systems Manager for operational runbooks.
- Make frequent, small, reversible changes: Design workloads to allow components to be updated regularly in small increments that can be reversed if they fail. Use blue/green or canary deployment patterns.
- Refine operations procedures frequently: Set regular cadences to review and validate that all procedures are effective. Conduct game days to simulate production failures.
- Anticipate failure: Perform pre-mortem exercises to identify potential sources of failure. Test failure scenarios and validate your understanding of their impact. Use chaos engineering practices with AWS Fault Injection Simulator.
- Learn from all operational failures: Drive improvement through lessons learned from all operational events and failures. Share learnings across teams.

### Key Best Practices

- **Organization**: Create a culture of cross-team collaboration. Evaluate internal and external customer needs. Establish shared understanding of the entire workload.
- **Prepare**: Design telemetry (CloudWatch metrics, X-Ray traces, CloudWatch Logs). Implement deployment pipelines (CodePipeline, CodeBuild, CodeDeploy). Validate readiness through checklists and runbooks.
- **Operate**: Use dashboards (CloudWatch Dashboards), define runbooks for routine activities, and playbooks for incident response. Automate responses to events using EventBridge and Lambda.
- **Evolve**: Dedicate time for continuous improvement. Analyze operational metrics to identify areas needing improvement. Implement feedback loops from incident reviews.

## Pillar 2: Security

Security focuses on protecting information, systems, and assets while delivering business value through risk assessments and mitigation strategies.

### Design Principles

- Implement a strong identity foundation: Use the principle of least privilege and enforce separation of duties with appropriate authorization for each interaction with AWS resources. Centralize identity management using IAM Identity Center (formerly AWS SSO).
- Maintain traceability: Monitor, alert, and audit actions and changes to your environment in real time. Enable CloudTrail in all accounts and regions. Integrate logs with a SIEM.
- Apply security at all layers: Apply a defense-in-depth approach with multiple security controls at every layer (edge, VPC, load balancer, instance, OS, application, data).
- Automate security best practices: Use automated software-based security mechanisms to scale more rapidly and cost-effectively. Implement security as code with AWS Config rules, GuardDuty, and Security Hub.
- Protect data in transit and at rest: Classify data into sensitivity levels and use mechanisms like encryption, tokenization, and access control. Enforce TLS everywhere and use KMS for encryption at rest.
- Keep people away from data: Use mechanisms and tools to reduce or eliminate the need for direct access or manual processing of data. Use Systems Manager Session Manager instead of SSH bastion hosts.
- Prepare for security events: Prepare for incidents by establishing incident management and investigation policies. Run incident response simulations and use tools like Amazon Detective for investigation.

### Key Services

- **Identity**: IAM, IAM Identity Center, Organizations (SCPs), STS
- **Detection**: CloudTrail, Config, GuardDuty, Security Hub, Macie, Inspector
- **Infrastructure Protection**: VPC, WAF, Shield, Firewall Manager
- **Data Protection**: KMS, CloudHSM, Certificate Manager, Secrets Manager
- **Incident Response**: Detective, EventBridge, Lambda, Step Functions

## Pillar 3: Reliability

Reliability ensures a workload performs its intended function correctly and consistently when expected, including the ability to operate and test the workload through its total lifecycle.

### Design Principles

- Automatically recover from failure: Monitor a workload for key performance indicators (KPIs) and trigger automation when a threshold is breached. Use Auto Scaling, health checks, and Route 53 failover.
- Test recovery procedures: Test how your workload fails, and validate recovery procedures. Use fault injection to create disruptive events and validate that the workload responds correctly.
- Scale horizontally to increase aggregate workload availability: Replace one large resource with multiple small resources to reduce the impact of a single failure on the overall workload.
- Stop guessing capacity: Use auto-scaling to automatically add or remove resources as demand changes. Monitor demand and workload utilization to ensure provisioning meets actual need.
- Manage change through automation: Use automation to make infrastructure changes. Manage changes through deployment pipelines and avoid manual changes to production.

### Key Best Practices

- **Foundations**: Set service quotas and constraints with AWS Service Quotas. Design network topology with redundancy across at least two Availability Zones. Use Transit Gateway for complex networking.
- **Workload Architecture**: Design services to be loosely coupled using SQS, SNS, EventBridge, and Step Functions. Design for idempotency. Use circuit breakers and bulkheads.
- **Change Management**: Monitor workload behavior with CloudWatch. Use Auto Scaling groups with proper health checks. Implement deployment strategies that limit blast radius.
- **Failure Management**: Back up data automatically (AWS Backup). Use multi-AZ and multi-region architectures. Implement disaster recovery strategies: backup/restore, pilot light, warm standby, or multi-site active/active. Define and test RTO/RPO objectives.

### Disaster Recovery Tiers

| Strategy | RTO | RPO | Cost | Complexity |
|----------|-----|-----|------|------------|
| Backup & Restore | Hours | Hours | $ | Low |
| Pilot Light | 10s of minutes | Minutes | $$ | Medium |
| Warm Standby | Minutes | Seconds | $$$ | Medium-High |
| Multi-Site Active/Active | Near-zero | Near-zero | $$$$ | High |

## Pillar 4: Performance Efficiency

Performance Efficiency focuses on using computing resources efficiently to meet system requirements and maintaining that efficiency as demand changes and technologies evolve.

### Design Principles

- Democratize advanced technologies: Let AWS manage complex technologies as services (managed databases, ML services, analytics) rather than asking your team to learn and host them.
- Go global in minutes: Deploy your workload in multiple AWS Regions around the world with a few clicks, providing lower latency and a better experience for customers at minimal cost.
- Use serverless architectures: Remove the need for you to run and maintain physical servers for traditional compute activities. Serverless architectures remove the operational burden.
- Experiment more often: Use virtual and automatable resources to carry out comparative testing using different types of instances, storage, or configurations.
- Consider mechanical sympathy: Understand how cloud services are consumed and always use the technology approach that aligns best to your workload goals.

### Key Best Practices

- **Selection**: Choose the best-performing resource types and sizes. Benchmark and load test to determine optimal compute (EC2, Lambda, Fargate), storage (S3, EBS gp3/io2, EFS, FSx), database (RDS, Aurora, DynamoDB, ElastiCache), and network (enhanced networking, placement groups, Global Accelerator).
- **Review**: Continually evaluate new instance families (Graviton), storage classes, and services. Track AWS announcements and re-evaluate architectures when beneficial.
- **Monitoring**: Use CloudWatch to monitor performance. Set alarms on key metrics. Use X-Ray for tracing and identifying bottlenecks.
- **Tradeoffs**: Evaluate caching (CloudFront, ElastiCache, DAX), read replicas, and partitioning strategies. Understand trade-offs between consistency and availability.

## Pillar 5: Cost Optimization

Cost Optimization focuses on avoiding unnecessary costs and understanding where money is being spent and optimizing resource usage.

### Design Principles

- Implement Cloud Financial Management: Dedicate time and resources to build capability in Cloud Financial Management (FinOps). Assign a team to manage cost and usage.
- Adopt a consumption model: Pay only for the computing resources you consume and increase or decrease usage depending on business requirements.
- Measure overall efficiency: Measure the business output of the workload and the costs associated with delivering it. Use this measure to understand the gains you make from increasing output and reducing costs.
- Stop spending money on undifferentiated heavy lifting: AWS does the heavy lifting of data center operations like racking, stacking, and powering servers. It also removes the operational burden of managing operating systems and applications with managed services.
- Analyze and attribute expenditure: Accurately identify the usage and cost of systems using cost allocation tags, AWS Cost Explorer, and AWS Cost and Usage Reports.

### Key Best Practices

- **Practice Cloud Financial Management**: Define a cost-optimization function. Establish partnerships between finance and technology. Establish cloud budgets and forecasts with AWS Budgets.
- **Expenditure and Usage Awareness**: Enable AWS Cost Explorer. Implement tagging policies. Use AWS Organizations for consolidated billing. Set up AWS Cost Anomaly Detection.
- **Cost-Effective Resources**: Use the right pricing model (On-Demand, Reserved Instances, Savings Plans, Spot). Right-size instances using AWS Compute Optimizer. Select appropriate storage classes and data lifecycle policies.
- **Manage Demand and Supply Resources**: Use Auto Scaling to match supply to demand. Use throttling, buffering (SQS), and time-based scaling to manage demand patterns.
- **Optimize Over Time**: Continually review and improve. Adopt new services that offer better price-performance (e.g., Graviton processors offer up to 40% better price-performance).

## Pillar 6: Sustainability

Sustainability focuses on minimizing the environmental impacts of running cloud workloads.

### Design Principles

- Understand your impact: Measure the impact of your cloud workload using the AWS Customer Carbon Footprint Tool.
- Establish sustainability goals: Set long-term goals for each workload, model return on investment (ROI), and give owners the resources to invest in sustainability goals.
- Maximize utilization: Right-size workloads and implement efficient design to ensure high utilization and maximize the energy efficiency of the underlying hardware.
- Anticipate and adopt new, more efficient hardware and software offerings: Partner with AWS on more efficient hardware (Graviton) and managed services to reduce the footprint.
- Use managed services: Shared services reduce the amount of infrastructure needed to support a broad range of workloads. Use managed services to move the sustainability burden to AWS.
- Reduce the downstream impact of your cloud workloads: Reduce the amount of energy or resources required for customers to use your services.

### Key Best Practices

- **Region Selection**: Choose Regions near Amazon renewable energy projects where feasible, while balancing latency and compliance requirements.
- **Alignment to Demand**: Auto-scale resources. Use Spot instances to leverage surplus capacity. Implement suspend-and-resume patterns for development and test environments.
- **Software and Architecture**: Optimize algorithms and code. Use efficient data formats (Parquet over CSV for analytics). Cache frequently accessed data.
- **Data Management**: Implement data lifecycle policies (S3 Intelligent-Tiering, Glacier). Remove unnecessary data and reduce storage footprint. Compress data before storage and transfer.
- **Hardware and Services**: Use Graviton-based instances for better performance per watt. Use managed services to benefit from AWS efficiency at scale.

## Using the Well-Architected Tool

The AWS Well-Architected Tool in the AWS Management Console helps you review your workloads against best practices. Key workflow:

1. Define your workload and its components
2. Answer questions for each applicable pillar
3. Review identified high-risk issues (HRIs) and medium-risk issues (MRIs)
4. Create an improvement plan with prioritized actions
5. Track progress over milestones
6. Re-assess periodically (recommended: quarterly)

### Lenses

In addition to the base framework, AWS provides focused lenses:
- **Serverless Lens**: Best practices for serverless workloads
- **SaaS Lens**: Multi-tenant SaaS architectures
- **Data Analytics Lens**: Analytics workloads
- **Machine Learning Lens**: ML model training and inference
- **IoT Lens**: Internet of Things workloads
- **Financial Services Lens**: Regulatory requirements
- **Container Build Lens**: Containerized workloads
- **Games Industry Lens**: Gaming workloads

Custom lenses can be created for organization-specific standards and shared across AWS accounts.

## Architecture Review Process

A Well-Architected review should be a collaborative, non-adversarial process:

1. Gather the team that designed and operates the workload
2. Walk through each pillar systematically
3. Focus on understanding why decisions were made, not assigning blame
4. Document risks and improvement actions
5. Prioritize improvements based on business impact
6. Implement improvements iteratively
7. Re-review after significant changes or at regular intervals

Reviews should be integrated into the development lifecycle, not treated as one-time audits. The goal is continuous improvement, not achieving a passing score.
