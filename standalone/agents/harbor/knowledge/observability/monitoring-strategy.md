---
framework: "Monitoring Strategy"
version: "1.0"
domain: "Observability"
agent: "nimbus"
tags: ["monitoring", "metrics", "prometheus", "grafana", "cloudwatch", "golden-signals"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Monitoring Strategy

Effective monitoring is the foundation of operational excellence. This document covers monitoring methodologies (golden signals, USE, RED), tooling (Prometheus, Grafana, cloud-native services), custom metrics, alerting, and dashboarding best practices.

## Golden Signals

The four golden signals, defined by Google's Site Reliability Engineering (SRE) book, are the most important metrics for monitoring user-facing systems.

### Latency

The time it takes to service a request. Measure both successful and failed request latency separately, as failed requests may be fast (immediate error) or slow (timeout).

**What to Measure**:
- P50 (median): Typical user experience
- P95: The experience of the majority of users
- P99: Tail latency affecting 1% of users. Critical for high-traffic services.
- P99.9: Extreme tail. Important for services with strict SLAs.

**Best Practices**:
- Measure latency at the edge (load balancer) and at each service boundary
- Use histograms (not averages) to understand latency distributions. Averages hide bimodal distributions and tail latency.
- Set SLOs on percentile latency (e.g., P99 < 200ms)
- Alert on sustained latency increases, not individual spikes

### Traffic

The amount of demand placed on the system. The specific metric depends on the service type.

**Examples**:
- HTTP services: Requests per second (RPS), by endpoint and status code
- Database: Queries per second, transactions per second
- Message queue: Messages published/consumed per second
- Streaming: Bytes per second, events per second

### Errors

The rate of requests that fail. Includes explicit errors (HTTP 5xx) and implicit errors (HTTP 200 with wrong content, responses exceeding latency SLO).

**What to Measure**:
- Error rate: Errors / Total requests. Express as a percentage.
- Error rate by type: 4xx (client errors) vs 5xx (server errors). 4xx may indicate client issues or API misuse. 5xx indicates server-side failures.
- Error budget: 1 - SLO. Example: 99.9% availability = 0.1% error budget = 43.2 minutes of downtime per month.

### Saturation

How full the service is. The measure of resource utilization approaching capacity limits.

**What to Measure**:
- CPU utilization (percentage of available CPU)
- Memory utilization (percentage of available memory)
- Disk I/O utilization (IOPS, throughput as percentage of capacity)
- Network bandwidth utilization
- Connection pool utilization (database connections, HTTP client connections)
- Queue depth (messages waiting to be processed)
- Thread pool utilization

## USE Method

The USE method (Utilization, Saturation, Errors) is designed for analyzing infrastructure and hardware resource performance. Apply it to every resource in the system.

### For Each Resource

- **Utilization**: The average time a resource is busy servicing work. Example: CPU utilization at 75% means the CPU is busy 75% of the time.
- **Saturation**: The degree to which a resource has extra work that it cannot service, often queued. Example: CPU run queue length. Saturation indicates the resource is a bottleneck.
- **Errors**: The count of error events for the resource. Example: disk errors, network interface errors, memory ECC errors.

### Applying USE to Cloud Resources

| Resource | Utilization | Saturation | Errors |
|----------|-------------|------------|--------|
| CPU | % CPU time | Run queue length, load average | Machine check exceptions |
| Memory | % memory used | Swap usage, OOM events | Memory errors |
| Network | Bytes/packets per second | Dropped packets, retransmits | Interface errors, CRC |
| Disk | % I/O time, IOPS | Queue depth, wait time | Read/write errors |
| GPU | % GPU utilization | Memory utilization | ECC errors |

## RED Method

The RED method (Rate, Errors, Duration) is designed for monitoring request-driven microservices. It aligns with the golden signals but is specifically scoped to service-level metrics.

### For Each Service

- **Rate**: Number of requests per second the service is handling
- **Errors**: Number of failed requests per second
- **Duration**: Distribution of response times (histogram)

The RED method is simpler than the golden signals and is a practical starting point for microservice monitoring. Every service should expose at minimum these three metric types.

## Prometheus and Grafana

### Prometheus

Prometheus is the CNCF-graduated monitoring system and time series database. It is the de facto standard for Kubernetes and cloud-native monitoring.

**Architecture**:
- Pull-based model: Prometheus scrapes metrics from HTTP endpoints at configured intervals
- Time series database: Stores metrics with labels (key-value pairs) for flexible querying
- PromQL: Powerful query language for aggregation, filtering, and computation
- Alertmanager: Handles alert routing, grouping, deduplication, and silencing

**Metric Types**:
- **Counter**: Monotonically increasing value. Use for: total requests, total errors, total bytes processed. Query rate of change with `rate()`.
- **Gauge**: Value that can go up and down. Use for: current temperature, memory usage, active connections, queue depth.
- **Histogram**: Samples observations and counts them in configurable buckets. Use for: request duration, response size. Enables percentile calculation.
- **Summary**: Similar to histogram but calculates quantiles on the client side. Less flexible for aggregation. Prefer histograms for most use cases.

**Best Practices**:
- Use consistent naming conventions: `{namespace}_{subsystem}_{name}_{unit}` (e.g., `http_requests_total`, `http_request_duration_seconds`)
- Use labels judiciously. High cardinality labels (user_id, request_id) cause excessive time series and memory usage. Keep label cardinality below 100 per metric.
- Configure appropriate scrape intervals (15-30 seconds for most workloads)
- Use recording rules to pre-compute expensive queries for dashboard performance
- Implement federation or remote write for multi-cluster setups. Thanos or Cortex/Mimir for long-term storage and global querying.

### Grafana

Grafana is the standard visualization platform for observability data.

**Key Capabilities**:
- **Data Sources**: Prometheus, CloudWatch, Azure Monitor, Cloud Monitoring, Elasticsearch, Loki, Tempo, and 100+ more
- **Dashboards**: Rich visualization with time series, tables, heatmaps, stat panels, logs panels, trace panels
- **Alerting**: Unified alerting across data sources. Contact points for Slack, PagerDuty, OpsGenie, email, webhooks
- **Explore**: Ad-hoc querying for investigation and troubleshooting
- **Dashboard as Code**: Export dashboards as JSON. Use Grafonnet (Jsonnet) or Terraform provider for version-controlled dashboards.

## Cloud-Native Monitoring Services

### AWS CloudWatch

- **Metrics**: Built-in metrics for all AWS services. Custom metrics via PutMetricData API or CloudWatch Agent. Metric Math for computed metrics. Anomaly Detection using ML.
- **Alarms**: Threshold-based, anomaly detection-based, and composite alarms. Actions: SNS notification, Auto Scaling, EC2 actions, Systems Manager.
- **Dashboards**: Custom dashboards with metrics, logs, and alarms. Cross-account and cross-region dashboards.
- **CloudWatch Agent**: Collect system-level metrics (memory, disk) and application logs from EC2, ECS, and on-premises servers. Unified agent for metrics and logs.
- **Container Insights**: Monitoring for EKS, ECS, and Fargate. Cluster, node, pod, and container-level metrics.
- **Application Signals (Preview)**: APM-like experience for application monitoring with SLO tracking.

### Azure Monitor

- **Metrics**: Platform metrics (automatic) and custom metrics. Metrics Explorer for visualization. Multi-resource metric alerts.
- **Log Analytics**: Centralized log repository using KQL (Kusto Query Language) for querying. Supports cross-workspace queries.
- **Application Insights**: Full APM with auto-instrumentation for .NET, Java, Node.js, Python. Distributed tracing, dependency mapping, live metrics, and availability tests.
- **Alerts**: Metric alerts, log alerts, activity log alerts, and smart detection. Action groups for notification and automation (Logic Apps, Azure Functions, webhooks, ITSM).
- **Workbooks**: Interactive reports combining metrics, logs, and text. Templates for common scenarios.
- **Azure Managed Grafana**: Fully managed Grafana with Azure Monitor, Azure Data Explorer, and Prometheus data source integration.

### GCP Cloud Monitoring

- **Metrics**: Built-in metrics for all GCP services. Custom metrics via the Monitoring API or OpenTelemetry. MQL (Monitoring Query Language) and PromQL support.
- **Dashboards**: Custom dashboards. Pre-built dashboards for GCP services.
- **Alerting**: Metric threshold, absence, and forecast alerts. Notification channels: email, Slack, PagerDuty, webhooks, Pub/Sub.
- **Uptime Checks**: Availability monitoring from global locations. TCP, HTTP, and HTTPS checks.
- **Managed Prometheus**: Fully managed Prometheus with global querying. PromQL support. Compatible with existing Prometheus exporters and Grafana dashboards.

## Custom Metrics

### Application-Level Metrics

Instrument applications to expose business and operational metrics beyond what infrastructure monitoring provides.

**Business Metrics**:
- Orders per minute, revenue per hour
- User registrations, active sessions
- Feature usage counts
- Cart abandonment rate

**Application Metrics**:
- Request rate, error rate, and duration per endpoint (RED)
- Database query duration and count per query type
- Cache hit/miss ratio
- External API call duration and error rate
- Queue processing rate and lag
- Circuit breaker state changes

### Instrumentation Libraries

- **OpenTelemetry SDK**: The standard for instrumentation. Supports metrics, traces, and logs. Libraries for all major languages. Vendor-neutral: export to Prometheus, CloudWatch, Azure Monitor, Cloud Monitoring, or any OTLP-compatible backend.
- **Prometheus Client Libraries**: Native Prometheus instrumentation for Go, Java, Python, Ruby, .NET. Expose a /metrics endpoint.
- **Micrometer (Java)**: Vendor-neutral metrics facade for the JVM. Backends for Prometheus, CloudWatch, Azure Monitor, Datadog, and more.
- **StatsD**: Simple UDP-based protocol for sending metrics. Language-agnostic. Good for legacy applications.

## Alerting Best Practices

### Alert Design

- **Alert on symptoms, not causes**: Alert on high error rate (symptom), not on high CPU (cause). Users care about service health, not individual resource health.
- **Set meaningful thresholds**: Use error budgets and SLOs to determine when to alert. Alert when the burn rate threatens the SLO, not on every transient spike.
- **Reduce noise**: Alert fatigue leads to ignored alerts. Every alert should be actionable. If an alert does not require human intervention, it should be automated or removed.
- **Use severity levels**: Critical (pages someone immediately, customer-impacting), Warning (investigate within business hours), Info (awareness only, no action needed).

### Multi-Window, Multi-Burn-Rate Alerts

Google SRE recommends alerting based on error budget burn rate over multiple time windows:
- **Fast burn (2% budget consumed in 1 hour)**: Pages immediately. Service is deteriorating rapidly.
- **Slow burn (5% budget consumed in 6 hours)**: Creates a ticket. Service is slowly degrading.

This approach provides early warning for rapid issues while avoiding false positives from brief transient spikes.

### On-Call Best Practices

- Limit on-call to 25% of an engineer's time (Google SRE recommendation)
- Provide runbooks for every alert with specific diagnostic steps and remediation actions
- Conduct blameless post-incident reviews for every page
- Track operational load metrics: pages per shift, time to acknowledge, time to resolve
- Automate recurring manual responses to reduce toil

## Dashboarding Best Practices

### Dashboard Hierarchy

1. **Executive Dashboard**: High-level service health. SLO compliance. Availability and error budget status. One per product or team.
2. **Service Dashboard**: Golden signals for a specific service. RED metrics per endpoint. Dependencies health. One per service.
3. **Infrastructure Dashboard**: USE metrics for compute, storage, network, and database resources. Capacity planning metrics. Per-cluster or per-environment.
4. **Debug Dashboard**: Detailed metrics for specific subsystems. Used during incident investigation. Per-component deep dives.

### Design Principles

- Use consistent color coding: green for healthy, yellow for warning, red for critical
- Show time context: use time selectors and compare with the same period last week
- Include annotations for deployments, incidents, and configuration changes
- Use template variables for environment, region, and service selection
- Place the most important panels at the top left (first thing seen)
- Limit panels per dashboard to 15-20 for readability and load performance
- Document the dashboard purpose and interpretation guidance in a text panel
