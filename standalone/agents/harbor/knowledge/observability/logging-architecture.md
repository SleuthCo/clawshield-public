---
framework: "Logging Architecture"
version: "1.0"
domain: "Observability"
agent: "nimbus"
tags: ["logging", "elk", "loki", "cloudwatch-logs", "structured-logging", "compliance"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Logging Architecture

Centralized logging is essential for debugging, security monitoring, compliance, and operational awareness. This document covers logging patterns, tooling, structured logging standards, retention policies, and compliance considerations.

## Centralized Logging Patterns

### Collection Architecture

All logging architectures follow a common pattern: collect logs from sources, process/enrich them, store them in a centralized system, and provide query/analysis capabilities.

**Agent-Based Collection**:
- Deploy a log shipping agent on every compute instance or as a sidecar/daemonset in Kubernetes
- Agents: Fluent Bit (lightweight, preferred for Kubernetes), Fluentd (flexible, plugin-rich), CloudWatch Agent (AWS), Azure Monitor Agent (Azure), Ops Agent (GCP), Vector (high-performance)
- Agents tail log files, parse and enrich records, buffer for reliability, and forward to the destination

**Sidecar Pattern (Kubernetes)**:
- Application writes logs to a shared emptyDir volume
- Log shipping sidecar container reads from the volume and forwards to the logging backend
- Use when: application cannot write to stdout/stderr, needs preprocessing before shipping

**DaemonSet Pattern (Kubernetes, Preferred)**:
- Log shipping agent runs as a DaemonSet (one pod per node)
- Reads container logs from the node filesystem (/var/log/containers/)
- More efficient than sidecar (one agent per node vs one per pod)
- Use Fluent Bit DaemonSet with output plugins for your backend (Elasticsearch, Loki, CloudWatch, etc.)

**Direct Integration**:
- Applications send logs directly to the logging backend via SDK or API
- Simplest architecture but creates tight coupling between application and logging backend
- Acceptable for serverless (Lambda, Cloud Functions) where agent deployment is not possible

## ELK/EFK Stack

### Elasticsearch, Logstash/Fluentd, Kibana

The ELK stack (or EFK when using Fluentd/Fluent Bit instead of Logstash) is the most widely deployed open-source logging solution.

**Elasticsearch**:
- Distributed search and analytics engine based on Apache Lucene
- Stores and indexes log data for fast full-text search and aggregation
- Scales horizontally with data nodes, master nodes, and coordinating nodes
- Index lifecycle management (ILM): automatically roll over, shrink, and delete indices based on age or size
- Data tiers: hot (fast SSDs for recent data), warm (slower storage for older data), cold (cheapest storage for archived data), frozen (searchable snapshots)

**Logstash** (Alternative: Fluentd/Fluent Bit):
- Log processing pipeline: input, filter, output stages
- Parse unstructured logs into structured fields
- Enrich logs with additional context (GeoIP, DNS lookup, external data)
- Transform and normalize log formats across different sources
- Fluent Bit is preferred for Kubernetes due to lower resource footprint

**Kibana**:
- Visualization and exploration interface for Elasticsearch
- Discover: Search and filter log records
- Dashboards: Visualize log patterns, error trends, and operational metrics
- Lens: Drag-and-drop visualization builder
- Alerting: Rules-based alerting on log patterns and aggregations
- Security: Role-based access control and space-based multi-tenancy

### OpenSearch

OpenSearch is the open-source fork of Elasticsearch (post-license change). API-compatible with Elasticsearch 7.x. Available as a managed service on AWS (Amazon OpenSearch Service).

- Drop-in replacement for Elasticsearch for most use cases
- OpenSearch Dashboards replaces Kibana
- Additional features: Anomaly Detection, SQL query support, Piped Processing Language (PPL)
- AWS OpenSearch Serverless: Serverless deployment with automatic scaling and no cluster management

## Grafana Loki

Loki is a log aggregation system designed to be cost-effective and easy to operate. Unlike Elasticsearch, Loki does not index the full content of logs. It indexes only metadata (labels) and stores compressed log content.

### Architecture

- **Distributor**: Receives log streams, validates, and routes to ingesters
- **Ingester**: Batches log streams in memory and flushes compressed chunks to object storage
- **Query Frontend/Scheduler**: Splits and schedules queries for parallel execution
- **Querier**: Executes queries against ingesters (recent data) and object storage (older data)
- **Compactor**: Compacts index files and applies retention policies

### Key Advantages

- **Cost**: 10-100x cheaper than Elasticsearch for the same data volume. Stores log data in object storage (S3, GCS, Azure Blob).
- **Simplicity**: No index management. No data tier management. Scales horizontally.
- **Label-Based**: Queries use labels to select log streams, then grep/regex to search within those streams. LogQL query language is similar to PromQL.
- **Grafana Integration**: Native Grafana data source. Correlate logs with metrics and traces in a single pane.

### When to Use Loki vs Elasticsearch

- **Loki**: Cost-sensitive environments, Grafana-centric observability stack, Kubernetes-native workloads, when log volume is high but querying is occasional, when label-based querying is sufficient.
- **Elasticsearch**: Need for full-text search across all log fields, complex aggregations and analytics, existing Elasticsearch expertise, compliance requirements for specific search capabilities.

## Cloud-Native Logging Services

### AWS CloudWatch Logs

- **Log Groups and Streams**: Organize logs by application/service (groups) and source instance (streams)
- **Insights**: SQL-like query language for searching and analyzing logs. Supports aggregation, filtering, and visualization.
- **Metric Filters**: Create CloudWatch metrics from log patterns (e.g., count ERROR occurrences, extract latency values)
- **Subscription Filters**: Stream logs in real-time to Lambda, Kinesis, or OpenSearch for processing
- **Cross-Account**: Centralize logs from multiple accounts using cross-account log delivery or organization-level logging
- **Retention**: Configurable per log group (1 day to 10 years, or indefinite). Set retention policies to control costs.

### Azure Monitor Logs (Log Analytics)

- **Workspaces**: Centralized log repository. One workspace per environment or region is common.
- **KQL**: Kusto Query Language for powerful log querying. Supports joins, time series analysis, rendering, and machine learning functions.
- **Data Collection Rules**: Configure which logs to collect and where to send them. Transformation at collection time to filter and reshape data.
- **Basic Logs**: Lower-cost tier for verbose, high-volume logs that are queried infrequently. Limited query capabilities.
- **Archive**: Move old logs to archive tier for long-term retention at minimal cost. Restore on demand.
- **Sentinel Integration**: Same Log Analytics workspace can serve both operational monitoring and security analytics (Sentinel).

### GCP Cloud Logging

- **Log Explorer**: Search and analyze logs with a powerful query language
- **Log Router**: Routes log entries to destinations (Cloud Storage, BigQuery, Pub/Sub, Cloud Logging buckets, Splunk)
- **Log Buckets**: Storage containers for logs with configurable retention (1-3650 days). Default bucket retains for 30 days.
- **Log Analytics**: SQL-based querying powered by BigQuery. Available on log buckets upgraded for analytics.
- **Exclusion Filters**: Reduce costs by excluding verbose, low-value logs from ingestion

## Structured Logging Standards

### JSON Structured Logging

All applications should emit logs as structured JSON for reliable parsing and querying. Unstructured text logs require fragile regex parsing and lose queryability.

**Standard Fields**:
```json
{
    "timestamp": "2025-01-15T10:30:45.123Z",
    "level": "ERROR",
    "message": "Failed to process payment",
    "service": "payment-service",
    "version": "2.1.0",
    "environment": "production",
    "trace_id": "abc123def456",
    "span_id": "789ghi012",
    "request_id": "req-uuid-1234",
    "user_id": "user-5678",
    "error": {
        "type": "PaymentGatewayException",
        "message": "Connection timeout",
        "stack_trace": "..."
    },
    "context": {
        "order_id": "ord-9012",
        "amount": 99.99,
        "currency": "USD"
    }
}
```

### Field Naming Conventions

- Use snake_case for field names (consistent with most logging frameworks)
- Use ISO 8601 for timestamps with timezone (UTC preferred)
- Include correlation IDs (trace_id, request_id) for distributed tracing correlation
- Use consistent field names across all services for cross-service querying
- Publish a logging schema document that all teams follow

## Log Levels

### Standard Levels and Usage

- **TRACE**: Finest-grained diagnostic information. Function entry/exit, variable values. Disabled in production.
- **DEBUG**: Detailed diagnostic information for debugging. Internal state, decision branches. Disabled in production by default. Enable per-service for troubleshooting.
- **INFO**: Normal operational events. Service started, request processed, job completed. The default production level.
- **WARN**: Unexpected situations that are handled but might indicate problems. Degraded performance, retry attempts, deprecated API usage.
- **ERROR**: Unhandled errors that affect a single operation but do not crash the service. Failed request, database query error, external service failure.
- **FATAL/CRITICAL**: Unrecoverable errors requiring immediate attention. Service cannot start, critical dependency unavailable, data corruption detected.

### Level Configuration Best Practices

- Default to INFO in production
- Use environment variables or feature flags to dynamically change log levels without redeployment
- Enable DEBUG temporarily for specific services during incident investigation
- Log security events (authentication failures, authorization denials) at WARN or higher
- Never log sensitive data (passwords, tokens, PII) at any level

## Log Retention Policies

### Retention Tiers

| Category | Hot Storage | Warm Storage | Cold/Archive | Total Retention |
|----------|-------------|--------------|--------------|-----------------|
| Application Logs | 7-30 days | 30-90 days | 90-365 days | 1 year |
| Security/Audit Logs | 30-90 days | 90-365 days | 1-7 years | 3-7 years |
| Access Logs | 7-30 days | 30-90 days | 90-365 days | 1-3 years |
| Debug Logs | 1-7 days | N/A | N/A | 7 days |
| Compliance Logs (PCI/HIPAA) | 90 days | 1 year | 1-7 years | 7 years |

### Cost Optimization

- Move logs between storage tiers based on age and access patterns
- Use log exclusion filters to drop verbose, low-value log lines before ingestion
- Sample high-volume logs (debug, trace) rather than collecting every record
- Compress logs in cold storage (most tools do this automatically)
- Delete logs promptly when retention period expires (do not keep data indefinitely without a business reason)

## Compliance Logging

### Audit Log Requirements

- **Immutability**: Audit logs must be tamper-proof. Use S3 Object Lock (WORM), Azure Immutable Blob Storage, or GCS Bucket Lock.
- **Completeness**: Capture all relevant events. Enable CloudTrail (all regions, all accounts), Azure Activity Log, GCP Cloud Audit Logs.
- **Access Control**: Restrict who can read and who can delete audit logs. Separate logging account with restricted access.
- **Retention**: Meet regulatory requirements. PCI DSS requires 1 year (3 months readily available). HIPAA requires 6 years. SOX requires 7 years.

### Centralized Logging Account Pattern

1. Create a dedicated logging/security account in your cloud organization
2. Route all audit logs (CloudTrail, Activity Logs, Cloud Audit Logs) to this account
3. Store in object storage with immutability locks and encryption
4. Restrict access to security and compliance teams only
5. Enable cross-account log querying for authorized investigators
6. Apply lifecycle policies for tiered storage (hot to cold to archive)

## Log-Based Alerting

### Patterns

- **Error Rate Threshold**: Alert when the rate of ERROR-level logs exceeds a threshold (e.g., more than 10 errors per minute for a service)
- **Pattern Matching**: Alert on specific log patterns indicating critical issues (OutOfMemoryError, database connection pool exhausted, certificate expiration warning)
- **Absence Detection**: Alert when expected periodic log entries stop appearing (heartbeat logs, scheduled job completion logs)
- **Anomaly Detection**: ML-based detection of unusual log patterns or volumes (AWS CloudWatch Logs Anomaly Detection, Elastic ML)

### Best Practices

- Prefer metric-based alerting over log-based alerting for golden signals (metrics are cheaper to query and lower latency)
- Use log-based alerting for specific error patterns and business events that are not captured in metrics
- Include the log query in the alert notification so responders can immediately investigate
- Link alerts to runbooks with specific diagnostic and remediation steps
