---
framework: "Distributed Tracing"
version: "1.0"
domain: "Observability"
agent: "nimbus"
tags: ["tracing", "opentelemetry", "jaeger", "zipkin", "xray", "sampling", "correlation"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Distributed Tracing

Distributed tracing tracks requests as they flow through a distributed system of microservices, message queues, and databases. It provides end-to-end visibility into request latency, error sources, and dependency relationships. This document covers OpenTelemetry instrumentation, context propagation, backends, sampling strategies, and correlation of telemetry signals.

## OpenTelemetry Instrumentation

OpenTelemetry (OTel) is the CNCF project that provides a single, vendor-neutral standard for traces, metrics, and logs. It is the convergence of OpenTracing and OpenCensus and is the recommended approach for all new instrumentation.

### Architecture

- **API**: Defines the interfaces for creating spans, setting attributes, and propagating context. Application code depends on the API.
- **SDK**: Implements the API. Configures span processors, samplers, and exporters. Initialized at application startup.
- **Exporters**: Send telemetry data to backends. OTLP (OpenTelemetry Protocol) is the native format. Exporters available for Jaeger, Zipkin, X-Ray, Cloud Trace, Datadog, and many others.
- **Collector**: Standalone process that receives, processes, and exports telemetry data. Runs as an agent (sidecar/DaemonSet) or gateway (centralized). Decouples applications from backends.

### Instrumentation Types

**Automatic (Zero-Code) Instrumentation**:
- Language agents that automatically instrument common libraries and frameworks
- Java: OpenTelemetry Java Agent (attach as -javaagent). Instruments Spring, gRPC, JDBC, HTTP clients, message brokers.
- Python: opentelemetry-instrument command. Instruments Flask, Django, requests, SQLAlchemy.
- Node.js: @opentelemetry/auto-instrumentations-node package. Instruments Express, Fastify, pg, mysql, redis.
- .NET: OpenTelemetry .NET Automatic Instrumentation. Instruments ASP.NET Core, HttpClient, SqlClient, gRPC.
- Go: Manual instrumentation required for most libraries due to the absence of a runtime agent. Instrumentation libraries wrap specific packages.

**Manual Instrumentation**:
- Create custom spans for business-critical operations not covered by auto-instrumentation
- Add attributes (tags) to spans for filtering and analysis
- Record events (logs) within spans for contextual information
- Set span status (OK, ERROR) with error messages

### Key Span Attributes

Standard semantic conventions define common attribute names:
- `http.method`, `http.url`, `http.status_code`: HTTP request attributes
- `db.system`, `db.statement`, `db.operation`: Database query attributes
- `messaging.system`, `messaging.operation`, `messaging.destination`: Message broker attributes
- `rpc.system`, `rpc.method`, `rpc.service`: RPC attributes
- `service.name`, `service.version`, `deployment.environment`: Resource attributes

Always set `service.name` as a resource attribute. This identifies which service a span belongs to and is the primary grouping field in all tracing backends.

## Trace Context Propagation

Context propagation carries trace identity (trace ID, span ID, sampling decision) across process boundaries (HTTP calls, message queues, async operations). Without correct propagation, traces break at service boundaries.

### W3C Trace Context

W3C Trace Context is the standard propagation format, supported by all modern tracing systems.

**Headers**:
- `traceparent`: Contains version, trace ID (32 hex chars), parent span ID (16 hex chars), and trace flags (sampling decision). Example: `00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01`
- `tracestate`: Vendor-specific trace context. Carries system-specific trace information alongside the standard traceparent.

### Other Propagation Formats

- **B3 (Zipkin)**: Legacy format. Uses `X-B3-TraceId`, `X-B3-SpanId`, `X-B3-ParentSpanId`, `X-B3-Sampled` headers. Or single-header format `b3`.
- **Jaeger**: Uses `uber-trace-id` header. Legacy format.
- **AWS X-Ray**: Uses `X-Amzn-Trace-Id` header. Format: `Root=1-{timestamp}-{random};Parent={parent_id};Sampled={0|1}`.

### Propagation Best Practices

- Use W3C Trace Context as the primary propagation format
- Configure composite propagators that support multiple formats for interoperability during migration
- Ensure message queues propagate context in message headers (not just HTTP calls)
- For async operations (Lambda, SQS, Kafka), store trace context in message attributes and extract on consumption
- Verify context propagation across every service boundary in your architecture. Broken propagation is the most common tracing issue.

## Tracing Backends

### Jaeger

Jaeger is a CNCF-graduated distributed tracing platform originally developed at Uber.

**Architecture**:
- Collector receives spans (via OTLP, Thrift, or gRPC)
- Storage backend: Cassandra, Elasticsearch, Kafka, or Badger (embedded)
- Query service and UI for trace search and visualization
- All-in-one binary for development and small deployments

**Key Features**:
- Service dependency graph showing relationships between services
- Trace comparison for comparing two traces side-by-side
- System architecture page showing live service topology
- Adaptive sampling for dynamic sampling decisions based on traffic patterns
- SPM (Service Performance Monitoring) for RED metrics derived from traces

### Zipkin

Zipkin is one of the original distributed tracing systems, created by Twitter based on the Google Dapper paper.

**Key Characteristics**:
- Simpler architecture than Jaeger (fewer components)
- Storage: Elasticsearch, Cassandra, MySQL, in-memory
- Web UI for trace search and visualization
- Dependency diagram showing service relationships
- Wide library support across languages

### Grafana Tempo

Grafana Tempo is a high-scale, cost-effective distributed tracing backend.

**Architecture**:
- Stores traces in object storage (S3, GCS, Azure Blob) with no external database dependency
- Does not index traces. Searches by trace ID (requires trace ID from logs or metrics). TraceQL enables search without knowing trace IDs.
- Extremely cost-effective for high-volume trace storage
- Native Grafana integration. Correlate traces with Loki logs and Prometheus metrics.
- Supports OTLP, Jaeger, Zipkin, and X-Ray trace formats for ingestion

## Cloud-Native Tracing Services

### AWS X-Ray

- Managed tracing service deeply integrated with AWS services
- Auto-instrumentation for Lambda, API Gateway, ECS, EKS, SNS, SQS, and more
- X-Ray SDK for custom instrumentation (being replaced by OpenTelemetry SDK with X-Ray exporter)
- Service Map: Visual representation of service dependencies with latency and error rates
- X-Ray Groups and Filter Expressions for organizing traces
- Insights: ML-based anomaly detection on trace data
- Integration with CloudWatch ServiceLens for unified observability

### GCP Cloud Trace

- Managed tracing service integrated with GCP services
- Automatic trace collection for App Engine, Cloud Run, Cloud Functions
- OpenTelemetry integration via Google Cloud exporter
- Trace analysis with latency reports and scatter plots
- Integration with Cloud Logging (correlated log entries in trace waterfall)

### Azure Application Insights (Distributed Tracing)

- Part of Azure Monitor's Application Insights
- Auto-instrumentation for .NET, Java, Node.js, Python
- Application Map: Visual topology of service dependencies
- End-to-end transaction details with correlated logs, metrics, and dependencies
- Smart Detection: ML-based anomaly detection
- OpenTelemetry SDK support with Azure Monitor exporter

## Sampling Strategies

Sampling determines which traces are recorded and which are discarded. With high-traffic services, recording every trace is cost-prohibitive and often unnecessary.

### Head-Based Sampling

The sampling decision is made at the beginning of the trace (at the entry point service) and propagated to all downstream services.

- **Probabilistic**: Sample a fixed percentage of traces (e.g., 1%, 10%). Simple and predictable. Downside: may miss rare but important traces (errors, high-latency requests).
- **Rate Limiting**: Sample a fixed number of traces per second (e.g., 10 traces/second). Provides consistent load regardless of traffic volume.

### Tail-Based Sampling

The sampling decision is made after the trace is complete, based on the full trace data. Requires a collector or buffer to hold complete traces before deciding.

- **Error-Based**: Always keep traces that contain errors. Discard most successful traces.
- **Latency-Based**: Always keep traces that exceed a latency threshold (e.g., P99). Capture slow requests regardless of overall sampling rate.
- **Attribute-Based**: Always keep traces matching specific criteria (specific user IDs, feature flags, request types).
- **Composite**: Combine multiple tail-sampling policies. Example: keep 100% of error traces + 100% of traces over 5 seconds + 1% of all other traces.

### OpenTelemetry Collector Tail Sampling

The OTel Collector supports tail-based sampling via the `tail_sampling` processor. Configure policies:

```yaml
processors:
  tail_sampling:
    decision_wait: 30s
    policies:
      - name: errors
        type: status_code
        status_code: {status_codes: [ERROR]}
      - name: slow-requests
        type: latency
        latency: {threshold_ms: 5000}
      - name: default
        type: probabilistic
        probabilistic: {sampling_percentage: 5}
```

### Sampling Best Practices

- Always record 100% of error traces and high-latency traces
- Use head-based sampling for development and low-traffic services
- Use tail-based sampling for production high-traffic services
- Configure the OpenTelemetry Collector (gateway mode) for centralized tail-based sampling
- Monitor the sampling rate itself to understand coverage. If you sample 1%, a trace appearing once might represent 100 actual occurrences.
- Communicate sampling rates in dashboards and alerts so operators understand the data is sampled

## Trace-Based Testing

### Trace-Driven Tests

Use production traces to generate realistic test scenarios. Replay recorded traces against staging environments to validate behavior under realistic traffic patterns.

### Contract Testing with Traces

Verify that services produce the expected spans and attributes. Check that:
- Expected spans are created for each service operation
- Required attributes are present on each span
- Span durations are within expected bounds
- Error statuses are correctly set for failure scenarios

### Performance Testing with Traces

- Use trace data to identify performance regressions in CI/CD
- Compare P95 latency of specific spans between the current and previous deployment
- Alert if critical path latency increases beyond a threshold

## Correlating Logs, Metrics, and Traces

The three pillars of observability are most powerful when correlated. A metric alert leads to relevant traces which lead to specific log entries.

### Correlation via Trace ID

- Include `trace_id` and `span_id` in every structured log entry
- Configure logging frameworks to automatically extract trace context from OpenTelemetry
- When investigating a trace, click through to see the logs for that specific request
- When viewing an error log, click through to see the full trace of the request that generated it

### Exemplars (Metrics to Traces)

Exemplars attach a trace ID to a specific metric data point. When viewing a metric spike in Grafana, exemplars provide direct links to representative traces.

- Prometheus supports exemplars on histograms and counters
- Grafana displays exemplars as dots on graphs. Click to navigate to the trace.
- OpenTelemetry SDK automatically records exemplars when both metrics and traces are configured

### Correlation Implementation

```
Alert fires (metric: error_rate > 5%)
  -> Dashboard shows metric spike with exemplar trace IDs
    -> Click exemplar to view full trace in Jaeger/Tempo
      -> Trace shows slow database call in payment-service
        -> Click log icon to view correlated logs for that span
          -> Log shows "Connection pool exhausted" error
```

### Tooling Support

- **Grafana**: Native correlation between Prometheus (metrics), Loki (logs), and Tempo (traces). Derived fields in Loki link log entries to traces. Exemplars in Prometheus link metrics to traces.
- **AWS**: CloudWatch ServiceLens correlates X-Ray traces, CloudWatch metrics, and CloudWatch Logs.
- **Azure**: Application Insights provides automatic correlation between traces, metrics, and logs using operation IDs.
- **GCP**: Cloud Trace and Cloud Logging correlate trace spans with log entries using trace ID and span ID fields.

### Best Practices for Correlation

- Use OpenTelemetry as the unified instrumentation framework for all three signals
- Ensure all services emit trace ID in logs (most OTel auto-instrumentation does this automatically)
- Use consistent service.name and deployment.environment labels across all signals
- Deploy the OpenTelemetry Collector to process and route all telemetry signals through a single pipeline
- Build dashboards that enable seamless navigation between metrics, traces, and logs
