---
framework: "Observability"
version: "1.0"
domain: "DevOps"
agent: "friday"
tags: ["observability", "logging", "metrics", "tracing", "opentelemetry", "sli", "slo", "alerting"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Observability

## Three Pillars of Observability

Observability is the ability to understand the internal state of a system by examining its external outputs. The three pillars are logs, metrics, and traces. Each provides a different lens into system behavior; together they enable comprehensive debugging and monitoring.

**Logs:** Discrete events with timestamps and context. Answer "what happened?" Useful for debugging specific requests, auditing, and understanding error details.

**Metrics:** Numeric measurements aggregated over time. Answer "how is the system performing overall?" Efficient for dashboards, alerting, and capacity planning.

**Traces:** Records of a request's journey through distributed services. Answer "where did the time go?" Essential for debugging latency issues across service boundaries.

## OpenTelemetry

OpenTelemetry (OTel) is the vendor-neutral observability framework for generating, collecting, and exporting telemetry data (traces, metrics, logs). It provides APIs, SDKs, and the Collector.

**Architecture:**

- **API:** Defines how to create spans, metrics, and log records. Vendor-neutral. Application code depends only on the API.
- **SDK:** Implements the API. Configures exporters, samplers, and processors. Swappable at deployment time.
- **Collector:** A standalone service that receives, processes, and exports telemetry data. Can run as a sidecar or centralized gateway.

**Instrumentation:**

```python
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

# Setup
provider = TracerProvider()
processor = BatchSpanProcessor(OTLPSpanExporter(endpoint="http://collector:4317"))
provider.add_span_processor(processor)
trace.set_tracer_provider(provider)

tracer = trace.get_tracer("my-service")

# Manual instrumentation
@tracer.start_as_current_span("process_order")
def process_order(order_id: str) -> None:
    span = trace.get_current_span()
    span.set_attribute("order.id", order_id)
    span.set_attribute("order.type", "standard")

    try:
        validate_order(order_id)
        charge_payment(order_id)
    except Exception as e:
        span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
        span.record_exception(e)
        raise
```

**Auto-instrumentation:** OTel provides auto-instrumentation for common libraries (HTTP clients, database drivers, message queues). Install the instrumentation package and it automatically creates spans for each operation without code changes.

**Collector configuration:**

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318

processors:
  batch:
    timeout: 5s
    send_batch_size: 1024
  memory_limiter:
    check_interval: 1s
    limit_mib: 512

exporters:
  otlp:
    endpoint: tempo:4317
    tls:
      insecure: true
  prometheus:
    endpoint: 0.0.0.0:8889

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [otlp]
    metrics:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [prometheus]
```

## Structured Logging

Structured logging outputs log records as key-value pairs (typically JSON) rather than free-form text. This enables efficient querying, filtering, and aggregation.

**Best practices:**

```json
{
  "timestamp": "2024-03-15T10:30:00.123Z",
  "level": "error",
  "message": "Failed to process payment",
  "service": "payment-service",
  "version": "1.2.3",
  "trace_id": "abc123def456",
  "span_id": "789ghi",
  "request_id": "req_xyzzy",
  "user_id": "usr_12345",
  "error": {
    "type": "PaymentDeclinedError",
    "message": "Insufficient funds",
    "stack_trace": "..."
  },
  "payment": {
    "amount": 99.99,
    "currency": "USD",
    "method": "credit_card"
  }
}
```

**Log levels and when to use them:**

- **TRACE:** Fine-grained debugging. Disabled in production.
- **DEBUG:** Diagnostic information for developers. Disabled in production by default; enable per-service for debugging.
- **INFO:** Normal operational events. Service started, request processed, job completed. Active in production.
- **WARN:** Unexpected but recoverable situations. Retry succeeded, deprecated feature used, approaching resource limits.
- **ERROR:** Operation failed but the service continues running. Payment declined, external service unavailable.
- **FATAL:** Service is crashing. Unrecoverable errors. Used sparingly.

**Correlation:** Include `trace_id`, `span_id`, and `request_id` in every log entry. This links logs to traces and enables filtering all logs for a specific request across services.

**Do not log:** Passwords, API keys, tokens, credit card numbers, PII (or encrypt/redact before logging). Use a log sanitization library or scrubbing pipeline.

## Metric Types

Metrics are numeric measurements collected over time. Understanding metric types is essential for correct instrumentation and alerting.

**Counter:** A monotonically increasing value. Reset only when the process restarts. Use for request counts, error counts, bytes sent. Query with `rate()` or `increase()` to get per-second rates.

```
http_requests_total{method="GET", path="/api/users", status="200"} 15234
http_requests_total{method="GET", path="/api/users", status="500"} 12
```

**Gauge:** A value that can go up or down. Use for current values: queue depth, active connections, memory usage, temperature.

```
active_connections{service="api"} 142
memory_usage_bytes{service="api"} 536870912
```

**Histogram:** Samples observations and counts them in configurable buckets. Use for request latencies, response sizes, anything where distribution matters. Enables percentile calculations (p50, p95, p99).

```
http_request_duration_seconds_bucket{le="0.01"} 5000
http_request_duration_seconds_bucket{le="0.05"} 12000
http_request_duration_seconds_bucket{le="0.1"} 14500
http_request_duration_seconds_bucket{le="0.5"} 15100
http_request_duration_seconds_bucket{le="1.0"} 15200
http_request_duration_seconds_bucket{le="+Inf"} 15234
http_request_duration_seconds_sum 1523.4
http_request_duration_seconds_count 15234
```

**Summary:** Similar to histogram but calculates quantiles on the client side. Not aggregatable across instances. Prefer histograms in most cases.

**Naming conventions (Prometheus):** Use `snake_case`. Include the unit as a suffix: `_seconds`, `_bytes`, `_total` (for counters). Prefix with the subsystem: `http_`, `db_`, `queue_`.

## Distributed Tracing

Distributed tracing follows a request through multiple services, creating a tree of spans that shows the timing and relationships of operations.

**Key concepts:**

- **Trace:** The complete journey of a request, identified by a unique trace ID.
- **Span:** A single operation within a trace. Has a name, start time, duration, status, attributes, and events.
- **Parent-child relationship:** Spans form a tree. A span can have one parent and multiple children.
- **Context propagation:** The trace ID and span ID are propagated across service boundaries through HTTP headers (`traceparent`, `tracestate` in W3C Trace Context) or message metadata.

**Sampling strategies:**

- **Head-based sampling:** Decide at the start of the trace whether to sample it. Simple but cannot consider the outcome (you might drop an interesting error trace).
- **Tail-based sampling:** Collect all spans, then decide whether to keep the trace after it completes. Can sample based on duration, error status, or specific attributes. Requires a collector that buffers complete traces. More expensive but keeps interesting traces.
- **Rate-based:** Sample a fixed number of traces per second. Ensures consistent load on the tracing backend.

**Common span attributes:**

```
http.method: "POST"
http.url: "https://api.example.com/orders"
http.status_code: 201
db.system: "postgresql"
db.statement: "SELECT * FROM users WHERE id = $1"
messaging.system: "kafka"
messaging.destination: "order-events"
```

## SLIs, SLOs, and SLAs

Service Level Indicators (SLIs), Service Level Objectives (SLOs), and Service Level Agreements (SLAs) form a hierarchy for measuring and committing to service reliability.

**SLI (Service Level Indicator):** A quantitative measure of some aspect of the level of service being provided. Examples: request latency, error rate, throughput, availability.

**Good SLI examples:**

- Availability: proportion of successful requests (status != 5xx) / total requests
- Latency: proportion of requests served faster than a threshold (e.g., < 200ms)
- Correctness: proportion of requests that return the correct result

**SLO (Service Level Objective):** A target value or range for an SLI over a time window. Examples: 99.9% of requests succeed over a 30-day rolling window. 95% of requests complete in under 200ms.

**Error budget:** The allowed amount of unreliability. If the SLO is 99.9% availability over 30 days, the error budget is 0.1% = ~43 minutes of downtime. When the error budget is exhausted, prioritize reliability work over features.

**SLA (Service Level Agreement):** A contractual commitment. SLAs should be less aggressive than SLOs. If your SLO is 99.9%, your SLA might be 99.5%. The gap gives you room to meet contractual obligations while alerting on the tighter internal target.

**Burn rate alerting:** Instead of alerting when the SLO is breached (too late), alert when the error budget is being consumed too quickly. A burn rate of 1x means you will exactly exhaust the budget by the end of the window. Alert on high burn rates (e.g., 14.4x over 1 hour for a 30-day window) to catch fast-burning incidents, and moderate burn rates (e.g., 6x over 6 hours) to catch slow-burning issues.

## Alerting Strategies

**Alert on symptoms, not causes:** Alert on "users are experiencing errors" (5xx rate above threshold), not "CPU usage is high" (which may or may not affect users).

**Alert levels:**

- **Page (wake someone up):** Service is significantly impaired. Users are affected. Error budget is burning fast. Requires immediate human attention.
- **Ticket:** Something needs attention but is not urgent. Elevated error rates that are within error budget. Capacity trending toward limits.
- **Log/dashboard only:** Informational. No immediate action needed.

**Reducing alert fatigue:**

- Tune thresholds to minimize false positives. An alert that fires and requires no action should be fixed or deleted.
- Use multi-window, multi-burn-rate alerting instead of simple threshold alerts.
- Deduplicate alerts from the same incident.
- Route alerts to the right team based on service ownership.
- Review alert quality regularly: for each alert that fired, ask whether it was actionable and timely.

**Tools:** Prometheus Alertmanager, Grafana Alerting, PagerDuty, OpsGenie, Datadog Monitors. Use runbooks linked from alerts to provide context and resolution steps.
