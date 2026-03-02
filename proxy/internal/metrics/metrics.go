// Package metrics provides Prometheus-compatible metrics for ClawShield.
//
// This is a zero-dependency implementation that outputs metrics in
// Prometheus exposition format, without requiring the prometheus/client_golang
// library. Metrics are thread-safe and can be scraped via the /metrics endpoint.
package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Collector is the global metrics collector for ClawShield.
// It tracks request counts, decision outcomes, scanner detections,
// latencies, and system health.
type Collector struct {
	startTime time.Time

	// Request/decision counters
	totalRequests   atomic.Int64
	totalAllowed    atomic.Int64
	totalDenied     atomic.Int64
	totalRedacted   atomic.Int64

	// Scanner detection counters
	injectionBlocked atomic.Int64
	malwareBlocked   atomic.Int64
	vulnBlocked      atomic.Int64
	secretsBlocked   atomic.Int64
	secretsRedacted  atomic.Int64
	piiBlocked       atomic.Int64
	piiRedacted      atomic.Int64
	policyDenied     atomic.Int64

	// Response scanning
	responsesScanned atomic.Int64
	responsesBlocked atomic.Int64
	responsesRedacted atomic.Int64

	// Latency tracking (evaluation time in microseconds)
	mu               sync.Mutex
	latencyBuckets   [8]atomic.Int64 // <1ms, <5ms, <10ms, <25ms, <50ms, <100ms, <500ms, >=500ms
	latencySum       atomic.Int64
	latencyCount     atomic.Int64

	// Active connections
	activeConnections atomic.Int64

	// Cross-layer events (if event bus is enabled)
	crossLayerEventsReceived atomic.Int64
	crossLayerEventsSent     atomic.Int64
	adaptiveActionsTriggered atomic.Int64

	// Error counters
	evaluationTimeouts  atomic.Int64
	upstreamErrors      atomic.Int64

	// Custom labeled counters
	labeledMu      sync.RWMutex
	deniedByTool   map[string]*atomic.Int64
	deniedByReason map[string]*atomic.Int64
}

// New creates a new metrics collector.
func New() *Collector {
	return &Collector{
		startTime:      time.Now(),
		deniedByTool:   make(map[string]*atomic.Int64),
		deniedByReason: make(map[string]*atomic.Int64),
	}
}

// --- Increment Methods ---

// RecordRequest increments the total request counter.
func (c *Collector) RecordRequest() {
	c.totalRequests.Add(1)
}

// RecordAllow increments the allowed decision counter.
func (c *Collector) RecordAllow() {
	c.totalAllowed.Add(1)
}

// RecordDeny increments the denied decision counter with optional labels.
func (c *Collector) RecordDeny(tool, reason string) {
	c.totalDenied.Add(1)

	if tool != "" {
		c.labeledMu.Lock()
		counter, ok := c.deniedByTool[tool]
		if !ok {
			counter = &atomic.Int64{}
			c.deniedByTool[tool] = counter
		}
		c.labeledMu.Unlock()
		counter.Add(1)
	}

	if reason != "" {
		// Normalize reason to a short label
		label := normalizeReason(reason)
		c.labeledMu.Lock()
		counter, ok := c.deniedByReason[label]
		if !ok {
			counter = &atomic.Int64{}
			c.deniedByReason[label] = counter
		}
		c.labeledMu.Unlock()
		counter.Add(1)
	}
}

// RecordRedacted increments the redacted response counter.
func (c *Collector) RecordRedacted() {
	c.totalRedacted.Add(1)
}

// RecordInjectionBlocked increments the injection detection counter.
func (c *Collector) RecordInjectionBlocked() {
	c.injectionBlocked.Add(1)
}

// RecordMalwareBlocked increments the malware detection counter.
func (c *Collector) RecordMalwareBlocked() {
	c.malwareBlocked.Add(1)
}

// RecordVulnBlocked increments the vulnerability detection counter.
func (c *Collector) RecordVulnBlocked() {
	c.vulnBlocked.Add(1)
}

// RecordSecretsBlocked increments the secrets blocked counter.
func (c *Collector) RecordSecretsBlocked() {
	c.secretsBlocked.Add(1)
}

// RecordSecretsRedacted increments the secrets redacted counter.
func (c *Collector) RecordSecretsRedacted() {
	c.secretsRedacted.Add(1)
}

// RecordPIIBlocked increments the PII blocked counter.
func (c *Collector) RecordPIIBlocked() {
	c.piiBlocked.Add(1)
}

// RecordPIIRedacted increments the PII redacted counter.
func (c *Collector) RecordPIIRedacted() {
	c.piiRedacted.Add(1)
}

// RecordPolicyDenied increments the policy denied counter.
func (c *Collector) RecordPolicyDenied() {
	c.policyDenied.Add(1)
}

// RecordResponseScanned increments the responses scanned counter.
func (c *Collector) RecordResponseScanned() {
	c.responsesScanned.Add(1)
}

// RecordResponseBlocked increments the responses blocked counter.
func (c *Collector) RecordResponseBlocked() {
	c.responsesBlocked.Add(1)
}

// RecordResponseRedacted increments the responses redacted counter.
func (c *Collector) RecordResponseRedacted() {
	c.responsesRedacted.Add(1)
}

// RecordEvaluationLatency records an evaluation duration in the histogram.
func (c *Collector) RecordEvaluationLatency(d time.Duration) {
	us := d.Microseconds()
	c.latencySum.Add(us)
	c.latencyCount.Add(1)

	switch {
	case us < 1000: // <1ms
		c.latencyBuckets[0].Add(1)
	case us < 5000: // <5ms
		c.latencyBuckets[1].Add(1)
	case us < 10000: // <10ms
		c.latencyBuckets[2].Add(1)
	case us < 25000: // <25ms
		c.latencyBuckets[3].Add(1)
	case us < 50000: // <50ms
		c.latencyBuckets[4].Add(1)
	case us < 100000: // <100ms
		c.latencyBuckets[5].Add(1)
	case us < 500000: // <500ms
		c.latencyBuckets[6].Add(1)
	default: // >=500ms
		c.latencyBuckets[7].Add(1)
	}
}

// RecordEvaluationTimeout increments the timeout counter.
func (c *Collector) RecordEvaluationTimeout() {
	c.evaluationTimeouts.Add(1)
}

// RecordUpstreamError increments the upstream error counter.
func (c *Collector) RecordUpstreamError() {
	c.upstreamErrors.Add(1)
}

// ConnectionOpened increments the active connections gauge.
func (c *Collector) ConnectionOpened() {
	c.activeConnections.Add(1)
}

// ConnectionClosed decrements the active connections gauge.
func (c *Collector) ConnectionClosed() {
	c.activeConnections.Add(-1)
}

// RecordCrossLayerEventReceived increments the cross-layer events received counter.
func (c *Collector) RecordCrossLayerEventReceived() {
	c.crossLayerEventsReceived.Add(1)
}

// RecordCrossLayerEventSent increments the cross-layer events sent counter.
func (c *Collector) RecordCrossLayerEventSent() {
	c.crossLayerEventsSent.Add(1)
}

// RecordAdaptiveAction increments the adaptive actions triggered counter.
func (c *Collector) RecordAdaptiveAction() {
	c.adaptiveActionsTriggered.Add(1)
}

// --- Prometheus Exposition ---

// Handler returns an http.Handler that serves metrics in Prometheus exposition format.
func (c *Collector) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(c.Render()))
	})
}

// Render returns all metrics in Prometheus exposition format.
func (c *Collector) Render() string {
	var b strings.Builder

	// Uptime
	uptime := time.Since(c.startTime).Seconds()
	writeGauge(&b, "clawshield_uptime_seconds", "Time since proxy start in seconds", uptime)

	// Active connections
	writeGauge(&b, "clawshield_active_connections", "Number of active WebSocket connections", float64(c.activeConnections.Load()))

	// Request/decision totals
	writeCounter(&b, "clawshield_requests_total", "Total number of requests evaluated", c.totalRequests.Load())
	writeCounter(&b, "clawshield_decisions_allowed_total", "Total number of allowed decisions", c.totalAllowed.Load())
	writeCounter(&b, "clawshield_decisions_denied_total", "Total number of denied decisions", c.totalDenied.Load())
	writeCounter(&b, "clawshield_decisions_redacted_total", "Total number of redacted decisions", c.totalRedacted.Load())

	// Scanner detection counters
	b.WriteString("# HELP clawshield_scanner_detections_total Total detections by scanner type and action\n")
	b.WriteString("# TYPE clawshield_scanner_detections_total counter\n")
	writeLabeledCounter(&b, "clawshield_scanner_detections_total", map[string]string{"scanner": "injection", "action": "blocked"}, c.injectionBlocked.Load())
	writeLabeledCounter(&b, "clawshield_scanner_detections_total", map[string]string{"scanner": "malware", "action": "blocked"}, c.malwareBlocked.Load())
	writeLabeledCounter(&b, "clawshield_scanner_detections_total", map[string]string{"scanner": "vuln", "action": "blocked"}, c.vulnBlocked.Load())
	writeLabeledCounter(&b, "clawshield_scanner_detections_total", map[string]string{"scanner": "secrets", "action": "blocked"}, c.secretsBlocked.Load())
	writeLabeledCounter(&b, "clawshield_scanner_detections_total", map[string]string{"scanner": "secrets", "action": "redacted"}, c.secretsRedacted.Load())
	writeLabeledCounter(&b, "clawshield_scanner_detections_total", map[string]string{"scanner": "pii", "action": "blocked"}, c.piiBlocked.Load())
	writeLabeledCounter(&b, "clawshield_scanner_detections_total", map[string]string{"scanner": "pii", "action": "redacted"}, c.piiRedacted.Load())
	writeLabeledCounter(&b, "clawshield_scanner_detections_total", map[string]string{"scanner": "policy", "action": "denied"}, c.policyDenied.Load())

	// Response scanning
	writeCounter(&b, "clawshield_responses_scanned_total", "Total responses scanned", c.responsesScanned.Load())
	writeCounter(&b, "clawshield_responses_blocked_total", "Total responses blocked", c.responsesBlocked.Load())
	writeCounter(&b, "clawshield_responses_redacted_total", "Total responses redacted", c.responsesRedacted.Load())

	// Evaluation latency histogram
	b.WriteString("# HELP clawshield_evaluation_duration_seconds Evaluation latency in seconds\n")
	b.WriteString("# TYPE clawshield_evaluation_duration_seconds histogram\n")
	bucketBounds := []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5}
	cumulative := int64(0)
	for i, bound := range bucketBounds {
		cumulative += c.latencyBuckets[i].Load()
		fmt.Fprintf(&b, "clawshield_evaluation_duration_seconds_bucket{le=\"%.3f\"} %d\n", bound, cumulative)
	}
	cumulative += c.latencyBuckets[7].Load()
	fmt.Fprintf(&b, "clawshield_evaluation_duration_seconds_bucket{le=\"+Inf\"} %d\n", cumulative)
	fmt.Fprintf(&b, "clawshield_evaluation_duration_seconds_sum %.6f\n", float64(c.latencySum.Load())/1e6)
	fmt.Fprintf(&b, "clawshield_evaluation_duration_seconds_count %d\n", c.latencyCount.Load())

	// Error counters
	writeCounter(&b, "clawshield_evaluation_timeouts_total", "Total evaluation timeouts", c.evaluationTimeouts.Load())
	writeCounter(&b, "clawshield_upstream_errors_total", "Total upstream gateway errors", c.upstreamErrors.Load())

	// Cross-layer events
	writeCounter(&b, "clawshield_crosslayer_events_received_total", "Total cross-layer events received", c.crossLayerEventsReceived.Load())
	writeCounter(&b, "clawshield_crosslayer_events_sent_total", "Total cross-layer events sent", c.crossLayerEventsSent.Load())
	writeCounter(&b, "clawshield_adaptive_actions_total", "Total adaptive response actions triggered", c.adaptiveActionsTriggered.Load())

	// Denied by tool (labeled)
	c.labeledMu.RLock()
	if len(c.deniedByTool) > 0 {
		b.WriteString("# HELP clawshield_denied_by_tool_total Denied requests by tool name\n")
		b.WriteString("# TYPE clawshield_denied_by_tool_total counter\n")
		tools := sortedKeys(c.deniedByTool)
		for _, tool := range tools {
			writeLabeledCounter(&b, "clawshield_denied_by_tool_total", map[string]string{"tool": tool}, c.deniedByTool[tool].Load())
		}
	}

	if len(c.deniedByReason) > 0 {
		b.WriteString("# HELP clawshield_denied_by_reason_total Denied requests by reason category\n")
		b.WriteString("# TYPE clawshield_denied_by_reason_total counter\n")
		reasons := sortedKeys(c.deniedByReason)
		for _, reason := range reasons {
			writeLabeledCounter(&b, "clawshield_denied_by_reason_total", map[string]string{"reason": reason}, c.deniedByReason[reason].Load())
		}
	}
	c.labeledMu.RUnlock()

	return b.String()
}

// --- Snapshot for testing ---

// Snapshot returns a point-in-time copy of key metrics for testing and assertions.
type Snapshot struct {
	TotalRequests    int64
	TotalAllowed     int64
	TotalDenied      int64
	TotalRedacted    int64
	InjectionBlocked int64
	MalwareBlocked   int64
	VulnBlocked      int64
	SecretsBlocked   int64
	SecretsRedacted  int64
	PIIBlocked       int64
	PIIRedacted      int64
	PolicyDenied     int64
	EvalTimeouts     int64
	UpstreamErrors   int64
	ActiveConns      int64
	LatencyCount     int64
}

// Snapshot returns a point-in-time copy of key metrics.
func (c *Collector) Snapshot() Snapshot {
	return Snapshot{
		TotalRequests:    c.totalRequests.Load(),
		TotalAllowed:     c.totalAllowed.Load(),
		TotalDenied:      c.totalDenied.Load(),
		TotalRedacted:    c.totalRedacted.Load(),
		InjectionBlocked: c.injectionBlocked.Load(),
		MalwareBlocked:   c.malwareBlocked.Load(),
		VulnBlocked:      c.vulnBlocked.Load(),
		SecretsBlocked:   c.secretsBlocked.Load(),
		SecretsRedacted:  c.secretsRedacted.Load(),
		PIIBlocked:       c.piiBlocked.Load(),
		PIIRedacted:      c.piiRedacted.Load(),
		PolicyDenied:     c.policyDenied.Load(),
		EvalTimeouts:     c.evaluationTimeouts.Load(),
		UpstreamErrors:   c.upstreamErrors.Load(),
		ActiveConns:      c.activeConnections.Load(),
		LatencyCount:     c.latencyCount.Load(),
	}
}

// --- Helpers ---

func writeCounter(b *strings.Builder, name, help string, value int64) {
	fmt.Fprintf(b, "# HELP %s %s\n", name, help)
	fmt.Fprintf(b, "# TYPE %s counter\n", name)
	fmt.Fprintf(b, "%s %d\n", name, value)
}

func writeGauge(b *strings.Builder, name, help string, value float64) {
	fmt.Fprintf(b, "# HELP %s %s\n", name, help)
	fmt.Fprintf(b, "# TYPE %s gauge\n", name)
	fmt.Fprintf(b, "%s %.6f\n", name, value)
}

func writeLabeledCounter(b *strings.Builder, name string, labels map[string]string, value int64) {
	var parts []string
	for k, v := range labels {
		parts = append(parts, fmt.Sprintf("%s=%q", k, v))
	}
	sort.Strings(parts)
	fmt.Fprintf(b, "%s{%s} %d\n", name, strings.Join(parts, ","), value)
}

func sortedKeys(m map[string]*atomic.Int64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func normalizeReason(reason string) string {
	switch {
	case strings.HasPrefix(reason, "prompt_injection"):
		return "injection"
	case strings.HasPrefix(reason, "malware_scan"):
		return "malware"
	case strings.HasPrefix(reason, "vuln_scan"):
		return "vuln"
	case strings.HasPrefix(reason, "secrets_scan"):
		return "secrets"
	case strings.HasPrefix(reason, "pii_scan"):
		return "pii"
	case strings.Contains(reason, "denylist"):
		return "denylist"
	case strings.Contains(reason, "not in allowlist"):
		return "not_in_allowlist"
	case strings.Contains(reason, "timeout"):
		return "timeout"
	case strings.Contains(reason, "sensitive data"):
		return "arg_filter"
	default:
		return "policy"
	}
}
