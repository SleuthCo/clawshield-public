package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	c := New()
	if c == nil {
		t.Fatal("expected non-nil collector")
	}
	snap := c.Snapshot()
	if snap.TotalRequests != 0 || snap.TotalAllowed != 0 || snap.TotalDenied != 0 {
		t.Error("expected all counters to start at zero")
	}
}

func TestRecordRequestDecisions(t *testing.T) {
	c := New()

	c.RecordRequest()
	c.RecordRequest()
	c.RecordRequest()
	c.RecordAllow()
	c.RecordAllow()
	c.RecordDeny("chat.send", "prompt_injection: role override")
	c.RecordRedacted()

	snap := c.Snapshot()
	if snap.TotalRequests != 3 {
		t.Errorf("expected 3 requests, got %d", snap.TotalRequests)
	}
	if snap.TotalAllowed != 2 {
		t.Errorf("expected 2 allowed, got %d", snap.TotalAllowed)
	}
	if snap.TotalDenied != 1 {
		t.Errorf("expected 1 denied, got %d", snap.TotalDenied)
	}
	if snap.TotalRedacted != 1 {
		t.Errorf("expected 1 redacted, got %d", snap.TotalRedacted)
	}
}

func TestRecordScannerDetections(t *testing.T) {
	c := New()

	c.RecordInjectionBlocked()
	c.RecordInjectionBlocked()
	c.RecordMalwareBlocked()
	c.RecordVulnBlocked()
	c.RecordSecretsBlocked()
	c.RecordSecretsRedacted()
	c.RecordPIIBlocked()
	c.RecordPIIRedacted()
	c.RecordPolicyDenied()

	snap := c.Snapshot()
	if snap.InjectionBlocked != 2 {
		t.Errorf("expected 2 injection blocks, got %d", snap.InjectionBlocked)
	}
	if snap.MalwareBlocked != 1 {
		t.Errorf("expected 1 malware block, got %d", snap.MalwareBlocked)
	}
	if snap.VulnBlocked != 1 {
		t.Errorf("expected 1 vuln block, got %d", snap.VulnBlocked)
	}
	if snap.SecretsBlocked != 1 {
		t.Errorf("expected 1 secrets block, got %d", snap.SecretsBlocked)
	}
	if snap.SecretsRedacted != 1 {
		t.Errorf("expected 1 secrets redacted, got %d", snap.SecretsRedacted)
	}
	if snap.PIIBlocked != 1 {
		t.Errorf("expected 1 PII block, got %d", snap.PIIBlocked)
	}
	if snap.PIIRedacted != 1 {
		t.Errorf("expected 1 PII redacted, got %d", snap.PIIRedacted)
	}
	if snap.PolicyDenied != 1 {
		t.Errorf("expected 1 policy denied, got %d", snap.PolicyDenied)
	}
}

func TestRecordLatency(t *testing.T) {
	c := New()

	c.RecordEvaluationLatency(500 * time.Microsecond) // <1ms bucket
	c.RecordEvaluationLatency(3 * time.Millisecond)    // <5ms bucket
	c.RecordEvaluationLatency(50 * time.Millisecond)   // <100ms bucket

	snap := c.Snapshot()
	if snap.LatencyCount != 3 {
		t.Errorf("expected 3 latency samples, got %d", snap.LatencyCount)
	}

	// Check that the histogram is in the rendered output
	output := c.Render()
	if !strings.Contains(output, "clawshield_evaluation_duration_seconds_bucket") {
		t.Error("expected histogram buckets in output")
	}
	if !strings.Contains(output, "clawshield_evaluation_duration_seconds_count 3") {
		t.Error("expected latency count of 3 in output")
	}
}

func TestActiveConnections(t *testing.T) {
	c := New()

	c.ConnectionOpened()
	c.ConnectionOpened()
	c.ConnectionOpened()
	c.ConnectionClosed()

	snap := c.Snapshot()
	if snap.ActiveConns != 2 {
		t.Errorf("expected 2 active connections, got %d", snap.ActiveConns)
	}
}

func TestErrorCounters(t *testing.T) {
	c := New()

	c.RecordEvaluationTimeout()
	c.RecordEvaluationTimeout()
	c.RecordUpstreamError()

	snap := c.Snapshot()
	if snap.EvalTimeouts != 2 {
		t.Errorf("expected 2 timeouts, got %d", snap.EvalTimeouts)
	}
	if snap.UpstreamErrors != 1 {
		t.Errorf("expected 1 upstream error, got %d", snap.UpstreamErrors)
	}
}

func TestDeniedByTool(t *testing.T) {
	c := New()

	c.RecordDeny("chat.send", "injection")
	c.RecordDeny("chat.send", "malware")
	c.RecordDeny("tools.invoke", "policy")

	output := c.Render()
	if !strings.Contains(output, `tool="chat.send"`) {
		t.Error("expected chat.send in denied_by_tool")
	}
	if !strings.Contains(output, `tool="tools.invoke"`) {
		t.Error("expected tools.invoke in denied_by_tool")
	}
}

func TestDeniedByReason(t *testing.T) {
	c := New()

	c.RecordDeny("", "prompt_injection: role override")
	c.RecordDeny("", "malware_scan: suspicious binary")
	c.RecordDeny("", "secrets_scan: AWS key detected")

	output := c.Render()
	if !strings.Contains(output, `reason="injection"`) {
		t.Error("expected injection reason label")
	}
	if !strings.Contains(output, `reason="malware"`) {
		t.Error("expected malware reason label")
	}
	if !strings.Contains(output, `reason="secrets"`) {
		t.Error("expected secrets reason label")
	}
}

func TestRender_PrometheusFormat(t *testing.T) {
	c := New()

	c.RecordRequest()
	c.RecordAllow()
	c.RecordEvaluationLatency(1 * time.Millisecond)

	output := c.Render()

	// Check HELP and TYPE annotations
	if !strings.Contains(output, "# HELP clawshield_requests_total") {
		t.Error("missing HELP for requests_total")
	}
	if !strings.Contains(output, "# TYPE clawshield_requests_total counter") {
		t.Error("missing TYPE for requests_total")
	}
	if !strings.Contains(output, "# TYPE clawshield_uptime_seconds gauge") {
		t.Error("missing TYPE for uptime gauge")
	}
	if !strings.Contains(output, "# TYPE clawshield_evaluation_duration_seconds histogram") {
		t.Error("missing TYPE for latency histogram")
	}

	// Verify uptime is positive
	if !strings.Contains(output, "clawshield_uptime_seconds") {
		t.Error("missing uptime metric")
	}
}

func TestHandler_HTTPEndpoint(t *testing.T) {
	c := New()
	c.RecordRequest()
	c.RecordAllow()

	handler := c.Handler()
	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/plain") {
		t.Errorf("expected text/plain content type, got %s", contentType)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "clawshield_requests_total 1") {
		t.Errorf("expected requests_total 1 in body, got:\n%s", body)
	}
}

func TestConcurrentAccess(t *testing.T) {
	c := New()

	var wg sync.WaitGroup
	n := 100
	wg.Add(n * 3)

	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			c.RecordRequest()
			c.RecordAllow()
			c.RecordEvaluationLatency(time.Millisecond)
		}()
		go func() {
			defer wg.Done()
			c.RecordDeny("chat.send", "prompt_injection: test")
			c.RecordInjectionBlocked()
		}()
		go func() {
			defer wg.Done()
			c.ConnectionOpened()
			c.ConnectionClosed()
			c.Render() // Concurrent reads
		}()
	}

	wg.Wait()

	snap := c.Snapshot()
	if snap.TotalRequests != int64(n) {
		t.Errorf("expected %d requests, got %d", n, snap.TotalRequests)
	}
	if snap.TotalAllowed != int64(n) {
		t.Errorf("expected %d allowed, got %d", n, snap.TotalAllowed)
	}
	if snap.TotalDenied != int64(n) {
		t.Errorf("expected %d denied, got %d", n, snap.TotalDenied)
	}
	if snap.ActiveConns != 0 {
		t.Errorf("expected 0 active connections after open+close, got %d", snap.ActiveConns)
	}
}

func TestNormalizeReason(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"prompt_injection: role override detected", "injection"},
		{"malware_scan: suspicious binary", "malware"},
		{"vuln_scan: SQL injection detected", "vuln"},
		{"secrets_scan: AWS key detected", "secrets"},
		{"pii_scan: email detected", "pii"},
		{"tool in denylist", "denylist"},
		{"tool not in allowlist", "not_in_allowlist"},
		{"evaluation timeout exceeded", "timeout"},
		{"sensitive data detected in arguments", "arg_filter"},
		{"default denied", "policy"},
		{"unknown reason", "policy"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeReason(tt.input)
			if got != tt.expected {
				t.Errorf("normalizeReason(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestCrossLayerMetrics(t *testing.T) {
	c := New()

	c.RecordCrossLayerEventReceived()
	c.RecordCrossLayerEventReceived()
	c.RecordCrossLayerEventSent()
	c.RecordAdaptiveAction()

	output := c.Render()
	if !strings.Contains(output, "clawshield_crosslayer_events_received_total 2") {
		t.Error("expected 2 cross-layer events received")
	}
	if !strings.Contains(output, "clawshield_crosslayer_events_sent_total 1") {
		t.Error("expected 1 cross-layer event sent")
	}
	if !strings.Contains(output, "clawshield_adaptive_actions_total 1") {
		t.Error("expected 1 adaptive action")
	}
}
