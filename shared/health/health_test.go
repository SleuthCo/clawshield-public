package health

import (
	"testing"
	"time"
)

func TestHealthChecker_AllHealthy(t *testing.T) {
	hc := NewHealthChecker()
	hc.SetLayerStatus(1, "proxy", StatusHealthy, "running")
	hc.SetLayerStatus(2, "firewall", StatusHealthy, "rules applied")
	hc.SetLayerStatus(3, "ebpf", StatusHealthy, "eBPF monitoring active")

	result := hc.Check()
	if result.Overall != StatusHealthy {
		t.Fatalf("expected healthy, got %s", result.Overall)
	}
	if len(result.Layers) != 3 {
		t.Fatalf("expected 3 layers, got %d", len(result.Layers))
	}
}

func TestHealthChecker_DegradedOnMissing(t *testing.T) {
	hc := NewHealthChecker()
	hc.SetLayerStatus(1, "proxy", StatusHealthy, "running")
	// Layer 2 and 3 not registered

	result := hc.Check()
	if result.Overall != StatusDegraded {
		t.Fatalf("expected degraded (missing layers), got %s", result.Overall)
	}
}

func TestHealthChecker_DownOverridesDegraded(t *testing.T) {
	hc := NewHealthChecker()
	hc.SetLayerStatus(1, "proxy", StatusHealthy, "running")
	hc.SetLayerStatus(2, "firewall", StatusDegraded, "partial rules")
	hc.SetLayerStatus(3, "ebpf", StatusDown, "crashed")

	result := hc.Check()
	if result.Overall != StatusDown {
		t.Fatalf("expected down, got %s", result.Overall)
	}
}

func TestHealthChecker_UpdateLayer(t *testing.T) {
	hc := NewHealthChecker()
	hc.UpdateLayer(3, LayerHealth{
		Name:    "ebpf",
		Status:  StatusDegraded,
		Backend: "procfs",
		Message: "eBPF unavailable, using procfs fallback",
		Metrics: map[string]int64{"events_published": 42, "events_dropped": 3},
	})

	result := hc.Check()
	ebpf := result.Layers[2] // index 2 = layer 3
	if ebpf.Backend != "procfs" {
		t.Fatalf("expected procfs backend, got %s", ebpf.Backend)
	}
	if ebpf.Metrics["events_published"] != 42 {
		t.Fatalf("expected 42 events, got %d", ebpf.Metrics["events_published"])
	}
}

func TestHealthChecker_JSON(t *testing.T) {
	hc := NewHealthChecker()
	hc.SetLayerStatus(1, "proxy", StatusHealthy, "running")

	result := hc.Check()
	data, err := result.JSON()
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty JSON")
	}
}

func TestHealthChecker_IsHealthy(t *testing.T) {
	hc := NewHealthChecker()
	hc.SetLayerStatus(1, "proxy", StatusHealthy, "ok")
	hc.SetLayerStatus(2, "firewall", StatusHealthy, "ok")
	hc.SetLayerStatus(3, "ebpf", StatusHealthy, "ok")

	if !hc.IsHealthy() {
		t.Fatal("expected healthy")
	}

	hc.SetLayerStatus(3, "ebpf", StatusDegraded, "procfs mode")
	if hc.IsHealthy() {
		t.Fatal("expected not healthy when degraded")
	}
}

func TestHealthChecker_LastCheck(t *testing.T) {
	hc := NewHealthChecker()
	before := time.Now()
	hc.SetLayerStatus(1, "proxy", StatusHealthy, "ok")
	after := time.Now()

	result := hc.Check()
	lc := result.Layers[0].LastCheck
	if lc.Before(before) || lc.After(after) {
		t.Fatalf("last_check %v not between %v and %v", lc, before, after)
	}
}
