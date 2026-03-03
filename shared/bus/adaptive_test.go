package bus

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/SleuthCo/clawshield/shared/types"
)

func TestAdaptiveControllerBasicTrigger(t *testing.T) {
	b := New()
	defer b.Close()

	rules := []types.AdaptiveRule{
		{
			Trigger: types.AdaptiveTrigger{
				Source: types.SourceEBPF,
				Type:   types.EventPrivesc,
			},
			Action: "elevate_sensitivity",
			Params: map[string]int{"duration_seconds": 10},
		},
	}

	ac := NewAdaptiveController(b, rules)

	var called atomic.Int32
	ac.OnElevateSensitivity = func(level string, duration time.Duration) {
		called.Add(1)
		if level != "high" {
			t.Errorf("expected level high, got %s", level)
		}
		if duration != 10*time.Second {
			t.Errorf("expected duration 10s, got %s", duration)
		}
	}

	ac.Start()
	defer ac.Stop()

	// Publish a matching event
	b.Publish(&types.SecurityEvent{
		EventType: types.EventPrivesc,
		Source:    types.SourceEBPF,
		Severity:  types.SeverityCritical,
		Timestamp: time.Now(),
		Reason:    "setuid(0) from non-root",
	})

	// Wait for async dispatch
	time.Sleep(200 * time.Millisecond)

	if called.Load() != 1 {
		t.Errorf("expected callback to be called once, got %d", called.Load())
	}
}

func TestAdaptiveControllerNoMatchWrongSource(t *testing.T) {
	b := New()
	defer b.Close()

	rules := []types.AdaptiveRule{
		{
			Trigger: types.AdaptiveTrigger{
				Source: types.SourceEBPF,
				Type:   types.EventPrivesc,
			},
			Action: "elevate_sensitivity",
			Params: map[string]int{"duration_seconds": 10},
		},
	}

	ac := NewAdaptiveController(b, rules)

	var called atomic.Int32
	ac.OnElevateSensitivity = func(level string, duration time.Duration) {
		called.Add(1)
	}

	ac.Start()
	defer ac.Stop()

	// Publish event from wrong source — should NOT trigger
	b.Publish(&types.SecurityEvent{
		EventType: types.EventPrivesc,
		Source:    types.SourceProxy, // Wrong source
		Severity:  types.SeverityCritical,
		Timestamp: time.Now(),
	})

	time.Sleep(200 * time.Millisecond)

	if called.Load() != 0 {
		t.Errorf("expected callback NOT to be called, got %d", called.Load())
	}
}

func TestAdaptiveControllerMinSeverity(t *testing.T) {
	b := New()
	defer b.Close()

	rules := []types.AdaptiveRule{
		{
			Trigger: types.AdaptiveTrigger{
				Source:      types.SourceProxy,
				Type:        types.EventInjectionBlocked,
				MinSeverity: types.SeverityHigh,
			},
			Action: "elevate_default_deny",
			Params: map[string]int{"duration_seconds": 60},
		},
	}

	ac := NewAdaptiveController(b, rules)

	var called atomic.Int32
	ac.OnElevateDefaultDeny = func(duration time.Duration) {
		called.Add(1)
	}

	ac.Start()
	defer ac.Stop()

	// Low severity — should NOT trigger
	b.Publish(&types.SecurityEvent{
		EventType: types.EventInjectionBlocked,
		Source:    types.SourceProxy,
		Severity:  types.SeverityLow,
		Timestamp: time.Now(),
	})

	time.Sleep(100 * time.Millisecond)
	if called.Load() != 0 {
		t.Errorf("low severity should not trigger, got %d calls", called.Load())
	}

	// High severity — SHOULD trigger
	b.Publish(&types.SecurityEvent{
		EventType: types.EventInjectionBlocked,
		Source:    types.SourceProxy,
		Severity:  types.SeverityHigh,
		Timestamp: time.Now(),
	})

	time.Sleep(200 * time.Millisecond)
	if called.Load() != 1 {
		t.Errorf("high severity should trigger, got %d calls", called.Load())
	}
}

func TestAdaptiveControllerCountThreshold(t *testing.T) {
	b := New()
	defer b.Close()

	rules := []types.AdaptiveRule{
		{
			Trigger: types.AdaptiveTrigger{
				Source:        types.SourceProxy,
				Type:          types.EventInjectionBlocked,
				MinCount:      3,
				WindowSeconds: 60,
			},
			Action: "block_session",
			Params: map[string]int{"duration_seconds": 300},
		},
	}

	ac := NewAdaptiveController(b, rules)

	var called atomic.Int32
	ac.OnBlockSession = func(sessionID string, duration time.Duration) {
		called.Add(1)
	}

	ac.Start()
	defer ac.Stop()

	// Send 2 events — should NOT trigger (below threshold)
	for i := 0; i < 2; i++ {
		b.Publish(&types.SecurityEvent{
			EventType: types.EventInjectionBlocked,
			Source:    types.SourceProxy,
			Severity:  types.SeverityHigh,
			Timestamp: time.Now(),
			SessionID: "sess-123",
		})
		time.Sleep(20 * time.Millisecond)
	}

	time.Sleep(100 * time.Millisecond)
	if called.Load() != 0 {
		t.Errorf("should not trigger with only 2 events, got %d calls", called.Load())
	}

	// Send 3rd event — SHOULD trigger
	b.Publish(&types.SecurityEvent{
		EventType: types.EventInjectionBlocked,
		Source:    types.SourceProxy,
		Severity:  types.SeverityHigh,
		Timestamp: time.Now(),
		SessionID: "sess-123",
	})

	time.Sleep(200 * time.Millisecond)
	if called.Load() != 1 {
		t.Errorf("should trigger after 3 events, got %d calls", called.Load())
	}
}

func TestAdaptiveControllerRateLimiting(t *testing.T) {
	b := New()
	defer b.Close()

	rules := []types.AdaptiveRule{
		{
			Trigger: types.AdaptiveTrigger{
				Source: types.SourceEBPF,
				Type:   types.EventExecSuspicious,
			},
			Action: "elevate_sensitivity",
			Params: map[string]int{"duration_seconds": 60},
		},
	}

	ac := NewAdaptiveController(b, rules)

	var called atomic.Int32
	ac.OnElevateSensitivity = func(level string, duration time.Duration) {
		called.Add(1)
	}

	ac.Start()
	defer ac.Stop()

	// Fire 5 matching events rapidly
	for i := 0; i < 5; i++ {
		b.Publish(&types.SecurityEvent{
			EventType: types.EventExecSuspicious,
			Source:    types.SourceEBPF,
			Severity:  types.SeverityHigh,
			Timestamp: time.Now(),
		})
		time.Sleep(10 * time.Millisecond)
	}

	time.Sleep(200 * time.Millisecond)

	// Should only fire once due to rate limiting (override still active)
	if called.Load() != 1 {
		t.Errorf("expected exactly 1 call due to rate limiting, got %d", called.Load())
	}
}

func TestAdaptiveControllerThreatScore(t *testing.T) {
	b := New()
	defer b.Close()

	ac := NewAdaptiveController(b, nil)
	ac.Start()
	defer ac.Stop()

	b.Publish(&types.SecurityEvent{
		EventType: types.EventPrivesc,
		Source:    types.SourceEBPF,
		Severity:  types.SeverityCritical, // Weight 5
		Timestamp: time.Now(),
	})

	b.Publish(&types.SecurityEvent{
		EventType: types.EventInjectionBlocked,
		Source:    types.SourceProxy,
		Severity:  types.SeverityHigh, // Weight 4
		Timestamp: time.Now(),
	})

	time.Sleep(100 * time.Millisecond)

	score := ac.ThreatScore()
	if score < 9 {
		t.Errorf("expected threat score >= 9 (5+4), got %d", score)
	}
}

func TestAdaptiveControllerThreatScoreCap(t *testing.T) {
	b := New()
	defer b.Close()

	ac := NewAdaptiveController(b, nil)
	ac.Start()
	defer ac.Stop()

	// Send enough critical events to exceed MaxThreatScore
	// Critical severity has weight 5, so 25 events = 125 which exceeds 100
	for i := 0; i < 25; i++ {
		b.Publish(&types.SecurityEvent{
			EventType: types.EventPrivesc,
			Source:    types.SourceEBPF,
			Severity:  types.SeverityCritical, // Weight 5
			Timestamp: time.Now(),
		})
		time.Sleep(5 * time.Millisecond)
	}

	time.Sleep(200 * time.Millisecond)

	score := ac.ThreatScore()
	if score > MaxThreatScore {
		t.Errorf("threat score %d exceeds MaxThreatScore %d", score, MaxThreatScore)
	}
	if score < 50 {
		t.Errorf("threat score %d unexpectedly low, expected near %d", score, MaxThreatScore)
	}
}

func TestAdaptiveControllerNilCallbackSafety(t *testing.T) {
	b := New()
	defer b.Close()

	rules := []types.AdaptiveRule{
		{
			Trigger: types.AdaptiveTrigger{
				Source: types.SourceEBPF,
				Type:   types.EventPrivesc,
			},
			Action: "elevate_sensitivity",
			Params: map[string]int{"duration_seconds": 10},
		},
		{
			Trigger: types.AdaptiveTrigger{
				Source: types.SourceProxy,
				Type:   types.EventInjectionBlocked,
			},
			Action: "restrict_domains",
			Params: map[string]int{"duration_seconds": 10},
		},
	}

	// Create controller WITHOUT setting any callbacks
	ac := NewAdaptiveController(b, rules)
	ac.Start()
	defer ac.Stop()

	// Trigger events that would invoke callbacks — should NOT panic
	b.Publish(&types.SecurityEvent{
		EventType: types.EventPrivesc,
		Source:    types.SourceEBPF,
		Severity:  types.SeverityCritical,
		Timestamp: time.Now(),
	})

	b.Publish(&types.SecurityEvent{
		EventType: types.EventInjectionBlocked,
		Source:    types.SourceProxy,
		Severity:  types.SeverityHigh,
		Timestamp: time.Now(),
	})

	// If we get here without panicking, the test passes
	time.Sleep(200 * time.Millisecond)
}

func TestAdaptiveControllerSourceTracking(t *testing.T) {
	b := New()
	defer b.Close()

	ac := NewAdaptiveController(b, nil)
	ac.Start()
	defer ac.Stop()

	// Publish events from two different sources
	for i := 0; i < 3; i++ {
		b.Publish(&types.SecurityEvent{
			EventType: types.EventPrivesc,
			Source:    types.SourceEBPF,
			Severity:  types.SeverityHigh,
			Timestamp: time.Now(),
		})
		time.Sleep(5 * time.Millisecond)
	}

	for i := 0; i < 5; i++ {
		b.Publish(&types.SecurityEvent{
			EventType: types.EventInjectionBlocked,
			Source:    types.SourceProxy,
			Severity:  types.SeverityMedium,
			Timestamp: time.Now(),
		})
		time.Sleep(5 * time.Millisecond)
	}

	time.Sleep(200 * time.Millisecond)

	ebpfCount := ac.SourceEventCount(string(types.SourceEBPF), 1*time.Minute)
	proxyCount := ac.SourceEventCount(string(types.SourceProxy), 1*time.Minute)

	if ebpfCount != 3 {
		t.Errorf("expected 3 eBPF events, got %d", ebpfCount)
	}
	if proxyCount != 5 {
		t.Errorf("expected 5 proxy events, got %d", proxyCount)
	}
}

func TestSourceTrackerCleanup(t *testing.T) {
	st := newSourceTracker()

	// Add old events
	oldTime := time.Now().Add(-10 * time.Minute)
	for i := 0; i < 5; i++ {
		st.recordEvent("old-source", oldTime)
	}

	// Add recent events
	recentTime := time.Now()
	for i := 0; i < 3; i++ {
		st.recordEvent("recent-source", recentTime)
	}

	// Cleanup with 5-minute max age
	st.cleanup(5 * time.Minute)

	// Old source should be removed
	oldCount := st.countInWindow("old-source", 15*time.Minute)
	if oldCount != 0 {
		t.Errorf("expected 0 old events after cleanup, got %d", oldCount)
	}

	// Recent source should be kept
	recentCount := st.countInWindow("recent-source", 15*time.Minute)
	if recentCount != 3 {
		t.Errorf("expected 3 recent events after cleanup, got %d", recentCount)
	}
}

func TestAdaptiveControllerOverrideExpiry(t *testing.T) {
	b := New()
	defer b.Close()

	rules := []types.AdaptiveRule{
		{
			Trigger: types.AdaptiveTrigger{
				Source: types.SourceEBPF,
				Type:   types.EventExecSuspicious,
			},
			Action: "elevate_sensitivity",
			Params: map[string]int{"duration_seconds": 1}, // 1 second — expires quickly
		},
	}

	ac := NewAdaptiveController(b, rules)

	var called atomic.Int32
	ac.OnElevateSensitivity = func(level string, duration time.Duration) {
		called.Add(1)
	}

	ac.Start()
	defer ac.Stop()

	// Fire first event — triggers action
	b.Publish(&types.SecurityEvent{
		EventType: types.EventExecSuspicious,
		Source:    types.SourceEBPF,
		Severity:  types.SeverityHigh,
		Timestamp: time.Now(),
	})

	time.Sleep(200 * time.Millisecond)
	if called.Load() != 1 {
		t.Fatalf("expected 1 call, got %d", called.Load())
	}

	// Wait for override to expire
	time.Sleep(1200 * time.Millisecond)

	// Fire again — should trigger since override expired
	b.Publish(&types.SecurityEvent{
		EventType: types.EventExecSuspicious,
		Source:    types.SourceEBPF,
		Severity:  types.SeverityHigh,
		Timestamp: time.Now(),
	})

	time.Sleep(200 * time.Millisecond)
	if called.Load() != 2 {
		t.Errorf("expected 2 calls after override expired, got %d", called.Load())
	}
}
