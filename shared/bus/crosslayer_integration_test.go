// +build integration

package bus

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/SleuthCo/clawshield/shared/types"
)

// TestCrossLayerEBPFToProxy simulates an eBPF event arriving via Unix socket
// and verifies the proxy's adaptive controller reacts by elevating sensitivity.
func TestCrossLayerEBPFToProxy(t *testing.T) {
	// Create event bus and socket listener
	eventBus := New()
	defer eventBus.Close()

	socketPath := "/tmp/clawshield-test-crosslayer.sock"
	listener := NewSocketListener(socketPath, eventBus)
	if err := listener.Start(); err != nil {
		t.Fatalf("Failed to start socket listener: %v", err)
	}
	defer listener.Stop()

	// Subscribe to all events to verify delivery
	ch, _ := eventBus.Subscribe(EventFilter{})

	// Set up adaptive controller with a rule: eBPF privesc → elevate sensitivity
	rules := []types.AdaptiveRule{
		{
			Trigger: types.AdaptiveTrigger{
				Source: types.SourceEBPF,
				Type:   types.EventPrivesc,
			},
			Action: "elevate_sensitivity",
			Params: map[string]int{"duration_seconds": 60},
		},
	}

	sensitivityElevated := make(chan string, 1)
	controller := NewAdaptiveController(eventBus, rules)
	controller.OnElevateSensitivity = func(level string, duration time.Duration) {
		sensitivityElevated <- level
	}
	controller.Start()
	defer controller.Stop()

	// Simulate eBPF sending an event via Unix socket (like the Python monitor would)
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to connect to event socket: %v", err)
	}
	defer conn.Close()

	event := map[string]interface{}{
		"event_type": "privesc",
		"severity":   "critical",
		"source":     "ebpf",
		"timestamp":  time.Now().Format(time.RFC3339Nano),
		"pid":        12345,
		"tool":       "bash",
		"reason":     "setuid(0) from non-root process",
		"details": map[string]string{
			"From UID": "1000",
			"To UID":   "0",
		},
	}

	data, _ := json.Marshal(event)
	data = append(data, '\n')
	if _, err := conn.Write(data); err != nil {
		t.Fatalf("Failed to write event to socket: %v", err)
	}

	// Verify the event was received by the bus
	select {
	case received := <-ch:
		if received.EventType != types.EventPrivesc {
			t.Errorf("expected event type %s, got %s", types.EventPrivesc, received.EventType)
		}
		if received.Source != types.SourceEBPF {
			t.Errorf("expected source %s, got %s", types.SourceEBPF, received.Source)
		}
		if received.Severity != types.SeverityCritical {
			t.Errorf("expected severity %s, got %s", types.SeverityCritical, received.Severity)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for event on bus")
	}

	// Verify the adaptive controller reacted
	select {
	case level := <-sensitivityElevated:
		if level != "high" {
			t.Errorf("expected sensitivity elevated to high, got %s", level)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for adaptive sensitivity elevation")
	}

	// Verify threat score increased
	score := controller.ThreatScore()
	if score < 5 {
		t.Errorf("expected threat score >= 5 (critical weight), got %d", score)
	}
}

// TestCrossLayerProxyPublishesEvents verifies that the event bus correctly
// delivers proxy-originated events to subscribers.
func TestCrossLayerProxyPublishesEvents(t *testing.T) {
	eventBus := New()
	defer eventBus.Close()

	// Subscribe only to proxy events
	ch, _ := eventBus.Subscribe(EventFilter{
		Sources: []types.EventSource{types.SourceProxy},
	})

	// Simulate proxy publishing an injection blocked event
	eventBus.Publish(&types.SecurityEvent{
		EventType: types.EventInjectionBlocked,
		Severity:  types.SeverityHigh,
		Source:    types.SourceProxy,
		Timestamp: time.Now(),
		SessionID: "session-abc123",
		Tool:      "chat.send",
		Reason:    "prompt_injection: role override attempt detected",
	})

	select {
	case received := <-ch:
		if received.EventType != types.EventInjectionBlocked {
			t.Errorf("expected %s, got %s", types.EventInjectionBlocked, received.EventType)
		}
		if received.Tool != "chat.send" {
			t.Errorf("expected tool chat.send, got %s", received.Tool)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for proxy event")
	}
}

// TestCrossLayerCountThresholdTrigger verifies that the adaptive controller
// fires a rule only after a count threshold is met within the time window.
func TestCrossLayerCountThresholdTrigger(t *testing.T) {
	eventBus := New()
	defer eventBus.Close()

	rules := []types.AdaptiveRule{
		{
			Trigger: types.AdaptiveTrigger{
				Source:        types.SourceProxy,
				Type:          types.EventInjectionBlocked,
				MinCount:      3,
				WindowSeconds: 60,
			},
			Action: "elevate_default_deny",
			Params: map[string]int{"duration_seconds": 120},
		},
	}

	denyActivated := make(chan struct{}, 1)
	controller := NewAdaptiveController(eventBus, rules)
	controller.OnElevateDefaultDeny = func(duration time.Duration) {
		denyActivated <- struct{}{}
	}
	controller.Start()
	defer controller.Stop()

	// Send 2 events — should NOT trigger
	for i := 0; i < 2; i++ {
		eventBus.Publish(&types.SecurityEvent{
			EventType: types.EventInjectionBlocked,
			Source:    types.SourceProxy,
			Severity:  types.SeverityHigh,
			Timestamp: time.Now(),
		})
		time.Sleep(20 * time.Millisecond)
	}

	select {
	case <-denyActivated:
		t.Fatal("should NOT trigger with only 2 events")
	case <-time.After(200 * time.Millisecond):
		// Good
	}

	// Send 3rd event — SHOULD trigger
	eventBus.Publish(&types.SecurityEvent{
		EventType: types.EventInjectionBlocked,
		Source:    types.SourceProxy,
		Severity:  types.SeverityHigh,
		Timestamp: time.Now(),
	})

	select {
	case <-denyActivated:
		// Good — triggered
	case <-time.After(2 * time.Second):
		t.Fatal("timeout: should have triggered after 3 events")
	}
}
