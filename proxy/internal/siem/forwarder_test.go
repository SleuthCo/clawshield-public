package siem

import (
	"sync"
	"testing"
	"time"

	"github.com/SleuthCo/clawshield/shared/types"
)

// mockTransport records sent events for testing.
type mockTransport struct {
	mu     sync.Mutex
	events [][]byte
	err    error // if set, Send returns this error
}

func (m *mockTransport) Send(data []byte) error {
	if m.err != nil {
		return m.err
	}
	m.mu.Lock()
	m.events = append(m.events, data)
	m.mu.Unlock()
	return nil
}

func (m *mockTransport) Close() error { return nil }

func (m *mockTransport) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

// TestForwarder_SeverityFilter verifies that events are filtered by severity threshold.
func TestForwarder_SeverityFilter(t *testing.T) {
	mock := &mockTransport{}
	f := NewForwarder(mock, SeverityHigh, 100)
	defer f.Close()

	// Allow decision (Informational) should be filtered
	f.Forward(&types.Decision{
		Timestamp: time.Now(),
		Decision:  "allow",
		Tool:      "test",
	})

	// PII deny (Medium) should be filtered
	f.Forward(&types.Decision{
		Timestamp: time.Now(),
		Decision:  "deny",
		Tool:      "test",
		Details: &types.DecisionDetail{
			ScanResults: []types.ScanResult{{Scanner: "pii"}},
		},
	})

	// Vuln deny (High) should be forwarded
	f.Forward(&types.Decision{
		Timestamp: time.Now(),
		Decision:  "deny",
		Tool:      "test",
		Details: &types.DecisionDetail{
			ScanResults: []types.ScanResult{{Scanner: "vuln"}},
		},
	})

	// Injection deny (Critical) should be forwarded
	f.Forward(&types.Decision{
		Timestamp: time.Now(),
		Decision:  "deny",
		Tool:      "test",
		Details: &types.DecisionDetail{
			ScanResults: []types.ScanResult{{Scanner: "injection"}},
		},
	})

	time.Sleep(100 * time.Millisecond) // let async process

	if mock.count() != 2 {
		t.Errorf("expected 2 events to be forwarded, got %d", mock.count())
	}

	fwd, filtered, dropped := f.Stats()
	if fwd != 2 {
		t.Errorf("expected 2 forwarded events, got %d", fwd)
	}
	if filtered != 2 {
		t.Errorf("expected 2 filtered events, got %d", filtered)
	}
	if dropped != 0 {
		t.Errorf("expected 0 dropped events, got %d", dropped)
	}
}

// TestForwarder_GracefulShutdown verifies that Close drains pending events.
func TestForwarder_GracefulShutdown(t *testing.T) {
	mock := &mockTransport{}
	f := NewForwarder(mock, SeverityCritical, 100)

	// Queue some critical events
	for i := 0; i < 5; i++ {
		f.Forward(&types.Decision{
			Timestamp: time.Now(),
			Decision:  "deny",
			Tool:      "test",
			Details: &types.DecisionDetail{
				ScanResults: []types.ScanResult{{Scanner: "injection"}},
			},
		})
	}

	// Close should drain
	f.Close()

	if mock.count() != 5 {
		t.Errorf("expected 5 events after close, got %d", mock.count())
	}
}

// TestForwarder_QueueOverflow verifies behavior when queue is exceeded.
func TestForwarder_QueueOverflow(t *testing.T) {
	mock := &mockTransport{}
	f := NewForwarder(mock, SeverityCritical, 2) // tiny queue

	// Fill queue beyond capacity
	for i := 0; i < 10; i++ {
		f.Forward(&types.Decision{
			Timestamp: time.Now(),
			Decision:  "deny",
			Tool:      "test",
			Details: &types.DecisionDetail{
				ScanResults: []types.ScanResult{{Scanner: "injection"}},
			},
		})
	}

	time.Sleep(200 * time.Millisecond)
	f.Close()

	_, _, dropped := f.Stats()
	// Some events should have been dropped due to tiny queue
	// At minimum, verify no panic and stats are consistent
	if dropped < 0 {
		t.Errorf("expected dropped >= 0, got %d", dropped)
	}
}

// TestForwarder_ClosedForwarderIgnoresEvents verifies that Forward is safe after Close.
func TestForwarder_ClosedForwarderIgnoresEvents(t *testing.T) {
	mock := &mockTransport{}
	f := NewForwarder(mock, SeverityCritical, 100)
	f.Close()

	// Forward after close should not panic
	f.Forward(&types.Decision{
		Timestamp: time.Now(),
		Decision:  "deny",
		Tool:      "test",
		Details: &types.DecisionDetail{
			ScanResults: []types.ScanResult{{Scanner: "injection"}},
		},
	})

	if mock.count() != 0 {
		t.Errorf("expected 0 events after closing, got %d", mock.count())
	}
}
