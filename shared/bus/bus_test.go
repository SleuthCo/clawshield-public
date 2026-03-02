package bus

import (
	"sync"
	"testing"
	"time"

	"github.com/SleuthCo/clawshield/shared/types"
)

func makeEvent(eventType types.EventType, source types.EventSource, severity types.Severity) *types.SecurityEvent {
	return &types.SecurityEvent{
		EventType: eventType,
		Source:    source,
		Severity:  severity,
		Timestamp: time.Now(),
		Reason:    "test event",
	}
}

func TestPublishSubscribe(t *testing.T) {
	b := New()
	defer b.Close()

	ch, _ := b.Subscribe(EventFilter{})

	event := makeEvent(types.EventInjectionBlocked, types.SourceProxy, types.SeverityHigh)
	b.Publish(event)

	select {
	case received := <-ch:
		if received.EventType != types.EventInjectionBlocked {
			t.Errorf("expected event type %s, got %s", types.EventInjectionBlocked, received.EventType)
		}
		if received.Source != types.SourceProxy {
			t.Errorf("expected source %s, got %s", types.SourceProxy, received.Source)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for event")
	}
}

func TestFilterByEventType(t *testing.T) {
	b := New()
	defer b.Close()

	ch, _ := b.Subscribe(EventFilter{
		EventTypes: []types.EventType{types.EventPrivesc},
	})

	// This should NOT be delivered
	b.Publish(makeEvent(types.EventInjectionBlocked, types.SourceProxy, types.SeverityHigh))

	// This SHOULD be delivered
	b.Publish(makeEvent(types.EventPrivesc, types.SourceEBPF, types.SeverityCritical))

	select {
	case received := <-ch:
		if received.EventType != types.EventPrivesc {
			t.Errorf("expected event type %s, got %s", types.EventPrivesc, received.EventType)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for filtered event")
	}

	// Verify no additional events
	select {
	case extra := <-ch:
		t.Errorf("unexpected extra event: %v", extra)
	case <-time.After(50 * time.Millisecond):
		// Good — no extra events
	}
}

func TestFilterBySource(t *testing.T) {
	b := New()
	defer b.Close()

	ch, _ := b.Subscribe(EventFilter{
		Sources: []types.EventSource{types.SourceEBPF},
	})

	// Should be filtered out
	b.Publish(makeEvent(types.EventInjectionBlocked, types.SourceProxy, types.SeverityHigh))

	// Should be delivered
	b.Publish(makeEvent(types.EventExecSuspicious, types.SourceEBPF, types.SeverityHigh))

	select {
	case received := <-ch:
		if received.Source != types.SourceEBPF {
			t.Errorf("expected source %s, got %s", types.SourceEBPF, received.Source)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for filtered event")
	}
}

func TestFilterByMinSeverity(t *testing.T) {
	b := New()
	defer b.Close()

	ch, _ := b.Subscribe(EventFilter{
		MinSeverity: types.SeverityHigh,
	})

	// Low severity — should be filtered out
	b.Publish(makeEvent(types.EventPolicyDeny, types.SourceProxy, types.SeverityLow))

	// Medium — should be filtered out
	b.Publish(makeEvent(types.EventPortScan, types.SourceEBPF, types.SeverityMedium))

	// High — should be delivered
	b.Publish(makeEvent(types.EventPrivesc, types.SourceEBPF, types.SeverityHigh))

	// Critical — should be delivered
	b.Publish(makeEvent(types.EventExecSuspicious, types.SourceEBPF, types.SeverityCritical))

	received := 0
	timeout := time.After(time.Second)
	for received < 2 {
		select {
		case ev := <-ch:
			received++
			if ev.Severity.Weight() < types.SeverityHigh.Weight() {
				t.Errorf("received event with severity %s below minimum high", ev.Severity)
			}
		case <-timeout:
			t.Fatalf("timeout: only received %d of 2 expected events", received)
		}
	}
}

func TestMultipleSubscribers(t *testing.T) {
	b := New()
	defer b.Close()

	ch1, _ := b.Subscribe(EventFilter{})
	ch2, _ := b.Subscribe(EventFilter{})

	event := makeEvent(types.EventInjectionBlocked, types.SourceProxy, types.SeverityHigh)
	b.Publish(event)

	for i, ch := range []<-chan *types.SecurityEvent{ch1, ch2} {
		select {
		case received := <-ch:
			if received.EventType != types.EventInjectionBlocked {
				t.Errorf("subscriber %d: expected event type %s, got %s", i, types.EventInjectionBlocked, received.EventType)
			}
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d: timeout waiting for event", i)
		}
	}
}

func TestUnsubscribe(t *testing.T) {
	b := New()
	defer b.Close()

	ch, id := b.Subscribe(EventFilter{})
	b.Unsubscribe(id)

	// Channel should be closed
	_, ok := <-ch
	if ok {
		t.Error("expected channel to be closed after unsubscribe")
	}
}

func TestPublishNil(t *testing.T) {
	b := New()
	defer b.Close()

	// Should not panic
	b.Publish(nil)
}

func TestPublishAfterClose(t *testing.T) {
	b := New()
	b.Close()

	// Should not panic
	b.Publish(makeEvent(types.EventInjectionBlocked, types.SourceProxy, types.SeverityHigh))
}

func TestConcurrentPublish(t *testing.T) {
	b := New()
	defer b.Close()

	ch, _ := b.Subscribe(EventFilter{})

	var wg sync.WaitGroup
	n := 100
	wg.Add(n)

	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			b.Publish(makeEvent(types.EventPolicyDeny, types.SourceProxy, types.SeverityLow))
		}()
	}

	wg.Wait()

	// Drain channel and count
	received := 0
	for {
		select {
		case <-ch:
			received++
		default:
			goto done
		}
	}
done:
	if received != n {
		t.Errorf("expected %d events, got %d", n, received)
	}
}

func TestDroppedEventsOnFullChannel(t *testing.T) {
	b := New()
	defer b.Close()

	// Subscribe but never read
	_, _ = b.Subscribe(EventFilter{})

	// Publish more than SubscriberBufferSize events
	for i := 0; i < SubscriberBufferSize+50; i++ {
		b.Publish(makeEvent(types.EventPolicyDeny, types.SourceProxy, types.SeverityLow))
	}

	if b.Dropped() == 0 {
		t.Error("expected some events to be dropped when subscriber channel is full")
	}
}

func TestSeverityWeight(t *testing.T) {
	tests := []struct {
		severity types.Severity
		weight   int
	}{
		{types.SeverityCritical, 5},
		{types.SeverityHigh, 4},
		{types.SeverityMedium, 3},
		{types.SeverityLow, 2},
		{types.SeverityInfo, 1},
		{types.Severity("unknown"), 0},
	}

	for _, tt := range tests {
		if got := tt.severity.Weight(); got != tt.weight {
			t.Errorf("severity %s: expected weight %d, got %d", tt.severity, tt.weight, got)
		}
	}
}
