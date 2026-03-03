// Package bus provides a cross-layer event bus for ClawShield security integration.
//
// The event bus enables communication between the three defense layers:
//   - Layer 1 (Proxy): publishes app-level security events, consumes kernel-level events
//   - Layer 2 (Firewall): consumes events to dynamically add temporary block rules
//   - Layer 3 (eBPF): publishes kernel-level security events via Unix socket
//
// Events are published non-blocking (dropped with logging if a subscriber is full)
// to ensure producers never stall on slow consumers.
package bus

import (
	"log"
	"sync"
	"sync/atomic"

	"github.com/SleuthCo/clawshield/shared/types"
)

// SubscriberBufferSize is the channel buffer size for each subscriber.
// Events are dropped if a subscriber falls behind by this many events.
const SubscriberBufferSize = 256

// EventFilter controls which events a subscriber receives.
// Zero-value fields match all events (no filtering on that dimension).
type EventFilter struct {
	// EventTypes limits delivery to these event types. Empty = all types.
	EventTypes []types.EventType

	// Sources limits delivery to events from these sources. Empty = all sources.
	Sources []types.EventSource

	// MinSeverity limits delivery to events at or above this severity. Empty = all severities.
	MinSeverity types.Severity
}

// subscriber wraps a channel and its filter.
type subscriber struct {
	ch     chan *types.SecurityEvent
	filter EventFilter
	id     int
}

// EventBus is a thread-safe in-process event bus that fans out SecurityEvents
// to registered subscribers with optional filtering.
type EventBus struct {
	mu          sync.RWMutex
	subscribers []subscriber
	nextID      int
	closed      bool
	published   atomic.Int64
	dropped     atomic.Int64 // Counter for dropped events (subscriber channel full)
}

// New creates a new EventBus ready for use.
func New() *EventBus {
	return &EventBus{}
}

// Subscribe registers a new subscriber with an optional filter.
// Returns a channel that will receive matching events and a subscription ID
// that can be used to unsubscribe.
func (b *EventBus) Subscribe(filter EventFilter) (<-chan *types.SecurityEvent, int) {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan *types.SecurityEvent, SubscriberBufferSize)
	id := b.nextID
	b.nextID++

	b.subscribers = append(b.subscribers, subscriber{
		ch:     ch,
		filter: filter,
		id:     id,
	})

	return ch, id
}

// Unsubscribe removes a subscriber by ID and closes its channel.
func (b *EventBus) Unsubscribe(id int) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for i, sub := range b.subscribers {
		if sub.id == id {
			close(sub.ch)
			b.subscribers = append(b.subscribers[:i], b.subscribers[i+1:]...)
			return
		}
	}
}

// Publish sends an event to all matching subscribers.
// Non-blocking: if a subscriber's channel is full, the event is dropped and
// the loss is counted. Check DroppedEvents() to monitor event pipeline health.
func (b *EventBus) Publish(event *types.SecurityEvent) {
	if event == nil {
		return
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return
	}

	for _, sub := range b.subscribers {
		if !matchesFilter(event, &sub.filter) {
			continue
		}

		select {
		case sub.ch <- event:
			b.published.Add(1)
		default:
			// Channel full — drop event to avoid blocking the producer
			dropped := b.dropped.Add(1)
			if dropped == 1 || dropped%100 == 0 {
				log.Printf("WARNING: event bus dropped %d events (subscriber backpressure)", dropped)
			}
		}
	}
}

// DroppedEvents returns the total number of events dropped due to slow subscribers.
func (b *EventBus) DroppedEvents() int64 {
	return b.dropped.Load()
}

// PublishedEvents returns the total number of events successfully published.
func (b *EventBus) PublishedEvents() int64 {
	return b.published.Load()
}

// Dropped returns the total number of events dropped due to slow subscribers.
// Deprecated: use DroppedEvents instead.
func (b *EventBus) Dropped() int64 {
	return b.dropped.Load()
}

// Close shuts down the event bus and closes all subscriber channels.
func (b *EventBus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return
	}
	b.closed = true

	for _, sub := range b.subscribers {
		close(sub.ch)
	}
	b.subscribers = nil
}

// matchesFilter checks if an event passes a subscriber's filter criteria.
func matchesFilter(event *types.SecurityEvent, filter *EventFilter) bool {
	// Check event type filter
	if len(filter.EventTypes) > 0 {
		found := false
		for _, et := range filter.EventTypes {
			if event.EventType == et {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check source filter
	if len(filter.Sources) > 0 {
		found := false
		for _, src := range filter.Sources {
			if event.Source == src {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check minimum severity filter
	if filter.MinSeverity != "" {
		if event.Severity.Weight() < filter.MinSeverity.Weight() {
			return false
		}
	}

	return true
}
