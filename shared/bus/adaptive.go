package bus

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/SleuthCo/clawshield/shared/types"
)

// MaxThreatScore is the upper bound for accumulated threat score.
// This prevents runaway escalation from burst events causing cascading over-restriction.
const MaxThreatScore = 100

// maxEventsPerKey caps the number of timestamps stored per event key to prevent unbounded memory growth.
const maxEventsPerKey = 10000

// AdaptiveController subscribes to the event bus and applies cross-layer
// response rules. When events from one layer match a trigger condition,
// the controller fires an action that adjusts another layer's behavior.
//
// Example: eBPF detects privilege escalation → proxy elevates injection
// scanner sensitivity to "high" for 5 minutes.
type AdaptiveController struct {
	bus   *EventBus
	rules []types.AdaptiveRule

	mu             sync.RWMutex
	threatScore    int       // Accumulated threat score based on event severity
	lastDecay      time.Time // When threatScore was last decayed
	eventCounts    map[string][]time.Time // Sliding window event counts keyed by "source:type"
	activeOverrides map[string]*Override  // Currently active behavioral overrides
	sourceTracker  *sourceTracker         // Per-source event tracking

	// Callbacks invoked when an adaptive action fires.
	// These are set by the layer that hosts the controller (typically the proxy).
	OnElevateSensitivity  func(level string, duration time.Duration)
	OnRestrictDomains     func(duration time.Duration)
	OnElevateDefaultDeny  func(duration time.Duration)
	OnBlockSession        func(sessionID string, duration time.Duration)
	OnAddTempFirewallRule func(ip string, duration time.Duration)

	subID int
	quit  chan struct{}
	wg    sync.WaitGroup
}

// Override tracks an active behavioral override with expiration.
type Override struct {
	Action    string
	ExpiresAt time.Time
	Params    map[string]int
}

// NewAdaptiveController creates a controller that processes events according
// to the given rules. Call Start() to begin processing.
func NewAdaptiveController(bus *EventBus, rules []types.AdaptiveRule) *AdaptiveController {
	return &AdaptiveController{
		bus:             bus,
		rules:           rules,
		lastDecay:       time.Now(),
		eventCounts:     make(map[string][]time.Time),
		activeOverrides: make(map[string]*Override),
		sourceTracker:   newSourceTracker(),
		quit:            make(chan struct{}),
	}
}

// sourceTracker provides per-source event tracking to isolate
// threat assessment per origin rather than globally.
type sourceTracker struct {
	mu     sync.Mutex
	counts map[string][]time.Time // source -> event timestamps
}

func newSourceTracker() *sourceTracker {
	return &sourceTracker{
		counts: make(map[string][]time.Time),
	}
}

func (st *sourceTracker) recordEvent(source string, t time.Time) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.counts[source] = append(st.counts[source], t)
	// Bound per-source entries
	if len(st.counts[source]) > maxEventsPerKey {
		st.counts[source] = st.counts[source][len(st.counts[source])-maxEventsPerKey:]
	}
}

func (st *sourceTracker) countInWindow(source string, window time.Duration) int {
	st.mu.Lock()
	defer st.mu.Unlock()
	cutoff := time.Now().Add(-window)
	events := st.counts[source]
	count := 0
	for _, t := range events {
		if t.After(cutoff) {
			count++
		}
	}
	return count
}

func (st *sourceTracker) cleanup(maxAge time.Duration) {
	st.mu.Lock()
	defer st.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for source, events := range st.counts {
		var kept []time.Time
		for _, t := range events {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(st.counts, source)
		} else {
			st.counts[source] = kept
		}
	}
}

// SourceEventCount returns the number of events from a source within a time window.
func (ac *AdaptiveController) SourceEventCount(source string, window time.Duration) int {
	return ac.sourceTracker.countInWindow(source, window)
}

// Start begins consuming events from the bus and evaluating adaptive rules.
func (ac *AdaptiveController) Start() {
	// Subscribe to all events — filtering is done per-rule
	ch, id := ac.bus.Subscribe(EventFilter{})
	ac.subID = id

	ac.wg.Add(1)
	go ac.processLoop(ch)

	// Periodic cleanup of expired overrides and event window counts
	ac.wg.Add(1)
	go ac.cleanupLoop()

	log.Printf("Adaptive controller started with %d rules", len(ac.rules))
}

// Stop gracefully shuts down the controller.
func (ac *AdaptiveController) Stop() {
	close(ac.quit)
	ac.bus.Unsubscribe(ac.subID)
	ac.wg.Wait()
}

// ThreatScore returns the current accumulated threat score.
func (ac *AdaptiveController) ThreatScore() int {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	return ac.threatScore
}

// ActiveOverrides returns a snapshot of currently active overrides.
func (ac *AdaptiveController) ActiveOverrides() map[string]*Override {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	result := make(map[string]*Override, len(ac.activeOverrides))
	for k, v := range ac.activeOverrides {
		copy := *v
		result[k] = &copy
	}
	return result
}

func (ac *AdaptiveController) processLoop(ch <-chan *types.SecurityEvent) {
	defer ac.wg.Done()

	for {
		select {
		case <-ac.quit:
			return
		case event, ok := <-ch:
			if !ok {
				return // Channel closed
			}
			ac.handleEvent(event)
		}
	}
}

func (ac *AdaptiveController) handleEvent(event *types.SecurityEvent) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	// Update threat score based on event severity, capped at MaxThreatScore
	newScore := ac.threatScore + event.Severity.Weight()
	if newScore > MaxThreatScore {
		ac.threatScore = MaxThreatScore
	} else {
		ac.threatScore = newScore
	}

	// Decay threat score over time (lose 1 point per 30 seconds of inactivity)
	now := time.Now()
	elapsed := now.Sub(ac.lastDecay)
	if elapsed > 30*time.Second {
		decay := int(elapsed.Seconds() / 30)
		ac.threatScore -= decay
		if ac.threatScore < 0 {
			ac.threatScore = 0
		}
		ac.lastDecay = now
	}

	// Record event in sliding window
	key := fmt.Sprintf("%s:%s", event.Source, event.EventType)
	ac.eventCounts[key] = append(ac.eventCounts[key], now)
	// Bound event counts per key to prevent unbounded memory growth
	if len(ac.eventCounts[key]) > maxEventsPerKey {
		ac.eventCounts[key] = ac.eventCounts[key][len(ac.eventCounts[key])-maxEventsPerKey:]
	}

	// Record per-source event
	ac.sourceTracker.recordEvent(string(event.Source), now)

	// Evaluate rules
	for _, rule := range ac.rules {
		if ac.ruleMatches(event, &rule, now) {
			ac.fireAction(event, &rule, now)
		}
	}
}

func (ac *AdaptiveController) ruleMatches(event *types.SecurityEvent, rule *types.AdaptiveRule, now time.Time) bool {
	trigger := &rule.Trigger

	// Check source
	if trigger.Source != "" && event.Source != trigger.Source {
		return false
	}

	// Check event type
	if trigger.Type != "" && event.EventType != trigger.Type {
		return false
	}

	// Check minimum severity
	if trigger.MinSeverity != "" && event.Severity.Weight() < trigger.MinSeverity.Weight() {
		return false
	}

	// Check count threshold within time window
	if trigger.MinCount > 0 {
		key := fmt.Sprintf("%s:%s", trigger.Source, trigger.Type)
		window := time.Duration(trigger.WindowSeconds) * time.Second
		if window <= 0 {
			window = 60 * time.Second // Default 60s window
		}

		cutoff := now.Add(-window)
		count := 0
		for _, t := range ac.eventCounts[key] {
			if t.After(cutoff) {
				count++
			}
		}
		if count < trigger.MinCount {
			return false
		}
	}

	return true
}

func (ac *AdaptiveController) fireAction(event *types.SecurityEvent, rule *types.AdaptiveRule, now time.Time) {
	action := rule.Action

	// Rate limit: don't fire the same action if it's already active and not expired
	if existing, ok := ac.activeOverrides[action]; ok {
		if now.Before(existing.ExpiresAt) {
			return // Already active, skip
		}
	}

	// Calculate duration from params
	durationSec := 300 // Default 5 minutes
	if d, ok := rule.Params["duration_seconds"]; ok && d > 0 {
		durationSec = d
	}
	duration := time.Duration(durationSec) * time.Second

	// Record the override
	ac.activeOverrides[action] = &Override{
		Action:    action,
		ExpiresAt: now.Add(duration),
		Params:    rule.Params,
	}

	log.Printf("ADAPTIVE: firing action=%s triggered_by=%s:%s severity=%s duration=%s",
		action, event.Source, event.EventType, event.Severity, duration)

	// Dispatch to the appropriate callback (unlocked, callbacks should be thread-safe)
	// We must not hold the lock while calling callbacks to avoid deadlocks.
	go ac.dispatchAction(action, event, duration, rule.Params)
}

func (ac *AdaptiveController) dispatchAction(action string, event *types.SecurityEvent, duration time.Duration, params map[string]int) {
	switch action {
	case "elevate_sensitivity":
		if ac.OnElevateSensitivity != nil {
			level := "high"
			if l, ok := params["level"]; ok {
				switch l {
				case 1:
					level = "low"
				case 2:
					level = "medium"
				case 3:
					level = "high"
				}
			}
			ac.OnElevateSensitivity(level, duration)
		} else {
			log.Printf("SECURITY WARNING: adaptive rule triggered action=%s but OnElevateSensitivity callback is nil", action)
		}

	case "restrict_domains":
		if ac.OnRestrictDomains != nil {
			ac.OnRestrictDomains(duration)
		} else {
			log.Printf("SECURITY WARNING: adaptive rule triggered action=%s but OnRestrictDomains callback is nil", action)
		}

	case "elevate_default_deny":
		if ac.OnElevateDefaultDeny != nil {
			ac.OnElevateDefaultDeny(duration)
		} else {
			log.Printf("SECURITY WARNING: adaptive rule triggered action=%s but OnElevateDefaultDeny callback is nil", action)
		}

	case "block_session":
		if ac.OnBlockSession != nil {
			sessionID := event.SessionID
			ac.OnBlockSession(sessionID, duration)
		} else {
			log.Printf("SECURITY WARNING: adaptive rule triggered action=%s but OnBlockSession callback is nil", action)
		}

	case "add_temp_firewall_rule":
		if ac.OnAddTempFirewallRule != nil {
			ip := ""
			if event.Details != nil {
				ip = event.Details["dest_ip"]
			}
			if ip != "" {
				ac.OnAddTempFirewallRule(ip, duration)
			}
		} else {
			log.Printf("SECURITY WARNING: adaptive rule triggered action=%s but OnAddTempFirewallRule callback is nil", action)
		}

	default:
		log.Printf("ADAPTIVE: unknown action %q", action)
	}

	// Publish a meta-event about the adaptive response
	ac.bus.Publish(&types.SecurityEvent{
		EventType: eventTypeForAction(action),
		Severity:  types.SeverityInfo,
		Source:    types.SourceAdaptive,
		Timestamp: time.Now(),
		Reason:    fmt.Sprintf("adaptive response: %s triggered by %s:%s", action, event.Source, event.EventType),
		Details: map[string]string{
			"trigger_event": string(event.EventType),
			"trigger_source": string(event.Source),
			"action":         action,
		},
	})
}

func (ac *AdaptiveController) cleanupLoop() {
	defer ac.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ac.quit:
			return
		case <-ticker.C:
			ac.cleanup()
		}
	}
}

func (ac *AdaptiveController) cleanup() {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	now := time.Now()

	// Remove expired overrides
	for key, override := range ac.activeOverrides {
		if now.After(override.ExpiresAt) {
			log.Printf("ADAPTIVE: override expired action=%s", key)
			delete(ac.activeOverrides, key)
		}
	}

	// Trim old event counts (keep only last 5 minutes)
	cutoff := now.Add(-5 * time.Minute)
	for key, times := range ac.eventCounts {
		trimmed := times[:0]
		for _, t := range times {
			if t.After(cutoff) {
				trimmed = append(trimmed, t)
			}
		}
		if len(trimmed) == 0 {
			delete(ac.eventCounts, key)
		} else {
			ac.eventCounts[key] = trimmed
		}
	}

	// Decay threat score
	elapsed := now.Sub(ac.lastDecay)
	if elapsed > 30*time.Second {
		decay := int(elapsed.Seconds() / 30)
		ac.threatScore -= decay
		if ac.threatScore < 0 {
			ac.threatScore = 0
		}
		ac.lastDecay = now
	}

	// Clean up per-source tracker (uses its own mutex, so safe to call here)
	ac.sourceTracker.cleanup(5 * time.Minute)
}

func eventTypeForAction(action string) types.EventType {
	switch action {
	case "elevate_sensitivity":
		return types.EventSensitivityElevated
	case "elevate_default_deny":
		return types.EventDefaultDenyActivated
	case "block_session":
		return types.EventSessionBlocked
	case "add_temp_firewall_rule":
		return types.EventTempRuleAdded
	default:
		return types.EventType("adaptive_" + action)
	}
}
