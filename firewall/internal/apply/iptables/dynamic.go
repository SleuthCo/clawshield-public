// Package iptables provides dynamic temporary rule management for the ClawShield firewall.
// Dynamic rules are added in response to cross-layer security events (e.g., eBPF detects
// port scanning → firewall temporarily blocks the destination IP).
package iptables

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// TempRule represents a temporary iptables rule with an expiration time.
type TempRule struct {
	Rule      string    // The iptables rule arguments (e.g., "-A OUTPUT -d 1.2.3.4 -j DROP")
	ExpiresAt time.Time // When this rule should be removed
	Reason    string    // Why this rule was added (for logging)
}

// DynamicRuleManager manages temporary iptables rules that expire after a configured duration.
// It is designed to be called from the adaptive controller when cross-layer events require
// immediate network-level responses.
type DynamicRuleManager struct {
	mu       sync.Mutex
	rules    map[string]*TempRule // Keyed by rule string for deduplication
	quit     chan struct{}
	wg       sync.WaitGroup
	executor func(args ...string) error // Allows injection for testing
}

// NewDynamicRuleManager creates a new manager that periodically cleans up expired rules.
func NewDynamicRuleManager() *DynamicRuleManager {
	return &DynamicRuleManager{
		rules:    make(map[string]*TempRule),
		quit:     make(chan struct{}),
		executor: defaultExecutor,
	}
}

// NewDynamicRuleManagerWithExecutor creates a manager with a custom command executor (for testing).
func NewDynamicRuleManagerWithExecutor(executor func(args ...string) error) *DynamicRuleManager {
	return &DynamicRuleManager{
		rules:    make(map[string]*TempRule),
		quit:     make(chan struct{}),
		executor: executor,
	}
}

// Start begins the periodic cleanup goroutine that removes expired rules.
func (m *DynamicRuleManager) Start() {
	m.wg.Add(1)
	go m.cleanupLoop()
	log.Println("Dynamic firewall rule manager started")
}

// Stop shuts down the manager and removes all temporary rules.
func (m *DynamicRuleManager) Stop() {
	close(m.quit)
	m.wg.Wait()

	// Remove all remaining temporary rules
	m.mu.Lock()
	defer m.mu.Unlock()

	for key, rule := range m.rules {
		if err := m.removeRule(rule.Rule); err != nil {
			log.Printf("WARNING: failed to remove temp rule on shutdown: %v", err)
		}
		delete(m.rules, key)
	}
}

// BlockIP adds a temporary iptables rule to block outbound traffic to the given IP address.
// The rule is automatically removed after the specified duration.
func (m *DynamicRuleManager) BlockIP(ip string, duration time.Duration, reason string) error {
	rule := fmt.Sprintf("-A OUTPUT -d %s -j DROP", ip)
	return m.AddTemporaryRule(rule, duration, reason)
}

// AddTemporaryRule adds an arbitrary temporary iptables rule with expiration.
// If the same rule already exists, its expiration is extended.
func (m *DynamicRuleManager) AddTemporaryRule(rule string, duration time.Duration, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	expiresAt := time.Now().Add(duration)

	// Check if rule already exists — extend expiration if so
	if existing, ok := m.rules[rule]; ok {
		if expiresAt.After(existing.ExpiresAt) {
			existing.ExpiresAt = expiresAt
			log.Printf("FIREWALL DYNAMIC: extended rule expiration: %s (reason: %s, expires: %s)",
				rule, reason, expiresAt.Format(time.RFC3339))
		}
		return nil
	}

	// Apply the iptables rule
	if err := m.applyRule(rule); err != nil {
		return fmt.Errorf("failed to apply dynamic rule: %w", err)
	}

	m.rules[rule] = &TempRule{
		Rule:      rule,
		ExpiresAt: expiresAt,
		Reason:    reason,
	}

	log.Printf("FIREWALL DYNAMIC: added temp rule: %s (reason: %s, duration: %s)",
		rule, reason, duration)

	return nil
}

// ActiveRules returns a snapshot of currently active temporary rules.
func (m *DynamicRuleManager) ActiveRules() []TempRule {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make([]TempRule, 0, len(m.rules))
	for _, r := range m.rules {
		result = append(result, *r)
	}
	return result
}

// ActiveCount returns the number of currently active temporary rules.
func (m *DynamicRuleManager) ActiveCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.rules)
}

func (m *DynamicRuleManager) cleanupLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.quit:
			return
		case <-ticker.C:
			m.removeExpired()
		}
	}
}

func (m *DynamicRuleManager) removeExpired() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for key, rule := range m.rules {
		if now.After(rule.ExpiresAt) {
			if err := m.removeRule(rule.Rule); err != nil {
				log.Printf("WARNING: failed to remove expired rule %s: %v", key, err)
				continue
			}
			log.Printf("FIREWALL DYNAMIC: removed expired rule: %s (was: %s)", key, rule.Reason)
			delete(m.rules, key)
		}
	}
}

func (m *DynamicRuleManager) applyRule(rule string) error {
	return m.executor("iptables", rule)
}

func (m *DynamicRuleManager) removeRule(rule string) error {
	// Convert -A to -D for deletion
	deleteRule := rule
	if len(deleteRule) > 2 && deleteRule[:2] == "-A" {
		deleteRule = "-D" + deleteRule[2:]
	}
	return m.executor("iptables", deleteRule)
}

func defaultExecutor(args ...string) error {
	if len(args) < 2 {
		return fmt.Errorf("insufficient arguments")
	}
	// Split the rule string into individual arguments for exec.Command.
	// e.g., "-A OUTPUT -d 192.168.1.100 -j DROP" → ["-A", "OUTPUT", "-d", "192.168.1.100", "-j", "DROP"]
	ruleArgs := strings.Fields(args[1])
	cmd := exec.Command(args[0], ruleArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(output))
	}
	return nil
}
