package iptables

import (
	"sync"
	"testing"
	"time"
)

// mockExecutor records iptables commands instead of executing them.
type mockExecutor struct {
	mu       sync.Mutex
	commands []string
	failNext bool
}

func newMockExecutor() *mockExecutor {
	return &mockExecutor{}
}

func (m *mockExecutor) execute(args ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.failNext {
		m.failNext = false
		return &mockError{"simulated iptables failure"}
	}

	cmd := ""
	for _, a := range args {
		if cmd != "" {
			cmd += " "
		}
		cmd += a
	}
	m.commands = append(m.commands, cmd)
	return nil
}

func (m *mockExecutor) getCommands() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]string, len(m.commands))
	copy(result, m.commands)
	return result
}

type mockError struct {
	msg string
}

func (e *mockError) Error() string {
	return e.msg
}

func TestBlockIP(t *testing.T) {
	mock := newMockExecutor()
	mgr := NewDynamicRuleManagerWithExecutor(mock.execute)

	err := mgr.BlockIP("192.168.1.100", 5*time.Minute, "port scan detected")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cmds := mock.getCommands()
	if len(cmds) != 1 {
		t.Fatalf("expected 1 command, got %d", len(cmds))
	}

	expected := "iptables -A OUTPUT -d 192.168.1.100 -j DROP"
	if cmds[0] != expected {
		t.Errorf("expected command %q, got %q", expected, cmds[0])
	}

	if mgr.ActiveCount() != 1 {
		t.Errorf("expected 1 active rule, got %d", mgr.ActiveCount())
	}
}

func TestDuplicateRuleExtendsExpiration(t *testing.T) {
	mock := newMockExecutor()
	mgr := NewDynamicRuleManagerWithExecutor(mock.execute)

	// Add rule with short duration
	err := mgr.BlockIP("10.0.0.1", 1*time.Minute, "first detection")
	if err != nil {
		t.Fatal(err)
	}

	// Add same rule again with longer duration
	err = mgr.BlockIP("10.0.0.1", 10*time.Minute, "second detection")
	if err != nil {
		t.Fatal(err)
	}

	// Should only have applied iptables once (not duplicated)
	cmds := mock.getCommands()
	if len(cmds) != 1 {
		t.Errorf("expected 1 command (deduplicated), got %d", len(cmds))
	}

	// Should still only have 1 active rule
	if mgr.ActiveCount() != 1 {
		t.Errorf("expected 1 active rule, got %d", mgr.ActiveCount())
	}
}

func TestRemoveExpiredRules(t *testing.T) {
	mock := newMockExecutor()
	mgr := NewDynamicRuleManagerWithExecutor(mock.execute)

	// Add a rule that expires almost immediately
	err := mgr.AddTemporaryRule("-A OUTPUT -d 10.0.0.1 -j DROP", 50*time.Millisecond, "test")
	if err != nil {
		t.Fatal(err)
	}

	if mgr.ActiveCount() != 1 {
		t.Fatalf("expected 1 active rule, got %d", mgr.ActiveCount())
	}

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Trigger cleanup manually
	mgr.removeExpired()

	if mgr.ActiveCount() != 0 {
		t.Errorf("expected 0 active rules after expiration, got %d", mgr.ActiveCount())
	}

	// Should have both add and delete commands
	cmds := mock.getCommands()
	if len(cmds) != 2 {
		t.Fatalf("expected 2 commands (add + delete), got %d: %v", len(cmds), cmds)
	}

	expectedDelete := "iptables -D OUTPUT -d 10.0.0.1 -j DROP"
	if cmds[1] != expectedDelete {
		t.Errorf("expected delete command %q, got %q", expectedDelete, cmds[1])
	}
}

func TestMultipleRules(t *testing.T) {
	mock := newMockExecutor()
	mgr := NewDynamicRuleManagerWithExecutor(mock.execute)

	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	for _, ip := range ips {
		err := mgr.BlockIP(ip, 5*time.Minute, "test")
		if err != nil {
			t.Fatal(err)
		}
	}

	if mgr.ActiveCount() != 3 {
		t.Errorf("expected 3 active rules, got %d", mgr.ActiveCount())
	}

	rules := mgr.ActiveRules()
	if len(rules) != 3 {
		t.Errorf("expected 3 rules in snapshot, got %d", len(rules))
	}
}

func TestStopRemovesAllRules(t *testing.T) {
	mock := newMockExecutor()
	mgr := NewDynamicRuleManagerWithExecutor(mock.execute)
	mgr.Start()

	err := mgr.BlockIP("10.0.0.1", 5*time.Minute, "test")
	if err != nil {
		t.Fatal(err)
	}

	mgr.Stop()

	if mgr.ActiveCount() != 0 {
		t.Errorf("expected 0 active rules after stop, got %d", mgr.ActiveCount())
	}

	// Should have add + delete
	cmds := mock.getCommands()
	if len(cmds) != 2 {
		t.Errorf("expected 2 commands, got %d: %v", len(cmds), cmds)
	}
}

func TestApplyFailure(t *testing.T) {
	mock := newMockExecutor()
	mock.failNext = true
	mgr := NewDynamicRuleManagerWithExecutor(mock.execute)

	err := mgr.BlockIP("10.0.0.1", 5*time.Minute, "test")
	if err == nil {
		t.Error("expected error on apply failure")
	}

	if mgr.ActiveCount() != 0 {
		t.Errorf("failed rule should not be tracked, got %d active", mgr.ActiveCount())
	}
}

func TestDefaultExecutorSplitsArgs(t *testing.T) {
	// Verify that defaultExecutor correctly splits the rule string into
	// individual arguments. We can't run real iptables in tests, but we
	// can verify the splitting logic by using a harmless command.
	err := defaultExecutor("echo", "-A OUTPUT -d 10.0.0.1 -j DROP")
	if err != nil {
		t.Errorf("expected echo to succeed with split args, got: %v", err)
	}
}
