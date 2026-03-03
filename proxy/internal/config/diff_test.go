package config

import (
	"strings"
	"testing"

	"github.com/SleuthCo/clawshield/proxy/internal/engine"
	"github.com/SleuthCo/clawshield/proxy/internal/scanner"
)

func TestDiffPolicies_NoDiff(t *testing.T) {
	p := &engine.Policy{DefaultAction: "allow", Allowlist: []string{"a", "b"}}
	changes := DiffPolicies(p, p)
	if len(changes) != 0 {
		t.Fatalf("expected no changes, got %d: %v", len(changes), changes)
	}
}

func TestDiffPolicies_DefaultActionChanged(t *testing.T) {
	old := &engine.Policy{DefaultAction: "allow"}
	new := &engine.Policy{DefaultAction: "deny"}
	changes := DiffPolicies(old, new)

	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
	if changes[0].Field != "default_action" {
		t.Fatalf("expected default_action change, got %s", changes[0].Field)
	}
	if changes[0].OldValue != "allow" || changes[0].NewValue != "deny" {
		t.Fatalf("expected allow->deny, got %s->%s", changes[0].OldValue, changes[0].NewValue)
	}
}

func TestDiffPolicies_AllowlistModified(t *testing.T) {
	old := &engine.Policy{Allowlist: []string{"a", "b", "c"}}
	new := &engine.Policy{Allowlist: []string{"b", "c", "d"}}
	changes := DiffPolicies(old, new)

	// Should detect "a" removed and "d" added
	hasAdded := false
	hasRemoved := false
	for _, c := range changes {
		if c.Field == "allowlist" && c.ChangeType == "added" {
			hasAdded = true
			if !strings.Contains(c.NewValue, "d") {
				t.Fatalf("expected 'd' in added, got %s", c.NewValue)
			}
		}
		if c.Field == "allowlist" && c.ChangeType == "removed" {
			hasRemoved = true
			if !strings.Contains(c.OldValue, "a") {
				t.Fatalf("expected 'a' in removed, got %s", c.OldValue)
			}
		}
	}
	if !hasAdded || !hasRemoved {
		t.Fatalf("expected added and removed changes, got %v", changes)
	}
}

func TestDiffPolicies_ScannerToggled(t *testing.T) {
	old := &engine.Policy{VulnScan: &scanner.VulnScanConfig{}}
	new := &engine.Policy{} // vuln_scan removed
	changes := DiffPolicies(old, new)

	found := false
	for _, c := range changes {
		if c.Field == "vuln_scan" {
			found = true
			if c.OldValue != "enabled" || c.NewValue != "disabled" {
				t.Fatalf("expected enabled->disabled, got %s->%s", c.OldValue, c.NewValue)
			}
		}
	}
	if !found {
		t.Fatal("expected vuln_scan change")
	}
}

func TestComputeEffectiveDiff(t *testing.T) {
	old := &engine.Policy{DefaultAction: "allow", Allowlist: []string{"a"}}
	new := &engine.Policy{DefaultAction: "deny", Allowlist: []string{"a", "b"}}

	summary := ComputeEffectiveDiff(old, new)
	if summary == "no changes" {
		t.Fatal("expected changes")
	}
	if !strings.Contains(summary, "default_action") {
		t.Fatalf("expected default_action in summary, got: %s", summary)
	}
	if !strings.Contains(summary, "allowlist") {
		t.Fatalf("expected allowlist in summary, got: %s", summary)
	}
}

func TestComputeEffectiveDiff_NoChanges(t *testing.T) {
	p := &engine.Policy{DefaultAction: "allow"}
	summary := ComputeEffectiveDiff(p, p)
	if summary != "no changes" {
		t.Fatalf("expected 'no changes', got: %s", summary)
	}
}
