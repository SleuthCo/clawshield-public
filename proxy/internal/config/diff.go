package config

import (
	"fmt"
	"sort"
	"strings"

	"github.com/SleuthCo/clawshield/proxy/internal/engine"
)

// PolicyChange describes a single difference between two policy versions.
type PolicyChange struct {
	Field      string // e.g. "default_action", "allowlist", "vuln_scan"
	OldValue   string // Human-readable old value
	NewValue   string // Human-readable new value
	ChangeType string // "added", "removed", "changed"
}

// String returns a human-readable representation of the change.
func (c PolicyChange) String() string {
	switch c.ChangeType {
	case "added":
		return fmt.Sprintf("%s: (none) → %s", c.Field, c.NewValue)
	case "removed":
		return fmt.Sprintf("%s: %s → (none)", c.Field, c.OldValue)
	default:
		return fmt.Sprintf("%s: %s → %s", c.Field, c.OldValue, c.NewValue)
	}
}

// DiffPolicies compares two policies and returns a list of changes.
// Returns nil if the policies are identical.
func DiffPolicies(old, new *engine.Policy) []PolicyChange {
	var changes []PolicyChange

	// Default action
	if old.DefaultAction != new.DefaultAction {
		changes = append(changes, PolicyChange{
			Field: "default_action", OldValue: old.DefaultAction,
			NewValue: new.DefaultAction, ChangeType: "changed",
		})
	}

	// Evaluation timeout
	if old.EvaluationTimeoutMs != new.EvaluationTimeoutMs {
		changes = append(changes, PolicyChange{
			Field: "evaluation_timeout_ms",
			OldValue: fmt.Sprintf("%d", old.EvaluationTimeoutMs),
			NewValue: fmt.Sprintf("%d", new.EvaluationTimeoutMs),
			ChangeType: "changed",
		})
	}

	// Max message bytes
	if old.MaxMessageBytes != new.MaxMessageBytes {
		changes = append(changes, PolicyChange{
			Field: "max_message_bytes",
			OldValue: fmt.Sprintf("%d", old.MaxMessageBytes),
			NewValue: fmt.Sprintf("%d", new.MaxMessageBytes),
			ChangeType: "changed",
		})
	}

	// Allowlist
	changes = append(changes, diffStringList("allowlist", old.Allowlist, new.Allowlist)...)

	// Denylist
	changes = append(changes, diffStringList("denylist", old.Denylist, new.Denylist)...)

	// Domain allowlist
	changes = append(changes, diffStringList("domain_allowlist", old.DomainAllowlist, new.DomainAllowlist)...)

	// Scanner toggles
	changes = append(changes, diffScanner("vuln_scan", old.VulnScan != nil, new.VulnScan != nil)...)
	changes = append(changes, diffScanner("prompt_injection", old.PromptInjection != nil, new.PromptInjection != nil)...)
	changes = append(changes, diffScanner("malware_scan", old.MalwareScan != nil, new.MalwareScan != nil)...)
	changes = append(changes, diffScanner("secrets_scan", old.SecretsScan != nil, new.SecretsScan != nil)...)
	changes = append(changes, diffScanner("pii_scan", old.PIIScan != nil, new.PIIScan != nil)...)

	// SIEM config
	oldSIEM := old.SIEM != nil && old.SIEM.Enabled
	newSIEM := new.SIEM != nil && new.SIEM.Enabled
	if oldSIEM != newSIEM {
		changes = append(changes, PolicyChange{
			Field: "siem.enabled",
			OldValue: fmt.Sprintf("%v", oldSIEM),
			NewValue: fmt.Sprintf("%v", newSIEM),
			ChangeType: "changed",
		})
	}

	return changes
}

// ComputeEffectiveDiff returns a single-line human-readable summary of the
// differences between two policies, suitable for logging.
func ComputeEffectiveDiff(old, new *engine.Policy) string {
	changes := DiffPolicies(old, new)
	if len(changes) == 0 {
		return "no changes"
	}

	parts := make([]string, len(changes))
	for i, c := range changes {
		parts[i] = c.String()
	}
	return strings.Join(parts, ", ")
}

// diffStringList computes additions and removals between two string slices.
func diffStringList(field string, old, new []string) []PolicyChange {
	var changes []PolicyChange

	oldSet := make(map[string]bool, len(old))
	newSet := make(map[string]bool, len(new))
	for _, s := range old {
		oldSet[s] = true
	}
	for _, s := range new {
		newSet[s] = true
	}

	// Find additions
	var added []string
	for _, s := range new {
		if !oldSet[s] {
			added = append(added, s)
		}
	}

	// Find removals
	var removed []string
	for _, s := range old {
		if !newSet[s] {
			removed = append(removed, s)
		}
	}

	sort.Strings(added)
	sort.Strings(removed)

	if len(added) > 0 {
		changes = append(changes, PolicyChange{
			Field: field, NewValue: fmt.Sprintf("+%d entries: %s", len(added), strings.Join(added, ", ")),
			ChangeType: "added",
		})
	}
	if len(removed) > 0 {
		changes = append(changes, PolicyChange{
			Field: field, OldValue: fmt.Sprintf("%d entries: %s", len(removed), strings.Join(removed, ", ")),
			ChangeType: "removed",
		})
	}

	return changes
}

// diffScanner detects scanner enable/disable changes.
func diffScanner(name string, oldEnabled, newEnabled bool) []PolicyChange {
	if oldEnabled == newEnabled {
		return nil
	}
	oldStr := "disabled"
	newStr := "disabled"
	if oldEnabled {
		oldStr = "enabled"
	}
	if newEnabled {
		newStr = "enabled"
	}
	return []PolicyChange{{
		Field: name, OldValue: oldStr, NewValue: newStr, ChangeType: "changed",
	}}
}
