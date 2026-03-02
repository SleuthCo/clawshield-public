package iptables

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
)

// ApplyRules applies iptables rules with automatic rollback on failure
func ApplyRules(rules []string) error {
	// Save current rules before applying (use -S for restorable format)
	current, err := getIptablesRules()
	if err != nil {
		return fmt.Errorf("failed to save current rules: %w", err)
	}

	// Apply new rules one by one with validation
	for _, rule := range rules {
		err := applyRule(rule)
		if err != nil {
			log.Printf("Failed to apply rule: %s", rule)
			rollback(current)
			return fmt.Errorf("failed to apply rule '%s': %w", rule, err)
		}
	}

	// Verify rules were applied (sanity check)
	applied, verifyErr := getIptablesRules()
	if verifyErr != nil {
		log.Printf("WARNING: failed to verify applied rules: %v", verifyErr)
	}
	if len(applied) == 0 {
		rollback(current)
		return fmt.Errorf("no rules detected after application")
	}

	log.Println("ClawShield rules applied successfully")
	return nil
}

// applyRule runs a single iptables command.
// Rules are passed as complete strings (e.g. "-A OUTPUT -d 1.2.3.4 -j ACCEPT",
// "-F OUTPUT", "-P OUTPUT DROP") and split into arguments for exec.
func applyRule(rule string) error {
	parts := strings.Fields(rule)
	if len(parts) == 0 {
		return fmt.Errorf("empty rule")
	}
	cmd := exec.Command("iptables", parts...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables failed: %s (%v)", string(output), err)
	}
	return nil
}

// getIptablesRules returns current OUTPUT chain rules in restorable -S format.
// Each line is like "-A OUTPUT -d 127.0.0.0/8 -j ACCEPT".
func getIptablesRules() ([]string, error) {
	cmd := exec.Command("iptables", "-S", "OUTPUT")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var rules []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Skip the policy line (e.g. "-P OUTPUT ACCEPT")
		if strings.HasPrefix(line, "-P ") {
			continue
		}
		rules = append(rules, line)
	}
	return rules, nil
}

// rollback restores the previous rule set.
// Errors during rollback are logged but do not cause a return error — rollback
// is best-effort. However, every failure is now logged so operators can detect
// a partial rollback state (which means the firewall may be misconfigured).
func rollback(oldRules []string) {
	log.Println("Rolling back iptables rules...")

	var rollbackErrors int

	// Flush OUTPUT chain first
	if err := exec.Command("iptables", "-F", "OUTPUT").Run(); err != nil {
		log.Printf("ERROR: rollback flush failed: %v", err)
		rollbackErrors++
	}

	// Reapply old rules in order (already in -S format: "-A OUTPUT ...")
	for _, rule := range oldRules {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}
		parts := strings.Fields(rule)
		if len(parts) < 2 {
			continue
		}
		cmd := exec.Command("iptables", parts...)
		if err := cmd.Run(); err != nil {
			log.Printf("ERROR: rollback failed to restore rule %q: %v", rule, err)
			rollbackErrors++
		}
	}

	if rollbackErrors > 0 {
		log.Printf("WARNING: rollback completed with %d errors — firewall may be in an inconsistent state", rollbackErrors)
	} else {
		log.Println("Rollback complete.")
	}
}
