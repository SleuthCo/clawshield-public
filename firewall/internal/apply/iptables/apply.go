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

	// Verify rules were applied (optional sanity check)
	applied, _ := getIptablesRules()
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

// rollback restores the previous rule set
func rollback(oldRules []string) {
	log.Println("Rolling back iptables rules...")

	// Flush OUTPUT chain first
	exec.Command("iptables", "-F", "OUTPUT").Run()

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
		cmd.Run() // best effort; don't fail rollback
	}
	log.Println("Rollback complete.")
}
