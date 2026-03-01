package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/SleuthCo/clawshield/firewall/internal/compile/iptables"
)

// allowedIptablesFlags is the whitelist of iptables flags that generated rules may use.
var allowedIptablesFlags = map[string]bool{
	"-A": true, "-D": true, "-I": true, "-F": true, "-P": true,
	"-d": true, "-s": true, "-j": true, "-p": true, "-m": true,
	"--dport": true, "--sport": true, "--state": true,
	"--limit": true, "--log-prefix": true, "--log-level": true,
	"OUTPUT": true, "INPUT": true, "FORWARD": true,
	"ACCEPT": true, "DROP": true, "REJECT": true, "LOG": true,
	"tcp": true, "udp": true, "icmp": true,
	"state": true, "limit": true,
	"NEW": true, "ESTABLISHED": true, "RELATED": true,
}

func main() {
	var rootCmd = &cobra.Command{
		Use:   "clawshield-fw",
		Short: "ClawShield Firewall CLI for WSL2 egress control",
	}

	var applyCmd = &cobra.Command{
		Use:   "apply",
		Short: "Apply iptables rules from YAML config",
		Run: func(cmd *cobra.Command, args []string) {
			configPath, _ := cmd.Flags().GetString("config")
			if err := applyRules(configPath); err != nil {
				log.Fatal(err)
			}
		},
	}
	applyCmd.Flags().StringP("config", "f", "", "path to YAML config file")
	applyCmd.MarkFlagRequired("config")

	var uninstallCmd = &cobra.Command{
		Use:   "uninstall",
		Short: "Remove all ClawShield iptables rules",
		Run: func(cmd *cobra.Command, args []string) {
			if err := uninstallRules(); err != nil {
				log.Fatal(err)
			}
		},
	}

	rootCmd.AddCommand(applyCmd)
	rootCmd.AddCommand(uninstallCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func applyRules(configPath string) error {
	fmt.Printf("Applying rules from %s\n", configPath)

	// Read config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	// Parse YAML
	var cfg iptables.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Generate rules
	rules, err := iptables.Generate(cfg)
	if err != nil {
		return fmt.Errorf("failed to generate rules: %w", err)
	}

	// Apply rules via iptables commands
	for _, rule := range rules {
		fmt.Printf("  %s\n", rule)

		if err := execIptablesRule(rule); err != nil {
			return fmt.Errorf("failed to apply rule '%s': %w", rule, err)
		}
	}

	fmt.Println("ClawShield firewall rules applied successfully.")
	return nil
}

// validateArg checks that an iptables argument is safe.
// Flags must be in the whitelist. Values (IP/CIDR) are validated separately.
// isRateLimit checks for rate limit values like "5/min", "10/sec", etc.
func isRateLimit(s string) bool {
	validUnits := map[string]bool{"sec": true, "min": true, "hour": true, "day": true}
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return false
	}
	for _, ch := range parts[0] {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return validUnits[parts[1]]
}

// isLogPrefix checks for safe log prefix values (alphanumeric, brackets, hyphens, spaces).
func isLogPrefix(s string) bool {
	for _, ch := range s {
		if !((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
			ch == '[' || ch == ']' || ch == '-' || ch == '_' || ch == ' ') {
			return false
		}
	}
	return len(s) > 0 && len(s) <= 64
}

func validateArg(arg string) error {
	// Known flags and values
	if allowedIptablesFlags[arg] {
		return nil
	}
	// IP address or CIDR
	if net.ParseIP(arg) != nil {
		return nil
	}
	if _, _, err := net.ParseCIDR(arg); err == nil {
		return nil
	}
	// Comma-separated states like "NEW,ESTABLISHED,RELATED"
	if isStateList(arg) {
		return nil
	}
	// Rate limit values like "5/min"
	if isRateLimit(arg) {
		return nil
	}
	// Log prefix values (safe characters only)
	if isLogPrefix(arg) {
		return nil
	}
	// Pure numbers (ports, log levels)
	allDigits := true
	for _, ch := range arg {
		if ch < '0' || ch > '9' {
			allDigits = false
			break
		}
	}
	if allDigits && len(arg) > 0 {
		return nil
	}
	return fmt.Errorf("disallowed iptables argument: %q", arg)
}

func isStateList(s string) bool {
	validStates := map[string]bool{
		"NEW": true, "ESTABLISHED": true, "RELATED": true, "INVALID": true,
	}
	for _, part := range strings.Split(s, ",") {
		if !validStates[strings.TrimSpace(part)] {
			return false
		}
	}
	return true
}

func execIptablesRule(rule string) error {
	parts := strings.Fields(rule)
	if len(parts) == 0 {
		return fmt.Errorf("empty rule")
	}

	// Validate every argument
	for _, arg := range parts {
		if err := validateArg(arg); err != nil {
			return fmt.Errorf("rule validation failed: %w", err)
		}
	}

	cmd := exec.Command("iptables", parts...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v", string(output), err)
	}
	return nil
}

func uninstallRules() error {
	fmt.Println("Uninstalling ClawShield firewall rules...")

	// Flush OUTPUT chain
	if err := exec.Command("iptables", "-F", "OUTPUT").Run(); err != nil {
		return fmt.Errorf("failed to flush OUTPUT chain: %w", err)
	}

	// Reset policy to ACCEPT
	if err := exec.Command("iptables", "-P", "OUTPUT", "ACCEPT").Run(); err != nil {
		return fmt.Errorf("failed to reset OUTPUT policy: %w", err)
	}

	fmt.Println("ClawShield firewall rules removed. Default policy: ACCEPT")
	return nil
}
