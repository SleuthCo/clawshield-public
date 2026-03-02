// +build integration

package iptables

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestFirewallPolicyToRules(t *testing.T) {
	// Test: policy → iptables rules → verification
	
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "firewall.yaml")
	
	configContent := `
allowed_domains:
  - google.com
  - github.com
  - cloudflare.com
dns_resolvers:
  - 8.8.8.8
  - 1.1.1.1
`
	
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to create config file: %v", err)
	}
	
	// 1. Load config
	data, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("failed to read config: %v", err)
	}
	
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}
	
	// 2. Generate rules
	rules, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}
	
	// 3. Verify rules
	if len(rules) == 0 {
		t.Fatal("no rules generated")
	}
	
	// Verify structure
	hasFlush := false
	hasDropPolicy := false
	hasLocalhostAllow := false
	dnsRules := 0
	domainRules := 0
	hasLogRule := false
	
	for _, rule := range rules {
		if strings.Contains(rule, "-F OUTPUT") {
			hasFlush = true
		}
		if strings.Contains(rule, "-P OUTPUT DROP") {
			hasDropPolicy = true
		}
		if strings.Contains(rule, "127.0.0.1/8") && strings.Contains(rule, "ACCEPT") {
			hasLocalhostAllow = true
		}
		if strings.Contains(rule, "--dport 53") {
			dnsRules++
		}
		if strings.Contains(rule, "ACCEPT") && 
		   !strings.Contains(rule, "127.0.0.1") &&
		   !strings.Contains(rule, "172.16.0.0") &&
		   !strings.Contains(rule, "dport 53") {
			domainRules++
		}
		if strings.Contains(rule, "LOG") {
			hasLogRule = true
		}
	}
	
	// Assertions
	if !hasFlush {
		t.Error("missing flush rule")
	}
	
	if !hasDropPolicy {
		t.Error("missing DROP policy")
	}
	
	if !hasLocalhostAllow {
		t.Error("missing localhost allow rule")
	}
	
	expectedDNSRules := len(cfg.DNSResolvers) * 2 // UDP + TCP
	if dnsRules != expectedDNSRules {
		t.Errorf("DNS rules = %d, want %d", dnsRules, expectedDNSRules)
	}
	
	// Each domain should resolve to at least 1 IP
	if domainRules < len(cfg.AllowedDomains) {
		t.Errorf("domain rules = %d, want at least %d", domainRules, len(cfg.AllowedDomains))
	}
	
	if !hasLogRule {
		t.Error("missing log rule")
	}
	
	// 4. Verify rule format (should be valid iptables syntax)
	for i, rule := range rules {
		// All rules should start with -F, -P, or -A
		if !strings.HasPrefix(rule, "-F") && 
		   !strings.HasPrefix(rule, "-P") && 
		   !strings.HasPrefix(rule, "-A") {
			t.Errorf("rule %d has invalid prefix: %s", i, rule)
		}
	}
}

func TestFirewallRuleApplication(t *testing.T) {
	// Simulate rule application workflow
	
	cfg := Config{
		AllowedDomains: []string{"example.com"},
		DNSResolvers:   []string{"8.8.8.8"},
	}
	
	// 1. Generate rules
	rules, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}
	
	// 2. Save rules to file (simulating apply phase)
	tmpDir := t.TempDir()
	rulesFile := filepath.Join(tmpDir, "iptables.rules")
	
	content := strings.Join(rules, "\n")
	if err := os.WriteFile(rulesFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write rules file: %v", err)
	}
	
	// 3. Verify file was written
	data, err := os.ReadFile(rulesFile)
	if err != nil {
		t.Fatalf("failed to read rules file: %v", err)
	}
	
	readRules := strings.Split(string(data), "\n")
	
	if len(readRules) != len(rules) {
		t.Errorf("read %d rules from file, want %d", len(readRules), len(rules))
	}
	
	// 4. Verify rules are idempotent (regenerating should produce same output)
	rules2, err := Generate(cfg)
	if err != nil {
		t.Fatalf("second Generate() failed: %v", err)
	}
	
	// Note: Rule order should be consistent
	// However, DNS resolution might return IPs in different order
	// So we check for same number of rules of each type
	
	countRuleType := func(rules []string, pattern string) int {
		count := 0
		for _, r := range rules {
			if strings.Contains(r, pattern) {
				count++
			}
		}
		return count
	}
	
	if countRuleType(rules, "ACCEPT") != countRuleType(rules2, "ACCEPT") {
		t.Error("ACCEPT rule count differs between generations")
	}
	
	if countRuleType(rules, "dport 53") != countRuleType(rules2, "dport 53") {
		t.Error("DNS rule count differs between generations")
	}
}

func TestFirewallComplexPolicy(t *testing.T) {
	// Test with a complex policy
	
	cfg := Config{
		AllowedDomains: []string{
			"google.com",
			"github.com",
			"stackoverflow.com",
			"npmjs.org",
			"pypi.org",
		},
		DNSResolvers: []string{
			"8.8.8.8",
			"8.8.4.4",
			"1.1.1.1",
			"1.0.0.1",
		},
	}
	
	rules, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}
	
	// Verify comprehensive coverage
	if len(rules) < 10 {
		t.Errorf("expected at least 10 rules for complex policy, got %d", len(rules))
	}
	
	// Count different rule types
	acceptRules := 0
	dnsRules := 0
	logRules := 0
	
	for _, rule := range rules {
		if strings.Contains(rule, "ACCEPT") {
			acceptRules++
		}
		if strings.Contains(rule, "dport 53") {
			dnsRules++
		}
		if strings.Contains(rule, "LOG") {
			logRules++
		}
	}
	
	// Should have:
	// - 1 localhost ACCEPT
	// - 1 WSL2 ACCEPT
	// - 8 DNS rules (4 resolvers * 2 protocols)
	// - At least 5 domain IP rules
	// - 1 LOG rule
	
	expectedDNSRules := len(cfg.DNSResolvers) * 2
	if dnsRules != expectedDNSRules {
		t.Errorf("DNS rules = %d, want %d", dnsRules, expectedDNSRules)
	}
	
	if logRules != 1 {
		t.Errorf("log rules = %d, want 1", logRules)
	}
	
	// At least localhost + WSL2 + domain IPs
	minAcceptRules := 2 + len(cfg.AllowedDomains)
	if acceptRules < minAcceptRules {
		t.Errorf("ACCEPT rules = %d, want at least %d", acceptRules, minAcceptRules)
	}
}

func TestFirewallErrorHandling(t *testing.T) {
	tests := []struct {
		name      string
		cfg       Config
		wantError bool
	}{
		{
			name: "invalid DNS resolver",
			cfg: Config{
				DNSResolvers: []string{"not-an-ip"},
			},
			wantError: true,
		},
		{
			name: "invalid domain",
			cfg: Config{
				AllowedDomains: []string{"this-definitely-does-not-exist-12345.invalid"},
				DNSResolvers:   []string{"8.8.8.8"},
			},
			// DNS resolution failures are treated as warnings, not errors.
			// Some DNS providers may resolve any domain, so this may succeed.
			wantError: false,
		},
		{
			name: "empty config",
			cfg: Config{
				AllowedDomains: []string{},
				DNSResolvers:   []string{},
			},
			wantError: false,
		},
		{
			name: "valid config",
			cfg: Config{
				AllowedDomains: []string{"google.com"},
				DNSResolvers:   []string{"8.8.8.8"},
			},
			wantError: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Generate(tt.cfg)
			
			if tt.wantError && err == nil {
				t.Error("Generate() succeeded, want error")
			}
			
			if !tt.wantError && err != nil {
				t.Errorf("Generate() failed: %v", err)
			}
		})
	}
}

func TestFirewallRuleOrdering(t *testing.T) {
	// Verify critical rules are in correct order
	
	cfg := Config{
		AllowedDomains: []string{"example.com"},
		DNSResolvers:   []string{"8.8.8.8"},
	}
	
	rules, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}
	
	// Find positions of critical rules
	flushPos := -1
	dropPolicyPos := -1
	logPos := -1
	
	for i, rule := range rules {
		if strings.Contains(rule, "-F OUTPUT") {
			flushPos = i
		}
		if strings.Contains(rule, "-P OUTPUT DROP") {
			dropPolicyPos = i
		}
		if strings.Contains(rule, "LOG") {
			logPos = i
		}
	}
	
	// Verify ordering
	if flushPos != 0 {
		t.Errorf("flush should be first rule (position %d)", flushPos)
	}
	
	if dropPolicyPos != 1 {
		t.Errorf("DROP policy should be second rule (position %d)", dropPolicyPos)
	}
	
	if logPos != len(rules)-1 {
		t.Errorf("LOG should be last rule (position %d, total %d)", logPos, len(rules))
	}
	
	// Verify ACCEPT rules come before LOG
	for i, rule := range rules {
		if i < logPos && strings.Contains(rule, "ACCEPT") {
			// Good - ACCEPT before LOG
		} else if i < logPos && strings.Contains(rule, "LOG") {
			t.Errorf("found LOG rule at position %d, should be last", i)
		}
	}
}

func TestFirewallDNSResolutionCaching(t *testing.T) {
	// Verify that DNS resolution happens at generation time
	// (not at runtime)
	
	cfg := Config{
		AllowedDomains: []string{"google.com"},
		DNSResolvers:   []string{"8.8.8.8"},
	}
	
	// Generate rules multiple times
	rules1, err := Generate(cfg)
	if err != nil {
		t.Fatalf("first Generate() failed: %v", err)
	}
	
	rules2, err := Generate(cfg)
	if err != nil {
		t.Fatalf("second Generate() failed: %v", err)
	}
	
	// Rules should contain resolved IP addresses, not domain names
	for _, rule := range rules1 {
		if strings.Contains(rule, "google.com") {
			t.Error("rules should contain resolved IPs, not domain names")
		}
	}
	
	// Both generations should produce IP-based rules
	hasIPRule1 := false
	hasIPRule2 := false
	
	for _, rule := range rules1 {
		if strings.Contains(rule, "ACCEPT") && 
		   !strings.Contains(rule, "127.0.0.1") &&
		   !strings.Contains(rule, "172.16.0.0") &&
		   !strings.Contains(rule, "dport 53") {
			hasIPRule1 = true
			break
		}
	}
	
	for _, rule := range rules2 {
		if strings.Contains(rule, "ACCEPT") && 
		   !strings.Contains(rule, "127.0.0.1") &&
		   !strings.Contains(rule, "172.16.0.0") &&
		   !strings.Contains(rule, "dport 53") {
			hasIPRule2 = true
			break
		}
	}
	
	if !hasIPRule1 || !hasIPRule2 {
		t.Error("rules should contain resolved IP addresses")
	}
}
