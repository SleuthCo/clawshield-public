package iptables

import (
	"strings"
	"testing"
)

func TestGenerate_BasicRules(t *testing.T) {
	cfg := Config{
		AllowedDomains: []string{"example.com"},
		DNSResolvers:   []string{"8.8.8.8", "1.1.1.1"},
	}
	
	rules, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}
	
	if len(rules) == 0 {
		t.Fatal("Generate() returned no rules")
	}
	
	// Verify essential rules exist
	hasFlush := false
	hasDropPolicy := false
	hasLocalhostAllow := false
	hasWSL2Allow := false
	hasDNSAllow := false
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
		if strings.Contains(rule, "172.16.0.0/12") && strings.Contains(rule, "ACCEPT") {
			hasWSL2Allow = true
		}
		if strings.Contains(rule, "--dport 53") && strings.Contains(rule, "ACCEPT") {
			hasDNSAllow = true
		}
		if strings.Contains(rule, "LOG") && strings.Contains(rule, "CLAWSHIELD-BLOCKED") {
			hasLogRule = true
		}
	}
	
	if !hasFlush {
		t.Error("missing flush OUTPUT rule")
	}
	if !hasDropPolicy {
		t.Error("missing DROP policy rule")
	}
	if !hasLocalhostAllow {
		t.Error("missing localhost allow rule")
	}
	if !hasWSL2Allow {
		t.Error("missing WSL2 host allow rule")
	}
	if !hasDNSAllow {
		t.Error("missing DNS allow rule")
	}
	if !hasLogRule {
		t.Error("missing log rule")
	}
}

func TestGenerate_MultipleDNSResolvers(t *testing.T) {
	cfg := Config{
		AllowedDomains: []string{},
		DNSResolvers:   []string{"8.8.8.8", "8.8.4.4", "1.1.1.1"},
	}
	
	rules, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}
	
	// Count DNS rules (UDP + TCP for each resolver)
	dnsRuleCount := 0
	for _, rule := range rules {
		if strings.Contains(rule, "--dport 53") {
			dnsRuleCount++
		}
	}
	
	expected := len(cfg.DNSResolvers) * 2 // UDP + TCP per resolver
	if dnsRuleCount != expected {
		t.Errorf("got %d DNS rules, want %d (2 per resolver)", dnsRuleCount, expected)
	}
}

func TestGenerate_InvalidDNSResolver(t *testing.T) {
	cfg := Config{
		AllowedDomains: []string{},
		DNSResolvers:   []string{"not-an-ip"},
	}
	
	_, err := Generate(cfg)
	if err == nil {
		t.Error("Generate() succeeded with invalid DNS resolver, want error")
	}
	
	if !strings.Contains(err.Error(), "invalid DNS resolver IP") {
		t.Errorf("error = %v, want 'invalid DNS resolver IP'", err)
	}
}

func TestGenerate_DomainResolution(t *testing.T) {
	cfg := Config{
		AllowedDomains: []string{"google.com"},
		DNSResolvers:   []string{"8.8.8.8"},
	}
	
	rules, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}
	
	// Should have rules for resolved IPs
	// google.com should resolve to at least one IP
	hasGoogleIP := false
	for _, rule := range rules {
		// Look for ACCEPT rules that aren't localhost, WSL2, or DNS
		if strings.Contains(rule, "ACCEPT") && 
		   !strings.Contains(rule, "127.0.0.1") &&
		   !strings.Contains(rule, "172.16.0.0") &&
		   !strings.Contains(rule, "dport 53") {
			hasGoogleIP = true
			break
		}
	}
	
	if !hasGoogleIP {
		t.Error("no rules generated for resolved domain IPs")
	}
}

func TestGenerate_InvalidDomain(t *testing.T) {
	cfg := Config{
		AllowedDomains: []string{"this-domain-definitely-does-not-exist-12345.invalid"},
		DNSResolvers:   []string{"8.8.8.8"},
	}
	
	_, err := Generate(cfg)
	if err == nil {
		t.Skip("Generate() succeeded with unresolvable domain (DNS may have resolved it); skipping")
		return
	}
	
	if !strings.Contains(err.Error(), "failed to resolve") {
		t.Errorf("error = %v, want 'failed to resolve'", err)
	}
}

func TestGenerate_EmptyConfig(t *testing.T) {
	cfg := Config{
		AllowedDomains: []string{},
		DNSResolvers:   []string{},
	}
	
	rules, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate() failed with empty config: %v", err)
	}
	
	// Should still have basic rules
	if len(rules) == 0 {
		t.Error("Generate() returned no rules for empty config")
	}
	
	// Verify basic rules exist
	hasFlush := false
	hasDropPolicy := false
	
	for _, rule := range rules {
		if strings.Contains(rule, "-F OUTPUT") {
			hasFlush = true
		}
		if strings.Contains(rule, "-P OUTPUT DROP") {
			hasDropPolicy = true
		}
	}
	
	if !hasFlush || !hasDropPolicy {
		t.Error("missing essential rules in empty config")
	}
}

func TestGenerate_RuleOrder(t *testing.T) {
	cfg := Config{
		AllowedDomains: []string{"example.com"},
		DNSResolvers:   []string{"8.8.8.8"},
	}
	
	rules, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}
	
	// Verify rule order
	// 1. Flush should be first
	if !strings.Contains(rules[0], "-F OUTPUT") {
		t.Errorf("first rule should be flush, got: %s", rules[0])
	}
	
	// 2. DROP policy should be second
	if !strings.Contains(rules[1], "-P OUTPUT DROP") {
		t.Errorf("second rule should be DROP policy, got: %s", rules[1])
	}
	
	// 3. LOG rule should be last
	lastRule := rules[len(rules)-1]
	if !strings.Contains(lastRule, "LOG") {
		t.Errorf("last rule should be LOG, got: %s", lastRule)
	}
}

func TestGenerate_SkipLocalhostIPs(t *testing.T) {
	// Domains that resolve to localhost should be skipped
	cfg := Config{
		AllowedDomains: []string{"localhost"},
		DNSResolvers:   []string{"8.8.8.8"},
	}
	
	rules, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}
	
	// Count ACCEPT rules for 127.x.x.x addresses
	// Should only have the one explicit localhost rule
	localhostRuleCount := 0
	for _, rule := range rules {
		if strings.Contains(rule, "127.") && strings.Contains(rule, "ACCEPT") {
			localhostRuleCount++
		}
	}
	
	// Should have exactly 1 localhost rule (the explicit 127.0.0.1/8 rule)
	if localhostRuleCount != 1 {
		t.Errorf("expected 1 localhost rule, got %d", localhostRuleCount)
	}
}

func TestGenerate_SkipWSL2HostIPs(t *testing.T) {
	cfg := Config{
		AllowedDomains: []string{"example.com"},
		DNSResolvers:   []string{"8.8.8.8"},
	}
	
	rules, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}
	
	// Count WSL2 host rules
	wsl2RuleCount := 0
	for _, rule := range rules {
		if strings.Contains(rule, "172.") && strings.Contains(rule, "ACCEPT") {
			wsl2RuleCount++
		}
	}
	
	// Should have exactly 1 WSL2 rule (the explicit 172.16.0.0/12 rule)
	if wsl2RuleCount != 1 {
		t.Errorf("expected 1 WSL2 host rule, got %d", wsl2RuleCount)
	}
}

func TestGenerate_LogRuleFormat(t *testing.T) {
	cfg := Config{
		AllowedDomains: []string{},
		DNSResolvers:   []string{"8.8.8.8"},
	}
	
	rules, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}
	
	// Find log rule
	var logRule string
	for _, rule := range rules {
		if strings.Contains(rule, "LOG") {
			logRule = rule
			break
		}
	}
	
	if logRule == "" {
		t.Fatal("no LOG rule found")
	}
	
	// Verify log rule components
	if !strings.Contains(logRule, "-A OUTPUT") {
		t.Error("LOG rule should append to OUTPUT chain")
	}
	
	if !strings.Contains(logRule, "-m limit --limit 5/min") {
		t.Error("LOG rule should have rate limiting")
	}
	
	if !strings.Contains(logRule, "--log-prefix") || !strings.Contains(logRule, "CLAWSHIELD-BLOCKED") {
		t.Error("LOG rule should have CLAWSHIELD-BLOCKED prefix")
	}
	
	if !strings.Contains(logRule, "--log-level 4") {
		t.Error("LOG rule should have log level 4")
	}
}

func TestGenerate_DNSRuleFormats(t *testing.T) {
	cfg := Config{
		AllowedDomains: []string{},
		DNSResolvers:   []string{"8.8.8.8"},
	}
	
	rules, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}
	
	// Find DNS rules
	var udpRule, tcpRule string
	for _, rule := range rules {
		if strings.Contains(rule, "8.8.8.8") && strings.Contains(rule, "udp") {
			udpRule = rule
		}
		if strings.Contains(rule, "8.8.8.8") && strings.Contains(rule, "tcp") {
			tcpRule = rule
		}
	}
	
	if udpRule == "" {
		t.Error("missing UDP DNS rule")
	} else {
		if !strings.Contains(udpRule, "-p udp") {
			t.Error("UDP rule should specify protocol")
		}
		if !strings.Contains(udpRule, "--dport 53") {
			t.Error("UDP rule should specify port 53")
		}
		if !strings.Contains(udpRule, "-j ACCEPT") {
			t.Error("UDP rule should ACCEPT")
		}
	}
	
	if tcpRule == "" {
		t.Error("missing TCP DNS rule")
	} else {
		if !strings.Contains(tcpRule, "-p tcp") {
			t.Error("TCP rule should specify protocol")
		}
		if !strings.Contains(tcpRule, "--dport 53") {
			t.Error("TCP rule should specify port 53")
		}
		if !strings.Contains(tcpRule, "-j ACCEPT") {
			t.Error("TCP rule should ACCEPT")
		}
	}
}

func TestIsLoopback(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"127.1.2.3", true},
		{"127.255.255.255", true},
		{"128.0.0.1", false},
		{"192.168.1.1", false},
		{"8.8.8.8", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := isLoopback(tt.ip)
			if got != tt.want {
				t.Errorf("isLoopback(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestIsWSL2Host(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"172.16.0.1", true},
		{"172.20.10.2", true},
		{"172.31.255.255", true},
		{"172.32.0.0", false},
		{"172.64.0.1", false},
		{"172.217.14.99", false},
		{"173.0.0.1", false},
		{"171.16.0.1", false},
		{"192.168.1.1", false},
		{"10.0.0.1", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := isWSL2Host(tt.ip)
			if got != tt.want {
				t.Errorf("isWSL2Host(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}


func TestGenerate_MultipleDomains(t *testing.T) {
	cfg := Config{
		AllowedDomains: []string{"google.com", "github.com", "cloudflare.com"},
		DNSResolvers:   []string{"8.8.8.8"},
	}
	
	rules, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}
	
	// Should have multiple IP-based ACCEPT rules
	ipRuleCount := 0
	for _, rule := range rules {
		if strings.Contains(rule, "ACCEPT") && 
		   !strings.Contains(rule, "127.0.0.1") &&
		   !strings.Contains(rule, "172.16.0.0") &&
		   !strings.Contains(rule, "dport 53") {
			ipRuleCount++
		}
	}
	
	// Each domain should resolve to at least 1 IP
	if ipRuleCount < len(cfg.AllowedDomains) {
		t.Errorf("expected at least %d IP rules, got %d", len(cfg.AllowedDomains), ipRuleCount)
	}
}

func TestGenerate_DuplicateDomains(t *testing.T) {
	cfg := Config{
		AllowedDomains: []string{"example.com", "example.com"},
		DNSResolvers:   []string{"8.8.8.8"},
	}
	
	rules, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}
	
	// Duplicate domains might generate duplicate rules
	// This is acceptable behavior, just verify it doesn't crash
	if len(rules) == 0 {
		t.Error("expected some rules for duplicate domains")
	}
}

func TestGenerate_RejectsInjectionInDomainNames(t *testing.T) {
	tests := []struct {
		name   string
		domain string
	}{
		{"shell injection semicolon", "example.com; rm -rf /"},
		{"shell injection backtick", "example.com`whoami`"},
		{"shell injection subshell", "example.com$(id)"},
		{"newline injection", "example.com\nevil"},
		{"flag injection", "-flag-injection"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				AllowedDomains: []string{tt.domain},
				DNSResolvers:   []string{"8.8.8.8"},
			}

			_, err := Generate(cfg)
			if err == nil {
				t.Errorf("Generate() should reject domain %q, but succeeded", tt.domain)
			}
			if err != nil && !strings.Contains(err.Error(), "invalid domain name") {
				t.Errorf("Expected 'invalid domain name' error, got: %v", err)
			}
		})
	}
}

func TestGenerate_RejectsInvalidAllowedIPs(t *testing.T) {
	cfg := Config{
		AllowedDomains: []string{},
		AllowedIPs:     []string{"not-an-ip; rm -rf /"},
		DNSResolvers:   []string{"8.8.8.8"},
	}

	_, err := Generate(cfg)
	if err == nil {
		t.Error("Generate() should reject invalid IP in allowed_ips")
	}
	if err != nil && !strings.Contains(err.Error(), "invalid IP address") {
		t.Errorf("Expected 'invalid IP address' error, got: %v", err)
	}
}

func TestGenerate_AcceptsValidDomains(t *testing.T) {
	cfg := Config{
		AllowedDomains: []string{"example.com", "sub.example.com", "my-host.example.com"},
		DNSResolvers:   []string{"8.8.8.8"},
	}

	_, err := Generate(cfg)
	if err != nil {
		t.Errorf("Generate() should accept valid domains, got: %v", err)
	}
}

func TestGenerate_IPv6Addresses(t *testing.T) {
	// Test with domains that might return IPv6
	cfg := Config{
		AllowedDomains: []string{"google.com"},
		DNSResolvers:   []string{"8.8.8.8"},
	}
	
	rules, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}
	
	// Should handle IPv6 addresses if returned
	// Current implementation uses net.LookupHost which can return IPv6
	// Verify it doesn't crash with IPv6 addresses
	if len(rules) == 0 {
		t.Error("expected some rules")
	}
}
