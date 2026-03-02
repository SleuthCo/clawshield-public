package iptables

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// validHostnameRe matches RFC 952/1123 hostnames (letters, digits, hyphens, dots).
// This prevents shell metacharacter injection via crafted domain names.
var validHostnameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$`)

// Config represents the YAML allowlist configuration
type Config struct {
	AllowedDomains []string `yaml:"allowed_domains"`
	AllowedIPs     []string `yaml:"allowed_ips"`
	DNSResolvers   []string `yaml:"dns_resolvers"`
}

// wsl2CIDR is the private IP range used by WSL2 host bridge.
var wsl2CIDR *net.IPNet

func init() {
	_, wsl2CIDR, _ = net.ParseCIDR("172.16.0.0/12")
}

// Generate generates iptables rules based on config
func Generate(cfg Config) ([]string, error) {
	var rules []string

	// Flush and set default DROP policy (for safety in apply phase)
	rules = append(rules, "-F OUTPUT")
	rules = append(rules, "-P OUTPUT DROP")

	// Accept localhost
	rules = append(rules, "-A OUTPUT -d 127.0.0.1/8 -j ACCEPT")

	// Accept WSL2 host bridge (172.16.0.0/12)
	rules = append(rules, "-A OUTPUT -d 172.16.0.0/12 -j ACCEPT")

	// Accept WSL2 internal DNS resolver
	rules = append(rules, "-A OUTPUT -d 10.255.255.254 -j ACCEPT")

	// Always allow GitHub (required for agent operations)
	rules = append(rules, "-A OUTPUT -d 140.82.112.0/20 -j ACCEPT")  // GitHub primary
	rules = append(rules, "-A OUTPUT -d 185.199.108.0/22 -j ACCEPT") // GitHub Pages / raw.githubusercontent
	rules = append(rules, "-A OUTPUT -d 192.30.252.0/22 -j ACCEPT")  // GitHub legacy

	// Allow DNS to allowed resolvers (UDP/TCP 53)
	for _, resolver := range cfg.DNSResolvers {
		ip := net.ParseIP(resolver)
		if ip == nil {
			return nil, fmt.Errorf("invalid DNS resolver IP: %s", resolver)
		}
		rules = append(rules, fmt.Sprintf("-A OUTPUT -d %s -p udp --dport 53 -j ACCEPT", ip.String()))
		rules = append(rules, fmt.Sprintf("-A OUTPUT -d %s -p tcp --dport 53 -j ACCEPT", ip.String()))
	}

	// Resolve allowed domains and add allow rules for each resolved IP
	for _, domain := range cfg.AllowedDomains {
		// SECURITY: Validate domain names against RFC 952/1123 to prevent
		// shell metacharacter injection when these values are passed to iptables.
		// A crafted domain like "example.com; rm -rf /" would be dangerous.
		if !validHostnameRe.MatchString(domain) {
			return nil, fmt.Errorf("invalid domain name (contains illegal characters): %s", domain)
		}
		if len(domain) > 253 {
			return nil, fmt.Errorf("domain name too long (max 253 chars): %s", domain)
		}

		addrs, err := net.LookupHost(domain)
		if err != nil {
			// Log warning but continue - domain might be temporarily unreachable
			fmt.Printf("Warning: failed to resolve %s: %v\n", domain, err)
			continue
		}
		for _, ip := range addrs {
			// Skip localhost, WSL2 host ranges, and IPv6 (iptables only handles IPv4)
			if isLoopback(ip) || isWSL2Host(ip) || isIPv6(ip) {
				continue
			}
			// SECURITY: Validate resolved IP is a valid address before using in rule
			if net.ParseIP(ip) == nil {
				fmt.Printf("Warning: skipping invalid resolved IP %s for domain %s\n", ip, domain)
				continue
			}
			rules = append(rules, fmt.Sprintf("-A OUTPUT -d %s -j ACCEPT", ip))
		}
	}

	// Add direct IPs (for when DNS doesn't return IPv4)
	for _, ip := range cfg.AllowedIPs {
		if isIPv6(ip) {
			continue
		}
		// SECURITY: Validate IP addresses to prevent injection via crafted config
		if net.ParseIP(ip) == nil {
			return nil, fmt.Errorf("invalid IP address in allowed_ips: %s", ip)
		}
		rules = append(rules, fmt.Sprintf("-A OUTPUT -d %s -j ACCEPT", ip))
	}

	// Log all blocked attempts
	rules = append(rules, "-A OUTPUT -m limit --limit 5/min -j LOG --log-prefix \"[CLAWSHIELD-BLOCKED] \" --log-level 4")

	return rules, nil
}

func isLoopback(ip string) bool {
	return strings.HasPrefix(ip, "127.")
}

func isWSL2Host(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return wsl2CIDR.Contains(parsed)
}

func isIPv6(ip string) bool {
	return strings.Contains(ip, ":")
}
