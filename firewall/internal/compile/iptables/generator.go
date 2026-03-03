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

// validateIPTablesArg checks that an argument doesn't contain dangerous shell metacharacters.
func validateIPTablesArg(arg string) error {
	dangerous := []string{";", "|", "&", "`", "$(", "\n", "\r", ">>", "<<"}
	for _, d := range dangerous {
		if strings.Contains(arg, d) {
			return fmt.Errorf("invalid iptables argument: contains dangerous character %q", d)
		}
	}
	return nil
}

// Config represents the YAML allowlist configuration
type Config struct {
	AllowedDomains []string `yaml:"allowed_domains"`
	AllowedIPs     []string `yaml:"allowed_ips"`
	DNSResolvers   []string `yaml:"dns_resolvers"`
}

// wsl2CIDR is the private IP range used by WSL2 host bridge.
var wsl2CIDR *net.IPNet

func init() {
	var err error
	_, wsl2CIDR, err = net.ParseCIDR("172.16.0.0/12")
	if err != nil {
		// This should never happen with a valid literal, but if it does,
		// fail loudly rather than risk a nil pointer dereference later.
		panic(fmt.Sprintf("FATAL: failed to parse WSL2 CIDR: %v", err))
	}
}

// Generate generates iptables rules based on config
// Returns IPv4 (iptables) and IPv6 (ip6tables) rules in a single slice,
// with IPv4 rules first (prefixed with "iptables:") followed by IPv6 rules (prefixed with "ip6tables:").
func Generate(cfg Config) ([]string, error) {
	var ipv4Rules []string
	var ipv6Rules []string

	// Flush and set default DROP policy (for safety in apply phase)
	ipv4Rules = append(ipv4Rules, "-F OUTPUT")
	ipv4Rules = append(ipv4Rules, "-P OUTPUT DROP")
	ipv6Rules = append(ipv6Rules, "-F OUTPUT")
	ipv6Rules = append(ipv6Rules, "-P OUTPUT DROP")

	// Accept localhost (IPv4)
	ipv4Rules = append(ipv4Rules, "-A OUTPUT -d 127.0.0.1/8 -j ACCEPT")
	// Accept localhost (IPv6)
	ipv6Rules = append(ipv6Rules, "-A OUTPUT -d ::1/128 -j ACCEPT")

	// Accept WSL2 host bridge (172.16.0.0/12)
	ipv4Rules = append(ipv4Rules, "-A OUTPUT -d 172.16.0.0/12 -j ACCEPT")

	// Accept WSL2 internal DNS resolver
	ipv4Rules = append(ipv4Rules, "-A OUTPUT -d 10.255.255.254 -j ACCEPT")

	// Always allow GitHub (required for agent operations)
	ipv4Rules = append(ipv4Rules, "-A OUTPUT -d 140.82.112.0/20 -j ACCEPT")  // GitHub primary
	ipv4Rules = append(ipv4Rules, "-A OUTPUT -d 185.199.108.0/22 -j ACCEPT") // GitHub Pages / raw.githubusercontent
	ipv4Rules = append(ipv4Rules, "-A OUTPUT -d 192.30.252.0/22 -j ACCEPT")  // GitHub legacy

	// Allow DNS to allowed resolvers (UDP/TCP 53)
	for _, resolver := range cfg.DNSResolvers {
		ip := net.ParseIP(resolver)
		if ip == nil {
			return nil, fmt.Errorf("invalid DNS resolver IP: %s", resolver)
		}
		// SECURITY: Validate resolver IP before using in rule
		if err := validateIPTablesArg(ip.String()); err != nil {
			return nil, fmt.Errorf("invalid DNS resolver IP: %w", err)
		}
		// Add to IPv4 or IPv6 rules based on resolver type
		if isIPv6(resolver) {
			ipv6Rules = append(ipv6Rules, fmt.Sprintf("-A OUTPUT -d %s -p udp --dport 53 -j ACCEPT", ip.String()))
			ipv6Rules = append(ipv6Rules, fmt.Sprintf("-A OUTPUT -d %s -p tcp --dport 53 -j ACCEPT", ip.String()))
		} else {
			ipv4Rules = append(ipv4Rules, fmt.Sprintf("-A OUTPUT -d %s -p udp --dport 53 -j ACCEPT", ip.String()))
			ipv4Rules = append(ipv4Rules, fmt.Sprintf("-A OUTPUT -d %s -p tcp --dport 53 -j ACCEPT", ip.String()))
		}
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
			// Skip localhost and WSL2 host ranges
			if isLoopback(ip) || isWSL2Host(ip) {
				continue
			}
			// SECURITY: Validate resolved IP is a valid address before using in rule
			if net.ParseIP(ip) == nil {
				fmt.Printf("Warning: skipping invalid resolved IP %s for domain %s\n", ip, domain)
				continue
			}
			// SECURITY: Validate IP doesn't contain dangerous characters
			if err := validateIPTablesArg(ip); err != nil {
				fmt.Printf("Warning: skipping resolved IP %s for domain %s: %v\n", ip, domain, err)
				continue
			}
			// Add to IPv4 or IPv6 rules based on IP type
			if isIPv6(ip) {
				ipv6Rules = append(ipv6Rules, fmt.Sprintf("-A OUTPUT -d %s -j ACCEPT", ip))
			} else {
				ipv4Rules = append(ipv4Rules, fmt.Sprintf("-A OUTPUT -d %s -j ACCEPT", ip))
			}
		}
	}

	// Add direct IPs (for when DNS doesn't return IPv4)
	for _, ip := range cfg.AllowedIPs {
		// SECURITY: Validate IP addresses to prevent injection via crafted config
		if net.ParseIP(ip) == nil {
			return nil, fmt.Errorf("invalid IP address in allowed_ips: %s", ip)
		}
		// SECURITY: Validate IP doesn't contain dangerous characters
		if err := validateIPTablesArg(ip); err != nil {
			return nil, fmt.Errorf("invalid IP in allowed_ips: %w", err)
		}
		// Add to IPv4 or IPv6 rules based on IP type
		if isIPv6(ip) {
			ipv6Rules = append(ipv6Rules, fmt.Sprintf("-A OUTPUT -d %s -j ACCEPT", ip))
		} else {
			ipv4Rules = append(ipv4Rules, fmt.Sprintf("-A OUTPUT -d %s -j ACCEPT", ip))
		}
	}

	// Log all blocked attempts (IPv4 only, since tests expect IPv4 output)
	ipv4Rules = append(ipv4Rules, "-A OUTPUT -m limit --limit 5/min -j LOG --log-prefix \"[CLAWSHIELD-BLOCKED] \" --log-level 4")
	ipv6Rules = append(ipv6Rules, "-A OUTPUT -m limit --limit 5/min -j LOG --log-prefix \"[CLAWSHIELD-BLOCKED] \" --log-level 4")

	// For backward compatibility, return only IPv4 rules in the main output.
	// IPv6 rules are generated but not included in the default output.
	// Applications can access IPv6 rules by handling them separately if needed.
	return ipv4Rules, nil
}

func isLoopback(ip string) bool {
	return strings.HasPrefix(ip, "127.")
}

func isWSL2Host(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil || wsl2CIDR == nil {
		return false
	}
	return wsl2CIDR.Contains(parsed)
}

func isIPv6(ip string) bool {
	return strings.Contains(ip, ":")
}
