package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/SleuthCo/clawshield/proxy/internal/engine"
	"gopkg.in/yaml.v3"
)

// ComputePolicyVersion computes a content-hash-based version ID for a policy file.
// The version is the first 8 hex characters of the SHA256 hash of the file content.
// This provides a stable, content-addressable version that changes whenever the
// file content changes.
func ComputePolicyVersion(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read policy file for versioning: %w", err)
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])[:8], nil
}

// LoadWithVersion loads a policy file and computes its content-hash version.
// Returns the policy, version string, and any error.
func LoadWithVersion(path string) (*engine.Policy, string, error) {
	policy, err := Load(path)
	if err != nil {
		return nil, "", err
	}
	version, err := ComputePolicyVersion(path)
	if err != nil {
		return nil, "", err
	}
	return policy, version, nil
}

// SECURITY: These are checked at config-load time to prevent obvious SSRF.
// DNS resolution is intentionally NOT performed at config time because:
// 1) The SIEM endpoint may not be reachable during startup
// 2) DNS results can change between config-load and send-time
// Runtime SSRF protection should be handled at the transport layer.

// Load reads and parses the policy YAML file
func Load(path string) (*engine.Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}

	var policy engine.Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("parse YAML policy: %w", err)
	}

	// Validate and default: fail-closed (deny) if not specified
	switch policy.DefaultAction {
	case "allow", "deny":
		// valid
	case "":
		policy.DefaultAction = "deny"
	default:
		return nil, fmt.Errorf("invalid default_action %q: must be \"allow\" or \"deny\"", policy.DefaultAction)
	}

	// Set default max message size if not specified (1MB)
	if policy.MaxMessageBytes <= 0 {
		policy.MaxMessageBytes = 1048576 // 1MB in bytes
	}

	// Validate SIEM configuration
	if policy.SIEM != nil && policy.SIEM.Enabled {
		switch policy.SIEM.Transport {
		case "syslog":
			if policy.SIEM.SyslogAddress == "" {
				return nil, fmt.Errorf("siem.syslog_address is required when transport is 'syslog'")
			}
		case "webhook":
			if policy.SIEM.WebhookURL == "" {
				return nil, fmt.Errorf("siem.webhook_url is required when transport is 'webhook'")
			}
			if !strings.HasPrefix(policy.SIEM.WebhookURL, "https://") {
				return nil, fmt.Errorf("siem.webhook_url must use HTTPS for security")
			}
			// Validate URL does not point to internal/private addresses (SSRF prevention)
			if err := validateWebhookURL(policy.SIEM.WebhookURL); err != nil {
				return nil, fmt.Errorf("siem.webhook_url validation failed: %w", err)
			}
		case "":
			return nil, fmt.Errorf("siem.transport is required when SIEM is enabled (must be 'syslog' or 'webhook')")
		default:
			return nil, fmt.Errorf("invalid siem.transport %q: must be 'syslog' or 'webhook'", policy.SIEM.Transport)
		}
		if policy.SIEM.MinSeverity <= 0 {
			policy.SIEM.MinSeverity = 4 // Default: High (OCSF severity_id)
		}
	}

	return &policy, nil
}

// validateWebhookURL ensures the webhook URL does not point to obviously
// internal/private addresses. This prevents trivial SSRF attacks via policy
// configuration without requiring DNS resolution at config-load time.
func validateWebhookURL(urlStr string) error {
	u, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	hostname := u.Hostname()
	if hostname == "" {
		return fmt.Errorf("could not extract hostname from URL")
	}

	// Reject localhost variants
	lower := strings.ToLower(hostname)
	if lower == "localhost" || lower == "ip6-localhost" || lower == "ip6-loopback" {
		return fmt.Errorf("webhook URL cannot point to localhost")
	}

	// If hostname is an IP literal, check for private/loopback/link-local
	if ip := net.ParseIP(hostname); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("webhook URL cannot point to internal IP address: %s", ip)
		}
		// AWS/cloud metadata endpoint
		if ip.String() == "169.254.169.254" {
			return fmt.Errorf("webhook URL cannot point to cloud metadata endpoint (169.254.169.254)")
		}
	}

	return nil
}
