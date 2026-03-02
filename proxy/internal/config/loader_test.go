package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad_ValidPolicy(t *testing.T) {
	// Create temp file with valid policy
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policy.yaml")
	
	policyContent := `
default_action: allow
allowlist:
  - read
  - write
  - web.fetch
denylist:
  - exec
  - shell
arg_filters:
  - tool: exec
    regex: "password.*"
domain_allowlist:
  - example.com
  - "*.github.com"
evaluation_timeout_ms: 200
max_message_bytes: 2097152
`
	
	if err := os.WriteFile(policyFile, []byte(policyContent), 0644); err != nil {
		t.Fatalf("failed to create test policy file: %v", err)
	}
	
	policy, err := Load(policyFile)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	
	// Verify policy fields
	if policy.DefaultAction != "allow" {
		t.Errorf("DefaultAction = %q, want %q", policy.DefaultAction, "allow")
	}
	
	if len(policy.Allowlist) != 3 {
		t.Errorf("len(Allowlist) = %d, want 3", len(policy.Allowlist))
	}
	
	if len(policy.Denylist) != 2 {
		t.Errorf("len(Denylist) = %d, want 2", len(policy.Denylist))
	}
	
	if len(policy.ArgFilters) != 1 {
		t.Errorf("len(ArgFilters) = %d, want 1", len(policy.ArgFilters))
	}
	
	if len(policy.DomainAllowlist) != 2 {
		t.Errorf("len(DomainAllowlist) = %d, want 2", len(policy.DomainAllowlist))
	}
	
	if policy.EvaluationTimeoutMs != 200 {
		t.Errorf("EvaluationTimeoutMs = %d, want 200", policy.EvaluationTimeoutMs)
	}
	
	if policy.MaxMessageBytes != 2097152 {
		t.Errorf("MaxMessageBytes = %d, want 2097152", policy.MaxMessageBytes)
	}
}

func TestLoad_MinimalPolicy(t *testing.T) {
	// Create temp file with minimal policy
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "minimal.yaml")
	
	policyContent := `
default_action: deny
`
	
	if err := os.WriteFile(policyFile, []byte(policyContent), 0644); err != nil {
		t.Fatalf("failed to create test policy file: %v", err)
	}
	
	policy, err := Load(policyFile)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	
	if policy.DefaultAction != "deny" {
		t.Errorf("DefaultAction = %q, want %q", policy.DefaultAction, "deny")
	}
	
	// Check defaults are applied
	if policy.MaxMessageBytes != 1048576 {
		t.Errorf("MaxMessageBytes = %d, want 1048576 (default)", policy.MaxMessageBytes)
	}
}

func TestLoad_EmptyPolicy(t *testing.T) {
	// Create temp file with empty policy
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "empty.yaml")
	
	if err := os.WriteFile(policyFile, []byte(""), 0644); err != nil {
		t.Fatalf("failed to create test policy file: %v", err)
	}
	
	policy, err := Load(policyFile)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	
	// Default action should be set to "deny" (fail-closed)
	if policy.DefaultAction != "deny" {
		t.Errorf("DefaultAction = %q, want %q (default)", policy.DefaultAction, "deny")
	}
	
	// Default max message bytes
	if policy.MaxMessageBytes != 1048576 {
		t.Errorf("MaxMessageBytes = %d, want 1048576 (default)", policy.MaxMessageBytes)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "invalid.yaml")
	
	invalidContent := `
default_action: allow
allowlist:
  - read
  this is not valid yaml: [
`
	
	if err := os.WriteFile(policyFile, []byte(invalidContent), 0644); err != nil {
		t.Fatalf("failed to create test policy file: %v", err)
	}
	
	_, err := Load(policyFile)
	if err == nil {
		t.Error("Load() succeeded with invalid YAML, want error")
	}
}

func TestLoad_NonexistentFile(t *testing.T) {
	_, err := Load("/nonexistent/path/policy.yaml")
	if err == nil {
		t.Error("Load() succeeded with nonexistent file, want error")
	}
}

func TestLoad_ComplexArgFilters(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "complex.yaml")
	
	policyContent := `
default_action: allow
arg_filters:
  - tool: exec
    regex: "password|secret|token"
  - tool: web.fetch
    regex: "api[_-]?key"
  - tool: database.query
    regex: "DROP TABLE|DELETE FROM"
`
	
	if err := os.WriteFile(policyFile, []byte(policyContent), 0644); err != nil {
		t.Fatalf("failed to create test policy file: %v", err)
	}
	
	policy, err := Load(policyFile)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	
	if len(policy.ArgFilters) != 3 {
		t.Errorf("len(ArgFilters) = %d, want 3", len(policy.ArgFilters))
	}
	
	// Verify each filter
	expectedFilters := map[string]string{
		"exec":           "password|secret|token",
		"web.fetch":      "api[_-]?key",
		"database.query": "DROP TABLE|DELETE FROM",
	}
	
	for _, filter := range policy.ArgFilters {
		expectedRegex, ok := expectedFilters[filter.Tool]
		if !ok {
			t.Errorf("unexpected tool in ArgFilters: %s", filter.Tool)
			continue
		}
		
		if filter.Regex != expectedRegex {
			t.Errorf("ArgFilter for %s: regex = %q, want %q", filter.Tool, filter.Regex, expectedRegex)
		}
	}
}

func TestLoad_WildcardDomains(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "domains.yaml")
	
	policyContent := `
default_action: deny
domain_allowlist:
  - example.com
  - "*.github.com"
  - "*.googleapis.com"
  - localhost
  - "127.0.0.1"
`
	
	if err := os.WriteFile(policyFile, []byte(policyContent), 0644); err != nil {
		t.Fatalf("failed to create test policy file: %v", err)
	}
	
	policy, err := Load(policyFile)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	
	if len(policy.DomainAllowlist) != 5 {
		t.Errorf("len(DomainAllowlist) = %d, want 5", len(policy.DomainAllowlist))
	}
	
	// Verify wildcards are preserved
	hasWildcard := false
	for _, domain := range policy.DomainAllowlist {
		if len(domain) > 0 && domain[0] == '*' {
			hasWildcard = true
			break
		}
	}
	
	if !hasWildcard {
		t.Error("expected at least one wildcard domain in allowlist")
	}
}

func TestLoad_DefaultsApplied(t *testing.T) {
	tests := []struct {
		name          string
		content       string
		wantAction    string
		wantMaxBytes  int64
	}{
		{
			name:         "no default_action specified",
			content:      `allowlist: [read]`,
			wantAction:   "deny",
			wantMaxBytes: 1048576,
		},
		{
			name:         "explicit deny",
			content:      `default_action: deny`,
			wantAction:   "deny",
			wantMaxBytes: 1048576,
		},
		{
			name:         "custom max_message_bytes",
			content:      `max_message_bytes: 5000000`,
			wantAction:   "deny",
			wantMaxBytes: 5000000,
		},
		{
			name:         "zero max_message_bytes gets default",
			content:      `max_message_bytes: 0`,
			wantAction:   "deny",
			wantMaxBytes: 1048576,
		},
		{
			name:         "negative max_message_bytes gets default",
			content:      `max_message_bytes: -100`,
			wantAction:   "deny",
			wantMaxBytes: 1048576,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			policyFile := filepath.Join(tmpDir, "test.yaml")
			
			if err := os.WriteFile(policyFile, []byte(tt.content), 0644); err != nil {
				t.Fatalf("failed to create test policy file: %v", err)
			}
			
			policy, err := Load(policyFile)
			if err != nil {
				t.Fatalf("Load() failed: %v", err)
			}
			
			if policy.DefaultAction != tt.wantAction {
				t.Errorf("DefaultAction = %q, want %q", policy.DefaultAction, tt.wantAction)
			}
			
			if policy.MaxMessageBytes != tt.wantMaxBytes {
				t.Errorf("MaxMessageBytes = %d, want %d", policy.MaxMessageBytes, tt.wantMaxBytes)
			}
		})
	}
}

func TestLoad_PermissionDenied(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping permission test when running as root")
	}
	
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "noperm.yaml")
	
	if err := os.WriteFile(policyFile, []byte("default_action: allow"), 0000); err != nil {
		t.Fatalf("failed to create test policy file: %v", err)
	}
	
	_, err := Load(policyFile)
	if err == nil {
		t.Error("Load() succeeded with unreadable file, want permission error")
	}
}

func TestLoad_LargePolicy(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "large.yaml")
	
	// Generate a large policy with many rules
	var content string
	content += "default_action: allow\nallowlist:\n"
	for i := 0; i < 1000; i++ {
		content += "  - tool_" + fmt.Sprintf("%d", i) + "\n"
	}
	
	if err := os.WriteFile(policyFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test policy file: %v", err)
	}
	
	policy, err := Load(policyFile)
	if err != nil {
		t.Fatalf("Load() failed with large policy: %v", err)
	}
	
	if len(policy.Allowlist) != 1000 {
		t.Errorf("len(Allowlist) = %d, want 1000", len(policy.Allowlist))
	}
}

func TestLoad_SpecialCharacters(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "special.yaml")
	
	policyContent := `
default_action: allow
allowlist:
  - "tool.with.dots"
  - "tool-with-hyphens"
  - "tool_with_underscores"
  - "tool/with/slashes"
domain_allowlist:
  - "example.com"
  - "sub-domain.example.com"
  - "*.wild-card.example.com"
`
	
	if err := os.WriteFile(policyFile, []byte(policyContent), 0644); err != nil {
		t.Fatalf("failed to create test policy file: %v", err)
	}
	
	policy, err := Load(policyFile)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	
	if len(policy.Allowlist) != 4 {
		t.Errorf("len(Allowlist) = %d, want 4", len(policy.Allowlist))
	}
	
	if len(policy.DomainAllowlist) != 3 {
		t.Errorf("len(DomainAllowlist) = %d, want 3", len(policy.DomainAllowlist))
	}
}

// =============================================================================
// HIGH-10: Config loader invalid default_action validation test
// =============================================================================

func TestLoad_InvalidDefaultAction(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name    string
		action  string
		wantErr bool
	}{
		{"allow is valid", "allow", false},
		{"deny is valid", "deny", false},
		{"empty defaults to deny", "", false},
		{"maybe is invalid", "maybe", true},
		{"ALLOW is invalid (case sensitive)", "ALLOW", true},
		{"permit is invalid", "permit", true},
		{"block is invalid", "block", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := fmt.Sprintf("default_action: %s\n", tt.action)
			if tt.action == "" {
				content = "# no default_action set\n"
			}
			path := filepath.Join(tmpDir, tt.name+".yaml")
			os.WriteFile(path, []byte(content), 0644)

			_, err := Load(path)
			if tt.wantErr && err == nil {
				t.Errorf("Load() should reject default_action=%q", tt.action)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Load() should accept default_action=%q, got error: %v", tt.action, err)
			}
		})
	}
}

// =============================================================================
// HIGH-11: Config loader timeout boundary tests
// =============================================================================

func TestLoad_EvaluationTimeoutBoundaries(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name      string
		timeout   int
		wantValue int
	}{
		{"zero timeout uses default", 0, 0},
		{"positive timeout preserved", 500, 500},
		{"large timeout preserved", 60000, 60000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var content string
			if tt.timeout == 0 {
				content = "default_action: allow\n"
			} else {
				content = fmt.Sprintf("default_action: allow\nevaluation_timeout_ms: %d\n", tt.timeout)
			}
			path := filepath.Join(tmpDir, tt.name+".yaml")
			os.WriteFile(path, []byte(content), 0644)

			policy, err := Load(path)
			if err != nil {
				t.Fatalf("Load() failed: %v", err)
			}
			if policy.EvaluationTimeoutMs != tt.wantValue {
				t.Errorf("EvaluationTimeoutMs = %d, want %d", policy.EvaluationTimeoutMs, tt.wantValue)
			}
		})
	}
}

// =============================================================================
// Helper function for SIEM config tests
// =============================================================================

func writeTempPolicy(t *testing.T, content string) string {
	t.Helper()
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp policy: %v", err)
	}
	return path
}

// =============================================================================
// SIEM Config Tests
// =============================================================================

func TestLoad_SIEMConfig_ValidWebhook(t *testing.T) {
	yaml := `
default_action: allow
siem:
  enabled: true
  transport: webhook
  webhook_url: "https://siem.example.com/events"
  min_severity: 4
`
	tmpFile := writeTempPolicy(t, yaml)
	defer os.Remove(tmpFile)

	policy, err := Load(tmpFile)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if policy.SIEM == nil {
		t.Fatalf("SIEM should not be nil")
	}
	if policy.SIEM.Enabled != true {
		t.Errorf("SIEM.Enabled = %v, want true", policy.SIEM.Enabled)
	}
	if policy.SIEM.Transport != "webhook" {
		t.Errorf("SIEM.Transport = %q, want webhook", policy.SIEM.Transport)
	}
	if policy.SIEM.WebhookURL != "https://siem.example.com/events" {
		t.Errorf("SIEM.WebhookURL = %q, want https://siem.example.com/events", policy.SIEM.WebhookURL)
	}
	if policy.SIEM.MinSeverity != 4 {
		t.Errorf("SIEM.MinSeverity = %d, want 4", policy.SIEM.MinSeverity)
	}
}

func TestLoad_SIEMConfig_ValidSyslog(t *testing.T) {
	yaml := `
default_action: allow
siem:
  enabled: true
  transport: syslog
  syslog_address: "siem.company.com:514"
`
	tmpFile := writeTempPolicy(t, yaml)
	defer os.Remove(tmpFile)

	policy, err := Load(tmpFile)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if policy.SIEM.Transport != "syslog" {
		t.Errorf("SIEM.Transport = %q, want syslog", policy.SIEM.Transport)
	}
	if policy.SIEM.SyslogAddress != "siem.company.com:514" {
		t.Errorf("SIEM.SyslogAddress = %q, want siem.company.com:514", policy.SIEM.SyslogAddress)
	}
	if policy.SIEM.MinSeverity != 4 {
		t.Errorf("SIEM.MinSeverity = %d, want 4 (default)", policy.SIEM.MinSeverity)
	}
}

func TestLoad_SIEMConfig_WebhookRequiresHTTPS(t *testing.T) {
	yaml := `
default_action: allow
siem:
  enabled: true
  transport: webhook
  webhook_url: "http://insecure.example.com/events"
`
	tmpFile := writeTempPolicy(t, yaml)
	defer os.Remove(tmpFile)

	_, err := Load(tmpFile)
	if err == nil {
		t.Fatal("Load() should reject insecure webhook URL, want error")
	}
	if !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("error should mention HTTPS: %v", err)
	}
}

func TestLoad_SIEMConfig_SyslogRequiresAddress(t *testing.T) {
	yaml := `
default_action: allow
siem:
  enabled: true
  transport: syslog
`
	tmpFile := writeTempPolicy(t, yaml)
	defer os.Remove(tmpFile)

	_, err := Load(tmpFile)
	if err == nil {
		t.Fatal("Load() should require syslog_address for syslog transport, want error")
	}
	if !strings.Contains(err.Error(), "syslog_address") {
		t.Errorf("error should mention syslog_address: %v", err)
	}
}

func TestLoad_SIEMConfig_InvalidTransport(t *testing.T) {
	yaml := `
default_action: allow
siem:
  enabled: true
  transport: kafka
`
	tmpFile := writeTempPolicy(t, yaml)
	defer os.Remove(tmpFile)

	_, err := Load(tmpFile)
	if err == nil {
		t.Fatal("Load() should reject invalid transport, want error")
	}
	if !strings.Contains(err.Error(), "syslog") || !strings.Contains(err.Error(), "webhook") {
		t.Errorf("error should mention valid transports (syslog, webhook): %v", err)
	}
}

func TestLoad_SIEMConfig_DisabledSkipsValidation(t *testing.T) {
	yaml := `
default_action: allow
siem:
  enabled: false
  transport: invalid
`
	tmpFile := writeTempPolicy(t, yaml)
	defer os.Remove(tmpFile)

	policy, err := Load(tmpFile)
	if err != nil {
		t.Fatalf("Load() should not validate disabled SIEM: %v", err)
	}
	if policy.SIEM == nil {
		t.Fatalf("SIEM should not be nil")
	}
	if policy.SIEM.Enabled != false {
		t.Errorf("SIEM.Enabled = %v, want false", policy.SIEM.Enabled)
	}
}
