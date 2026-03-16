package permissions

import (
	"os"
	"path/filepath"
	"testing"
)

func loadTestConfig(t *testing.T) *Config {
	t.Helper()
	// Find config relative to test file
	configPath := filepath.Join("..", "..", "..", "config", "permissions.yaml")
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("failed to load test config: %v", err)
	}
	return cfg
}

func TestLoadConfig(t *testing.T) {
	cfg := loadTestConfig(t)

	if len(cfg.Agents) == 0 {
		t.Fatal("expected at least one agent profile")
	}
	if cfg.Agents["anvil"] == nil {
		t.Fatal("expected anvil agent profile")
	}
	if !cfg.Agents["anvil"].Enabled {
		t.Error("expected anvil to be enabled")
	}
}

func TestLoadConfigFromBytes(t *testing.T) {
	yaml := []byte(`
agents:
  test:
    enabled: true
    max_classification: INTERNAL
    aliases: [tester]
    platforms:
      jira: [READ]
classification:
  block_restricted: true
  rules: []
bridge_dlp:
  mode: OFF
  builtin_patterns: []
response_sanitizer:
  injection_patterns: []
  cross_action_patterns: []
`)
	cfg, err := Parse(yaml)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if cfg.Agents["test"] == nil {
		t.Fatal("expected test agent")
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/path.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestCheckAgentScope(t *testing.T) {
	cfg := loadTestConfig(t)

	tests := []struct {
		name       string
		agent      string
		platform   string
		permission string
		allowed    bool
	}{
		{"anvil can read jira", "anvil", "jira", "READ", true},
		{"anvil can write jira", "anvil", "jira", "WRITE", true},
		{"anvil cannot access slack", "anvil", "slack", "READ", false},
		{"harbor can read google", "harbor", "google", "READ", true},
		{"harbor cannot write google", "harbor", "google", "WRITE", false},
		{"beacon can write slack", "beacon", "slack", "WRITE", true},
		{"shield cannot access confluence", "shield", "confluence", "READ", false},
		{"lens can read jira", "lens", "jira", "READ", true},
		{"lens cannot write jira", "lens", "jira", "WRITE", false},
		{"default can only access openclaw", "default", "openclaw", "READ", true},
		{"default cannot access jira", "default", "jira", "READ", false},
		{"unknown agent gets default", "unknown", "openclaw", "READ", true},
		{"unknown agent blocked on jira", "unknown", "jira", "READ", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cfg.CheckAgentScope(tt.agent, tt.platform, tt.permission)
			if result.Allowed != tt.allowed {
				t.Errorf("CheckAgentScope(%s, %s, %s) = %v, want %v (reason: %s)",
					tt.agent, tt.platform, tt.permission, result.Allowed, tt.allowed, result.Reason)
			}
		})
	}
}

func TestAgentAliases(t *testing.T) {
	cfg := loadTestConfig(t)

	// friday is an alias for anvil
	result := cfg.CheckAgentScope("friday", "jira", "READ")
	if !result.Allowed {
		t.Error("friday (alias for anvil) should have jira READ access")
	}

	// nimbus is an alias for harbor
	result = cfg.CheckAgentScope("nimbus", "google", "READ")
	if !result.Allowed {
		t.Error("nimbus (alias for harbor) should have google READ access")
	}

	// sentinel is an alias for shield
	result = cfg.CheckAgentScope("sentinel", "jira", "WRITE")
	if !result.Allowed {
		t.Error("sentinel (alias for shield) should have jira WRITE access")
	}

	// Case-insensitive
	result = cfg.CheckAgentScope("Friday", "jira", "READ")
	if !result.Allowed {
		t.Error("Friday (case-insensitive alias) should have jira READ access")
	}
}

func TestCheckClassificationCeiling(t *testing.T) {
	cfg := loadTestConfig(t)

	tests := []struct {
		name    string
		agent   string
		level   string
		allowed bool
	}{
		{"anvil can handle CONFIDENTIAL", "anvil", "CONFIDENTIAL", true},
		{"anvil can handle INTERNAL", "anvil", "INTERNAL", true},
		{"anvil can handle PUBLIC", "anvil", "PUBLIC", true},
		{"anvil cannot handle RESTRICTED", "anvil", "RESTRICTED", false},
		{"harbor can handle INTERNAL", "harbor", "INTERNAL", true},
		{"harbor cannot handle CONFIDENTIAL", "harbor", "CONFIDENTIAL", false},
		{"default can only handle PUBLIC", "default", "PUBLIC", true},
		{"default cannot handle INTERNAL", "default", "INTERNAL", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cfg.CheckClassificationCeiling(tt.agent, tt.level)
			if result != tt.allowed {
				t.Errorf("CheckClassificationCeiling(%s, %s) = %v, want %v",
					tt.agent, tt.level, result, tt.allowed)
			}
		})
	}
}

func TestGetAgentPlatforms(t *testing.T) {
	cfg := loadTestConfig(t)

	platforms := cfg.GetAgentPlatforms("anvil")
	if len(platforms) == 0 {
		t.Fatal("expected platforms for anvil")
	}

	found := make(map[string]bool)
	for _, p := range platforms {
		found[p] = true
	}
	if !found["jira"] || !found["confluence"] || !found["openclaw"] {
		t.Errorf("anvil should have jira, confluence, openclaw; got %v", platforms)
	}
	if found["slack"] {
		t.Error("anvil should not have slack")
	}
}

func TestDisabledAgent(t *testing.T) {
	yaml := []byte(`
agents:
  disabled_bot:
    enabled: false
    max_classification: PUBLIC
    platforms:
      jira: [READ]
classification:
  block_restricted: true
  rules: []
bridge_dlp:
  mode: OFF
  builtin_patterns: []
response_sanitizer:
  injection_patterns: []
  cross_action_patterns: []
`)
	cfg, err := Parse(yaml)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	result := cfg.CheckAgentScope("disabled_bot", "jira", "READ")
	if result.Allowed {
		t.Error("disabled agent should be blocked")
	}
}

func TestEphemeralSessions(t *testing.T) {
	cfg := loadTestConfig(t)
	if !cfg.EphemeralSessions() {
		t.Error("expected ephemeral sessions to be enabled in default config")
	}
}

func TestParseInvalidYAML(t *testing.T) {
	_, err := Parse([]byte(`{{{invalid yaml`))
	if err == nil {
		t.Fatal("expected parse error for invalid YAML")
	}
}

func TestParseInvalidRegex(t *testing.T) {
	yaml := []byte(`
agents: {}
classification:
  rules:
    - pattern: '(?P<invalid'
      level: RESTRICTED
      label: bad regex
bridge_dlp:
  mode: OFF
  builtin_patterns: []
response_sanitizer:
  injection_patterns: []
  cross_action_patterns: []
`)
	_, err := Parse(yaml)
	if err == nil {
		t.Fatal("expected error for invalid regex in classification rules")
	}
}

// Ensure the real config file loads without errors
func TestRealConfigLoads(t *testing.T) {
	configPath := filepath.Join("..", "..", "..", "config", "permissions.yaml")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Skip("config file not found at expected path")
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("real config failed to load: %v", err)
	}

	// Verify all expected agents exist
	for _, name := range []string{"anvil", "harbor", "shield", "beacon", "lens", "default"} {
		if cfg.Agents[name] == nil {
			t.Errorf("missing agent profile: %s", name)
		}
	}

	// Verify sub-systems compiled
	if cfg.Classifier() == nil {
		t.Error("classifier not compiled")
	}
	if cfg.DLPEngine() == nil {
		t.Error("DLP engine not compiled")
	}
	if cfg.ResponseSanitizerEngine() == nil {
		t.Error("sanitizer not compiled")
	}
}
