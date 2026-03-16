package permissions

import (
	"strings"
	"testing"
)

func TestClassifyRestricted(t *testing.T) {
	cfg := loadTestConfig(t)
	c := cfg.Classifier()

	tests := []struct {
		name  string
		input string
		level string
	}{
		{"Anthropic API key", "Here is the key: sk-ant-api03-DtI0abcdefghijklmnop", LevelRestricted},
		{"GitHub PAT", "Use this token: ghp_abcdefghijklmnopqrstuvwxyz1234567890", LevelRestricted},
		{"Slack bot token", "Bot token: xoxb-fake-test-token-not-real", LevelRestricted},
		{"Slack user token", "User token: xoxp-fake-test-token-not-real", LevelRestricted},
		{"GitLab PAT", "Token: glpat-abcdefghij_klmnopqrst", LevelRestricted},
		{"Google API key", "Key: AIzaSyAbcdefghijklmnopqrstuvwxyz12345678", LevelRestricted},
		{"Atlassian API token", "Token: ATATT3xAbcDefGhIjKlMnOpQrStUv", LevelRestricted},
		{"password assignment", "password = my_secret_pass_123", LevelRestricted},
		{"secret assignment", "api_key = abcdef12345678", LevelRestricted},
		{"private key", "-----BEGIN PRIVATE KEY-----\nMIIE...", LevelRestricted},
		{"RSA private key", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...", LevelRestricted},
		{"SSN", "SSN: 123-45-6789", LevelRestricted},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := c.Classify(tt.input)
			if result.Level != tt.level {
				t.Errorf("Classify(%q) level = %s, want %s", tt.input, result.Level, tt.level)
			}
			if !result.Blocked {
				t.Errorf("Classify(%q) should be blocked (RESTRICTED + block_restricted=true)", tt.input)
			}
		})
	}
}

func TestClassifyConfidential(t *testing.T) {
	cfg := loadTestConfig(t)
	c := cfg.Classifier()

	tests := []struct {
		name  string
		input string
	}{
		{"phone number", "Call me at 555-123-4567"},
		{"CVE reference", "Found CVE-2024-12345 in the scan"},
		{"large code block", "```" + strings.Repeat("x", 501) + "```"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := c.Classify(tt.input)
			if result.Level != LevelConfidential {
				t.Errorf("Classify(%q) level = %s, want CONFIDENTIAL", tt.input[:min(len(tt.input), 40)], result.Level)
			}
			// block_confidential defaults to false
			if result.Blocked {
				t.Errorf("Classify(%q) should not be blocked (block_confidential=false)", tt.input[:min(len(tt.input), 40)])
			}
		})
	}
}

func TestClassifyInternal(t *testing.T) {
	cfg := loadTestConfig(t)
	c := cfg.Classifier()

	tests := []struct {
		name  string
		input string
	}{
		{"email address", "Contact alan@sleuthco.ai for details"},
		{"Jira issue key", "Working on PROJ-1234"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := c.Classify(tt.input)
			if result.Level != LevelInternal {
				t.Errorf("Classify(%q) level = %s, want INTERNAL", tt.input, result.Level)
			}
			if result.Blocked {
				t.Error("INTERNAL should not be blocked by default")
			}
		})
	}
}

func TestClassifyPublic(t *testing.T) {
	cfg := loadTestConfig(t)
	c := cfg.Classifier()

	result := c.Classify("Hello, how can I help you today?")
	if result.Level != LevelPublic {
		t.Errorf("expected PUBLIC, got %s", result.Level)
	}
	if result.Blocked {
		t.Error("PUBLIC should not be blocked")
	}
	if len(result.MatchedPatterns) != 0 {
		t.Errorf("expected no matched patterns, got %d", len(result.MatchedPatterns))
	}
}

func TestClassifyHighestLevel(t *testing.T) {
	// Message with both INTERNAL and RESTRICTED patterns
	cfg := loadTestConfig(t)
	c := cfg.Classifier()

	input := "Email alan@test.com about password = secret123"
	result := c.Classify(input)
	if result.Level != LevelRestricted {
		t.Errorf("expected RESTRICTED (highest), got %s", result.Level)
	}
	if len(result.MatchedPatterns) < 2 {
		t.Errorf("expected at least 2 matched patterns, got %d", len(result.MatchedPatterns))
	}
}

func TestClassifyBlockConfidential(t *testing.T) {
	yaml := []byte(`
agents: {}
classification:
  block_restricted: true
  block_confidential: true
  rules:
    - pattern: 'CVE-\d{4}-\d{4,}'
      level: CONFIDENTIAL
      label: CVE
bridge_dlp:
  mode: OFF
  builtin_patterns: []
response_sanitizer:
  injection_patterns: []
  cross_action_patterns: []
`)
	cfg, err := Parse(yaml)
	if err != nil {
		t.Fatal(err)
	}

	result := cfg.Classifier().Classify("Found CVE-2024-99999")
	if !result.Blocked {
		t.Error("CONFIDENTIAL should be blocked when block_confidential=true")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
