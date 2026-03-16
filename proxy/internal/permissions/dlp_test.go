package permissions

import (
	"strings"
	"testing"
)

func TestDLPRedactConfluenceURL(t *testing.T) {
	cfg := loadTestConfig(t)
	dlp := cfg.DLPEngine()

	result := dlp.Scrub("Check https://foo.atlassian.net/wiki/spaces/DOC/pages/123")
	if !result.Allowed {
		t.Error("REDACT mode should allow the message")
	}
	if !strings.Contains(result.ScrubbedMessage, "[CONFLUENCE-URL]") {
		t.Errorf("expected Confluence URL to be redacted, got: %s", result.ScrubbedMessage)
	}
	if strings.Contains(result.ScrubbedMessage, "atlassian.net/wiki") {
		t.Error("original Confluence URL should not remain in scrubbed message")
	}
	if len(result.Redactions) == 0 {
		t.Error("expected at least one redaction")
	}
}

func TestDLPRedactJiraURL(t *testing.T) {
	cfg := loadTestConfig(t)
	dlp := cfg.DLPEngine()

	result := dlp.Scrub("See https://mysite.atlassian.net/browse/PROJ-123")
	if !result.Allowed {
		t.Error("REDACT mode should allow")
	}
	if !strings.Contains(result.ScrubbedMessage, "[JIRA-URL]") {
		t.Errorf("expected Jira URL redacted, got: %s", result.ScrubbedMessage)
	}
}

func TestDLPRedactJSMURL(t *testing.T) {
	cfg := loadTestConfig(t)
	dlp := cfg.DLPEngine()

	result := dlp.Scrub("Ticket at https://site.atlassian.net/servicedesk/customer/portal/1")
	if !result.Allowed {
		t.Error("REDACT mode should allow")
	}
	if !strings.Contains(result.ScrubbedMessage, "[JSM-URL]") {
		t.Errorf("expected JSM URL redacted, got: %s", result.ScrubbedMessage)
	}
}

func TestDLPRedactGoogleDocs(t *testing.T) {
	cfg := loadTestConfig(t)
	dlp := cfg.DLPEngine()

	result := dlp.Scrub("Doc: https://docs.google.com/document/d/1abc123/edit")
	if !strings.Contains(result.ScrubbedMessage, "[GOOGLE-DOCS-URL]") {
		t.Errorf("expected Google Docs URL redacted, got: %s", result.ScrubbedMessage)
	}
}

func TestDLPRedactGoogleDrive(t *testing.T) {
	cfg := loadTestConfig(t)
	dlp := cfg.DLPEngine()

	result := dlp.Scrub("File: https://drive.google.com/file/d/1abc123/view")
	if !strings.Contains(result.ScrubbedMessage, "[GOOGLE-DRIVE-URL]") {
		t.Errorf("expected Google Drive URL redacted, got: %s", result.ScrubbedMessage)
	}
}

func TestDLPRedactJiraKey(t *testing.T) {
	cfg := loadTestConfig(t)
	dlp := cfg.DLPEngine()

	result := dlp.Scrub("Working on PROJ-1234 today")
	if !strings.Contains(result.ScrubbedMessage, "[JIRA-KEY]") {
		t.Errorf("expected Jira key redacted, got: %s", result.ScrubbedMessage)
	}
}

func TestDLPBlockMode(t *testing.T) {
	yaml := []byte(`
agents: {}
classification:
  block_restricted: true
  rules: []
bridge_dlp:
  mode: BLOCK
  builtin_patterns:
    - pattern: 'https?://\S+\.atlassian\.net/wiki/\S+'
      label: Confluence URL
      replacement: '[CONFLUENCE-URL]'
response_sanitizer:
  injection_patterns: []
  cross_action_patterns: []
`)
	cfg, err := Parse(yaml)
	if err != nil {
		t.Fatal(err)
	}

	result := cfg.DLPEngine().Scrub("Check https://foo.atlassian.net/wiki/spaces/DOC")
	if result.Allowed {
		t.Error("BLOCK mode should reject the message")
	}
}

func TestDLPOffMode(t *testing.T) {
	yaml := []byte(`
agents: {}
classification:
  block_restricted: true
  rules: []
bridge_dlp:
  mode: "OFF"
  builtin_patterns:
    - pattern: 'https?://\S+\.atlassian\.net/wiki/\S+'
      label: Confluence URL
      replacement: '[CONFLUENCE-URL]'
response_sanitizer:
  injection_patterns: []
  cross_action_patterns: []
`)
	cfg, err := Parse(yaml)
	if err != nil {
		t.Fatal(err)
	}

	input := "Check https://foo.atlassian.net/wiki/spaces/DOC"
	result := cfg.DLPEngine().Scrub(input)
	if !result.Allowed {
		t.Error("OFF mode should allow everything")
	}
	if result.ScrubbedMessage != input {
		t.Error("OFF mode should not modify the message")
	}
}

func TestDLPCorporateEmail(t *testing.T) {
	yaml := []byte(`
agents: {}
classification:
  block_restricted: true
  rules: []
bridge_dlp:
  mode: REDACT
  builtin_patterns: []
  corporate_email_domains: [atlassian.com, sleuthco.ai]
response_sanitizer:
  injection_patterns: []
  cross_action_patterns: []
`)
	cfg, err := Parse(yaml)
	if err != nil {
		t.Fatal(err)
	}

	result := cfg.DLPEngine().Scrub("Contact user@atlassian.com or alan@sleuthco.ai")
	if !result.Allowed {
		t.Error("REDACT mode should allow")
	}
	if strings.Contains(result.ScrubbedMessage, "atlassian.com") {
		t.Error("corporate email should be redacted")
	}
	if !strings.Contains(result.ScrubbedMessage, "[CORP-EMAIL]") {
		t.Errorf("expected [CORP-EMAIL] placeholder, got: %s", result.ScrubbedMessage)
	}
}

func TestDLPAllowlistPhrase(t *testing.T) {
	yaml := []byte(`
agents: {}
classification:
  block_restricted: true
  rules: []
bridge_dlp:
  mode: REDACT
  builtin_patterns:
    - pattern: '\b[A-Z]{2,10}-\d{1,6}\b'
      label: Jira issue key
      replacement: '[JIRA-KEY]'
  allowlist_phrases: ["PROJ-1234"]
response_sanitizer:
  injection_patterns: []
  cross_action_patterns: []
`)
	cfg, err := Parse(yaml)
	if err != nil {
		t.Fatal(err)
	}

	// PROJ-1234 is allowlisted, should not be redacted
	result := cfg.DLPEngine().Scrub("Working on PROJ-1234 and TEST-5678")
	if !result.Allowed {
		t.Error("should allow in REDACT mode")
	}
	if !strings.Contains(result.ScrubbedMessage, "PROJ-1234") {
		t.Error("allowlisted PROJ-1234 should be preserved")
	}
	if !strings.Contains(result.ScrubbedMessage, "[JIRA-KEY]") {
		t.Error("non-allowlisted TEST-5678 should be redacted")
	}
}

func TestDLPCustomPattern(t *testing.T) {
	yaml := []byte(`
agents: {}
classification:
  block_restricted: true
  rules: []
bridge_dlp:
  mode: REDACT
  builtin_patterns: []
  custom_patterns:
    - pattern: 'INTERNAL-\d+'
      label: internal ID
      replacement: '[INTERNAL-ID]'
response_sanitizer:
  injection_patterns: []
  cross_action_patterns: []
`)
	cfg, err := Parse(yaml)
	if err != nil {
		t.Fatal(err)
	}

	result := cfg.DLPEngine().Scrub("Found INTERNAL-9999 in the data")
	if !strings.Contains(result.ScrubbedMessage, "[INTERNAL-ID]") {
		t.Errorf("custom pattern should be redacted, got: %s", result.ScrubbedMessage)
	}
}

func TestDLPNoMatchesPassthrough(t *testing.T) {
	cfg := loadTestConfig(t)
	dlp := cfg.DLPEngine()

	input := "Hello, this is a clean message with no sensitive data."
	result := dlp.Scrub(input)
	if !result.Allowed {
		t.Error("clean message should be allowed")
	}
	if result.ScrubbedMessage != input {
		t.Error("clean message should not be modified")
	}
	if len(result.Redactions) != 0 {
		t.Errorf("expected no redactions, got %d", len(result.Redactions))
	}
}

func TestDLPMultipleRedactions(t *testing.T) {
	cfg := loadTestConfig(t)
	dlp := cfg.DLPEngine()

	input := "See https://foo.atlassian.net/wiki/spaces/DOC and https://docs.google.com/document/d/1/edit"
	result := dlp.Scrub(input)
	if !result.Allowed {
		t.Error("REDACT mode should allow")
	}
	if len(result.Redactions) < 2 {
		t.Errorf("expected at least 2 redactions, got %d", len(result.Redactions))
	}
}
