package scanner

import (
	"strings"
	"testing"
)

func TestNewSecretsScanner_Disabled(t *testing.T) {
	s := NewSecretsScanner(nil)
	if s != nil {
		t.Error("expected nil scanner when config is nil")
	}

	s = NewSecretsScanner(&SecretsConfig{Enabled: false})
	if s != nil {
		t.Error("expected nil scanner when disabled")
	}
}

func TestNewSecretsScanner_AllRules(t *testing.T) {
	s := NewSecretsScanner(&SecretsConfig{
		Enabled:       true,
		ScanRequests:  true,
		ScanResponses: true,
	})
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
	if s.RuleCount() == 0 {
		t.Error("expected rules to be compiled")
	}
	t.Logf("Total rules compiled: %d", s.RuleCount())
}

func TestNewSecretsScanner_SelectiveRules(t *testing.T) {
	s := NewSecretsScanner(&SecretsConfig{
		Enabled:       true,
		ScanRequests:  true,
		Rules:         []string{"aws", "github"},
	})
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
	// Should have only AWS + GitHub rules
	allRules := NewSecretsScanner(&SecretsConfig{Enabled: true, ScanRequests: true})
	if s.RuleCount() >= allRules.RuleCount() {
		t.Errorf("selective rules (%d) should be fewer than all rules (%d)", s.RuleCount(), allRules.RuleCount())
	}
}

func TestSecretsScanner_AWSAccessKey(t *testing.T) {
	s := NewSecretsScanner(&SecretsConfig{
		Enabled:      true,
		ScanRequests: true,
		Rules:        []string{"aws"},
	})

	tests := []struct {
		name    string
		input   string
		blocked bool
	}{
		{"AWS access key", `config: AKIAIOSFODNN7EXAMPLE`, true},
		{"AWS key in JSON", `{"key": "AKIAIOSFODNN7EXAMPLE"}`, true},
		{"Not an AWS key", `config: NOTANAWSKEY1234567`, false},
		{"Benign text", `Hello world, this is normal text`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, reason := s.ScanRequest("chat.send", tt.input)
			if blocked != tt.blocked {
				t.Errorf("blocked=%v, want %v (reason: %s)", blocked, tt.blocked, reason)
			}
		})
	}
}

func TestSecretsScanner_GitHubTokens(t *testing.T) {
	s := NewSecretsScanner(&SecretsConfig{
		Enabled:      true,
		ScanRequests: true,
		Rules:        []string{"github"},
	})

	tests := []struct {
		name    string
		input   string
		blocked bool
	}{
		{"GitHub PAT", `token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij`, true},
		{"GitHub OAuth", `token: gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij`, true},
		{"GitHub App", `token: ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij`, true},
		{"Not a GitHub token", `token: ghx_notavalidprefix`, false},
		{"Benign text", `Use GitHub for version control`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, reason := s.ScanRequest("chat.send", tt.input)
			if blocked != tt.blocked {
				t.Errorf("blocked=%v, want %v (reason: %s)", blocked, tt.blocked, reason)
			}
		})
	}
}

// buildTestSecret constructs test secret values at runtime to avoid
// triggering GitHub's push protection on literal secret patterns in source.
func buildTestSecret(prefix, suffix string) string {
	return prefix + suffix
}

func TestSecretsScanner_StripeKeys(t *testing.T) {
	s := NewSecretsScanner(&SecretsConfig{
		Enabled:      true,
		ScanRequests: true,
		Rules:        []string{"stripe"},
	})

	tests := []struct {
		name    string
		input   string
		blocked bool
	}{
		{"Stripe live key", "key: " + buildTestSecret("sk_"+"live_", "TESTONLY00000000000000fake"), true},
		{"Stripe test key", "key: " + buildTestSecret("sk_"+"test_", "TESTONLY00000000000000fake"), true},
		{"Stripe restricted", "key: " + buildTestSecret("rk_"+"live_", "TESTONLY00000000000000fake"), true},
		{"Not a Stripe key", `key: pk_live_something`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, reason := s.ScanRequest("chat.send", tt.input)
			if blocked != tt.blocked {
				t.Errorf("blocked=%v, want %v (reason: %s)", blocked, tt.blocked, reason)
			}
		})
	}
}

func TestSecretsScanner_JWT(t *testing.T) {
	s := NewSecretsScanner(&SecretsConfig{
		Enabled:      true,
		ScanRequests: true,
		Rules:        []string{"jwt"},
	})

	jwt := "eyJhbGciOiJURVNUIiwidHlwIjoiSldUIn0.eyJzdWIiOiJGQUtFIiwibmFtZSI6IlRlc3QiLCJpYXQiOjB9.FAKEsignatureTESTONLY000000"

	blocked, reason := s.ScanRequest("chat.send", "Authorization: Bearer "+jwt)
	if !blocked {
		t.Errorf("expected JWT to be detected (reason: %s)", reason)
	}

	blocked, _ = s.ScanRequest("chat.send", "This is normal text without tokens")
	if blocked {
		t.Error("expected no detection on benign text")
	}
}

func TestSecretsScanner_PrivateKeys(t *testing.T) {
	s := NewSecretsScanner(&SecretsConfig{
		Enabled:      true,
		ScanRequests: true,
		Rules:        []string{"private_key"},
	})

	tests := []struct {
		name    string
		input   string
		blocked bool
	}{
		{"RSA key", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----", true},
		{"EC key", "-----BEGIN EC PRIVATE KEY-----\nMHQC...\n-----END EC PRIVATE KEY-----", true},
		{"OpenSSH key", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl...", true},
		{"PGP key", "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: ...", true},
		{"PKCS8 key", "-----BEGIN PRIVATE KEY-----\nMIIE...", true},
		{"Public key", "-----BEGIN PUBLIC KEY-----\nMIIB...", false},
		{"Certificate", "-----BEGIN CERTIFICATE-----\nMIID...", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, reason := s.ScanRequest("chat.send", tt.input)
			if blocked != tt.blocked {
				t.Errorf("blocked=%v, want %v (reason: %s)", blocked, tt.blocked, reason)
			}
		})
	}
}

func TestSecretsScanner_DatabaseConnStrings(t *testing.T) {
	s := NewSecretsScanner(&SecretsConfig{
		Enabled:      true,
		ScanRequests: true,
		Rules:        []string{"database"},
	})

	tests := []struct {
		name    string
		input   string
		blocked bool
	}{
		{"PostgreSQL", `DATABASE_URL=postgresql://user:password123@db.example.com:5432/mydb`, true},
		{"MySQL", `url: mysql://admin:secret@localhost:3306/app`, true},
		{"MongoDB", `MONGO_URI=mongodb+srv://user:pass@cluster.mongodb.net/db`, true},
		{"Redis", `REDIS_URL=redis://:secretpass@redis.example.com:6379`, true},
		{"No credentials", `url: https://api.example.com/v1/data`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, reason := s.ScanRequest("chat.send", tt.input)
			if blocked != tt.blocked {
				t.Errorf("blocked=%v, want %v (reason: %s)", blocked, tt.blocked, reason)
			}
		})
	}
}

func TestSecretsScanner_SlackTokens(t *testing.T) {
	s := NewSecretsScanner(&SecretsConfig{
		Enabled:      true,
		ScanRequests: true,
		Rules:        []string{"slack"},
	})

	tests := []struct {
		name    string
		input   string
		blocked bool
	}{
		{"Slack bot token", "SLACK_TOKEN=" + buildTestSecret("xox"+"b-0000000000000-", "0000000000000-FAKEFAKEFAKEFAKEFAKEFAKE"), true},
		{"Slack webhook", "url: " + buildTestSecret("https://hooks.slack"+".com/services/", "TFAKETEST/BFAKETEST/FAKETESTfaketestFAKETEST"), true},
		{"Benign Slack mention", `Please check the Slack channel`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, reason := s.ScanRequest("chat.send", tt.input)
			if blocked != tt.blocked {
				t.Errorf("blocked=%v, want %v (reason: %s)", blocked, tt.blocked, reason)
			}
		})
	}
}

func TestSecretsScanner_GCPKeys(t *testing.T) {
	s := NewSecretsScanner(&SecretsConfig{
		Enabled:      true,
		ScanRequests: true,
		Rules:        []string{"gcp"},
	})

	tests := []struct {
		name    string
		input   string
		blocked bool
	}{
		{"GCP API key", `key: AIzaSyA1234567890abcdefghijklmnopqrstuvw`, true},
		{"GCP service account", `{"type": "service_account", "project_id": "my-project"}`, true},
		{"Not a GCP key", `key: AIxaNOTVALID`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, reason := s.ScanRequest("chat.send", tt.input)
			if blocked != tt.blocked {
				t.Errorf("blocked=%v, want %v (reason: %s)", blocked, tt.blocked, reason)
			}
		})
	}
}

func TestSecretsScanner_GenericAPIKeys(t *testing.T) {
	s := NewSecretsScanner(&SecretsConfig{
		Enabled:      true,
		ScanRequests: true,
		Rules:        []string{"generic_api"},
	})

	tests := []struct {
		name    string
		input   string
		blocked bool
	}{
		{"SendGrid key", `apikey: SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr`, true},
		{"NPM token", `token: npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij`, true},
		{"Secret key assignment", `secret_key = "abcdefghijklmnopqrstuvwxyz1234567890"`, true},
		{"Bearer token", `Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0`, true},
		{"Normal text", `This is a regular message with no secrets`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, reason := s.ScanRequest("chat.send", tt.input)
			if blocked != tt.blocked {
				t.Errorf("blocked=%v, want %v (reason: %s)", blocked, tt.blocked, reason)
			}
		})
	}
}

func TestSecretsScanner_ResponseScanning(t *testing.T) {
	s := NewSecretsScanner(&SecretsConfig{
		Enabled:       true,
		ScanRequests:  true,
		ScanResponses: true,
	})

	// Secrets in responses should be caught
	blocked, reason := s.ScanResponse("tools.invoke", `{"result": "Here's the key: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"}`)
	if !blocked {
		t.Errorf("expected GitHub token in response to be detected (reason: %s)", reason)
	}

	// When scan_responses is disabled, should not block
	reqOnly := NewSecretsScanner(&SecretsConfig{
		Enabled:       true,
		ScanRequests:  true,
		ScanResponses: false,
	})
	blocked, _ = reqOnly.ScanResponse("tools.invoke", `ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij`)
	if blocked {
		t.Error("should not scan responses when scan_responses is false")
	}
}

func TestSecretsScanner_ExcludeTools(t *testing.T) {
	s := NewSecretsScanner(&SecretsConfig{
		Enabled:      true,
		ScanRequests: true,
		ExcludeTools: []string{"vault.read", "secrets.get"},
	})

	// Excluded tool should not be scanned
	blocked, _ := s.ScanRequest("vault.read", buildTestSecret("sk_"+"live_", "TESTONLY00000000000000fake"))
	if blocked {
		t.Error("excluded tool should not be scanned")
	}

	// Non-excluded tool should be scanned
	blocked, _ = s.ScanRequest("chat.send", buildTestSecret("sk_"+"live_", "TESTONLY00000000000000fake"))
	if !blocked {
		t.Error("non-excluded tool should be scanned")
	}
}

func TestSecretsScanner_CustomPatterns(t *testing.T) {
	s := NewSecretsScanner(&SecretsConfig{
		Enabled:      true,
		ScanRequests: true,
		CustomPatterns: []CustomSecretPattern{
			{
				Name:        "Internal Service Token",
				Pattern:     `intl_svc_[a-zA-Z0-9]{32}`,
				Description: "internal service-to-service token",
			},
		},
	})

	blocked, reason := s.ScanRequest("chat.send", "token: intl_svc_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef")
	if !blocked {
		t.Errorf("expected custom pattern to match (reason: %s)", reason)
	}

	blocked, _ = s.ScanRequest("chat.send", "token: intl_svc_tooshort")
	if blocked {
		t.Error("short value should not match custom pattern")
	}
}

func TestSecretsScanner_RedactSecrets(t *testing.T) {
	s := NewSecretsScanner(&SecretsConfig{
		Enabled:      true,
		ScanRequests: true,
	})

	input := `Here is a GitHub token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij and some normal text`
	redacted, found := s.RedactSecrets(input)

	if len(found) == 0 {
		t.Error("expected secrets to be found for redaction")
	}

	if redacted == input {
		t.Error("expected text to be modified after redaction")
	}

	// The GitHub token should be replaced
	if containsStr(redacted, "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij") {
		t.Error("expected GitHub token to be redacted from output")
	}

	t.Logf("Redacted: %s", redacted)
	t.Logf("Found: %v", found)
}

func TestSecretsScanner_NilSafety(t *testing.T) {
	var s *SecretsScanner

	blocked, _ := s.ScanRequest("test", buildTestSecret("sk_"+"live_", "secret123456789012345678"))
	if blocked {
		t.Error("nil scanner should not block")
	}

	blocked, _ = s.ScanResponse("test", buildTestSecret("sk_"+"live_", "secret123456789012345678"))
	if blocked {
		t.Error("nil scanner should not block")
	}

	text, found := s.RedactSecrets("some text")
	if text != "some text" || found != nil {
		t.Error("nil scanner should return input unchanged")
	}

	if s.Action() != "block" {
		t.Error("nil scanner action should default to block")
	}

	if s.RuleCount() != 0 {
		t.Error("nil scanner should have 0 rules")
	}
}

func TestSecretsScanner_MultipleFindingsInSameText(t *testing.T) {
	s := NewSecretsScanner(&SecretsConfig{
		Enabled:      true,
		ScanRequests: true,
	})

	// Text with multiple different secrets
	input := `AWS key: AKIAIOSFODNN7EXAMPLE, GitHub: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij`
	blocked, reason := s.ScanRequest("chat.send", input)
	if !blocked {
		t.Errorf("expected detection with multiple secrets (reason: %s)", reason)
	}
}

// helper
func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && strings.Contains(s, substr)
}
