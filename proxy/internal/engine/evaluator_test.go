package engine

import (
	"context"
	"testing"
	"time"

	"github.com/SleuthCo/clawshield/proxy/internal/scanner"
)

func TestNewEvaluator(t *testing.T) {
	t.Run("valid regex compilation", func(t *testing.T) {
		policy := &Policy{
			DefaultAction: Allow,
			ArgFilters: []struct {
				Tool  string `yaml:"tool"`
				Regex string `yaml:"regex"`
			}{
				{Tool: "exec", Regex: `password.*`},
				{Tool: "web.fetch", Regex: `api[_-]?key`},
			},
		}

		evaluator := NewEvaluator(policy)
		if evaluator == nil {
			t.Fatal("NewEvaluator returned nil")
		}

		if len(evaluator.argFilterRegex) != 2 {
			t.Errorf("expected 2 compiled regexes, got %d", len(evaluator.argFilterRegex))
		}
	})

	t.Run("invalid regex handling", func(t *testing.T) {
		policy := &Policy{
			DefaultAction: Allow,
			ArgFilters: []struct {
				Tool  string `yaml:"tool"`
				Regex string `yaml:"regex"`
			}{
				{Tool: "bad", Regex: `[invalid(`},
			},
		}

		evaluator := NewEvaluator(policy)
		if evaluator == nil {
			t.Fatal("NewEvaluator returned nil")
		}

		// Should skip invalid regex and continue
		if len(evaluator.argFilterRegex) != 0 {
			t.Errorf("expected 0 compiled regexes for invalid regex, got %d", len(evaluator.argFilterRegex))
		}
	})
}

func TestEvaluateWithContext_BasicDecisions(t *testing.T) {
	tests := []struct {
		name               string
		policy             *Policy
		message            string
		wantDecision       string
		wantReasonContains string
	}{
		{
			name: "allow by default",
			policy: &Policy{
				DefaultAction: Allow,
			},
			message:            `{"method": "tools.list", "params": {}}`,
			wantDecision:       Allow,
			wantReasonContains: "default allowed",
		},
		{
			name: "deny by default",
			policy: &Policy{
				DefaultAction: Deny,
			},
			message:            `{"method": "tools.list", "params": {}}`,
			wantDecision:       Deny,
			wantReasonContains: "default denied",
		},
		{
			name: "invalid JSON",
			policy: &Policy{
				DefaultAction: Allow,
			},
			message:            `{not valid json`,
			wantDecision:       Deny,
			wantReasonContains: "invalid JSON-RPC format",
		},
		{
			name: "missing method",
			policy: &Policy{
				DefaultAction: Allow,
			},
			message:            `{"params": {}}`,
			wantDecision:       Deny,
			wantReasonContains: "missing method field",
		},
		{
			name: "params as string is valid JSON",
			policy: &Policy{
				DefaultAction: Allow,
			},
			message:            `{"method": "test", "params": "valid-string"}`,
			wantDecision:       Allow,
			wantReasonContains: "default allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evaluator := NewEvaluator(tt.policy)
			ctx := context.Background()

			decision, reason := evaluator.EvaluateWithContext(ctx, tt.message)

			if decision != tt.wantDecision {
				t.Errorf("got decision %s, want %s", decision, tt.wantDecision)
			}

			if tt.wantReasonContains != "" && !contains(reason, tt.wantReasonContains) {
				t.Errorf("got reason %q, want to contain %q", reason, tt.wantReasonContains)
			}
		})
	}
}

func TestEvaluateWithContext_Denylist(t *testing.T) {
	policy := &Policy{
		DefaultAction: Allow,
		Denylist:      []string{"exec", "shell", "dangerous.tool"},
	}

	evaluator := NewEvaluator(policy)
	ctx := context.Background()

	tests := []struct {
		name               string
		message            string
		wantDecision       string
		wantReasonContains string
	}{
		{
			name:               "blocked by denylist",
			message:            `{"method": "exec", "params": {"command": "ls"}}`,
			wantDecision:       Deny,
			wantReasonContains: "explicitly denied by denylist",
		},
		{
			name:               "allowed tool",
			message:            `{"method": "read", "params": {"path": "file.txt"}}`,
			wantDecision:       Allow,
			wantReasonContains: "default allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, reason := evaluator.EvaluateWithContext(ctx, tt.message)

			if decision != tt.wantDecision {
				t.Errorf("got decision %s, want %s", decision, tt.wantDecision)
			}

			if !contains(reason, tt.wantReasonContains) {
				t.Errorf("got reason %q, want to contain %q", reason, tt.wantReasonContains)
			}
		})
	}
}

func TestEvaluateWithContext_Allowlist(t *testing.T) {
	policy := &Policy{
		DefaultAction: Allow,
		Allowlist:     []string{"read", "write", "web.fetch"},
	}

	evaluator := NewEvaluator(policy)
	ctx := context.Background()

	tests := []struct {
		name               string
		message            string
		wantDecision       string
		wantReasonContains string
	}{
		{
			name:               "allowed tool in allowlist",
			message:            `{"method": "read", "params": {"path": "file.txt"}}`,
			wantDecision:       Allow,
			wantReasonContains: "allowlist",
		},
		{
			name:               "blocked tool not in allowlist",
			message:            `{"method": "exec", "params": {"command": "ls"}}`,
			wantDecision:       Deny,
			wantReasonContains: "not in allowlist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, reason := evaluator.EvaluateWithContext(ctx, tt.message)

			if decision != tt.wantDecision {
				t.Errorf("got decision %s, want %s", decision, tt.wantDecision)
			}

			if !contains(reason, tt.wantReasonContains) {
				t.Errorf("got reason %q, want to contain %q", reason, tt.wantReasonContains)
			}
		})
	}
}

func TestEvaluateWithContext_ArgFilters(t *testing.T) {
	policy := &Policy{
		DefaultAction: Allow,
		ArgFilters: []struct {
			Tool  string `yaml:"tool"`
			Regex string `yaml:"regex"`
		}{
			{Tool: "exec", Regex: `password`},
			{Tool: "web.fetch", Regex: `api[_-]?key`},
		},
	}

	evaluator := NewEvaluator(policy)
	ctx := context.Background()

	tests := []struct {
		name               string
		message            string
		wantDecision       string
		wantReasonContains string
	}{
		{
			name:               "blocked by arg filter",
			message:            `{"method": "exec", "params": {"command": "echo password123"}}`,
			wantDecision:       Deny,
			wantReasonContains: "sensitive data detected",
		},
		{
			name:               "allowed - no match",
			message:            `{"method": "exec", "params": {"command": "ls -la"}}`,
			wantDecision:       Allow,
			wantReasonContains: "default allowed",
		},
		{
			name:               "blocked api key pattern",
			message:            `{"method": "web.fetch", "params": {"url": "http://example.com?api_key=secret"}}`,
			wantDecision:       Deny,
			wantReasonContains: "sensitive data detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, reason := evaluator.EvaluateWithContext(ctx, tt.message)

			if decision != tt.wantDecision {
				t.Errorf("got decision %s, want %s", decision, tt.wantDecision)
			}

			if !contains(reason, tt.wantReasonContains) {
				t.Errorf("got reason %q, want to contain %q", reason, tt.wantReasonContains)
			}
		})
	}
}

func TestEvaluateWithContext_DomainAllowlist(t *testing.T) {
	policy := &Policy{
		DefaultAction:   Allow,
		DomainAllowlist: []string{"example.com", "*.github.com"},
	}

	evaluator := NewEvaluator(policy)
	ctx := context.Background()

	tests := []struct {
		name               string
		message            string
		wantDecision       string
		wantReasonContains string
	}{
		{
			name:               "allowed domain",
			message:            `{"method": "web.fetch", "params": {"url": "https://example.com/page"}}`,
			wantDecision:       Allow,
			wantReasonContains: "default allowed",
		},
		{
			name:               "allowed wildcard subdomain",
			message:            `{"method": "web.fetch", "params": {"url": "https://api.github.com/repos"}}`,
			wantDecision:       Allow,
			wantReasonContains: "default allowed",
		},
		{
			name:               "blocked domain",
			message:            `{"method": "web.fetch", "params": {"url": "https://evil.com"}}`,
			wantDecision:       Deny,
			wantReasonContains: "domain not in allowlist",
		},
		{
			name:               "non-web tool ignores domain allowlist",
			message:            `{"method": "read", "params": {"path": "file.txt"}}`,
			wantDecision:       Allow,
			wantReasonContains: "default allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, reason := evaluator.EvaluateWithContext(ctx, tt.message)

			if decision != tt.wantDecision {
				t.Errorf("got decision %s, want %s", decision, tt.wantDecision)
			}

			if !contains(reason, tt.wantReasonContains) {
				t.Errorf("got reason %q, want to contain %q", reason, tt.wantReasonContains)
			}
		})
	}
}

func TestEvaluateWithContext_Timeout(t *testing.T) {
	policy := &Policy{
		DefaultAction:   Allow,
		DomainAllowlist: []string{"example.com"},
	}

	evaluator := NewEvaluator(policy)

	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	decision, reason := evaluator.EvaluateWithContext(ctx, `{"method": "web.fetch", "params": {"url": "https://example.com"}}`)

	if decision != Deny {
		t.Errorf("got decision %s, want %s", decision, Deny)
	}

	if !contains(reason, "timeout exceeded") {
		t.Errorf("got reason %q, want to contain 'timeout exceeded'", reason)
	}
}

func TestEvaluateWithContext_TimeoutDuringDomainCheck(t *testing.T) {
	policy := &Policy{
		DefaultAction:   Allow,
		DomainAllowlist: make([]string, 10000), // Large list to slow down processing
	}

	// Fill with dummy domains
	for i := 0; i < 10000; i++ {
		policy.DomainAllowlist[i] = "example.com"
	}

	evaluator := NewEvaluator(policy)

	// Create a context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	time.Sleep(10 * time.Millisecond) // Ensure timeout triggers

	decision, reason := evaluator.EvaluateWithContext(ctx, `{"method": "web.fetch", "params": {"url": "https://example.com"}}`)

	if decision != Deny {
		t.Errorf("got decision %s, want %s", decision, Deny)
	}

	if !contains(reason, "timeout exceeded") {
		t.Errorf("got reason %q, want to contain 'timeout exceeded'", reason)
	}
}

func TestEvaluateResponse_RedactSecrets(t *testing.T) {
	policy := &Policy{
		DefaultAction: Allow,
		SecretsScan: &scanner.SecretsConfig{
			Enabled:       true,
			ScanResponses: true,
			Action:        "redact",
		},
	}

	evaluator := NewEvaluator(policy)

	// Build GitHub token at runtime to avoid GitHub push protection
	ghToken := "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
	response := `{"result": "Token is ` + ghToken + `"}`

	result := evaluator.EvaluateResponse(context.Background(), "tools.invoke", response)

	if result.Decision != Allow {
		t.Errorf("expected Allow with redaction, got %s (reason: %s)", result.Decision, result.Reason)
	}
	if !result.WasRedacted {
		t.Error("expected WasRedacted to be true")
	}
	if result.RedactedBody == response {
		t.Error("expected redacted body to differ from original")
	}
	if contains(result.RedactedBody, ghToken) {
		t.Error("expected secret to be redacted from body")
	}
	if !contains(result.Reason, "secrets redacted") {
		t.Errorf("expected reason to mention secrets redacted, got: %s", result.Reason)
	}
	t.Logf("Redacted body: %s", result.RedactedBody)
	t.Logf("Reason: %s", result.Reason)
}

func TestEvaluateResponse_BlockSecrets(t *testing.T) {
	policy := &Policy{
		DefaultAction: Allow,
		SecretsScan: &scanner.SecretsConfig{
			Enabled:       true,
			ScanResponses: true,
			Action:        "block", // Block instead of redact
		},
	}

	evaluator := NewEvaluator(policy)

	ghToken := "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
	response := `{"result": "Token is ` + ghToken + `"}`

	result := evaluator.EvaluateResponse(context.Background(), "tools.invoke", response)

	if result.Decision != Deny {
		t.Errorf("expected Deny when action is block, got %s", result.Decision)
	}
	if result.WasRedacted {
		t.Error("expected WasRedacted to be false when blocking")
	}
}

func TestEvaluateResponse_RedactPII(t *testing.T) {
	policy := &Policy{
		DefaultAction: Allow,
		PIIScan: &scanner.PIIConfig{
			Enabled:       true,
			ScanResponses: true,
			Action:        "redact",
		},
	}

	evaluator := NewEvaluator(policy)

	response := `{"result": "Contact user@example.com for details, SSN: 123-45-6789"}`

	result := evaluator.EvaluateResponse(context.Background(), "tools.invoke", response)

	if result.Decision != Allow {
		t.Errorf("expected Allow with redaction, got %s (reason: %s)", result.Decision, result.Reason)
	}
	if !result.WasRedacted {
		t.Error("expected WasRedacted to be true")
	}
	if contains(result.RedactedBody, "user@example.com") {
		t.Error("expected email to be redacted from body")
	}
	if !contains(result.Reason, "PII redacted") {
		t.Errorf("expected reason to mention PII redacted, got: %s", result.Reason)
	}
	t.Logf("Redacted body: %s", result.RedactedBody)
}

func TestEvaluateResponse_BlockPII(t *testing.T) {
	policy := &Policy{
		DefaultAction: Allow,
		PIIScan: &scanner.PIIConfig{
			Enabled:       true,
			ScanResponses: true,
			Action:        "block",
		},
	}

	evaluator := NewEvaluator(policy)

	response := `{"result": "Email is user@example.com"}`

	result := evaluator.EvaluateResponse(context.Background(), "tools.invoke", response)

	if result.Decision != Deny {
		t.Errorf("expected Deny when PII action is block, got %s", result.Decision)
	}
}

func TestEvaluateResponse_CleanResponse(t *testing.T) {
	policy := &Policy{
		DefaultAction: Allow,
		SecretsScan: &scanner.SecretsConfig{
			Enabled:       true,
			ScanResponses: true,
			Action:        "redact",
		},
		PIIScan: &scanner.PIIConfig{
			Enabled:       true,
			ScanResponses: true,
			Action:        "redact",
		},
	}

	evaluator := NewEvaluator(policy)

	result := evaluator.EvaluateResponse(context.Background(), "tools.invoke", `{"result": "All good, no secrets here"}`)

	if result.Decision != Allow {
		t.Errorf("expected Allow for clean response, got %s", result.Decision)
	}
	if result.WasRedacted {
		t.Error("expected WasRedacted to be false for clean response")
	}
	if result.RedactedBody != "" {
		t.Error("expected empty RedactedBody for clean response")
	}
	if result.Reason != "response clean" {
		t.Errorf("expected reason 'response clean', got: %s", result.Reason)
	}
}

func TestEvaluateResponse_BothRedactionsApplied(t *testing.T) {
	policy := &Policy{
		DefaultAction: Allow,
		SecretsScan: &scanner.SecretsConfig{
			Enabled:       true,
			ScanResponses: true,
			Action:        "redact",
		},
		PIIScan: &scanner.PIIConfig{
			Enabled:       true,
			ScanResponses: true,
			Action:        "redact",
		},
	}

	evaluator := NewEvaluator(policy)

	ghToken := "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
	response := `{"result": "Token: ` + ghToken + `, Email: user@example.com"}`

	result := evaluator.EvaluateResponse(context.Background(), "tools.invoke", response)

	if result.Decision != Allow {
		t.Errorf("expected Allow with dual redaction, got %s", result.Decision)
	}
	if !result.WasRedacted {
		t.Error("expected WasRedacted to be true")
	}
	if contains(result.RedactedBody, ghToken) {
		t.Error("expected secret to be redacted")
	}
	if contains(result.RedactedBody, "user@example.com") {
		t.Error("expected email to be redacted")
	}
	if !contains(result.Reason, "secrets redacted") {
		t.Errorf("expected reason to mention secrets, got: %s", result.Reason)
	}
	if !contains(result.Reason, "PII redacted") {
		t.Errorf("expected reason to mention PII, got: %s", result.Reason)
	}
	t.Logf("Dual redacted body: %s", result.RedactedBody)
}

func TestEvaluateResponseSimple_BackwardCompat(t *testing.T) {
	policy := &Policy{
		DefaultAction: Allow,
	}

	evaluator := NewEvaluator(policy)

	decision, reason := evaluator.EvaluateResponseSimple(context.Background(), "chat.send", "clean response")
	if decision != Allow {
		t.Errorf("expected Allow, got %s", decision)
	}
	if reason != "response clean" {
		t.Errorf("expected 'response clean', got %s", reason)
	}
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "full URL with scheme",
			url:  "https://example.com/path",
			want: "example.com",
		},
		{
			name: "URL with port",
			url:  "https://example.com:8080/path",
			want: "example.com",
		},
		{
			name: "subdomain",
			url:  "https://api.github.com",
			want: "api.github.com",
		},
		{
			name: "no scheme",
			url:  "example.com/path",
			want: "example.com",
		},
		{
			name: "invalid URL",
			url:  "://invalid",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDomain(tt.url)
			if got != tt.want {
				t.Errorf("extractDomain(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestEvaluateWithContext_DenylistPriority(t *testing.T) {
	// Denylist should override allowlist
	policy := &Policy{
		DefaultAction: Allow,
		Allowlist:     []string{"exec", "read"},
		Denylist:      []string{"exec"},
	}

	evaluator := NewEvaluator(policy)
	ctx := context.Background()

	decision, reason := evaluator.EvaluateWithContext(ctx, `{"method": "exec", "params": {"command": "ls"}}`)

	if decision != Deny {
		t.Errorf("got decision %s, want %s (denylist should override allowlist)", decision, Deny)
	}

	if !contains(reason, "explicitly denied by denylist") {
		t.Errorf("got reason %q, want to contain 'explicitly denied by denylist'", reason)
	}
}

func TestEvaluateWithContext_EdgeCases(t *testing.T) {
	policy := &Policy{
		DefaultAction: Allow,
	}

	evaluator := NewEvaluator(policy)
	ctx := context.Background()

	tests := []struct {
		name               string
		message            string
		wantDecision       string
		wantReasonContains string
	}{
		{
			name:               "empty message",
			message:            "",
			wantDecision:       Deny,
			wantReasonContains: "invalid JSON-RPC format",
		},
		{
			name:               "empty object",
			message:            "{}",
			wantDecision:       Deny,
			wantReasonContains: "missing method field",
		},
		{
			name:               "null params",
			message:            `{"method": "test", "params": null}`,
			wantDecision:       Allow,
			wantReasonContains: "default allowed",
		},
		{
			name:               "empty params",
			message:            `{"method": "test", "params": {}}`,
			wantDecision:       Allow,
			wantReasonContains: "default allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, reason := evaluator.EvaluateWithContext(ctx, tt.message)

			if decision != tt.wantDecision {
				t.Errorf("got decision %s, want %s", decision, tt.wantDecision)
			}

			if !contains(reason, tt.wantReasonContains) {
				t.Errorf("got reason %q, want to contain %q", reason, tt.wantReasonContains)
			}
		})
	}
}

func TestEvaluateResponse(t *testing.T) {
	tests := []struct {
		name               string
		policy             *Policy
		method             string
		responseBody       string
		wantDecision       string
		wantReasonContains string
	}{
		{
			name: "response clean without scanners",
			policy: &Policy{
				DefaultAction: Allow,
			},
			method:             "tools.list",
			responseBody:       `{"result": "success"}`,
			wantDecision:       Allow,
			wantReasonContains: "response clean",
		},
		{
			name: "response clean with nil scanners",
			policy: &Policy{
				DefaultAction: Allow,
			},
			method:             "web.fetch",
			responseBody:       `{"content": "legitimate data"}`,
			wantDecision:       Allow,
			wantReasonContains: "response clean",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evaluator := NewEvaluator(tt.policy)
			ctx := context.Background()

			result := evaluator.EvaluateResponse(ctx, tt.method, tt.responseBody)

			if result.Decision != tt.wantDecision {
				t.Errorf("got decision %s, want %s", result.Decision, tt.wantDecision)
			}

			if !contains(result.Reason, tt.wantReasonContains) {
				t.Errorf("got reason %q, want to contain %q", result.Reason, tt.wantReasonContains)
			}
		})
	}
}

func TestEvaluateResponse_Timeout(t *testing.T) {
	policy := &Policy{
		DefaultAction: Allow,
	}

	evaluator := NewEvaluator(policy)

	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := evaluator.EvaluateResponse(ctx, "tools.list", `{"result": "success"}`)

	if result.Decision != Deny {
		t.Errorf("got decision %s, want %s", result.Decision, Deny)
	}

	if !contains(result.Reason, "timeout exceeded") {
		t.Errorf("got reason %q, want to contain 'timeout exceeded'", result.Reason)
	}
}

func TestEvaluateAgentScope(t *testing.T) {
	evaluator := NewEvaluator(&Policy{})

	tests := []struct {
		name               string
		responseBody       string
		agentScopes        []string
		wantDecision       string
		wantReasonContains string
	}{
		{
			name:               "no scope restrictions",
			responseBody:       `Use slack-send and github-create`,
			agentScopes:        []string{},
			wantDecision:       Allow,
			wantReasonContains: "no scope restrictions",
		},
		{
			name:               "allowed scope - all platforms allowed",
			responseBody:       `Use slack-send and github-create`,
			agentScopes:        []string{"slack", "github"},
			wantDecision:       Allow,
			wantReasonContains: "response within agent scope",
		},
		{
			name:               "denied - cross scope reference",
			responseBody:       `Please use slack-send to notify`,
			agentScopes:        []string{"github"},
			wantDecision:       Deny,
			wantReasonContains: "cross_scope",
		},
		{
			name:               "denied - invoke pattern",
			responseBody:       `Invoke github-create-issue to track this`,
			agentScopes:        []string{"slack"},
			wantDecision:       Deny,
			wantReasonContains: "cross_scope",
		},
		{
			name:               "denied - call pattern",
			responseBody:       `Call jira-search to find related tickets`,
			agentScopes:        []string{"slack", "github"},
			wantDecision:       Deny,
			wantReasonContains: "cross_scope",
		},
		{
			name:               "case insensitive scope matching",
			responseBody:       `Use SLACK-send-msg`,
			agentScopes:        []string{"Slack"},
			wantDecision:       Allow,
			wantReasonContains: "response within agent scope",
		},
		{
			name:               "denied - confluence update action",
			responseBody:       `confluence-update the page with new content`,
			agentScopes:        []string{"github", "jira"},
			wantDecision:       Deny,
			wantReasonContains: "cross_scope",
		},
		{
			name:               "allowed - mention without action pattern",
			responseBody:       `The slack tool is great but not used here`,
			agentScopes:        []string{"github"},
			wantDecision:       Allow,
			wantReasonContains: "response within agent scope",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, reason := evaluator.EvaluateAgentScope(tt.responseBody, tt.agentScopes)

			if decision != tt.wantDecision {
				t.Errorf("got decision %s, want %s", decision, tt.wantDecision)
			}

			if !contains(reason, tt.wantReasonContains) {
				t.Errorf("got reason %q, want to contain %q", reason, tt.wantReasonContains)
			}
		})
	}
}

func TestEvaluateOpenClawAgent(t *testing.T) {
	tests := []struct {
		name               string
		policy             *Policy
		agentID            string
		wantDecision       string
		wantReasonContains string
	}{
		{
			name: "no agent allowlist configured",
			policy: &Policy{
				DefaultAction: Allow,
				OpenClaw:      nil,
			},
			agentID:            "agent123",
			wantDecision:       Allow,
			wantReasonContains: "no agent allowlist configured",
		},
		{
			name: "empty agent allowlist",
			policy: &Policy{
				DefaultAction: Allow,
				OpenClaw: &OpenClawConfig{
					AgentAllowlist: []string{},
				},
			},
			agentID:            "agent123",
			wantDecision:       Allow,
			wantReasonContains: "no agent allowlist configured",
		},
		{
			name: "agent in allowlist",
			policy: &Policy{
				DefaultAction: Allow,
				OpenClaw: &OpenClawConfig{
					AgentAllowlist: []string{"agent1", "agent2", "agent3"},
				},
			},
			agentID:            "agent2",
			wantDecision:       Allow,
			wantReasonContains: "agent in allowlist",
		},
		{
			name: "agent not in allowlist",
			policy: &Policy{
				DefaultAction: Allow,
				OpenClaw: &OpenClawConfig{
					AgentAllowlist: []string{"agent1", "agent2"},
				},
			},
			agentID:            "agent3",
			wantDecision:       Deny,
			wantReasonContains: "not in allowlist",
		},
		{
			name: "case insensitive matching",
			policy: &Policy{
				DefaultAction: Allow,
				OpenClaw: &OpenClawConfig{
					AgentAllowlist: []string{"Agent1", "Agent2"},
				},
			},
			agentID:            "agent1",
			wantDecision:       Allow,
			wantReasonContains: "agent in allowlist",
		},
		{
			name: "case insensitive matching uppercase",
			policy: &Policy{
				DefaultAction: Allow,
				OpenClaw: &OpenClawConfig{
					AgentAllowlist: []string{"agent1", "agent2"},
				},
			},
			agentID:            "AGENT1",
			wantDecision:       Allow,
			wantReasonContains: "agent in allowlist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evaluator := NewEvaluator(tt.policy)
			decision, reason := evaluator.EvaluateOpenClawAgent(tt.agentID)

			if decision != tt.wantDecision {
				t.Errorf("got decision %s, want %s", decision, tt.wantDecision)
			}

			if !contains(reason, tt.wantReasonContains) {
				t.Errorf("got reason %q, want to contain %q", reason, tt.wantReasonContains)
			}
		})
	}
}

func TestEvaluateOpenClawChannel(t *testing.T) {
	tests := []struct {
		name               string
		policy             *Policy
		channel            string
		tool               string
		wantDecision       string
		wantReasonContains string
	}{
		{
			name: "no channel policies configured",
			policy: &Policy{
				DefaultAction: Allow,
				OpenClaw:      nil,
			},
			channel:            "general",
			tool:               "read",
			wantDecision:       Allow,
			wantReasonContains: "no channel policies configured",
		},
		{
			name: "empty channel policies",
			policy: &Policy{
				DefaultAction: Allow,
				OpenClaw: &OpenClawConfig{
					ChannelPolicies: map[string]ChannelPolicy{},
				},
			},
			channel:            "general",
			tool:               "read",
			wantDecision:       Allow,
			wantReasonContains: "no channel policies configured",
		},
		{
			name: "no policy for channel",
			policy: &Policy{
				DefaultAction: Allow,
				OpenClaw: &OpenClawConfig{
					ChannelPolicies: map[string]ChannelPolicy{
						"dev": {AllowedTools: []string{"read", "write"}},
					},
				},
			},
			channel:            "general",
			tool:               "exec",
			wantDecision:       Allow,
			wantReasonContains: "no policy for channel",
		},
		{
			name: "tool blocked for channel",
			policy: &Policy{
				DefaultAction: Allow,
				OpenClaw: &OpenClawConfig{
					ChannelPolicies: map[string]ChannelPolicy{
						"general": {BlockedTools: []string{"exec", "shell"}},
					},
				},
			},
			channel:            "general",
			tool:               "exec",
			wantDecision:       Deny,
			wantReasonContains: "blocked for channel",
		},
		{
			name: "tool in allowed list",
			policy: &Policy{
				DefaultAction: Allow,
				OpenClaw: &OpenClawConfig{
					ChannelPolicies: map[string]ChannelPolicy{
						"dev": {AllowedTools: []string{"read", "write"}},
					},
				},
			},
			channel:            "dev",
			tool:               "read",
			wantDecision:       Allow,
			wantReasonContains: "tool allowed for channel",
		},
		{
			name: "tool not in allowed list",
			policy: &Policy{
				DefaultAction: Allow,
				OpenClaw: &OpenClawConfig{
					ChannelPolicies: map[string]ChannelPolicy{
						"dev": {AllowedTools: []string{"read", "write"}},
					},
				},
			},
			channel:            "dev",
			tool:               "exec",
			wantDecision:       Deny,
			wantReasonContains: "not in allowed list",
		},
		{
			name: "tool not restricted when no allowed list",
			policy: &Policy{
				DefaultAction: Allow,
				OpenClaw: &OpenClawConfig{
					ChannelPolicies: map[string]ChannelPolicy{
						"general": {BlockedTools: []string{"exec"}},
					},
				},
			},
			channel:            "general",
			tool:               "read",
			wantDecision:       Allow,
			wantReasonContains: "tool not restricted for channel",
		},
		{
			name: "blocked takes priority over allowed absence",
			policy: &Policy{
				DefaultAction: Allow,
				OpenClaw: &OpenClawConfig{
					ChannelPolicies: map[string]ChannelPolicy{
						"dev": {
							AllowedTools: []string{"read", "write"},
							BlockedTools: []string{"write"},
						},
					},
				},
			},
			channel:            "dev",
			tool:               "write",
			wantDecision:       Deny,
			wantReasonContains: "blocked for channel",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evaluator := NewEvaluator(tt.policy)
			decision, reason := evaluator.EvaluateOpenClawChannel(tt.channel, tt.tool)

			if decision != tt.wantDecision {
				t.Errorf("got decision %s, want %s", decision, tt.wantDecision)
			}

			if !contains(reason, tt.wantReasonContains) {
				t.Errorf("got reason %q, want to contain %q", reason, tt.wantReasonContains)
			}
		})
	}
}

func TestHasDuplicateKeys(t *testing.T) {
	tests := []struct {
		name      string
		data      string
		wantFound bool
	}{
		{
			name:      "no duplicates",
			data:      `{"method": "test", "params": {}}`,
			wantFound: false,
		},
		{
			name:      "duplicate keys",
			data:      `{"method": "test", "method": "test2"}`,
			wantFound: true,
		},
		{
			name:      "nested objects without duplicates",
			data:      `{"method": "test", "params": {"key": "value", "other": "data"}}`,
			wantFound: false,
		},
		{
			name:      "duplicate in nested object (detected recursively)",
			data:      `{"method": "test", "params": {"key": "value", "key": "value2"}}`,
			wantFound: true,
		},
		{
			name:      "empty object",
			data:      `{}`,
			wantFound: false,
		},
		{
			name:      "not an object",
			data:      `[]`,
			wantFound: false,
		},
		{
			name:      "invalid JSON",
			data:      `{not valid`,
			wantFound: false,
		},
		{
			name:      "three duplicates",
			data:      `{"key": 1, "other": 2, "key": 3}`,
			wantFound: true,
		},
		{
			name:      "duplicate with array value",
			data:      `{"method": "test", "params": [], "method": "test2"}`,
			wantFound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasDuplicateKeys([]byte(tt.data))

			if got != tt.wantFound {
				t.Errorf("hasDuplicateKeys(%q) = %v, want %v", tt.data, got, tt.wantFound)
			}
		})
	}
}

func TestValidateURLSafety(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		wantError bool
	}{
		{
			name:      "safe URL",
			url:       "https://example.com/path",
			wantError: false,
		},
		{
			name:      "safe URL with query",
			url:       "https://example.com/path?key=value",
			wantError: false,
		},
		{
			name:      "URL with embedded credentials",
			url:       "https://user:pass@example.com/path",
			wantError: true,
		},
		{
			name:      "URL with backslash",
			url:       "https://example.com\\path",
			wantError: true,
		},
		{
			name:      "URL with null byte",
			url:       "https://example.com/path\x00evil",
			wantError: true,
		},
		{
			name:      "URL with percent-encoded host",
			url:       "https://example%2Ecom/path",
			wantError: true,
		},
		{
			name:      "HTTP URL safe",
			url:       "http://example.com",
			wantError: false,
		},
		{
			name:      "URL without scheme",
			url:       "example.com/path",
			wantError: false,
		},
		{
			name:      "invalid URL format",
			url:       "://invalid",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateURLSafety(tt.url)

			gotError := err != nil
			if gotError != tt.wantError {
				t.Errorf("validateURLSafety(%q) error = %v, wantError %v", tt.url, err, tt.wantError)
			}
		})
	}
}

func TestMatchDomain(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		pattern string
		want    bool
	}{
		{
			name:    "exact match",
			domain:  "example.com",
			pattern: "example.com",
			want:    true,
		},
		{
			name:    "no match",
			domain:  "evil.com",
			pattern: "example.com",
			want:    false,
		},
		{
			name:    "wildcard match subdomain",
			domain:  "api.example.com",
			pattern: "*.example.com",
			want:    true,
		},
		{
			name:    "wildcard match base domain",
			domain:  "example.com",
			pattern: "*.example.com",
			want:    true,
		},
		{
			name:    "wildcard no match different domain",
			domain:  "api.other.com",
			pattern: "*.example.com",
			want:    false,
		},
		{
			name:    "wildcard with deeper subdomain",
			domain:  "v2.api.example.com",
			pattern: "*.example.com",
			want:    true,
		},
		{
			name:    "case sensitive match",
			domain:  "Example.com",
			pattern: "example.com",
			want:    false,
		},
		{
			name:    "wildcard no prefix",
			domain:  "example.com",
			pattern: "example.com",
			want:    true,
		},
		{
			name:    "single letter subdomain",
			domain:  "a.example.com",
			pattern: "*.example.com",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchDomain(tt.domain, tt.pattern)

			if got != tt.want {
				t.Errorf("matchDomain(%q, %q) = %v, want %v", tt.domain, tt.pattern, got, tt.want)
			}
		})
	}
}

// TestEvaluateWithDetails_CaseInsensitiveDenylist tests case-insensitive denylist matching
func TestEvaluateWithDetails_CaseInsensitiveDenylist(t *testing.T) {
	t.Run("exact denylist match", func(t *testing.T) {
		policy := &Policy{
			DefaultAction: Allow,
			Denylist:      []string{"shell.exec"},
		}
		evaluator := NewEvaluator(policy)

		// Should deny both exact case and different case
		testCases := []string{
			`{"method":"shell.exec","params":{}}`,
			`{"method":"Shell.Exec","params":{}}`,
			`{"method":"SHELL.EXEC","params":{}}`,
			`{"method":"sHeLL.eXeC","params":{}}`,
		}

		for _, msg := range testCases {
			decision, reason, _ := evaluator.EvaluateWithDetails(context.Background(), msg)
			if decision != Deny {
				t.Errorf("expected Deny, got %s for message: %s", decision, msg)
			}
			if reason != "tool explicitly denied by denylist" {
				t.Errorf("expected denylist reason, got: %s", reason)
			}
		}
	})
}

// TestEvaluateWithDetails_CaseInsensitiveAllowlist tests case-insensitive allowlist matching
func TestEvaluateWithDetails_CaseInsensitiveAllowlist(t *testing.T) {
	t.Run("case-insensitive allowlist match", func(t *testing.T) {
		policy := &Policy{
			DefaultAction: Deny,
			Allowlist:     []string{"code.generate"},
		}
		evaluator := NewEvaluator(policy)

		// Should allow both exact case and different case
		testCases := []string{
			`{"method":"code.generate","params":{}}`,
			`{"method":"Code.Generate","params":{}}`,
			`{"method":"CODE.GENERATE","params":{}}`,
			`{"method":"cOdE.gEnErAtE","params":{}}`,
		}

		for _, msg := range testCases {
			decision, reason, _ := evaluator.EvaluateWithDetails(context.Background(), msg)
			if decision != Allow {
				t.Errorf("expected Allow, got %s for message: %s (reason: %s)", decision, msg, reason)
			}
		}
	})
}

// TestEvaluateWithDetails_MethodWhitespaceNormalization tests whitespace normalization in method names
func TestEvaluateWithDetails_MethodWhitespaceNormalization(t *testing.T) {
	t.Run("method with leading/trailing whitespace", func(t *testing.T) {
		policy := &Policy{
			DefaultAction: Deny,
			Denylist:      []string{"shell.exec"},
		}
		evaluator := NewEvaluator(policy)

		// Should normalize whitespace and deny
		testCases := []string{
			`{"method":" shell.exec ","params":{}}`,
			`{"method":"  shell.exec  ","params":{}}`,
			`{"method":"shell.exec ","params":{}}`,
			`{"method":" shell.exec","params":{}}`,
		}

		for _, msg := range testCases {
			decision, reason, _ := evaluator.EvaluateWithDetails(context.Background(), msg)
			if decision != Deny {
				t.Errorf("expected Deny, got %s for message: %s", decision, msg)
			}
			if reason != "tool explicitly denied by denylist" {
				t.Errorf("expected denylist reason, got: %s", reason)
			}
		}
	})

	t.Run("method with internal whitespace normalization", func(t *testing.T) {
		policy := &Policy{
			DefaultAction: Deny,
			Denylist:      []string{"shell exec"},
		}
		evaluator := NewEvaluator(policy)

		// Should normalize internal whitespace: "shell  exec" -> "shell exec"
		msg := `{"method":"shell  exec","params":{}}`
		decision, reason, _ := evaluator.EvaluateWithDetails(context.Background(), msg)
		if decision != Deny {
			t.Errorf("expected Deny, got %s", decision)
		}
		if reason != "tool explicitly denied by denylist" {
			t.Errorf("expected denylist reason, got: %s", reason)
		}
	})
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && containsImpl(s, substr)))
}

func containsImpl(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
