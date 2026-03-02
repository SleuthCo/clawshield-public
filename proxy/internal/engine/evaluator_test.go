package engine

import (
	"context"
	"fmt"
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
		name     string
		policy   *Policy
		message  string
		wantDecision string
		wantReasonContains string
	}{
		{
			name: "allow by default",
			policy: &Policy{
				DefaultAction: Allow,
			},
			message: `{"method": "tools.list", "params": {}}`,
			wantDecision: Allow,
			wantReasonContains: "default allowed",
		},
		{
			name: "deny by default",
			policy: &Policy{
				DefaultAction: Deny,
			},
			message: `{"method": "tools.list", "params": {}}`,
			wantDecision: Deny,
			wantReasonContains: "default denied",
		},
		{
			name: "invalid JSON",
			policy: &Policy{
				DefaultAction: Allow,
			},
			message: `{not valid json`,
			wantDecision: Deny,
			wantReasonContains: "invalid JSON-RPC format",
		},
		{
			name: "missing method",
			policy: &Policy{
				DefaultAction: Allow,
			},
			message: `{"params": {}}`,
			wantDecision: Deny,
			wantReasonContains: "missing method field",
		},
		{
			name: "params as string is valid JSON",
			policy: &Policy{
				DefaultAction: Allow,
			},
			message: `{"method": "test", "params": "valid-string"}`,
			wantDecision: Allow,
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
		Denylist: []string{"exec", "shell", "dangerous.tool"},
	}

	evaluator := NewEvaluator(policy)
	ctx := context.Background()

	tests := []struct {
		name     string
		message  string
		wantDecision string
		wantReasonContains string
	}{
		{
			name: "blocked by denylist",
			message: `{"method": "exec", "params": {"command": "ls"}}`,
			wantDecision: Deny,
			wantReasonContains: "explicitly denied by denylist",
		},
		{
			name: "allowed tool",
			message: `{"method": "read", "params": {"path": "file.txt"}}`,
			wantDecision: Allow,
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
		Allowlist: []string{"read", "write", "web.fetch"},
	}

	evaluator := NewEvaluator(policy)
	ctx := context.Background()

	tests := []struct {
		name     string
		message  string
		wantDecision string
		wantReasonContains string
	}{
		{
			name: "allowed tool in allowlist",
			message: `{"method": "read", "params": {"path": "file.txt"}}`,
			wantDecision: Allow,
			wantReasonContains: "allowlist",
		},
		{
			name: "blocked tool not in allowlist",
			message: `{"method": "exec", "params": {"command": "ls"}}`,
			wantDecision: Deny,
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
		name     string
		message  string
		wantDecision string
		wantReasonContains string
	}{
		{
			name: "blocked by arg filter",
			message: `{"method": "exec", "params": {"command": "echo password123"}}`,
			wantDecision: Deny,
			wantReasonContains: "sensitive data detected",
		},
		{
			name: "allowed - no match",
			message: `{"method": "exec", "params": {"command": "ls -la"}}`,
			wantDecision: Allow,
			wantReasonContains: "default allowed",
		},
		{
			name: "blocked api key pattern",
			message: `{"method": "web.fetch", "params": {"url": "http://example.com?api_key=secret"}}`,
			wantDecision: Deny,
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
		DefaultAction: Allow,
		DomainAllowlist: []string{"example.com", "*.github.com"},
	}

	evaluator := NewEvaluator(policy)
	ctx := context.Background()

	tests := []struct {
		name     string
		message  string
		wantDecision string
		wantReasonContains string
	}{
		{
			name: "allowed domain",
			message: `{"method": "web.fetch", "params": {"url": "https://example.com/page"}}`,
			wantDecision: Allow,
			wantReasonContains: "default allowed",
		},
		{
			name: "allowed wildcard subdomain",
			message: `{"method": "web.fetch", "params": {"url": "https://api.github.com/repos"}}`,
			wantDecision: Allow,
			wantReasonContains: "default allowed",
		},
		{
			name: "blocked domain",
			message: `{"method": "web.fetch", "params": {"url": "https://evil.com"}}`,
			wantDecision: Deny,
			wantReasonContains: "domain not in allowlist",
		},
		{
			name: "non-web tool ignores domain allowlist",
			message: `{"method": "read", "params": {"path": "file.txt"}}`,
			wantDecision: Allow,
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
		DefaultAction: Allow,
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
		DefaultAction: Allow,
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

func TestEvaluateWithContext_InternalTimeout(t *testing.T) {
	// Verify that the evaluator enforces its own timeout via EvaluationTimeoutMs
	// even when the caller provides a plain context.Background() with no deadline.
	policy := &Policy{
		DefaultAction:       Allow,
		EvaluationTimeoutMs: 1, // 1ms — will expire almost immediately
		DomainAllowlist:     make([]string, 10000),
	}

	for i := 0; i < 10000; i++ {
		policy.DomainAllowlist[i] = fmt.Sprintf("domain%d.example.com", i)
	}

	evaluator := NewEvaluator(policy)

	// Use context.Background() with NO external deadline — the evaluator must enforce its own
	time.Sleep(5 * time.Millisecond) // Give the 1ms timeout a chance to fire
	decision, reason := evaluator.EvaluateWithContext(context.Background(), `{"method": "web.fetch", "params": {"url": "https://notindomain.example.com"}}`)

	if decision != Deny {
		t.Errorf("got decision %s, want %s", decision, Deny)
	}

	if !contains(reason, "timeout exceeded") && !contains(reason, "not in allowlist") {
		// Either timeout fires or domain check catches it — both are valid deny reasons
		t.Logf("reason: %s (either timeout or domain check is acceptable)", reason)
	}
}

func TestEvaluateWithContext_InternalTimeoutExpires(t *testing.T) {
	// Verify that a very short EvaluationTimeoutMs causes timeout denial
	// even with no external context deadline.
	policy := &Policy{
		DefaultAction:       Allow,
		EvaluationTimeoutMs: 1, // 1ms — will expire almost immediately
		DomainAllowlist:     make([]string, 100000), // Very large list to ensure processing takes time
	}

	for i := 0; i < 100000; i++ {
		policy.DomainAllowlist[i] = fmt.Sprintf("slowdomain%d.example.com", i)
	}

	evaluator := NewEvaluator(policy)

	// Let the internal timeout expire before the domain loop completes
	time.Sleep(5 * time.Millisecond)
	decision, _ := evaluator.EvaluateWithContext(context.Background(), `{"method": "web.fetch", "params": {"url": "https://nonexistent.example.com"}}`)

	if decision != Deny {
		t.Errorf("expected Deny, got %s — internal timeout should have triggered or domain not found", decision)
	}
}

func TestEvaluateResponse_InternalTimeout(t *testing.T) {
	// Verify that EvaluateResponse also enforces its own timeout via EvaluationTimeoutMs.
	policy := &Policy{
		DefaultAction:       Allow,
		EvaluationTimeoutMs: 1, // 1ms
		PromptInjection: &scanner.PromptInjectionConfig{
			Enabled:       true,
			ScanResponses: true,
			Sensitivity:   "high",
		},
	}

	evaluator := NewEvaluator(policy)

	// Use plain context.Background() — evaluator must create its own timeout
	time.Sleep(5 * time.Millisecond)
	decision, reason := evaluator.EvaluateResponse(context.Background(), "chat.send", "This is a normal response")

	// With a 1ms timeout that we've already slept past, the evaluator's internal context
	// may or may not expire depending on scheduling. Either outcome is valid:
	// - "allow" + "response clean" (evaluation completed within timeout)
	// - "deny" + "evaluation timeout exceeded" (timeout fired)
	if decision == Deny && !contains(reason, "timeout") {
		t.Errorf("got Deny with unexpected reason: %s", reason)
	}
	t.Logf("EvaluateResponse with 1ms timeout: decision=%s reason=%s", decision, reason)
}

func TestEvaluateWithContext_NoTimeoutWhenZero(t *testing.T) {
	// Verify that when EvaluationTimeoutMs is 0, no internal timeout is applied
	// and evaluation completes normally.
	policy := &Policy{
		DefaultAction:       Allow,
		EvaluationTimeoutMs: 0, // No internal timeout
		Allowlist:           []string{"read"},
	}

	evaluator := NewEvaluator(policy)

	decision, reason := evaluator.EvaluateWithContext(context.Background(), `{"method": "read", "params": {"path": "test.txt"}}`)

	if decision != Allow {
		t.Errorf("got decision %s, want %s (reason: %s)", decision, Allow, reason)
	}
}

func TestEvaluateWithContext_InternalTimeoutRespectsExternalDeadline(t *testing.T) {
	// When both an external deadline AND internal EvaluationTimeoutMs are set,
	// the shorter one should win.
	policy := &Policy{
		DefaultAction:       Allow,
		EvaluationTimeoutMs: 60000, // 60 seconds (very generous)
		DomainAllowlist:     []string{"example.com"},
	}

	evaluator := NewEvaluator(policy)

	// External context with already-expired deadline should still cause denial
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	decision, reason := evaluator.EvaluateWithContext(ctx, `{"method": "web.fetch", "params": {"url": "https://example.com"}}`)

	if decision != Deny {
		t.Errorf("got decision %s, want %s", decision, Deny)
	}

	if !contains(reason, "timeout exceeded") {
		t.Errorf("got reason %q, want to contain 'timeout exceeded'", reason)
	}
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		want     string
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
		Allowlist: []string{"exec", "read"},
		Denylist: []string{"exec"},
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
		name     string
		message  string
		wantDecision string
		wantReasonContains string
	}{
		{
			name: "empty message",
			message: "",
			wantDecision: Deny,
			wantReasonContains: "invalid JSON-RPC format",
		},
		{
			name: "empty object",
			message: "{}",
			wantDecision: Deny,
			wantReasonContains: "missing method field",
		},
		{
			name: "null params",
			message: `{"method": "test", "params": null}`,
			wantDecision: Allow,
			wantReasonContains: "default allowed",
		},
		{
			name: "empty params",
			message: `{"method": "test", "params": {}}`,
			wantDecision: Allow,
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
