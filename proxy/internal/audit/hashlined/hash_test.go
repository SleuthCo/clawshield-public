package hashlined

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestHashArguments(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid JSON with sensitive field",
			input:   `{"apikey": "secret123", "url": "https://example.com"}`,
			wantErr: false,
		},
		{
			name:    "valid JSON without sensitive fields",
			input:   `{"url": "https://example.com", "timeout": 30}`,
			wantErr: false,
		},
		{
			name:    "empty object",
			input:   `{}`,
			wantErr: false,
		},
		{
			name:    "invalid JSON",
			input:   `{not valid json`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := HashArguments(tt.input)
			
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			
			// Hash should be 64 characters (SHA-256 in hex)
			if len(hash) != 64 {
				t.Errorf("hash length = %d, want 64", len(hash))
			}
		})
	}
}

func TestHashArguments_Consistency(t *testing.T) {
	// Same input should produce same hash
	input := `{"apikey": "secret123", "url": "https://example.com"}`
	
	hash1, err := HashArguments(input)
	if err != nil {
		t.Fatalf("first hash failed: %v", err)
	}
	
	hash2, err := HashArguments(input)
	if err != nil {
		t.Fatalf("second hash failed: %v", err)
	}
	
	if hash1 != hash2 {
		t.Errorf("hashes don't match: %s != %s", hash1, hash2)
	}
}

func TestHashArguments_RedactionConsistency(t *testing.T) {
	// Different sensitive values should produce same hash after redaction
	input1 := `{"apikey": "secret123", "url": "https://example.com"}`
	input2 := `{"apikey": "different_secret", "url": "https://example.com"}`
	
	hash1, err := HashArguments(input1)
	if err != nil {
		t.Fatalf("first hash failed: %v", err)
	}
	
	hash2, err := HashArguments(input2)
	if err != nil {
		t.Fatalf("second hash failed: %v", err)
	}
	
	if hash1 != hash2 {
		t.Errorf("hashes should match after redaction: %s != %s", hash1, hash2)
	}
}

func TestHashArguments_DifferentNonSensitiveValues(t *testing.T) {
	// Different non-sensitive values should produce different hashes
	input1 := `{"url": "https://example.com", "timeout": 30}`
	input2 := `{"url": "https://different.com", "timeout": 30}`
	
	hash1, err := HashArguments(input1)
	if err != nil {
		t.Fatalf("first hash failed: %v", err)
	}
	
	hash2, err := HashArguments(input2)
	if err != nil {
		t.Fatalf("second hash failed: %v", err)
	}
	
	if hash1 == hash2 {
		t.Errorf("hashes should differ for different non-sensitive values")
	}
}

func TestIsSensitiveKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want bool
	}{
		// Exact matches
		{name: "apikey lowercase", key: "apikey", want: true},
		{name: "token lowercase", key: "token", want: true},
		{name: "password lowercase", key: "password", want: true},
		
		// Case variations
		{name: "API_KEY uppercase", key: "API_KEY", want: true},
		{name: "Password mixed case", key: "Password", want: true},
		{name: "TOKEN uppercase", key: "TOKEN", want: true},
		
		// Snake case variations
		{name: "api_key snake_case", key: "api_key", want: true},
		{name: "private_key snake_case", key: "private_key", want: true},
		
		// Kebab case variations
		{name: "api-key kebab-case", key: "api-key", want: true},
		
		// CamelCase variations
		{name: "apiKey camelCase", key: "apiKey", want: true},
		{name: "privateKey camelCase", key: "privateKey", want: true},
		
		// AWS-specific
		{name: "aws_access_key_id", key: "aws_access_key_id", want: true},
		{name: "AWS_SECRET_ACCESS_KEY", key: "AWS_SECRET_ACCESS_KEY", want: true},
		{name: "awsAccessKeyId camelCase", key: "awsAccessKeyId", want: true},
		
		// PII
		{name: "email", key: "email", want: true},
		{name: "phone", key: "phone", want: true},
		{name: "ssn", key: "ssn", want: true},
		
		// Financial
		{name: "credit_card", key: "credit_card", want: true},
		{name: "cvv", key: "cvv", want: true},
		{name: "account_number", key: "account_number", want: true},
		
		// Non-sensitive
		{name: "url", key: "url", want: false},
		{name: "timeout", key: "timeout", want: false},
		{name: "method", key: "method", want: false},
		{name: "name", key: "name", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsSensitiveKey(tt.key)
			if got != tt.want {
				t.Errorf("IsSensitiveKey(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

func TestRedactArguments(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantRedacted map[string]interface{}
		wantErr bool
	}{
		{
			name:  "redact apikey",
			input: `{"apikey": "secret123", "url": "https://example.com"}`,
			wantRedacted: map[string]interface{}{
				"apikey": "[REDACTED]",
				"url":    "https://example.com",
			},
			wantErr: false,
		},
		{
			name:  "redact multiple sensitive fields",
			input: `{"token": "abc", "password": "pass123", "url": "test"}`,
			wantRedacted: map[string]interface{}{
				"token":    "[REDACTED]",
				"password": "[REDACTED]",
				"url":      "test",
			},
			wantErr: false,
		},
		{
			name:  "no sensitive fields",
			input: `{"url": "https://example.com", "timeout": 30}`,
			wantRedacted: map[string]interface{}{
				"url":     "https://example.com",
				"timeout": float64(30),
			},
			wantErr: false,
		},
		{
			name:    "invalid JSON",
			input:   `{not valid`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := RedactArguments(tt.input)
			
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			
			var got map[string]interface{}
			if err := json.Unmarshal([]byte(result), &got); err != nil {
				t.Fatalf("failed to unmarshal result: %v", err)
			}
			
			if len(got) != len(tt.wantRedacted) {
				t.Errorf("result has %d fields, want %d", len(got), len(tt.wantRedacted))
			}
			
			for k, wantV := range tt.wantRedacted {
				gotV, ok := got[k]
				if !ok {
					t.Errorf("missing field %q in result", k)
					continue
				}
				
				// Compare as strings for simplicity
				if fmt.Sprint(gotV) != fmt.Sprint(wantV) {
					t.Errorf("field %q = %v, want %v", k, gotV, wantV)
				}
			}
		})
	}
}

func TestHashArguments_ComplexNesting(t *testing.T) {
	// Test with nested objects (current implementation is flat, but ensure it doesn't crash)
	input := `{"outer": {"apikey": "secret"}, "url": "test"}`
	
	hash, err := HashArguments(input)
	if err != nil {
		t.Fatalf("unexpected error with nested object: %v", err)
	}
	
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64", len(hash))
	}
	
	// Note: Current implementation doesn't handle nested redaction,
	// but it shouldn't crash
}

func TestHashArguments_ArrayValues(t *testing.T) {
	input := `{"apikey": "secret", "items": [1, 2, 3]}`
	
	hash, err := HashArguments(input)
	if err != nil {
		t.Fatalf("unexpected error with array values: %v", err)
	}
	
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64", len(hash))
	}
}

func TestSensitiveKeys_Coverage(t *testing.T) {
	// Ensure all keys in SensitiveKeys map are normalized correctly
	for key := range SensitiveKeys {
		// All keys should be lowercase
		if key != strings.ToLower(key) {
			t.Errorf("SensitiveKeys contains non-lowercase key: %q", key)
		}
		
		// Note: Some keys like access_token, session_id contain underscores
		// because they are explicitly listed variants
		// This is acceptable as IsSensitiveKey normalizes input before matching
	}
}

func TestHashArguments_CollisionResistance(t *testing.T) {
	// Generate many different inputs and ensure no collisions
	hashes := make(map[string]string)
	
	testInputs := []string{
		`{"url": "https://example.com"}`,
		`{"url": "https://different.com"}`,
		`{"timeout": 30}`,
		`{"timeout": 60}`,
		`{"apikey": "any", "url": "https://example.com"}`,
		`{"token": "any", "url": "https://example.com"}`,
		`{"password": "any", "url": "https://example.com"}`,
		`{"method": "test1"}`,
		`{"method": "test2"}`,
		`{"data": [1, 2, 3]}`,
		`{"data": [3, 2, 1]}`,
	}
	
	for _, input := range testInputs {
		hash, err := HashArguments(input)
		if err != nil {
			t.Fatalf("hash failed for %q: %v", input, err)
		}
		
		if existingInput, exists := hashes[hash]; exists {
			// Check if this is expected (sensitive field redaction)
			var obj1, obj2 map[string]interface{}
			json.Unmarshal([]byte(input), &obj1)
			json.Unmarshal([]byte(existingInput), &obj2)
			
			// If both have same non-sensitive fields, collision is expected
			allSensitive := true
			for k := range obj1 {
				if !IsSensitiveKey(k) {
					allSensitive = false
					break
				}
			}
			
			if !allSensitive {
				t.Errorf("collision detected:\n  %q\n  %q\nboth produced hash: %s", 
					input, existingInput, hash)
			}
		}
		
		hashes[hash] = input
	}
}
