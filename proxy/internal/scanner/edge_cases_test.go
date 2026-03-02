package scanner

import (
	"strings"
	"testing"
)

// =============================================================================
// HIGH-8: Edge case tests for all scanners (empty, null bytes, large input)
// =============================================================================

// --- Injection Detector Edge Cases ---

func TestInjectionDetector_EmptyInput(t *testing.T) {
	d := NewInjectionDetector(&PromptInjectionConfig{
		Enabled:      true,
		ScanRequests: true,
		Sensitivity:  "high",
	})
	if d == nil {
		t.Fatal("detector should not be nil")
	}

	blocked, _ := d.ScanRequest("test", "")
	if blocked {
		t.Error("empty input should not be blocked")
	}
}

func TestInjectionDetector_WhitespaceOnly(t *testing.T) {
	d := NewInjectionDetector(&PromptInjectionConfig{
		Enabled:      true,
		ScanRequests: true,
		Sensitivity:  "high",
	})

	blocked, _ := d.ScanRequest("test", "   \n\n\t  ")
	if blocked {
		t.Error("whitespace-only input should not be blocked")
	}
}

func TestInjectionDetector_LargeInput(t *testing.T) {
	d := NewInjectionDetector(&PromptInjectionConfig{
		Enabled:      true,
		ScanRequests: true,
		Sensitivity:  "high",
	})

	// 200KB of clean text should not panic or block
	largeInput := strings.Repeat("This is a perfectly normal sentence about programming. ", 4000)
	blocked, _ := d.ScanRequest("test", largeInput)
	if blocked {
		t.Error("large clean input should not be blocked")
	}
}

func TestInjectionDetector_ResponseEmpty(t *testing.T) {
	d := NewInjectionDetector(&PromptInjectionConfig{
		Enabled:       true,
		ScanResponses: true,
		Sensitivity:   "high",
	})

	blocked, _ := d.ScanResponse("test", "")
	if blocked {
		t.Error("empty response should not be blocked")
	}
}

// --- Malware Scanner Edge Cases ---

func TestMalwareScanner_EmptyInput(t *testing.T) {
	s := NewMalwareScanner(&MalwareScanConfig{
		Enabled: true,
		Checks:  []string{"magic_bytes", "signatures", "script_detection"},
	})
	if s == nil {
		t.Fatal("scanner should not be nil")
	}

	blocked, _ := s.ScanResponse("")
	if blocked {
		t.Error("empty input should not be blocked")
	}
}

func TestMalwareScanner_WhitespaceOnly(t *testing.T) {
	s := NewMalwareScanner(&MalwareScanConfig{
		Enabled: true,
		Checks:  []string{"magic_bytes", "signatures", "script_detection"},
	})

	blocked, _ := s.ScanResponse("   \n\n\t  ")
	if blocked {
		t.Error("whitespace-only input should not be blocked")
	}
}

func TestMalwareScanner_LargeCleanInput(t *testing.T) {
	s := NewMalwareScanner(&MalwareScanConfig{
		Enabled: true,
		Checks:  []string{"magic_bytes", "signatures"},
	})

	largeInput := strings.Repeat("Normal text content without any malware signatures. ", 5000)
	blocked, _ := s.ScanResponse(largeInput)
	if blocked {
		t.Error("large clean input should not be blocked")
	}
}

// --- Vuln Scanner Edge Cases ---

func TestVulnScanner_EmptyInput(t *testing.T) {
	s := NewVulnScanner(&VulnScanConfig{
		Enabled: true,
		Rules:   []string{"sqli", "path_traversal", "ssrf", "command_injection"},
	})
	if s == nil {
		t.Fatal("scanner should not be nil")
	}

	blocked, _ := s.Scan("test", "")
	if blocked {
		t.Error("empty input should not be blocked")
	}
}

func TestVulnScanner_WhitespaceOnly(t *testing.T) {
	s := NewVulnScanner(&VulnScanConfig{
		Enabled: true,
		Rules:   []string{"sqli", "path_traversal"},
	})

	blocked, _ := s.Scan("test", "   \n\n\t  ")
	if blocked {
		t.Error("whitespace-only input should not be blocked")
	}
}

func TestVulnScanner_LargeCleanInput(t *testing.T) {
	s := NewVulnScanner(&VulnScanConfig{
		Enabled: true,
		Rules:   []string{"sqli", "path_traversal", "ssrf", "command_injection"},
	})

	largeInput := strings.Repeat("Normal user query about database design patterns. ", 5000)
	blocked, _ := s.Scan("test", largeInput)
	if blocked {
		t.Error("large clean input should not be blocked")
	}
}

// --- PII Scanner Edge Cases ---

func TestPIIScanner_EmptyInput(t *testing.T) {
	s := NewPIIScanner(&PIIConfig{
		Enabled:      true,
		ScanRequests: true,
		Action:       "redact",
	})
	if s == nil {
		t.Fatal("scanner should not be nil")
	}

	blocked, _ := s.ScanRequest("test", "")
	if blocked {
		t.Error("empty input should not be blocked")
	}
}

func TestPIIScanner_WhitespaceOnly(t *testing.T) {
	s := NewPIIScanner(&PIIConfig{
		Enabled:      true,
		ScanRequests: true,
		Action:       "redact",
	})

	blocked, _ := s.ScanRequest("test", "   \n\n\t  ")
	if blocked {
		t.Error("whitespace-only input should not be blocked")
	}
}

func TestPIIScanner_LargeCleanInput(t *testing.T) {
	s := NewPIIScanner(&PIIConfig{
		Enabled:      true,
		ScanRequests: true,
		Action:       "redact",
	})

	largeInput := strings.Repeat("This is normal text without any personally identifiable information. ", 5000)
	blocked, _ := s.ScanRequest("test", largeInput)
	if blocked {
		t.Error("large clean input should not be blocked")
	}
}

// --- Secrets Scanner Edge Cases ---

func TestSecretsScanner_EmptyInput(t *testing.T) {
	s := NewSecretsScanner(&SecretsConfig{
		Enabled:      true,
		ScanRequests: true,
		Action:       "redact",
	})
	if s == nil {
		t.Fatal("scanner should not be nil")
	}

	blocked, _ := s.ScanRequest("test", "")
	if blocked {
		t.Error("empty input should not be blocked")
	}
}

func TestSecretsScanner_WhitespaceOnly(t *testing.T) {
	s := NewSecretsScanner(&SecretsConfig{
		Enabled:      true,
		ScanRequests: true,
		Action:       "redact",
	})

	blocked, _ := s.ScanRequest("test", "   \n\n\t  ")
	if blocked {
		t.Error("whitespace-only input should not be blocked")
	}
}

func TestSecretsScanner_LargeCleanInput(t *testing.T) {
	s := NewSecretsScanner(&SecretsConfig{
		Enabled:      true,
		ScanRequests: true,
		Action:       "redact",
	})

	largeInput := strings.Repeat("This is normal text without any secrets or API keys. ", 5000)
	blocked, _ := s.ScanRequest("test", largeInput)
	if blocked {
		t.Error("large clean input should not be blocked")
	}
}

// =============================================================================
// HIGH-9: Vuln scanner false-positive tests
// =============================================================================

func TestVulnScanner_FalsePositive_NaturalLanguageSQL(t *testing.T) {
	s := NewVulnScanner(&VulnScanConfig{
		Enabled: true,
		Rules:   []string{"sqli"},
	})

	// Natural language that contains SQL-like words but is NOT an attack
	falsePositives := []string{
		"Please select the items from the table and drop them in the basket",
		"The union of selected workers represents all departments",
		"I need to insert a new row in my spreadsheet",
		"Can you update the report or delete the old version",
		"Let me describe the table layout for the meeting room",
	}

	for _, input := range falsePositives {
		blocked, reason := s.Scan("chat", input)
		if blocked {
			t.Errorf("FALSE POSITIVE: natural language blocked as SQLi: %q (reason: %s)", input, reason)
		}
	}
}

func TestVulnScanner_FalsePositive_PathTraversal(t *testing.T) {
	s := NewVulnScanner(&VulnScanConfig{
		Enabled: true,
		Rules:   []string{"path_traversal"},
	})

	// Legitimate paths that should NOT trigger path traversal
	falsePositives := []string{
		"/home/user/documents/report.pdf",
		"/var/log/application.log",
		"C:\\Users\\john\\Desktop\\file.txt",
		"./src/main.go",
	}

	for _, input := range falsePositives {
		blocked, reason := s.Scan("file.read", input)
		if blocked {
			t.Errorf("FALSE POSITIVE: legitimate path blocked: %q (reason: %s)", input, reason)
		}
	}
}

func TestVulnScanner_FalsePositive_CommandInjection(t *testing.T) {
	s := NewVulnScanner(&VulnScanConfig{
		Enabled: true,
		Rules:   []string{"command_injection"},
	})

	// Natural language with shell-like characters
	falsePositives := []string{
		"The price is $100 and the quantity is 5",
		"Please check if (a > b) and update accordingly",
		"Use the pipe character | to separate values",
	}

	for _, input := range falsePositives {
		blocked, reason := s.Scan("chat", input)
		if blocked {
			t.Errorf("FALSE POSITIVE: natural language blocked as command injection: %q (reason: %s)", input, reason)
		}
	}
}
