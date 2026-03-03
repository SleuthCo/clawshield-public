package scanner

import (
	"strings"
	"testing"
)

func TestNewPIIScanner_Disabled(t *testing.T) {
	s := NewPIIScanner(nil)
	if s != nil {
		t.Error("expected nil scanner when config is nil")
	}

	s = NewPIIScanner(&PIIConfig{Enabled: false})
	if s != nil {
		t.Error("expected nil scanner when disabled")
	}
}

func TestNewPIIScanner_AllRules(t *testing.T) {
	s := NewPIIScanner(&PIIConfig{
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
	t.Logf("Total PII rules compiled: %d", s.RuleCount())
}

func TestNewPIIScanner_SelectiveRules(t *testing.T) {
	s := NewPIIScanner(&PIIConfig{
		Enabled:      true,
		ScanRequests: true,
		Rules:        []string{"email", "ssn"},
	})
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}

	allRules := NewPIIScanner(&PIIConfig{Enabled: true, ScanRequests: true})
	if s.RuleCount() >= allRules.RuleCount() {
		t.Errorf("selective rules (%d) should be fewer than all rules (%d)", s.RuleCount(), allRules.RuleCount())
	}
}

func TestPIIScanner_Email(t *testing.T) {
	s := NewPIIScanner(&PIIConfig{
		Enabled:      true,
		ScanRequests: true,
		Rules:        []string{"email"},
	})

	tests := []struct {
		name    string
		input   string
		blocked bool
	}{
		{"simple email", `contact: user@example.com`, true},
		{"email in JSON", `{"email": "john.doe@company.org"}`, true},
		{"email with plus", `notify: user+tag@gmail.com`, true},
		{"email with subdomain", `admin@mail.corp.example.com`, true},
		{"not an email", `this is just @ sign`, false},
		{"domain only", `visit example.com`, false},
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

func TestPIIScanner_PhoneNumbers(t *testing.T) {
	s := NewPIIScanner(&PIIConfig{
		Enabled:      true,
		ScanRequests: true,
		Rules:        []string{"phone"},
	})

	tests := []struct {
		name    string
		input   string
		blocked bool
	}{
		{"US phone formatted", `call: (555) 123-4567`, true},
		{"US phone with 1", `phone: +1-555-123-4567`, true},
		{"US phone dots", `tel: 555.123.4567`, true},
		{"international E.164", `phone: +442071234567`, true},
		{"too short", `code: 12345`, false},
		{"not a phone", `regular text here`, false},
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

func TestPIIScanner_SSN(t *testing.T) {
	s := NewPIIScanner(&PIIConfig{
		Enabled:      true,
		ScanRequests: true,
		Rules:        []string{"ssn"},
	})

	tests := []struct {
		name    string
		input   string
		blocked bool
	}{
		{"SSN formatted", `ssn: 123-45-6789`, true},
		{"SSN in text", `Social Security Number is 234-56-7890`, true},
		{"invalid SSN (000)", `ssn: 000-12-3456`, false},
		{"invalid SSN (666)", `ssn: 666-12-3456`, false},
		{"invalid SSN (9xx)", `ssn: 900-12-3456`, false},
		{"not SSN", `reference: ABC-DE-FGHI`, false},
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

func TestPIIScanner_CreditCards(t *testing.T) {
	s := NewPIIScanner(&PIIConfig{
		Enabled:      true,
		ScanRequests: true,
		Rules:        []string{"credit_card"},
	})

	tests := []struct {
		name    string
		input   string
		blocked bool
	}{
		// Using valid Luhn test numbers
		{"Visa test card", `card: 4111111111111111`, true},
		{"Visa with dashes", `card: 4111-1111-1111-1111`, true},
		{"Visa with spaces", `card: 4111 1111 1111 1111`, true},
		{"Mastercard test", `card: 5500000000000004`, true},
		{"Amex test", `card: 371449635398431`, true},
		{"Discover test", `card: 6011111111111117`, true},
		{"fails Luhn", `card: 4111111111111112`, false},
		{"not a card number", `order: 12345`, false},
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

func TestPIIScanner_IPAddress(t *testing.T) {
	s := NewPIIScanner(&PIIConfig{
		Enabled:       true,
		ScanRequests:  true,
		Rules:         []string{"ip_address"},
		MinConfidence: "low", // IP addresses are low confidence
	})

	tests := []struct {
		name    string
		input   string
		blocked bool
	}{
		{"public IP", `connected from 203.0.113.42`, true},
		{"another public IP", `server: 8.8.8.8`, true},
		{"private 10.x", `host: 10.0.0.1`, false},
		{"private 192.168", `host: 192.168.1.1`, false},
		{"private 172.16", `host: 172.16.0.1`, false},
		{"loopback", `host: 127.0.0.1`, false},
		{"not an IP", `version: 3.2.1`, false},
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

func TestPIIScanner_IPAddress_FilteredByConfidence(t *testing.T) {
	// With medium confidence (default), IPs should NOT be flagged
	s := NewPIIScanner(&PIIConfig{
		Enabled:       true,
		ScanRequests:  true,
		Rules:         []string{"ip_address"},
		MinConfidence: "medium",
	})

	blocked, _ := s.ScanRequest("chat.send", `connected from 203.0.113.42`)
	if blocked {
		t.Error("IP addresses should not trigger at medium confidence")
	}
}

func TestPIIScanner_DateOfBirth(t *testing.T) {
	s := NewPIIScanner(&PIIConfig{
		Enabled:      true,
		ScanRequests: true,
		Rules:        []string{"date_of_birth"},
	})

	tests := []struct {
		name    string
		input   string
		blocked bool
	}{
		{"DOB labeled", `DOB: 03/15/1990`, true},
		{"date of birth", `date of birth: 1990-03-15`, true},
		{"born on", `born: 12/25/1985`, true},
		{"just a date", `created: 2024-01-15`, false},
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

func TestPIIScanner_PostalAddress(t *testing.T) {
	s := NewPIIScanner(&PIIConfig{
		Enabled:      true,
		ScanRequests: true,
		Rules:        []string{"postal_address"},
	})

	tests := []struct {
		name    string
		input   string
		blocked bool
	}{
		{"street address", `lives at 123 Main Street`, true},
		{"avenue address", `office: 456 Park Avenue`, true},
		{"zip with context", `zip: 90210`, true},
		{"just a number", `count: 42`, false},
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

func TestPIIScanner_IBAN(t *testing.T) {
	s := NewPIIScanner(&PIIConfig{
		Enabled:      true,
		ScanRequests: true,
		Rules:        []string{"iban"},
	})

	tests := []struct {
		name    string
		input   string
		blocked bool
	}{
		{"German IBAN", `account: DE89 3704 0044 0532 0130 00`, true},
		{"UK IBAN", `IBAN: GB29 NWBK 6016 1331 9268 19`, true},
		{"too short", `code: DE89 3704`, false},
		{"not IBAN", `reference: 12345678901234`, false},
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

func TestPIIScanner_DriversLicense(t *testing.T) {
	s := NewPIIScanner(&PIIConfig{
		Enabled:      true,
		ScanRequests: true,
		Rules:        []string{"drivers_license"},
	})

	tests := []struct {
		name    string
		input   string
		blocked bool
	}{
		{"DL reference", `DL number: D1234567`, true},
		{"drivers license", `drivers license: AB123456789`, true},
		{"no context", `id: ABC123`, false},
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

func TestPIIScanner_ResponseScanning(t *testing.T) {
	s := NewPIIScanner(&PIIConfig{
		Enabled:       true,
		ScanRequests:  true,
		ScanResponses: true,
	})

	blocked, reason := s.ScanResponse("tools.invoke", `{"result": "Contact john.doe@example.com for details"}`)
	if !blocked {
		t.Errorf("expected email in response to be detected (reason: %s)", reason)
	}

	reqOnly := NewPIIScanner(&PIIConfig{
		Enabled:       true,
		ScanRequests:  true,
		ScanResponses: false,
	})
	blocked, _ = reqOnly.ScanResponse("tools.invoke", `john.doe@example.com`)
	if blocked {
		t.Error("should not scan responses when scan_responses is false")
	}
}

func TestPIIScanner_ExcludeTools(t *testing.T) {
	s := NewPIIScanner(&PIIConfig{
		Enabled:      true,
		ScanRequests: true,
		ExcludeTools: []string{"crm.lookup", "user.profile"},
	})

	blocked, _ := s.ScanRequest("crm.lookup", `email: user@example.com`)
	if blocked {
		t.Error("excluded tool should not be scanned")
	}

	blocked, _ = s.ScanRequest("chat.send", `email: user@example.com`)
	if !blocked {
		t.Error("non-excluded tool should be scanned")
	}
}

func TestPIIScanner_RedactPII(t *testing.T) {
	s := NewPIIScanner(&PIIConfig{
		Enabled:      true,
		ScanRequests: true,
	})

	input := `Contact user@example.com or call (555) 123-4567 for help`
	redacted, found := s.RedactPII(input)

	if len(found) == 0 {
		t.Error("expected PII to be found for redaction")
	}

	if redacted == input {
		t.Error("expected text to be modified after redaction")
	}

	if strings.Contains(redacted, "user@example.com") {
		t.Error("expected email to be redacted")
	}

	t.Logf("Redacted: %s", redacted)
	t.Logf("Found: %v", found)
}

func TestPIIScanner_NilSafety(t *testing.T) {
	var s *PIIScanner

	blocked, _ := s.ScanRequest("test", "user@example.com")
	if blocked {
		t.Error("nil scanner should not block")
	}

	blocked, _ = s.ScanResponse("test", "user@example.com")
	if blocked {
		t.Error("nil scanner should not block")
	}

	text, found := s.RedactPII("some text")
	if text != "some text" || found != nil {
		t.Error("nil scanner should return input unchanged")
	}

	if s.Action() != "redact" {
		t.Error("nil scanner action should default to redact")
	}

	if s.RuleCount() != 0 {
		t.Error("nil scanner should have 0 rules")
	}
}

func TestPIIScanner_MultiplePII(t *testing.T) {
	s := NewPIIScanner(&PIIConfig{
		Enabled:      true,
		ScanRequests: true,
	})

	input := `Name: John Doe, Email: john@example.com, SSN: 123-45-6789, Card: 4111111111111111`
	blocked, reason := s.ScanRequest("chat.send", input)
	if !blocked {
		t.Errorf("expected detection with multiple PII (reason: %s)", reason)
	}
}

// --- Validation function tests ---

func TestValidateLuhn(t *testing.T) {
	tests := []struct {
		number string
		valid  bool
	}{
		{"4111111111111111", true},  // Visa test
		{"5500000000000004", true},  // Mastercard test
		{"371449635398431", true},   // Amex test
		{"6011111111111117", true},  // Discover test
		{"4111111111111112", false}, // Invalid
		{"1234567890123456", false}, // Random
		{"123", false},              // Too short
	}

	for _, tt := range tests {
		t.Run(tt.number, func(t *testing.T) {
			if got := validateLuhn(tt.number); got != tt.valid {
				t.Errorf("validateLuhn(%s) = %v, want %v", tt.number, got, tt.valid)
			}
		})
	}
}

func TestValidateSSN(t *testing.T) {
	tests := []struct {
		ssn   string
		valid bool
	}{
		{"123-45-6789", true},
		{"234-56-7890", true},
		{"000-12-3456", false}, // Area 000
		{"666-12-3456", false}, // Area 666
		{"900-12-3456", false}, // Area 9xx
		{"123-00-6789", false}, // Group 00
		{"123-45-0000", false}, // Serial 0000
	}

	for _, tt := range tests {
		t.Run(tt.ssn, func(t *testing.T) {
			if got := validateSSN(tt.ssn); got != tt.valid {
				t.Errorf("validateSSN(%s) = %v, want %v", tt.ssn, got, tt.valid)
			}
		})
	}
}

func TestValidateIPv4NotPrivate(t *testing.T) {
	tests := []struct {
		ip    string
		valid bool
	}{
		{"8.8.8.8", true},       // Public (Google DNS)
		{"203.0.113.42", true},  // Public
		{"10.0.0.1", false},     // Private
		{"192.168.1.1", false},  // Private
		{"172.16.0.1", false},   // Private
		{"127.0.0.1", false},    // Loopback
		{"0.0.0.0", false},      // Zero
		{"255.255.255.255", false}, // Broadcast
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			if got := validateIPv4NotPrivate(tt.ip); got != tt.valid {
				t.Errorf("validateIPv4NotPrivate(%s) = %v, want %v", tt.ip, got, tt.valid)
			}
		})
	}
}

func TestPIIScanner_InternationalPhone(t *testing.T) {
	s := NewPIIScanner(&PIIConfig{
		Enabled:      true,
		ScanRequests: true,
		Rules:        []string{"phone"},
	})

	tests := []struct {
		name    string
		input   string
		blocked bool
	}{
		{"UK phone E.164", `Contact: +442071234567`, true},
		{"France phone E.164", `phone: +33123456789`, true},
		{"Germany phone context", `tel: +49301234567`, true},
		{"Phone with spaces", `phone: +44 20 7123 4567`, true},
		{"Short invalid", `+1234`, false},
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

func TestPIIScanner_InternationalPassport(t *testing.T) {
	s := NewPIIScanner(&PIIConfig{
		Enabled:      true,
		ScanRequests: true,
		Rules:        []string{"passport"},
	})

	tests := []struct {
		name    string
		input   string
		blocked bool
	}{
		{"International passport", `passport number: AB1234567`, true},
		{"Single letter passport", `passport: A12345678`, true},
		{"Passport label context", `travel doc number: CD1234567`, true},
		{"Too short", `passport: A123`, false},
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
