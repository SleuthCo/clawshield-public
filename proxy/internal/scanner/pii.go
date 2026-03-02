// Package scanner provides security scanning for MCP tool call arguments and responses.
//
// pii.go implements value-based Personally Identifiable Information (PII) detection.
// Unlike key-name-based redaction (hashlined/hash.go), this scanner detects PII by
// format patterns — email addresses, phone numbers, SSNs, credit card numbers, etc. —
// regardless of which JSON field they appear in.
package scanner

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// PIIConfig holds the policy configuration for PII scanning.
type PIIConfig struct {
	Enabled       bool     `yaml:"enabled"`
	ScanRequests  bool     `yaml:"scan_requests"`
	ScanResponses bool     `yaml:"scan_responses"`
	Action        string   `yaml:"action"`         // "block" or "redact" (default: "redact")
	Rules         []string `yaml:"rules"`           // Which PII categories to detect (empty = all)
	ExcludeTools  []string `yaml:"exclude_tools"`   // Tools exempt from PII scanning
	MinConfidence string   `yaml:"min_confidence"`  // "low", "medium", "high" (default: "medium")
}

// PIICategory groups PII detection rules by type.
type PIICategory string

const (
	PIICategoryEmail      PIICategory = "email"
	PIICategoryPhone      PIICategory = "phone"
	PIICategorySSN        PIICategory = "ssn"
	PIICategoryCreditCard PIICategory = "credit_card"
	PIICategoryIPAddress  PIICategory = "ip_address"
	PIICategoryPassport   PIICategory = "passport"
	PIICategoryDOB        PIICategory = "date_of_birth"
	PIICategoryAddress    PIICategory = "postal_address"
	PIICategoryIBAN       PIICategory = "iban"
	PIICategoryDL         PIICategory = "drivers_license"
)

// piiConfidence represents the confidence level of a PII detection.
type piiConfidence int

const (
	confidenceLow    piiConfidence = 1
	confidenceMedium piiConfidence = 2
	confidenceHigh   piiConfidence = 3
)

// piiRule defines a single PII detection pattern with metadata.
type piiRule struct {
	name        string
	category    PIICategory
	pattern     *regexp.Regexp
	description string
	confidence  piiConfidence
	validate    func(match string) bool // Optional post-match validation (e.g., Luhn check)
}

// PIIScanner detects personally identifiable information in text by matching value patterns.
type PIIScanner struct {
	scanRequests  bool
	scanResponses bool
	action        string // "block" or "redact"
	excludeTools  map[string]bool
	minConfidence piiConfidence
	rules         []piiRule
}

// NewPIIScanner creates a PIIScanner from policy configuration.
func NewPIIScanner(cfg *PIIConfig) *PIIScanner {
	if cfg == nil || !cfg.Enabled {
		return nil
	}

	s := &PIIScanner{
		scanRequests:  cfg.ScanRequests,
		scanResponses: cfg.ScanResponses,
		action:        cfg.Action,
		excludeTools:  make(map[string]bool),
		minConfidence: confidenceMedium,
	}

	if s.action == "" {
		s.action = "redact" // PII defaults to redact (less disruptive than block)
	}

	switch cfg.MinConfidence {
	case "low":
		s.minConfidence = confidenceLow
	case "high":
		s.minConfidence = confidenceHigh
	default:
		s.minConfidence = confidenceMedium
	}

	for _, t := range cfg.ExcludeTools {
		s.excludeTools[t] = true
	}

	// Determine which categories to enable
	enabledCategories := make(map[PIICategory]bool)
	if len(cfg.Rules) == 0 {
		for _, cat := range allPIICategories() {
			enabledCategories[cat] = true
		}
	} else {
		for _, r := range cfg.Rules {
			enabledCategories[PIICategory(r)] = true
		}
	}

	s.compileRules(enabledCategories)
	return s
}

// ScanRequest checks outbound tool arguments for PII.
func (s *PIIScanner) ScanRequest(method string, decodedParams string) (bool, string) {
	if s == nil || !s.scanRequests {
		return false, ""
	}
	if s.excludeTools[method] {
		return false, ""
	}
	return s.scan(decodedParams)
}

// ScanResponse checks inbound tool responses for PII.
func (s *PIIScanner) ScanResponse(method string, responseBody string) (bool, string) {
	if s == nil || !s.scanResponses {
		return false, ""
	}
	if s.excludeTools[method] {
		return false, ""
	}
	return s.scan(responseBody)
}

// Action returns the configured action ("block" or "redact").
func (s *PIIScanner) Action() string {
	if s == nil {
		return "redact"
	}
	return s.action
}

// RuleCount returns the number of active detection rules.
func (s *PIIScanner) RuleCount() int {
	if s == nil {
		return 0
	}
	return len(s.rules)
}

// RedactPII replaces detected PII in text with category-specific placeholders.
// Returns the redacted text and a list of what was redacted.
func (s *PIIScanner) RedactPII(text string) (string, []string) {
	if s == nil {
		return text, nil
	}

	var redacted []string
	result := text

	for _, rule := range s.rules {
		matches := rule.pattern.FindAllString(result, -1)
		for _, match := range matches {
			if rule.validate != nil && !rule.validate(match) {
				continue
			}
			if !containsPIIRedacted(redacted, rule.name) {
				redacted = append(redacted, rule.name)
			}
			placeholder := fmt.Sprintf("[%s_REDACTED]", strings.ToUpper(string(rule.category)))
			result = strings.Replace(result, match, placeholder, 1)
		}
	}

	return result, redacted
}

func (s *PIIScanner) scan(text string) (bool, string) {
	for _, rule := range s.rules {
		if rule.confidence < s.minConfidence {
			continue
		}
		matches := rule.pattern.FindAllString(text, 1)
		if len(matches) > 0 {
			match := matches[0]
			if rule.validate != nil && !rule.validate(match) {
				continue
			}
			return true, fmt.Sprintf("pii_scan: %s detected (%s)", rule.name, rule.description)
		}
	}
	return false, ""
}

func allPIICategories() []PIICategory {
	return []PIICategory{
		PIICategoryEmail,
		PIICategoryPhone,
		PIICategorySSN,
		PIICategoryCreditCard,
		PIICategoryIPAddress,
		PIICategoryPassport,
		PIICategoryDOB,
		PIICategoryAddress,
		PIICategoryIBAN,
		PIICategoryDL,
	}
}

func (s *PIIScanner) compileRules(enabled map[PIICategory]bool) {
	type ruleDef struct {
		name        string
		category    PIICategory
		pattern     string
		description string
		confidence  piiConfidence
		validate    func(string) bool
	}

	builtins := []ruleDef{
		// --- Email ---
		{
			name:        "Email Address",
			category:    PIICategoryEmail,
			pattern:     `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
			description: "email address",
			confidence:  confidenceHigh,
		},

		// --- Phone Numbers ---
		{
			name:        "US Phone Number",
			category:    PIICategoryPhone,
			pattern:     `(?:^|[^0-9])(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?:[^0-9]|$)`,
			description: "US phone number",
			confidence:  confidenceMedium,
		},
		{
			name:        "International Phone Number",
			category:    PIICategoryPhone,
			pattern:     `\+[1-9]\d{6,14}`,
			description: "international phone number (E.164)",
			confidence:  confidenceMedium,
		},

		// --- Social Security Numbers ---
		{
			name:        "US Social Security Number",
			category:    PIICategorySSN,
			pattern:     `(?:^|[^0-9])(?:0[1-9]|[1-5]\d|6[0-5]\d|66[0-5]|66[7-9]|6[7-8]\d|690|7[0-2]\d|73[0-3]|750|76[4-9]|77[0-2])[-\s]?(?:0[1-9]|[1-9]\d)[-\s]?(?:000[1-9]|00[1-9]\d|0[1-9]\d{2}|[1-9]\d{3})(?:[^0-9]|$)`,
			description: "US Social Security Number (XXX-XX-XXXX)",
			confidence:  confidenceHigh,
			validate:    validateSSN,
		},
		{
			name:        "US SSN (formatted)",
			category:    PIICategorySSN,
			pattern:     `\b\d{3}-\d{2}-\d{4}\b`,
			description: "US SSN in XXX-XX-XXXX format",
			confidence:  confidenceHigh,
			validate:    validateSSN,
		},

		// --- Credit Card Numbers ---
		{
			name:        "Visa Card Number",
			category:    PIICategoryCreditCard,
			pattern:     `\b4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`,
			description: "Visa card number",
			confidence:  confidenceHigh,
			validate:    validateLuhn,
		},
		{
			name:        "Mastercard Number",
			category:    PIICategoryCreditCard,
			pattern:     `\b5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`,
			description: "Mastercard number",
			confidence:  confidenceHigh,
			validate:    validateLuhn,
		},
		{
			name:        "Amex Card Number",
			category:    PIICategoryCreditCard,
			pattern:     `\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b`,
			description: "American Express card number",
			confidence:  confidenceHigh,
			validate:    validateLuhn,
		},
		{
			name:        "Discover Card Number",
			category:    PIICategoryCreditCard,
			pattern:     `\b6(?:011|5\d{2})[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`,
			description: "Discover card number",
			confidence:  confidenceHigh,
			validate:    validateLuhn,
		},

		// --- IP Addresses ---
		{
			name:        "IPv4 Address",
			category:    PIICategoryIPAddress,
			pattern:     `\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`,
			description: "IPv4 address",
			confidence:  confidenceLow, // IPs are very common in technical contexts
			validate:    validateIPv4NotPrivate,
		},

		// --- Passport Numbers ---
		{
			name:        "US Passport Number",
			category:    PIICategoryPassport,
			pattern:     `(?i)(?:passport|travel\s*doc(?:ument)?)\s*(?:no|number|#|num)?\s*[:=]?\s*[A-Z]?\d{8,9}\b`,
			description: "US passport number",
			confidence:  confidenceMedium,
		},

		// --- Date of Birth ---
		{
			name:        "Date of Birth",
			category:    PIICategoryDOB,
			pattern:     `(?i)(?:dob|date\s*of\s*birth|birth\s*date|born)\s*[:=]?\s*(?:\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}|\d{4}[/\-\.]\d{1,2}[/\-\.]\d{1,2})`,
			description: "date of birth",
			confidence:  confidenceHigh,
		},

		// --- Postal Addresses ---
		{
			name:        "US ZIP Code with Context",
			category:    PIICategoryAddress,
			pattern:     `(?i)(?:zip|postal|address)\s*[:=]?\s*\d{5}(?:-\d{4})?`,
			description: "US ZIP code with address context",
			confidence:  confidenceMedium,
		},
		{
			name:        "US Street Address",
			category:    PIICategoryAddress,
			pattern:     `\b\d{1,5}\s+(?:[A-Z][a-z]+\s+){1,3}(?:St(?:reet)?|Ave(?:nue)?|Blvd|Boulevard|Dr(?:ive)?|Ln|Lane|Rd|Road|Ct|Court|Pl(?:ace)?|Way|Cir(?:cle)?)\b`,
			description: "US street address",
			confidence:  confidenceMedium,
		},

		// --- IBAN ---
		{
			name:        "IBAN Number",
			category:    PIICategoryIBAN,
			pattern:     `\b[A-Z]{2}\d{2}\s?(?:[A-Z0-9]{4}\s?){3,7}[A-Z0-9]{1,4}\b`,
			description: "International Bank Account Number (IBAN)",
			confidence:  confidenceHigh,
			validate:    validateIBAN,
		},

		// --- Driver's License ---
		{
			name:        "Driver's License Reference",
			category:    PIICategoryDL,
			pattern:     `(?i)(?:driver'?s?\s*lic(?:ense|ence)?|DL)\s*(?:no|number|#|num)?\s*[:=]\s*[A-Z0-9]{5,15}`,
			description: "driver's license number reference",
			confidence:  confidenceMedium,
		},
	}

	for _, def := range builtins {
		if !enabled[def.category] {
			continue
		}
		re, err := regexp.Compile(def.pattern)
		if err != nil {
			continue
		}
		s.rules = append(s.rules, piiRule{
			name:        def.name,
			category:    def.category,
			pattern:     re,
			description: def.description,
			confidence:  def.confidence,
			validate:    def.validate,
		})
	}
}

// --- Validation Functions ---

// validateLuhn performs the Luhn algorithm check on a credit card number.
func validateLuhn(s string) bool {
	// Strip non-digit characters
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, s)

	if len(digits) < 13 || len(digits) > 19 {
		return false
	}

	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		d, _ := strconv.Atoi(string(digits[i]))
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}

	return sum%10 == 0
}

// validateSSN checks that a matched SSN is not an obviously invalid pattern.
func validateSSN(s string) bool {
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, s)

	if len(digits) != 9 {
		return false
	}

	// SSN cannot start with 000, 666, or 9xx
	area := digits[:3]
	if area == "000" || area == "666" || area[0] == '9' {
		return false
	}

	// Group cannot be 00
	if digits[3:5] == "00" {
		return false
	}

	// Serial cannot be 0000
	if digits[5:] == "0000" {
		return false
	}

	return true
}

// validateIPv4NotPrivate rejects private/reserved IP ranges to reduce false positives.
func validateIPv4NotPrivate(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}

	first, err := strconv.Atoi(parts[0])
	if err != nil {
		return false
	}
	second, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}

	// Skip private ranges (10.x, 172.16-31.x, 192.168.x) and loopback (127.x)
	if first == 10 || first == 127 {
		return false
	}
	if first == 172 && second >= 16 && second <= 31 {
		return false
	}
	if first == 192 && second == 168 {
		return false
	}
	// Skip 0.x.x.x and 255.x.x.x
	if first == 0 || first == 255 {
		return false
	}

	return true
}

// validateIBAN performs basic IBAN length validation by country code.
func validateIBAN(s string) bool {
	// Strip spaces
	clean := strings.ReplaceAll(s, " ", "")
	if len(clean) < 15 || len(clean) > 34 {
		return false
	}
	// First 2 chars must be letters, next 2 must be digits
	if len(clean) < 4 {
		return false
	}
	for _, c := range clean[:2] {
		if c < 'A' || c > 'Z' {
			return false
		}
	}
	for _, c := range clean[2:4] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func containsPIIRedacted(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
