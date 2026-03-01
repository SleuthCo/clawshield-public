package scanner

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode"
)

// InjectionSensitivity controls heuristic thresholds.
type InjectionSensitivity string

const (
	SensitivityLow    InjectionSensitivity = "low"
	SensitivityMedium InjectionSensitivity = "medium"
	SensitivityHigh   InjectionSensitivity = "high"
)

// PromptInjectionConfig holds the policy configuration for prompt injection detection.
type PromptInjectionConfig struct {
	Enabled              bool     `yaml:"enabled"`
	ScanRequests         bool     `yaml:"scan_requests"`
	ScanResponses        bool     `yaml:"scan_responses"`
	CanaryTokens         bool     `yaml:"canary_tokens"`
	Sensitivity          string   `yaml:"sensitivity"`
	TrustedResponseTools []string `yaml:"trusted_response_tools"`
}

// InjectionDetector detects prompt injection attacks in both directions.
type InjectionDetector struct {
	scanRequests         bool
	scanResponses        bool
	canaryTokens         bool
	sensitivity          InjectionSensitivity
	trustedResponseTools map[string]bool

	// Tier 1: heuristic regex patterns
	roleOverridePatterns []*regexp.Regexp
	instructionPatterns  []*regexp.Regexp
	encodingPatterns     []*regexp.Regexp
	delimiterPatterns    []*regexp.Regexp

	// Tier 3: canary token state
	activeCanary string
}

// NewInjectionDetector creates an InjectionDetector from policy configuration.
func NewInjectionDetector(cfg *PromptInjectionConfig) *InjectionDetector {
	if cfg == nil || !cfg.Enabled {
		return nil
	}

	d := &InjectionDetector{
		scanRequests:         cfg.ScanRequests,
		scanResponses:        cfg.ScanResponses,
		canaryTokens:         cfg.CanaryTokens,
		trustedResponseTools: make(map[string]bool),
	}

	switch cfg.Sensitivity {
	case "low":
		d.sensitivity = SensitivityLow
	case "high":
		d.sensitivity = SensitivityHigh
	default:
		d.sensitivity = SensitivityMedium
	}

	for _, t := range cfg.TrustedResponseTools {
		d.trustedResponseTools[t] = true
	}

	d.compilePatterns()

	if d.canaryTokens {
		d.activeCanary = generateCanary()
	}

	return d
}

// ScanRequest checks outbound tool arguments for prompt injection attempts.
func (d *InjectionDetector) ScanRequest(method string, params string) (bool, string) {
	if d == nil || !d.scanRequests {
		return false, ""
	}

	lower := strings.ToLower(params)

	// Tier 1: heuristic patterns
	if blocked, reason := d.checkHeuristicPatterns(lower); blocked {
		return true, reason
	}

	// Tier 2: structural analysis (medium/high sensitivity only)
	if d.sensitivity != SensitivityLow {
		if blocked, reason := d.checkStructuralRequest(params); blocked {
			return true, reason
		}
	}

	return false, ""
}

// ScanResponse checks inbound tool responses for prompt injection attempts.
// The method parameter identifies which tool produced the response (for trusted tool bypass).
func (d *InjectionDetector) ScanResponse(method string, responseBody string) (bool, string) {
	if d == nil || !d.scanResponses {
		return false, ""
	}

	if d.trustedResponseTools[method] {
		return false, ""
	}

	lower := strings.ToLower(responseBody)

	// Tier 1: heuristic patterns
	if blocked, reason := d.checkHeuristicPatterns(lower); blocked {
		return true, fmt.Sprintf("prompt_injection_response: %s", reason)
	}

	// Tier 2: structural analysis
	if d.sensitivity != SensitivityLow {
		if blocked, reason := d.checkStructuralResponse(responseBody); blocked {
			return true, reason
		}
	}

	// Tier 3: canary token leak detection
	if d.canaryTokens && d.activeCanary != "" {
		if strings.Contains(responseBody, d.activeCanary) {
			return true, "prompt_injection_response: canary token leaked — cross-tool data exfiltration detected"
		}
	}

	return false, ""
}

// GetCanaryToken returns the current canary token for injection into tool call params.
// Returns empty string if canary tokens are disabled.
func (d *InjectionDetector) GetCanaryToken() string {
	if d == nil || !d.canaryTokens {
		return ""
	}
	return d.activeCanary
}

// --- Tier 1: Heuristic Pattern Matching ---

func (d *InjectionDetector) compilePatterns() {
	// Role override patterns
	rolePatterns := []string{
		`(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|directions?)`,
		`(?i)you\s+are\s+now\s+(a|an|the)\b`,
		`(?i)system\s*:\s*you\s+are`,
		`(?i)<\|im_start\|>\s*system`,
		`(?i)\[system\]\s*#`,
		`(?i)new\s+role\s*:\s`,
		`(?i)forget\s+(everything|all|your)\s+(you|instructions?|rules?)`,
		`(?i)override\s+(your|system|all)\s+\w*\s*(instructions?|rules?|prompts?)`,
	}
	d.roleOverridePatterns = compilePatterns(rolePatterns)

	// Instruction injection patterns
	instrPatterns := []string{
		`(?i)do\s+not\s+follow\s+(the|your|any)\s+(previous|original|above)`,
		`(?i)disregard\s+(all|any|the|previous|your)\s+\w*\s*(instructions?|rules?|prompts?)`,
		`(?i)instead\s*,?\s*(you\s+)?(should|must|will|shall)\s`,
		`(?i)new\s+instructions?\s*:\s`,
		`(?i)actual\s+instructions?\s*:\s`,
		`(?i)real\s+instructions?\s*:\s`,
		`(?i)secret\s+instructions?\s*:\s`,
		`(?i)hidden\s+instructions?\s*:\s`,
	}
	d.instructionPatterns = compilePatterns(instrPatterns)

	// Encoding attack patterns
	encPatterns := []string{
		// Zero-width characters (U+200B, U+200C, U+200D, U+FEFF)
		`[\x{200B}\x{200C}\x{200D}\x{FEFF}]`,
		// Unicode tag characters (U+E0000-U+E007F)
		`[\x{E0001}-\x{E007F}]`,
	}
	d.encodingPatterns = compilePatterns(encPatterns)

	// Delimiter injection patterns
	delimPatterns := []string{
		// Fake tool output boundaries
		"(?i)```\\s*(tool_output|tool_result|function_result|assistant|system)",
		// Fake JSON-RPC response framing
		`(?i)\{"jsonrpc"\s*:\s*"2\.0"\s*,\s*"result"`,
		// Fake end-of-response markers
		`(?i)(END_TOOL_OUTPUT|END_FUNCTION_CALL|<\/tool_response>|<\/function_output>)`,
		// M4: Rovo cross-action attack patterns — agent response tries to invoke other actions
		`(?i)use\s+the\s+[\w-]+\s+action`,
		`(?i)(create|delete|send|post)\s+(a\s+)?(jira|confluence|slack|github)\s+(issue|page|message)`,
	}
	d.delimiterPatterns = compilePatterns(delimPatterns)
}

func (d *InjectionDetector) checkHeuristicPatterns(lower string) (bool, string) {
	for _, re := range d.roleOverridePatterns {
		if re.MatchString(lower) {
			return true, fmt.Sprintf("prompt_injection: role override attempt detected (pattern: %s)", re.String())
		}
	}

	for _, re := range d.instructionPatterns {
		if re.MatchString(lower) {
			return true, fmt.Sprintf("prompt_injection: instruction injection detected (pattern: %s)", re.String())
		}
	}

	for _, re := range d.encodingPatterns {
		if re.MatchString(lower) {
			return true, fmt.Sprintf("prompt_injection: encoding attack detected (pattern: %s)", re.String())
		}
	}

	for _, re := range d.delimiterPatterns {
		if re.MatchString(lower) {
			return true, fmt.Sprintf("prompt_injection: delimiter injection detected (pattern: %s)", re.String())
		}
	}

	return false, ""
}

// --- Tier 2: Structural Analysis ---

func (d *InjectionDetector) checkStructuralRequest(params string) (bool, string) {
	// Check for base64-encoded instruction blocks
	if d.sensitivity == SensitivityHigh {
		if blocked, reason := checkBase64Instructions(params); blocked {
			return true, reason
		}
	}

	// Check for high imperative verb density (medium + high)
	if isHighImperativeDensity(params) {
		return true, "prompt_injection: high imperative instruction density in tool arguments"
	}

	return false, ""
}

func (d *InjectionDetector) checkStructuralResponse(response string) (bool, string) {
	// Check for base64-encoded instruction blocks
	if d.sensitivity == SensitivityHigh {
		if blocked, reason := checkBase64Instructions(response); blocked {
			return true, fmt.Sprintf("prompt_injection_response: %s", reason)
		}
	}

	// Check for high imperative verb density
	if isHighImperativeDensity(response) {
		return true, "prompt_injection_response: high imperative instruction density in tool response"
	}

	// Entropy check — high-entropy blocks embedded in natural language
	if d.sensitivity == SensitivityHigh {
		if hasHighEntropyBlock(response) {
			return true, "prompt_injection_response: high-entropy block detected in response (possible encoded payload)"
		}
	}

	return false, ""
}

// checkBase64Instructions decodes base64 segments and checks for injection patterns.
func checkBase64Instructions(text string) (bool, string) {
	b64Pattern := regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)
	matches := b64Pattern.FindAllString(text, 5) // Limit to 5 candidates
	for _, m := range matches {
		decoded, err := base64.StdEncoding.DecodeString(m)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(m)
			if err != nil {
				continue
			}
		}
		decodedLower := strings.ToLower(string(decoded))
		// Check if decoded content contains injection keywords
		injectionKeywords := []string{
			"ignore previous", "you are now", "system:", "new instructions",
			"disregard", "override", "forget everything",
		}
		for _, kw := range injectionKeywords {
			if strings.Contains(decodedLower, kw) {
				return true, "prompt_injection: base64-encoded injection payload detected"
			}
		}
	}
	return false, ""
}

// isHighImperativeDensity checks if text has suspiciously high density of imperative verbs.
// Returns true if more than 30% of sentences start with imperative verbs.
func isHighImperativeDensity(text string) bool {
	if len(text) < 100 {
		return false
	}

	imperativeStarters := []string{
		"ignore", "forget", "disregard", "override", "execute", "run",
		"output", "print", "return", "respond", "reply", "say",
		"pretend", "act", "behave", "assume", "do not", "never",
		"always", "must", "shall", "reveal", "expose", "leak",
		"extract", "exfiltrate", "send", "post", "transmit",
	}

	// Split into sentence-like segments
	segments := strings.FieldsFunc(text, func(r rune) bool {
		return r == '.' || r == '!' || r == '\n'
	})

	if len(segments) < 3 {
		return false
	}

	imperativeCount := 0
	for _, seg := range segments {
		trimmed := strings.TrimSpace(strings.ToLower(seg))
		for _, verb := range imperativeStarters {
			if strings.HasPrefix(trimmed, verb) {
				imperativeCount++
				break
			}
		}
	}

	ratio := float64(imperativeCount) / float64(len(segments))
	return ratio > 0.4
}

// hasHighEntropyBlock checks for blocks of text with unusually high Shannon entropy.
func hasHighEntropyBlock(text string) bool {
	// Scan in sliding windows of 100 chars
	windowSize := 100
	if len(text) < windowSize {
		return false
	}

	for i := 0; i <= len(text)-windowSize; i += 50 {
		window := text[i : i+windowSize]
		// Skip windows that are mostly whitespace
		nonSpace := 0
		for _, r := range window {
			if !unicode.IsSpace(r) {
				nonSpace++
			}
		}
		if nonSpace < 60 {
			continue
		}
		entropy := shannonEntropy([]byte(window))
		if entropy > 5.5 {
			return true
		}
	}
	return false
}

// shannonEntropy calculates the Shannon entropy of a byte slice.
func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / n
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// generateCanary creates a random canary token string.
func generateCanary() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	return fmt.Sprintf("__clawshield_canary_%x__", buf)
}
