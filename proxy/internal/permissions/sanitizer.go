package permissions

import (
	"fmt"
	"regexp"
	"strings"
)

// SanitizeResult is the result of response sanitization.
type SanitizeResult struct {
	Clean   bool
	Blocked bool
	Reason  string
}

// Sanitizer validates agent responses for prompt injection and cross-action attacks.
type Sanitizer struct {
	maxResponseLength   int
	injectionPatterns   []compiledPattern
	crossActionPatterns []compiledPattern
}

// newSanitizer compiles all sanitizer patterns.
func newSanitizer(cfg *SanitizerConfig) (*Sanitizer, error) {
	s := &Sanitizer{
		maxResponseLength: cfg.MaxResponseLength,
	}
	if s.maxResponseLength <= 0 {
		s.maxResponseLength = 8192
	}

	for _, rule := range cfg.InjectionPatterns {
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid injection regex %q (%s): %w", rule.Pattern, rule.Label, err)
		}
		s.injectionPatterns = append(s.injectionPatterns, compiledPattern{re: re, label: rule.Label})
	}

	for _, rule := range cfg.CrossActionPatterns {
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid cross-action regex %q (%s): %w", rule.Pattern, rule.Label, err)
		}
		s.crossActionPatterns = append(s.crossActionPatterns, compiledPattern{re: re, label: rule.Label})
	}

	return s, nil
}

// Sanitize checks a response for injection attacks and cross-action references.
// agentPlatforms is the list of platforms the agent has access to — references
// to platforms outside this list are flagged.
func (s *Sanitizer) Sanitize(content string, agentPlatforms []string) SanitizeResult {
	// Length check
	if len(content) > s.maxResponseLength {
		return SanitizeResult{
			Clean:   false,
			Blocked: true,
			Reason:  fmt.Sprintf("response exceeds max length (%d > %d)", len(content), s.maxResponseLength),
		}
	}

	// Injection pattern check
	for _, pat := range s.injectionPatterns {
		if pat.re.MatchString(content) {
			return SanitizeResult{
				Clean:   false,
				Blocked: true,
				Reason:  fmt.Sprintf("injection detected: %s", pat.label),
			}
		}
	}

	// Cross-action pattern check
	for _, pat := range s.crossActionPatterns {
		if pat.re.MatchString(content) {
			return SanitizeResult{
				Clean:   false,
				Blocked: true,
				Reason:  fmt.Sprintf("cross-action detected: %s", pat.label),
			}
		}
	}

	// Scope-aware check: flag references to platforms outside the agent's scope
	if len(agentPlatforms) > 0 {
		allowed := make(map[string]bool, len(agentPlatforms))
		for _, p := range agentPlatforms {
			allowed[strings.ToLower(p)] = true
		}

		lower := strings.ToLower(content)
		for _, platform := range AllPlatforms {
			if allowed[platform] {
				continue
			}
			// Check for action-like references to this platform
			actionSuffixes := []string{"-send", "-create", "-delete", "-update", "-search", "-list", "-get"}
			for _, suffix := range actionSuffixes {
				if strings.Contains(lower, platform+suffix) {
					return SanitizeResult{
						Clean:   false,
						Blocked: true,
						Reason:  fmt.Sprintf("cross-scope: response references %s platform (agent lacks access)", platform),
					}
				}
			}
			// Check for directive patterns
			directives := []string{"use " + platform, "invoke " + platform, "call " + platform}
			for _, d := range directives {
				if strings.Contains(lower, d) {
					return SanitizeResult{
						Clean:   false,
						Blocked: true,
						Reason:  fmt.Sprintf("cross-scope: response directs use of %s platform (agent lacks access)", platform),
					}
				}
			}
		}
	}

	return SanitizeResult{Clean: true}
}
