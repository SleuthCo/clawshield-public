package permissions

import (
	"fmt"
	"regexp"
	"strings"
)

// DLPResult is the result of DLP scrubbing.
type DLPResult struct {
	Allowed           bool
	ScrubbedMessage   string
	Redactions        []Redaction
	AllowlistBypasses []string
	Mode              string
}

// Redaction records a single DLP replacement.
type Redaction struct {
	Label       string
	Original    string
	Replacement string
}

// DLP performs bridge data loss prevention scrubbing.
type DLP struct {
	mode              string
	patterns          []dlpCompiledPattern
	corporateEmailRe  *regexp.Regexp
	allowlistPhrases  []string
}

type dlpCompiledPattern struct {
	re          *regexp.Regexp
	label       string
	replacement string
}

// newDLP compiles all DLP patterns.
func newDLP(cfg *DLPConfig) (*DLP, error) {
	d := &DLP{
		mode:             strings.ToUpper(cfg.Mode),
		allowlistPhrases: cfg.AllowlistPhrases,
	}

	if d.mode == "" {
		d.mode = DLPRedact
	}

	// Compile builtin patterns
	for _, pat := range cfg.BuiltinPatterns {
		re, err := regexp.Compile(pat.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid DLP builtin regex %q (%s): %w", pat.Pattern, pat.Label, err)
		}
		d.patterns = append(d.patterns, dlpCompiledPattern{
			re:          re,
			label:       pat.Label,
			replacement: pat.Replacement,
		})
	}

	// Compile custom patterns
	for _, pat := range cfg.CustomPatterns {
		re, err := regexp.Compile(pat.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid DLP custom regex %q (%s): %w", pat.Pattern, pat.Label, err)
		}
		repl := pat.Replacement
		if repl == "" {
			repl = "[REDACTED]"
		}
		d.patterns = append(d.patterns, dlpCompiledPattern{
			re:          re,
			label:       pat.Label,
			replacement: repl,
		})
	}

	// Compile corporate email domain pattern
	if len(cfg.CorporateEmailDomains) > 0 {
		escaped := make([]string, len(cfg.CorporateEmailDomains))
		for i, domain := range cfg.CorporateEmailDomains {
			escaped[i] = regexp.QuoteMeta(domain)
		}
		pattern := `[a-zA-Z0-9._%+\-]+@(?:` + strings.Join(escaped, "|") + `)`
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid corporate email domain pattern: %w", err)
		}
		d.corporateEmailRe = re
	}

	return d, nil
}

// Scrub applies DLP rules to a message based on the configured mode.
func (d *DLP) Scrub(text string) DLPResult {
	result := DLPResult{
		Allowed: true,
		Mode:    d.mode,
	}

	if d.mode == DLPOff {
		result.ScrubbedMessage = text
		return result
	}

	scrubbed := text

	// Check each pattern
	for _, pat := range d.patterns {
		matches := pat.re.FindAllString(scrubbed, -1)
		if len(matches) == 0 {
			continue
		}

		for _, match := range matches {
			// Check allowlist before redacting
			if d.isAllowlisted(match) {
				result.AllowlistBypasses = append(result.AllowlistBypasses, match)
				continue
			}

			if d.mode == DLPBlock {
				result.Allowed = false
				result.ScrubbedMessage = text
				result.Redactions = append(result.Redactions, Redaction{
					Label:    pat.label,
					Original: match,
				})
				return result
			}

			// REDACT mode
			result.Redactions = append(result.Redactions, Redaction{
				Label:       pat.label,
				Original:    match,
				Replacement: pat.replacement,
			})
		}

		if d.mode == DLPRedact {
			scrubbed = pat.re.ReplaceAllStringFunc(scrubbed, func(m string) string {
				if d.isAllowlisted(m) {
					return m
				}
				return pat.replacement
			})
		}
	}

	// Corporate email domains
	if d.corporateEmailRe != nil {
		corpMatches := d.corporateEmailRe.FindAllString(scrubbed, -1)
		for _, match := range corpMatches {
			if d.isAllowlisted(match) {
				result.AllowlistBypasses = append(result.AllowlistBypasses, match)
				continue
			}

			if d.mode == DLPBlock {
				result.Allowed = false
				result.ScrubbedMessage = text
				result.Redactions = append(result.Redactions, Redaction{
					Label:    "corporate email",
					Original: match,
				})
				return result
			}

			result.Redactions = append(result.Redactions, Redaction{
				Label:       "corporate email",
				Original:    match,
				Replacement: "[CORP-EMAIL]",
			})
		}

		if d.mode == DLPRedact && d.corporateEmailRe != nil {
			scrubbed = d.corporateEmailRe.ReplaceAllStringFunc(scrubbed, func(m string) string {
				if d.isAllowlisted(m) {
					return m
				}
				return "[CORP-EMAIL]"
			})
		}
	}

	result.ScrubbedMessage = scrubbed
	return result
}

// isAllowlisted checks if a match contains any allowlisted phrase.
func (d *DLP) isAllowlisted(text string) bool {
	lower := strings.ToLower(text)
	for _, phrase := range d.allowlistPhrases {
		if strings.Contains(lower, strings.ToLower(phrase)) {
			return true
		}
	}
	return false
}

// Mode returns the current DLP mode.
func (d *DLP) Mode() string {
	return d.mode
}
