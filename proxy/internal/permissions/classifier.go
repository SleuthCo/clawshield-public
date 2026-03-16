package permissions

import (
	"fmt"
	"regexp"
	"strings"
)

// ClassificationResult is the result of classifying a message.
type ClassificationResult struct {
	Level           string
	Blocked         bool
	MatchedPatterns []MatchedPattern
}

// MatchedPattern records which rule matched.
type MatchedPattern struct {
	Label string
	Level string
}

// Classifier runs regex-based data classification on messages.
type Classifier struct {
	rules           []classifierRule
	blockRestricted bool
	blockConfidential bool
}

type classifierRule struct {
	re    *regexp.Regexp
	level string
	label string
}

// newClassifier compiles all classification rules.
func newClassifier(cfg *ClassificationConfig) (*Classifier, error) {
	c := &Classifier{
		blockRestricted:   cfg.BlockRestricted,
		blockConfidential: cfg.BlockConfidential,
	}

	for _, rule := range cfg.Rules {
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid classification regex %q (%s): %w", rule.Pattern, rule.Label, err)
		}
		c.rules = append(c.rules, classifierRule{
			re:    re,
			level: strings.ToUpper(rule.Level),
			label: rule.Label,
		})
	}

	return c, nil
}

// Classify scans text and returns the highest classification level found.
func (c *Classifier) Classify(text string) ClassificationResult {
	result := ClassificationResult{
		Level: LevelPublic,
	}

	highestOrder := 0

	for _, rule := range c.rules {
		if rule.re.MatchString(text) {
			result.MatchedPatterns = append(result.MatchedPatterns, MatchedPattern{
				Label: rule.label,
				Level: rule.level,
			})
			order := classificationOrder[rule.level]
			if order > highestOrder {
				highestOrder = order
				result.Level = rule.level
			}
		}
	}

	// Check blocking
	if result.Level == LevelRestricted && c.blockRestricted {
		result.Blocked = true
	}
	if result.Level == LevelConfidential && c.blockConfidential {
		result.Blocked = true
	}

	return result
}
