// Package permissions implements a config-driven agent permission system
// for ClawShield. It provides agent scope checking, data classification,
// DLP scrubbing, and response sanitization — ported from the TypeScript
// implementation in agent-observatory-clean.
package permissions

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Classification levels ordered by sensitivity.
const (
	LevelPublic       = "PUBLIC"
	LevelInternal     = "INTERNAL"
	LevelConfidential = "CONFIDENTIAL"
	LevelRestricted   = "RESTRICTED"
)

// Permission types for platform access.
const (
	PermRead  = "READ"
	PermWrite = "WRITE"
)

// DLP modes.
const (
	DLPOff    = "OFF"
	DLPRedact = "REDACT"
	DLPBlock  = "BLOCK"
)

var classificationOrder = map[string]int{
	LevelPublic:       0,
	LevelInternal:     1,
	LevelConfidential: 2,
	LevelRestricted:   3,
}

// Config is the top-level permissions configuration loaded from YAML.
type Config struct {
	Agents            map[string]*AgentProfile `yaml:"agents"`
	Classification    ClassificationConfig     `yaml:"classification"`
	BridgeDLP         DLPConfig                `yaml:"bridge_dlp"`
	ResponseSanitizer SanitizerConfig          `yaml:"response_sanitizer"`
	Sessions          SessionConfig            `yaml:"sessions"`

	// Runtime state (not from YAML)
	mu          sync.RWMutex
	aliasMap    map[string]string // alias → canonical name
	compiled    bool
	classifier  *Classifier
	dlp         *DLP
	sanitizer   *Sanitizer
}

// AgentProfile defines what an agent can access.
type AgentProfile struct {
	Enabled           bool                `yaml:"enabled"`
	MaxClassification string              `yaml:"max_classification"`
	Aliases           []string            `yaml:"aliases"`
	Platforms         map[string][]string `yaml:"platforms"` // platform → [READ, WRITE]
}

// ClassificationConfig defines data classification rules.
type ClassificationConfig struct {
	BlockRestricted   bool                 `yaml:"block_restricted"`
	BlockConfidential bool                 `yaml:"block_confidential"`
	Rules             []ClassificationRule `yaml:"rules"`
}

// ClassificationRule is a single regex-based classification pattern.
type ClassificationRule struct {
	Pattern string `yaml:"pattern"`
	Level   string `yaml:"level"`
	Label   string `yaml:"label"`
}

// DLPConfig defines bridge DLP settings.
type DLPConfig struct {
	Mode                  string       `yaml:"mode"`
	BuiltinPatterns       []DLPPattern `yaml:"builtin_patterns"`
	CorporateEmailDomains []string     `yaml:"corporate_email_domains"`
	CustomPatterns        []DLPPattern `yaml:"custom_patterns"`
	AllowlistPhrases      []string     `yaml:"allowlist_phrases"`
}

// DLPPattern is a single DLP regex pattern with replacement text.
type DLPPattern struct {
	Pattern     string `yaml:"pattern"`
	Label       string `yaml:"label"`
	Replacement string `yaml:"replacement"`
}

// SanitizerConfig defines response sanitization settings.
type SanitizerConfig struct {
	MaxResponseLength   int              `yaml:"max_response_length"`
	InjectionPatterns   []SanitzerRule   `yaml:"injection_patterns"`
	CrossActionPatterns []SanitzerRule   `yaml:"cross_action_patterns"`
}

// SanitzerRule is a regex pattern for response sanitization.
type SanitzerRule struct {
	Pattern string `yaml:"pattern"`
	Label   string `yaml:"label"`
}

// SessionConfig controls M2 session isolation.
type SessionConfig struct {
	Ephemeral bool `yaml:"ephemeral"`
}

// Load reads and compiles a permissions YAML config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read permissions file: %w", err)
	}
	return Parse(data)
}

// Parse parses permissions config from YAML bytes and compiles all regexes.
func Parse(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse permissions YAML: %w", err)
	}
	if err := cfg.compile(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// compile builds the alias map and initializes sub-systems.
func (c *Config) compile() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Build alias → canonical name map
	c.aliasMap = make(map[string]string)
	for name, profile := range c.Agents {
		lower := strings.ToLower(name)
		c.aliasMap[lower] = lower
		for _, alias := range profile.Aliases {
			c.aliasMap[strings.ToLower(alias)] = lower
		}
	}

	// Compile sub-systems
	var err error
	c.classifier, err = newClassifier(&c.Classification)
	if err != nil {
		return fmt.Errorf("compile classifier: %w", err)
	}

	c.dlp, err = newDLP(&c.BridgeDLP)
	if err != nil {
		return fmt.Errorf("compile DLP: %w", err)
	}

	c.sanitizer, err = newSanitizer(&c.ResponseSanitizer)
	if err != nil {
		return fmt.Errorf("compile sanitizer: %w", err)
	}

	c.compiled = true
	return nil
}

// resolveAgent maps an agent name (or alias) to the canonical profile.
func (c *Config) resolveAgent(name string) (string, *AgentProfile) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	lower := strings.ToLower(name)
	canonical, ok := c.aliasMap[lower]
	if !ok {
		// Fall back to "default" profile
		if def, exists := c.Agents["default"]; exists {
			return "default", def
		}
		return "", nil
	}
	if profile, exists := c.Agents[canonical]; exists {
		return canonical, profile
	}
	return "", nil
}

// ScopeResult is the result of a scope check.
type ScopeResult struct {
	Allowed  bool
	Reason   string
	Agent    string
	Platform string
}

// CheckAgentScope checks if an agent has the required permission on a platform.
func (c *Config) CheckAgentScope(agentName, platform, permission string) ScopeResult {
	canonical, profile := c.resolveAgent(agentName)
	if profile == nil {
		return ScopeResult{Allowed: false, Reason: fmt.Sprintf("unknown agent %q", agentName)}
	}
	if !profile.Enabled {
		return ScopeResult{Allowed: false, Reason: fmt.Sprintf("agent %q is disabled", canonical), Agent: canonical, Platform: platform}
	}

	perms, ok := profile.Platforms[strings.ToLower(platform)]
	if !ok {
		return ScopeResult{
			Allowed:  false,
			Reason:   fmt.Sprintf("agent %q has no access to platform %q", canonical, platform),
			Agent:    canonical,
			Platform: platform,
		}
	}

	perm := strings.ToUpper(permission)
	for _, p := range perms {
		if strings.ToUpper(p) == perm {
			return ScopeResult{Allowed: true, Reason: "scope allowed", Agent: canonical, Platform: platform}
		}
	}

	return ScopeResult{
		Allowed:  false,
		Reason:   fmt.Sprintf("agent %q lacks %s permission on %q", canonical, perm, platform),
		Agent:    canonical,
		Platform: platform,
	}
}

// GetAgentPlatforms returns the list of platforms an agent has access to.
func (c *Config) GetAgentPlatforms(agentName string) []string {
	_, profile := c.resolveAgent(agentName)
	if profile == nil {
		return nil
	}
	platforms := make([]string, 0, len(profile.Platforms))
	for p := range profile.Platforms {
		platforms = append(platforms, p)
	}
	return platforms
}

// CheckClassificationCeiling returns true if the message classification level
// is within the agent's allowed ceiling.
func (c *Config) CheckClassificationCeiling(agentName, messageLevel string) bool {
	_, profile := c.resolveAgent(agentName)
	if profile == nil {
		return false
	}
	msgOrder, ok := classificationOrder[strings.ToUpper(messageLevel)]
	if !ok {
		return false
	}
	ceilOrder, ok := classificationOrder[strings.ToUpper(profile.MaxClassification)]
	if !ok {
		return false
	}
	return msgOrder <= ceilOrder
}

// Classifier returns the compiled data classifier.
func (c *Config) Classifier() *Classifier {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.classifier
}

// DLPEngine returns the compiled DLP scrubber.
func (c *Config) DLPEngine() *DLP {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.dlp
}

// ResponseSanitizerEngine returns the compiled response sanitizer.
func (c *Config) ResponseSanitizerEngine() *Sanitizer {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sanitizer
}

// EphemeralSessions returns whether M2 ephemeral sessions are enabled.
func (c *Config) EphemeralSessions() bool {
	return c.Sessions.Ephemeral
}

// AllPlatforms is the list of all known platforms for scope validation.
var AllPlatforms = []string{
	"slack", "github", "jira", "confluence", "google",
	"microsoft", "gitlab", "jsm", "openclaw",
}

// compiledPattern holds a pre-compiled regex with its label.
type compiledPattern struct {
	re    *regexp.Regexp
	label string
}
