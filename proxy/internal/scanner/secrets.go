// Package scanner provides security scanning for MCP tool call arguments and responses.
//
// secrets.go implements value-based secrets detection. Unlike key-name-based redaction
// (hashlined/hash.go), this scanner detects secrets by their format patterns —
// AWS access keys, GitHub tokens, Stripe keys, JWTs, private keys, etc. — regardless
// of which JSON field they appear in.
package scanner

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/SleuthCo/clawshield/shared/types"
)

// SecretsConfig holds the policy configuration for secrets scanning.
type SecretsConfig struct {
	Enabled       bool     `yaml:"enabled"`
	ScanRequests  bool     `yaml:"scan_requests"`
	ScanResponses bool     `yaml:"scan_responses"`
	Action        string   `yaml:"action"`         // "block" or "redact" (default: "block")
	Rules         []string `yaml:"rules"`           // Which rule categories to enable (empty = all)
	ExcludeTools  []string `yaml:"exclude_tools"`   // Tools exempt from scanning
	CustomPatterns []CustomSecretPattern `yaml:"custom_patterns"` // User-defined patterns
}

// CustomSecretPattern allows users to define their own secret detection patterns.
type CustomSecretPattern struct {
	Name        string `yaml:"name"`
	Pattern     string `yaml:"pattern"`
	Description string `yaml:"description"`
}

// SecretRuleCategory groups secret detection rules by provider/type.
type SecretRuleCategory string

const (
	RuleCategoryAWS         SecretRuleCategory = "aws"
	RuleCategoryGCP         SecretRuleCategory = "gcp"
	RuleCategoryAzure       SecretRuleCategory = "azure"
	RuleCategoryGitHub      SecretRuleCategory = "github"
	RuleCategoryGitLab      SecretRuleCategory = "gitlab"
	RuleCategorySlack       SecretRuleCategory = "slack"
	RuleCategoryStripe      SecretRuleCategory = "stripe"
	RuleCategoryGenericAPI  SecretRuleCategory = "generic_api"
	RuleCategoryJWT         SecretRuleCategory = "jwt"
	RuleCategoryPrivateKey  SecretRuleCategory = "private_key"
	RuleCategoryDatabase    SecretRuleCategory = "database"
	RuleCategoryAtlassian   SecretRuleCategory = "atlassian"
	RuleCategoryCustom      SecretRuleCategory = "custom"
)

// secretRule defines a single secret detection pattern with metadata.
type secretRule struct {
	name        string
	category    SecretRuleCategory
	pattern     *regexp.Regexp
	description string
}

// SecretsScanner detects secrets and credentials in text by matching value patterns.
type SecretsScanner struct {
	scanRequests  bool
	scanResponses bool
	action        string // "block" or "redact"
	excludeTools  map[string]bool
	rules         []secretRule
}

// NewSecretsScanner creates a SecretsScanner from policy configuration.
func NewSecretsScanner(cfg *SecretsConfig) *SecretsScanner {
	if cfg == nil || !cfg.Enabled {
		return nil
	}

	s := &SecretsScanner{
		scanRequests:  cfg.ScanRequests,
		scanResponses: cfg.ScanResponses,
		action:        cfg.Action,
		excludeTools:  make(map[string]bool),
	}

	if s.action == "" {
		s.action = "block"
	}

	for _, t := range cfg.ExcludeTools {
		s.excludeTools[t] = true
	}

	// Determine which rule categories to enable
	enabledCategories := make(map[SecretRuleCategory]bool)
	if len(cfg.Rules) == 0 {
		// Enable all built-in categories
		for _, cat := range allCategories() {
			enabledCategories[cat] = true
		}
	} else {
		for _, r := range cfg.Rules {
			enabledCategories[SecretRuleCategory(r)] = true
		}
	}

	// Compile built-in rules
	s.compileBuiltinRules(enabledCategories)

	// Compile custom patterns
	if enabledCategories[RuleCategoryCustom] || len(cfg.CustomPatterns) > 0 {
		for _, cp := range cfg.CustomPatterns {
			re, err := regexp.Compile(cp.Pattern)
			if err != nil {
				continue
			}
			s.rules = append(s.rules, secretRule{
				name:        cp.Name,
				category:    RuleCategoryCustom,
				pattern:     re,
				description: cp.Description,
			})
		}
	}

	return s
}

// ScanRequestDetail checks outbound tool arguments for leaked secrets.
// Returns a *types.ScanResult if a secret is detected, nil otherwise.
func (s *SecretsScanner) ScanRequestDetail(method string, decodedParams string) *types.ScanResult {
	if s == nil || !s.scanRequests {
		return nil
	}
	if s.excludeTools[method] {
		return nil
	}
	return s.scanDetail(decodedParams)
}

// ScanRequest checks outbound tool arguments for leaked secrets.
func (s *SecretsScanner) ScanRequest(method string, decodedParams string) (bool, string) {
	result := s.ScanRequestDetail(method, decodedParams)
	if result != nil {
		return true, result.Description
	}
	return false, ""
}

// ScanResponseDetail checks inbound tool responses for leaked secrets.
// Returns a *types.ScanResult if a secret is detected, nil otherwise.
func (s *SecretsScanner) ScanResponseDetail(method string, responseBody string) *types.ScanResult {
	if s == nil || !s.scanResponses {
		return nil
	}
	if s.excludeTools[method] {
		return nil
	}
	return s.scanDetail(responseBody)
}

// ScanResponse checks inbound tool responses for leaked secrets.
func (s *SecretsScanner) ScanResponse(method string, responseBody string) (bool, string) {
	result := s.ScanResponseDetail(method, responseBody)
	if result != nil {
		return true, result.Description
	}
	return false, ""
}

// Action returns the configured action ("block" or "redact").
func (s *SecretsScanner) Action() string {
	if s == nil {
		return "block"
	}
	return s.action
}

// RuleCount returns the number of active detection rules.
func (s *SecretsScanner) RuleCount() int {
	if s == nil {
		return 0
	}
	return len(s.rules)
}

func (s *SecretsScanner) scanDetail(text string) *types.ScanResult {
	for _, rule := range s.rules {
		if rule.pattern.MatchString(text) {
			ruleID := toSnakeCase(rule.name)
			return &types.ScanResult{
				Scanner:      "secrets",
				RuleID:       ruleID,
				Description:  fmt.Sprintf("secrets_scan: %s detected (%s)", rule.name, rule.description),
				MatchExcerpt: types.RedactExcerpt(rule.name),
				Confidence:   "high",
				Blocked:      true,
				Metadata:     make(map[string]string),
			}
		}
	}
	return nil
}

func (s *SecretsScanner) scan(text string) (bool, string) {
	result := s.scanDetail(text)
	if result != nil {
		return true, result.Description
	}
	return false, ""
}

func allCategories() []SecretRuleCategory {
	return []SecretRuleCategory{
		RuleCategoryAWS,
		RuleCategoryGCP,
		RuleCategoryAzure,
		RuleCategoryGitHub,
		RuleCategoryGitLab,
		RuleCategorySlack,
		RuleCategoryStripe,
		RuleCategoryGenericAPI,
		RuleCategoryJWT,
		RuleCategoryPrivateKey,
		RuleCategoryDatabase,
		RuleCategoryAtlassian,
	}
}

func (s *SecretsScanner) compileBuiltinRules(enabled map[SecretRuleCategory]bool) {
	type ruleDef struct {
		name        string
		category    SecretRuleCategory
		pattern     string
		description string
	}

	builtins := []ruleDef{
		// --- AWS ---
		{
			name:        "AWS Access Key ID",
			category:    RuleCategoryAWS,
			pattern:     `(?:^|[^A-Za-z0-9])(AKIA[0-9A-Z]{16})(?:[^A-Za-z0-9]|$)`,
			description: "AWS access key ID (AKIA...)",
		},
		{
			name:        "AWS Secret Access Key",
			category:    RuleCategoryAWS,
			pattern:     `(?:^|[^A-Za-z0-9/+=])([A-Za-z0-9/+=]{40})(?:[^A-Za-z0-9/+=]|$)`,
			description: "potential AWS secret access key (40-char base64)",
		},
		{
			name:        "AWS Session Token",
			category:    RuleCategoryAWS,
			pattern:     `(?i)aws[_\-\.]?session[_\-\.]?token\s*[:=]\s*["']?[A-Za-z0-9/+=]{100,}`,
			description: "AWS session token",
		},

		// --- GCP ---
		{
			name:        "GCP Service Account Key",
			category:    RuleCategoryGCP,
			pattern:     `"type"\s*:\s*"service_account"`,
			description: "GCP service account key JSON",
		},
		{
			name:        "GCP API Key",
			category:    RuleCategoryGCP,
			pattern:     `AIza[0-9A-Za-z\-_]{35}`,
			description: "Google API key (AIza...)",
		},
		{
			name:        "GCP OAuth Client ID",
			category:    RuleCategoryGCP,
			pattern:     `[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com`,
			description: "Google OAuth client ID",
		},

		// --- Azure ---
		{
			name:        "Azure Storage Account Key",
			category:    RuleCategoryAzure,
			pattern:     `(?i)(?:account[_\-]?key|storage[_\-]?key)\s*[:=]\s*["']?[A-Za-z0-9/+=]{86,88}==`,
			description: "Azure storage account key",
		},
		{
			name:        "Azure AD Client Secret",
			category:    RuleCategoryAzure,
			pattern:     `(?i)(?:client[_\-]?secret|azure[_\-]?secret)\s*[:=]\s*["']?[A-Za-z0-9~._\-]{34,40}`,
			description: "Azure AD client secret",
		},

		// --- GitHub ---
		{
			name:        "GitHub Personal Access Token",
			category:    RuleCategoryGitHub,
			pattern:     `ghp_[A-Za-z0-9]{36}`,
			description: "GitHub personal access token (ghp_...)",
		},
		{
			name:        "GitHub OAuth Access Token",
			category:    RuleCategoryGitHub,
			pattern:     `gho_[A-Za-z0-9]{36}`,
			description: "GitHub OAuth access token (gho_...)",
		},
		{
			name:        "GitHub App Token",
			category:    RuleCategoryGitHub,
			pattern:     `(ghu|ghs)_[A-Za-z0-9]{36}`,
			description: "GitHub app token (ghu_/ghs_...)",
		},
		{
			name:        "GitHub Fine-Grained Token",
			category:    RuleCategoryGitHub,
			pattern:     `github_pat_[A-Za-z0-9_]{82}`,
			description: "GitHub fine-grained personal access token",
		},

		// --- GitLab ---
		{
			name:        "GitLab Personal Access Token",
			category:    RuleCategoryGitLab,
			pattern:     `glpat-[A-Za-z0-9\-_]{20,}`,
			description: "GitLab personal access token (glpat-...)",
		},
		{
			name:        "GitLab Pipeline Token",
			category:    RuleCategoryGitLab,
			pattern:     `glptt-[A-Za-z0-9\-_]{20,}`,
			description: "GitLab pipeline trigger token",
		},

		// --- Slack ---
		{
			name:        "Slack Bot Token",
			category:    RuleCategorySlack,
			pattern:     `xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,34}`,
			description: "Slack bot token (xoxb-...)",
		},
		{
			name:        "Slack User Token",
			category:    RuleCategorySlack,
			pattern:     `xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}`,
			description: "Slack user token (xoxp-...)",
		},
		{
			name:        "Slack Webhook URL",
			category:    RuleCategorySlack,
			pattern:     `https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}`,
			description: "Slack incoming webhook URL",
		},

		// --- Stripe ---
		{
			name:        "Stripe Secret Key",
			category:    RuleCategoryStripe,
			pattern:     `sk_(live|test)_[A-Za-z0-9]{24,99}`,
			description: "Stripe secret API key (sk_live_/sk_test_...)",
		},
		{
			name:        "Stripe Restricted Key",
			category:    RuleCategoryStripe,
			pattern:     `rk_(live|test)_[A-Za-z0-9]{24,99}`,
			description: "Stripe restricted API key",
		},

		// --- Atlassian ---
		{
			name:        "Atlassian API Token",
			category:    RuleCategoryAtlassian,
			pattern:     `(?i)(?:atlassian|jira|confluence)[_\-\.]?(?:api[_\-\.]?)?token\s*[:=]\s*["']?[A-Za-z0-9]{24,}`,
			description: "Atlassian API token",
		},

		// --- JWT ---
		{
			name:        "JSON Web Token",
			category:    RuleCategoryJWT,
			pattern:     `eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]{10,}`,
			description: "JSON Web Token (JWT)",
		},

		// --- Private Keys ---
		{
			name:        "RSA Private Key",
			category:    RuleCategoryPrivateKey,
			pattern:     `-----BEGIN RSA PRIVATE KEY-----`,
			description: "RSA private key (PEM format)",
		},
		{
			name:        "EC Private Key",
			category:    RuleCategoryPrivateKey,
			pattern:     `-----BEGIN EC PRIVATE KEY-----`,
			description: "EC private key (PEM format)",
		},
		{
			name:        "OpenSSH Private Key",
			category:    RuleCategoryPrivateKey,
			pattern:     `-----BEGIN OPENSSH PRIVATE KEY-----`,
			description: "OpenSSH private key",
		},
		{
			name:        "PGP Private Key",
			category:    RuleCategoryPrivateKey,
			pattern:     `-----BEGIN PGP PRIVATE KEY BLOCK-----`,
			description: "PGP private key block",
		},
		{
			name:        "Generic Private Key",
			category:    RuleCategoryPrivateKey,
			pattern:     `-----BEGIN PRIVATE KEY-----`,
			description: "PKCS#8 private key (PEM format)",
		},

		// --- Database ---
		{
			name:        "PostgreSQL Connection String",
			category:    RuleCategoryDatabase,
			pattern:     `(?i)postgres(?:ql)?://[^\s"']+:[^\s"']+@[^\s"']+`,
			description: "PostgreSQL connection string with credentials",
		},
		{
			name:        "MySQL Connection String",
			category:    RuleCategoryDatabase,
			pattern:     `(?i)mysql://[^\s"']+:[^\s"']+@[^\s"']+`,
			description: "MySQL connection string with credentials",
		},
		{
			name:        "MongoDB Connection String",
			category:    RuleCategoryDatabase,
			pattern:     `(?i)mongodb(\+srv)?://[^\s"']+:[^\s"']+@[^\s"']+`,
			description: "MongoDB connection string with credentials",
		},
		{
			name:        "Redis Connection String",
			category:    RuleCategoryDatabase,
			pattern:     `(?i)redis://[^\s"']*:[^\s"']+@[^\s"']+`,
			description: "Redis connection string with credentials",
		},

		// --- Generic API Keys ---
		{
			name:        "Generic Secret Assignment",
			category:    RuleCategoryGenericAPI,
			pattern:     `(?i)(?:secret|private)[_\-\.]?key\s*[:=]\s*["']?[A-Za-z0-9/+=_\-]{20,}`,
			description: "generic secret/private key assignment",
		},
		{
			name:        "Generic Bearer Token",
			category:    RuleCategoryGenericAPI,
			pattern:     `(?i)(?:authorization|bearer)\s*[:=]\s*["']?Bearer\s+[A-Za-z0-9\-._~+/]+=*`,
			description: "Bearer authorization token",
		},
		{
			name:        "SendGrid API Key",
			category:    RuleCategoryGenericAPI,
			pattern:     `SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}`,
			description: "SendGrid API key (SG....)",
		},
		{
			name:        "Twilio API Key",
			category:    RuleCategoryGenericAPI,
			pattern:     `SK[0-9a-fA-F]{32}`,
			description: "Twilio API key (SK...)",
		},
		{
			name:        "Mailgun API Key",
			category:    RuleCategoryGenericAPI,
			pattern:     `key-[A-Za-z0-9]{32}`,
			description: "Mailgun API key (key-...)",
		},
		{
			name:        "NPM Token",
			category:    RuleCategoryGenericAPI,
			pattern:     `npm_[A-Za-z0-9]{36}`,
			description: "NPM access token (npm_...)",
		},
		{
			name:        "PyPI Token",
			category:    RuleCategoryGenericAPI,
			pattern:     `pypi-[A-Za-z0-9_\-]{50,}`,
			description: "PyPI API token (pypi-...)",
		},
		{
			name:        "Heroku API Key",
			category:    RuleCategoryGenericAPI,
			pattern:     `(?i)heroku[_\-\.]?api[_\-\.]?key\s*[:=]\s*["']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`,
			description: "Heroku API key (UUID format)",
		},
		{
			name:        "Datadog API Key",
			category:    RuleCategoryGenericAPI,
			pattern:     `(?i)(?:dd|datadog)[_\-\.]?(?:api[_\-\.]?)?key\s*[:=]\s*["']?[a-f0-9]{32}`,
			description: "Datadog API key",
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
		s.rules = append(s.rules, secretRule{
			name:        def.name,
			category:    def.category,
			pattern:     re,
			description: def.description,
		})
	}
}

// RedactSecrets replaces detected secrets in text with [REDACTED].
// Returns the redacted text and a list of what was redacted.
func (s *SecretsScanner) RedactSecrets(text string) (string, []string) {
	if s == nil {
		return text, nil
	}

	var redacted []string
	result := text

	for _, rule := range s.rules {
		if rule.pattern.MatchString(result) {
			redacted = append(redacted, rule.name)
			result = rule.pattern.ReplaceAllStringFunc(result, func(match string) string {
				// Preserve any leading/trailing non-secret characters from the match
				// (due to boundary anchors in the pattern)
				trimmed := strings.TrimSpace(match)
				if len(trimmed) > 8 {
					return match[:4] + "[REDACTED]" + match[len(match)-2:]
				}
				return "[REDACTED]"
			})
		}
	}

	return result, redacted
}

// toSnakeCase converts a string to snake_case by lowercasing and replacing spaces with underscores.
func toSnakeCase(s string) string {
	return strings.ReplaceAll(strings.ToLower(s), " ", "_")
}
