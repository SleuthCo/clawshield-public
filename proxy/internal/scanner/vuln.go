// Package scanner provides security scanning for MCP tool call arguments and responses.
package scanner

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/SleuthCo/clawshield/shared/types"
)

// VulnType identifies the class of vulnerability detected.
type VulnType string

const (
	VulnSQLi             VulnType = "sqli"
	VulnSSRF             VulnType = "ssrf"
	VulnPathTraversal    VulnType = "path_traversal"
	VulnCommandInjection VulnType = "command_injection"
	VulnXSS              VulnType = "xss"
)

// VulnScanConfig holds the policy configuration for vulnerability scanning.
type VulnScanConfig struct {
	Enabled      bool     `yaml:"enabled"`
	Rules        []string `yaml:"rules"`
	ExcludeTools []string `yaml:"exclude_tools"`
}

// VulnScanner detects injection attacks in tool call arguments.
type VulnScanner struct {
	enabledRules map[VulnType]bool
	excludeTools map[string]bool
	sqliPatterns []*regexp.Regexp
	ssrfNets     []*net.IPNet
	pathPatterns []*regexp.Regexp
	cmdPatterns  []*regexp.Regexp
	xssPatterns  []*regexp.Regexp
}

// NewVulnScanner creates a VulnScanner from policy configuration.
func NewVulnScanner(cfg *VulnScanConfig) *VulnScanner {
	if cfg == nil || !cfg.Enabled {
		return nil
	}

	s := &VulnScanner{
		enabledRules: make(map[VulnType]bool),
		excludeTools: make(map[string]bool),
	}

	for _, r := range cfg.Rules {
		s.enabledRules[VulnType(r)] = true
	}
	// If no rules specified, enable all
	if len(s.enabledRules) == 0 {
		s.enabledRules[VulnSQLi] = true
		s.enabledRules[VulnSSRF] = true
		s.enabledRules[VulnPathTraversal] = true
		s.enabledRules[VulnCommandInjection] = true
		s.enabledRules[VulnXSS] = true
	}

	for _, t := range cfg.ExcludeTools {
		s.excludeTools[t] = true
	}

	s.compileSQLiPatterns()
	s.compileSSRFNets()
	s.compilePathPatterns()
	s.compileCmdPatterns()
	s.compileXSSPatterns()

	return s
}

// ScanDetail checks decoded tool arguments for vulnerability payloads.
// Returns a *types.ScanResult if a vulnerability is detected, nil otherwise.
func (s *VulnScanner) ScanDetail(method string, decodedParams string) *types.ScanResult {
	if s == nil {
		return nil
	}
	if s.excludeTools[method] {
		return nil
	}

	lower := strings.ToLower(decodedParams)

	if s.enabledRules[VulnSQLi] {
		if result := s.checkSQLiDetail(lower); result != nil {
			return result
		}
	}

	if s.enabledRules[VulnSSRF] {
		if result := s.checkSSRFDetail(decodedParams); result != nil {
			return result
		}
	}

	if s.enabledRules[VulnPathTraversal] {
		if result := s.checkPathTraversalDetail(decodedParams, lower); result != nil {
			return result
		}
	}

	if s.enabledRules[VulnCommandInjection] {
		if result := s.checkCommandInjectionDetail(decodedParams); result != nil {
			return result
		}
	}

	if s.enabledRules[VulnXSS] {
		if result := s.checkXSSDetail(lower); result != nil {
			return result
		}
	}

	return nil
}

// Scan checks decoded tool arguments for vulnerability payloads.
// Returns (blocked bool, reason string).
func (s *VulnScanner) Scan(method string, decodedParams string) (bool, string) {
	result := s.ScanDetail(method, decodedParams)
	if result != nil {
		return true, result.Description
	}
	return false, ""
}

// --- SQL Injection Detection ---

func (s *VulnScanner) compileSQLiPatterns() {
	patterns := []string{
		// UNION-based injection
		`(?i)\bunion\s+(all\s+)?select\b`,
		// OR/AND tautologies
		`(?i)\b(or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?`,
		`(?i)\b(or|and)\s+['"]?[a-z]+['"]?\s*=\s*['"]?[a-z]+['"]?`,
		// Comment-based truncation
		`(?i)['";]\s*--`,
		`(?i)['";]\s*/\*`,
		// Stacked queries
		`(?i)['";]\s*;\s*(drop|alter|create|insert|update|delete|exec|execute|xp_)\b`,
		// Classic string escape
		`(?i)'\s*(or|and)\s+'`,
		// SLEEP/BENCHMARK (blind SQLi)
		`(?i)\b(sleep|benchmark|pg_sleep)\s*\(`,
		// WAITFOR DELAY (MSSQL blind SQLi)
		`(?i)\bwaitfor\s+delay\b`,
		// Information schema probing
		`(?i)\binformation_schema\b`,
		// INTO OUTFILE / LOAD_FILE
		`(?i)\b(into\s+outfile|load_file)\b`,
	}
	s.sqliPatterns = compilePatterns(patterns)
}

func (s *VulnScanner) checkSQLiDetail(lower string) *types.ScanResult {
	for _, re := range s.sqliPatterns {
		if re.MatchString(lower) {
			return &types.ScanResult{
				Scanner:      "vuln",
				RuleID:       "sqli",
				Description:  fmt.Sprintf("vuln_scan: SQL injection detected (pattern: %s)", re.String()),
				MatchExcerpt: types.TruncateExcerpt(re.String()),
				Confidence:   "high",
				Blocked:      true,
				Metadata:     make(map[string]string),
			}
		}
	}
	return nil
}

func (s *VulnScanner) checkSQLi(lower string) (bool, string) {
	result := s.checkSQLiDetail(lower)
	if result != nil {
		return true, result.Description
	}
	return false, ""
}

// --- SSRF Detection ---

func (s *VulnScanner) compileSSRFNets() {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16", // link-local + cloud metadata
		"0.0.0.0/8",
		"::1/128",
		"fc00::/7", // IPv6 ULA
		"fe80::/10", // IPv6 link-local
	}
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			s.ssrfNets = append(s.ssrfNets, network)
		}
	}
}

func (s *VulnScanner) checkSSRFDetail(params string) *types.ScanResult {
	// Extract URLs from the decoded params
	urls := extractURLsFromText(params)
	for _, rawURL := range urls {
		u, err := url.Parse(rawURL)
		if err != nil {
			continue
		}

		// Scheme allowlist
		scheme := strings.ToLower(u.Scheme)
		if scheme != "" && scheme != "http" && scheme != "https" {
			if scheme == "file" || scheme == "gopher" || scheme == "dict" || scheme == "ftp" {
				return &types.ScanResult{
					Scanner:      "vuln",
					RuleID:       "ssrf",
					Description:  fmt.Sprintf("vuln_scan: SSRF detected — disallowed scheme %q", scheme),
					MatchExcerpt: types.TruncateExcerpt(scheme),
					Confidence:   "high",
					Blocked:      true,
					Metadata:     make(map[string]string),
				}
			}
		}

		host := u.Hostname()
		if host == "" {
			continue
		}

		// Cloud metadata endpoints
		if host == "169.254.169.254" || host == "metadata.google.internal" {
			return &types.ScanResult{
				Scanner:      "vuln",
				RuleID:       "ssrf",
				Description:  "vuln_scan: SSRF detected — cloud metadata endpoint",
				MatchExcerpt: types.TruncateExcerpt(host),
				Confidence:   "high",
				Blocked:      true,
				Metadata:     make(map[string]string),
			}
		}

		// Private IP check
		ip := net.ParseIP(host)
		if ip != nil {
			for _, network := range s.ssrfNets {
				if network.Contains(ip) {
					return &types.ScanResult{
						Scanner:      "vuln",
						RuleID:       "ssrf",
						Description:  fmt.Sprintf("vuln_scan: SSRF detected — private/internal IP %s", host),
						MatchExcerpt: types.TruncateExcerpt(host),
						Confidence:   "high",
						Blocked:      true,
						Metadata:     make(map[string]string),
					}
				}
			}
		}

		// Decimal IP (e.g., http://2130706433 = 127.0.0.1)
		if isDecimalIP(host) {
			return &types.ScanResult{
				Scanner:      "vuln",
				RuleID:       "ssrf",
				Description:  "vuln_scan: SSRF detected — decimal IP encoding",
				MatchExcerpt: types.TruncateExcerpt(host),
				Confidence:   "high",
				Blocked:      true,
				Metadata:     make(map[string]string),
			}
		}

		// Hex IP (e.g., http://0x7f000001 = 127.0.0.1)
		if strings.HasPrefix(strings.ToLower(host), "0x") {
			return &types.ScanResult{
				Scanner:      "vuln",
				RuleID:       "ssrf",
				Description:  "vuln_scan: SSRF detected — hex IP encoding",
				MatchExcerpt: types.TruncateExcerpt(host),
				Confidence:   "high",
				Blocked:      true,
				Metadata:     make(map[string]string),
			}
		}
	}
	return nil
}

func (s *VulnScanner) checkSSRF(params string) (bool, string) {
	result := s.checkSSRFDetail(params)
	if result != nil {
		return true, result.Description
	}
	return false, ""
}

// --- Path Traversal Detection ---

func (s *VulnScanner) compilePathPatterns() {
	patterns := []string{
		// Direct traversal
		`\.\.(/|\\)`,
		// URL-encoded variants
		`(?i)(%2e%2e|%2e%2e%2f|%2e%2e/|\.\.%2f|%2e%2e%5c|\.\.%5c)`,
		// Double URL-encoding
		`(?i)(%252e%252e|%252e%252e%252f)`,
		// Null byte injection (path truncation)
		`%00`,
		// Windows UNC paths
		`(?i)^\\\\[a-z0-9]`,
	}
	s.pathPatterns = compilePatterns(patterns)
}

func (s *VulnScanner) checkPathTraversalDetail(params, lower string) *types.ScanResult {
	for _, re := range s.pathPatterns {
		if re.MatchString(params) || re.MatchString(lower) {
			return &types.ScanResult{
				Scanner:      "vuln",
				RuleID:       "path_traversal",
				Description:  fmt.Sprintf("vuln_scan: path traversal detected (pattern: %s)", re.String()),
				MatchExcerpt: types.TruncateExcerpt(re.String()),
				Confidence:   "high",
				Blocked:      true,
				Metadata:     make(map[string]string),
			}
		}
	}

	// Check for null bytes in raw string (already decoded from JSON)
	if strings.Contains(params, "\x00") {
		return &types.ScanResult{
			Scanner:      "vuln",
			RuleID:       "path_traversal",
			Description:  "vuln_scan: path traversal detected — null byte in path",
			MatchExcerpt: "null byte",
			Confidence:   "high",
			Blocked:      true,
			Metadata:     make(map[string]string),
		}
	}

	return nil
}

func (s *VulnScanner) checkPathTraversal(params, lower string) (bool, string) {
	result := s.checkPathTraversalDetail(params, lower)
	if result != nil {
		return true, result.Description
	}
	return false, ""
}

// --- Command Injection Detection ---

func (s *VulnScanner) compileCmdPatterns() {
	patterns := []string{
		// Shell metacharacters after content
		`[;&|` + "`" + `]\s*(cat|ls|id|whoami|uname|curl|wget|nc|ncat|bash|sh|python|perl|ruby|php)\b`,
		// Command substitution
		`\$\([^)]+\)`,
		// Backtick execution
		"`[^`]+`",
		// Pipe to shell
		`\|\s*(bash|sh|zsh|csh|ksh|fish)\b`,
		// Newline injection for shell
		`\n\s*(cat|ls|id|whoami|uname|curl|wget|nc|bash|sh)\b`,
		// Semicolon-separated commands
		`;\s*(rm|dd|mkfs|chmod|chown|kill|reboot|shutdown|halt)\b`,
		// && or || chained execution
		`(&&|\|\|)\s*(rm|dd|mkfs|chmod|chown|curl|wget|nc|bash|sh)\b`,
	}
	s.cmdPatterns = compilePatterns(patterns)
}

func (s *VulnScanner) checkCommandInjectionDetail(params string) *types.ScanResult {
	for _, re := range s.cmdPatterns {
		if re.MatchString(params) {
			return &types.ScanResult{
				Scanner:      "vuln",
				RuleID:       "command_injection",
				Description:  fmt.Sprintf("vuln_scan: command injection detected (pattern: %s)", re.String()),
				MatchExcerpt: types.TruncateExcerpt(re.String()),
				Confidence:   "high",
				Blocked:      true,
				Metadata:     make(map[string]string),
			}
		}
	}
	return nil
}

func (s *VulnScanner) checkCommandInjection(params string) (bool, string) {
	result := s.checkCommandInjectionDetail(params)
	if result != nil {
		return true, result.Description
	}
	return false, ""
}

// --- XSS Detection ---

func (s *VulnScanner) compileXSSPatterns() {
	patterns := []string{
		// Script tags
		`(?i)<\s*script[\s>]`,
		`(?i)<\s*/\s*script\s*>`,
		// Event handlers
		`(?i)\bon(error|load|click|mouseover|focus|blur|submit|change|input|keyup|keydown)\s*=`,
		// javascript: URIs
		`(?i)javascript\s*:`,
		// data: URIs with script content
		`(?i)data\s*:\s*text/html`,
		// SVG script injection
		`(?i)<\s*svg[\s/].*?on\w+\s*=`,
		// IMG tag injection
		`(?i)<\s*img[^>]+on(error|load)\s*=`,
		// Encoded variants
		`(?i)&#(x6a|106);?\s*&#(x61|97);?\s*&#(x76|118);?\s*&#(x61|97);?`, // j a v a
		// Expression injection (IE)
		`(?i)expression\s*\(`,
		// Style-based XSS
		`(?i)style\s*=\s*["'][^"']*expression\s*\(`,
	}
	s.xssPatterns = compilePatterns(patterns)
}

func (s *VulnScanner) checkXSSDetail(lower string) *types.ScanResult {
	for _, re := range s.xssPatterns {
		if re.MatchString(lower) {
			return &types.ScanResult{
				Scanner:      "vuln",
				RuleID:       "xss",
				Description:  fmt.Sprintf("vuln_scan: XSS detected (pattern: %s)", re.String()),
				MatchExcerpt: types.TruncateExcerpt(re.String()),
				Confidence:   "high",
				Blocked:      true,
				Metadata:     make(map[string]string),
			}
		}
	}
	return nil
}

func (s *VulnScanner) checkXSS(lower string) (bool, string) {
	result := s.checkXSSDetail(lower)
	if result != nil {
		return true, result.Description
	}
	return false, ""
}

// --- Helpers ---

func compilePatterns(patterns []string) []*regexp.Regexp {
	var compiled []*regexp.Regexp
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			continue
		}
		compiled = append(compiled, re)
	}
	return compiled
}

// extractURLsFromText finds URLs in free text.
var urlPattern = regexp.MustCompile(`(?i)(https?://[^\s"'<>]+|file://[^\s"'<>]+|gopher://[^\s"'<>]+|dict://[^\s"'<>]+|ftp://[^\s"'<>]+)`)

func extractURLsFromText(text string) []string {
	return urlPattern.FindAllString(text, -1)
}

// isDecimalIP checks if a host string looks like a decimal-encoded IP.
func isDecimalIP(host string) bool {
	// Pure numeric string that's too large to be a port
	if len(host) == 0 {
		return false
	}
	for _, c := range host {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(host) > 5 // Longer than max port (65535)
}

// decodeHexBytes attempts to decode a hex-encoded string to check for hidden payloads.
func decodeHexBytes(s string) ([]byte, error) {
	cleaned := strings.ReplaceAll(s, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "\\x", "")
	return hex.DecodeString(cleaned)
}
