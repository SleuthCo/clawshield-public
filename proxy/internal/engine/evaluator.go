package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/SleuthCo/clawshield/proxy/internal/scanner"
	"github.com/SleuthCo/clawshield/shared/types"
)

type Policy struct {
	DefaultAction        string   `yaml:"default_action"`
	Allowlist            []string `yaml:"allowlist"`
	Denylist             []string `yaml:"denylist"`
	ArgFilters           []struct {
		Tool  string `yaml:"tool"`
		Regex string `yaml:"regex"`
	} `yaml:"arg_filters"`
	DomainAllowlist      []string `yaml:"domain_allowlist"`
	EvaluationTimeoutMs  int      `yaml:"evaluation_timeout_ms"`
	MaxMessageBytes      int64    `yaml:"max_message_bytes"`

	// Security scanner configuration
	VulnScan        *scanner.VulnScanConfig        `yaml:"vuln_scan"`
	PromptInjection *scanner.PromptInjectionConfig  `yaml:"prompt_injection"`
	MalwareScan     *scanner.MalwareScanConfig      `yaml:"malware_scan"`
	SecretsScan     *scanner.SecretsConfig           `yaml:"secrets_scan"`
	PIIScan         *scanner.PIIConfig               `yaml:"pii_scan"`

	// OpenClaw gateway integration
	OpenClaw *OpenClawConfig `yaml:"openclaw"`

	// Cross-layer adaptive response configuration
	Adaptive *types.AdaptiveConfig `yaml:"adaptive"`

	// SIEM log forwarding configuration
	SIEM *SIEMConfig `yaml:"siem"`
}

// SIEMConfig holds configuration for the SIEM log forwarder.
// Defined here to avoid circular imports between engine and siem packages.
type SIEMConfig struct {
	Enabled           bool   `yaml:"enabled"`
	MinSeverity       int    `yaml:"min_severity"`        // OCSF severity_id threshold (default: 4 = High)
	Transport         string `yaml:"transport"`            // "syslog" or "webhook"
	SyslogAddress     string `yaml:"syslog_address"`       // e.g. "siem.company.com:514"
	SyslogTLS         bool   `yaml:"syslog_tls"`
	SyslogCertFile    string `yaml:"syslog_cert_file"`
	SyslogKeyFile     string `yaml:"syslog_key_file"`
	WebhookURL        string `yaml:"webhook_url"`
	WebhookAuthHeader string `yaml:"webhook_auth_header"` // e.g. "Bearer token123"
	WebhookTimeoutMs  int    `yaml:"webhook_timeout_ms"`  // default: 5000
	QueueSize         int    `yaml:"queue_size"`           // default: 10000
}

// ChannelPolicy defines per-channel tool restrictions for OpenClaw.
type ChannelPolicy struct {
	AllowedTools []string `yaml:"allowed_tools"`
	BlockedTools []string `yaml:"blocked_tools"`
}

// OpenClawConfig holds OpenClaw-specific policy options.
type OpenClawConfig struct {
	GatewayPort    int                      `yaml:"gateway_port"`
	ProxyListen    string                   `yaml:"proxy_listen"`
	AuthToken      string                   `yaml:"auth_token"`
	AgentAllowlist []string                 `yaml:"agent_allowlist"`
	ChannelPolicies map[string]ChannelPolicy `yaml:"channel_policies"`
}

type Evaluator struct {
	policy             *Policy
	argFilterRegex     map[string]*regexp.Regexp
	vulnScanner        *scanner.VulnScanner
	injectionDetector  *scanner.InjectionDetector
	malwareScanner     *scanner.MalwareScanner
	secretsScanner     *scanner.SecretsScanner
	piiScanner         *scanner.PIIScanner

	// Cross-layer adaptive override fields
	// Cross-layer adaptive override fields — allow temporary policy changes
	// in response to detected threats (e.g. elevate sensitivity when under attack).
	overrideMu             sync.RWMutex
	sensitivityOverride    string
	sensitivityOverrideExp time.Time
	defaultActionOverride    string
	defaultActionOverrideExp time.Time
}

func NewEvaluator(policy *Policy) *Evaluator {
	e := &Evaluator{
		policy:         policy,
		argFilterRegex: make(map[string]*regexp.Regexp),
	}

	for _, filter := range policy.ArgFilters {
		re, err := regexp.Compile(filter.Regex)
		if err != nil {
			log.Printf("ERROR: Invalid regex for tool %s: %v - This will be ignored during evaluation", filter.Tool, err)
			continue
		}
		e.argFilterRegex[filter.Tool] = re
	}

	// Initialize security scanners (nil config = disabled, returns nil scanner)
	e.vulnScanner = scanner.NewVulnScanner(policy.VulnScan)
	e.injectionDetector = scanner.NewInjectionDetector(policy.PromptInjection)
	e.malwareScanner = scanner.NewMalwareScanner(policy.MalwareScan)
	e.secretsScanner = scanner.NewSecretsScanner(policy.SecretsScan)
	e.piiScanner = scanner.NewPIIScanner(policy.PIIScan)

	return e
}

// VulnScanner returns the vulnerability scanner (may be nil if disabled).
func (e *Evaluator) VulnScanner() *scanner.VulnScanner {
	return e.vulnScanner
}

// InjectionDetector returns the prompt injection detector (may be nil if disabled).
func (e *Evaluator) InjectionDetector() *scanner.InjectionDetector {
	return e.injectionDetector
}

// MalwareScanner returns the malware scanner (may be nil if disabled).
func (e *Evaluator) MalwareScanner() *scanner.MalwareScanner {
	return e.malwareScanner
}

// SecretsScanner returns the secrets scanner (may be nil if disabled).
func (e *Evaluator) SecretsScanner() *scanner.SecretsScanner {
	return e.secretsScanner
}

// PIIScanner returns the PII scanner (may be nil if disabled).
func (e *Evaluator) PIIScanner() *scanner.PIIScanner {
	return e.piiScanner
}

// AgentAllowlist returns the configured agent allowlist from OpenClaw policy.
func (e *Evaluator) AgentAllowlist() []string {
	if e.policy != nil && e.policy.OpenClaw != nil {
		return e.policy.OpenClaw.AgentAllowlist
	}
	return nil
}

const (
	Allow = "allow"
	Deny  = "deny"
)

// EvaluateWithDetails evaluates a message and returns detailed forensic information
// about the decision, enabling explainability for allow/deny/redact decisions.
// Returns (decision, reason, *DecisionDetail).
func (e *Evaluator) EvaluateWithDetails(ctx context.Context, message string) (string, string, *types.DecisionDetail) {
	startTime := time.Now()
	detail := &types.DecisionDetail{
		ScanResults:     []types.ScanResult{},
		ActiveOverrides: []string{},
	}

	if e.policy.EvaluationTimeoutMs > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(e.policy.EvaluationTimeoutMs)*time.Millisecond)
		defer cancel()
	}

	select {
	case <-ctx.Done():
		detail.PipelineStage = "timeout"
		detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
		return Deny, "evaluation timeout exceeded", detail
	default:
	}

	// Reject messages with duplicate JSON keys (parser differential attack)
	if hasDuplicateKeys([]byte(message)) {
		detail.PipelineStage = "duplicate_keys"
		detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
		return Deny, "duplicate JSON keys detected", detail
	}

	var rpc struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}

	if err := json.Unmarshal([]byte(message), &rpc); err != nil {
		detail.PipelineStage = "parse_error"
		detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
		return Deny, "invalid JSON-RPC format: " + err.Error(), detail
	}

	if rpc.Method == "" {
		detail.PipelineStage = "parse_error"
		detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
		return Deny, "missing method field in JSON-RPC", detail
	}

	if !json.Valid(rpc.Params) {
		detail.PipelineStage = "parse_error"
		detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
		return Deny, "invalid params JSON in JSON-RPC", detail
	}

	// Check denylist first (highest priority)
	for _, deniedTool := range e.policy.Denylist {
		if rpc.Method == deniedTool {
			detail.PipelineStage = "denylist"
			detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
			e.recordActiveOverrides(detail)
			return Deny, "tool explicitly denied by denylist", detail
		}
	}

	// Check allowlist — if method is explicitly listed, it's allowed
	// (still subject to security scanners below)
	inAllowlist := false
	if len(e.policy.Allowlist) > 0 {
		for _, allowedTool := range e.policy.Allowlist {
			if rpc.Method == allowedTool {
				inAllowlist = true
				break
			}
		}
		if !inAllowlist {
			detail.PipelineStage = "allowlist"
			detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
			e.recordActiveOverrides(detail)
			return Deny, "tool not in allowlist", detail
		}
	}

	// Apply argument filters on DECODED string values (not raw JSON bytes)
	// This defeats unicode escape bypass attacks
	if compiledRe, exists := e.argFilterRegex[rpc.Method]; exists {
		select {
		case <-ctx.Done():
			detail.PipelineStage = "timeout"
			detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
			return Deny, "evaluation timeout exceeded", detail
		default:
		}
		// Decode params to canonical string form to defeat \\uXXXX escapes
		decoded := decodeJSONStrings(rpc.Params)
		if compiledRe.MatchString(decoded) {
			detail.PipelineStage = "arg_filter"
			detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
			e.recordActiveOverrides(detail)
			return Deny, "sensitive data detected in arguments", detail
		}
	}

	// Domain allowlist for web.* tools
	if strings.HasPrefix(rpc.Method, "web.") && len(e.policy.DomainAllowlist) > 0 {
		select {
		case <-ctx.Done():
			detail.PipelineStage = "timeout"
			detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
			return Deny, "evaluation timeout exceeded", detail
		default:
		}

		var params struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(rpc.Params, &params); err != nil || params.URL == "" {
			detail.PipelineStage = "domain_allowlist"
			detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
			e.recordActiveOverrides(detail)
			return Deny, "cannot extract URL from web request for domain validation", detail
		}

		// Reject URLs with suspicious characters that cause parser differentials
		if err := validateURLSafety(params.URL); err != nil {
			detail.PipelineStage = "domain_allowlist"
			detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
			e.recordActiveOverrides(detail)
			return Deny, "unsafe URL rejected: " + err.Error(), detail
		}

		domain := extractDomain(params.URL)
		if domain == "" {
			detail.PipelineStage = "domain_allowlist"
			detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
			e.recordActiveOverrides(detail)
			return Deny, "cannot parse domain from URL", detail
		}

		allowed := false
		for _, allowedDomain := range e.policy.DomainAllowlist {
			select {
			case <-ctx.Done():
				detail.PipelineStage = "timeout"
				detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
				return Deny, "evaluation timeout exceeded", detail
			default:
			}
			if matchDomain(domain, allowedDomain) {
				allowed = true
				break
			}
		}
		if !allowed {
			detail.PipelineStage = "domain_allowlist"
			detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
			e.recordActiveOverrides(detail)
			return Deny, "domain not in allowlist", detail
		}
	}

	// Vulnerability scanning on decoded argument strings
	if e.vulnScanner != nil {
		select {
		case <-ctx.Done():
			detail.PipelineStage = "timeout"
			detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
			return Deny, "evaluation timeout exceeded", detail
		default:
		}
		decoded := decodeJSONStrings(rpc.Params)
		if scanResult := e.vulnScanner.ScanDetail(rpc.Method, decoded); scanResult != nil {
			detail.PipelineStage = "vuln_scan"
			detail.ScanResults = append(detail.ScanResults, *scanResult)
			detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
			e.recordActiveOverrides(detail)
			return Deny, scanResult.Description, detail
		}
	}

	// Prompt injection scanning on request arguments
	if e.injectionDetector != nil {
		select {
		case <-ctx.Done():
			detail.PipelineStage = "timeout"
			detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
			return Deny, "evaluation timeout exceeded", detail
		default:
		}
		decoded := decodeJSONStrings(rpc.Params)
		if scanResult := e.injectionDetector.ScanRequestDetail(rpc.Method, decoded); scanResult != nil {
			detail.PipelineStage = "injection_scan"
			detail.ScanResults = append(detail.ScanResults, *scanResult)
			detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
			e.recordActiveOverrides(detail)
			return Deny, scanResult.Description, detail
		}
	}

	// Secrets scanning on request arguments
	if e.secretsScanner != nil {
		select {
		case <-ctx.Done():
			detail.PipelineStage = "timeout"
			detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
			return Deny, "evaluation timeout exceeded", detail
		default:
		}
		decoded := decodeJSONStrings(rpc.Params)
		if scanResult := e.secretsScanner.ScanRequestDetail(rpc.Method, decoded); scanResult != nil {
			detail.PipelineStage = "secrets_scan"
			detail.ScanResults = append(detail.ScanResults, *scanResult)
			detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
			e.recordActiveOverrides(detail)
			return Deny, scanResult.Description, detail
		}
	}

	// PII scanning on request arguments
	if e.piiScanner != nil {
		select {
		case <-ctx.Done():
			detail.PipelineStage = "timeout"
			detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
			return Deny, "evaluation timeout exceeded", detail
		default:
		}
		decoded := decodeJSONStrings(rpc.Params)
		if scanResult := e.piiScanner.ScanRequestDetail(rpc.Method, decoded); scanResult != nil {
			detail.PipelineStage = "pii_scan"
			detail.ScanResults = append(detail.ScanResults, *scanResult)
			detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
			e.recordActiveOverrides(detail)
			return Deny, scanResult.Description, detail
		}
	}

	// If method was explicitly in the allowlist and passed all security scans, allow it
	if inAllowlist {
		detail.PipelineStage = "allowlist"
		detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
		e.recordActiveOverrides(detail)
		return Allow, "tool in allowlist, scans passed", detail
	}

	effectiveDefault := e.effectiveDefaultAction()
	detail.PipelineStage = "default_action"
	detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
	e.recordActiveOverrides(detail)
	if effectiveDefault == Allow {
		return Allow, "default allowed", detail
	}
	return Deny, "default denied", detail
}

// recordActiveOverrides records any adaptive overrides that are currently active.
func (e *Evaluator) recordActiveOverrides(detail *types.DecisionDetail) {
	e.overrideMu.RLock()
	defer e.overrideMu.RUnlock()

	now := time.Now()
	if e.sensitivityOverride != "" && now.Before(e.sensitivityOverrideExp) {
		detail.ActiveOverrides = append(detail.ActiveOverrides, "sensitivity_override:"+e.sensitivityOverride)
	}
	if e.defaultActionOverride != "" && now.Before(e.defaultActionOverrideExp) {
		detail.ActiveOverrides = append(detail.ActiveOverrides, "default_action_override:"+e.defaultActionOverride)
	}
}

// EvaluateWithContext evaluates with context cancellation and timeout support.
// If the policy defines evaluation_timeout_ms, the evaluator enforces that timeout
// internally, regardless of whether the caller provides a deadline.
func (e *Evaluator) EvaluateWithContext(ctx context.Context, message string) (string, string) {
	decision, reason, _ := e.EvaluateWithDetails(ctx, message)
	return decision, reason
}

// ResponseResult holds the result of a response evaluation, including
// any redacted content when scanners are configured in "redact" mode.
type ResponseResult struct {
	Decision     string               // "allow" or "deny"
	Reason       string               // Human-readable explanation
	RedactedBody string               // Modified response body (empty if no redaction applied)
	WasRedacted  bool                 // True if the response body was modified by redaction
	Details      *types.DecisionDetail // NEW: Structured forensic detail for explainability
}

// EvaluateResponse scans an MCP server response for malicious content.
// Returns a ResponseResult with the decision, reason, and optionally a redacted
// version of the response body when scanners are configured in "redact" mode.
//
// Scanners with action="block" will deny the response entirely.
// Scanners with action="redact" will sanitize the response and allow it through.
func (e *Evaluator) EvaluateResponse(ctx context.Context, method string, responseBody string) ResponseResult {
	startTime := time.Now()
	detail := &types.DecisionDetail{
		ScanResults:     []types.ScanResult{},
		ActiveOverrides: []string{},
	}

	select {
	case <-ctx.Done():
		detail.PipelineStage = "timeout"
		detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
		return ResponseResult{Decision: Deny, Reason: "evaluation timeout exceeded", Details: detail}
	default:
	}

	// Prompt injection response scanning — always blocks (no redact mode)
	if e.injectionDetector != nil {
		if blocked, reason := e.injectionDetector.ScanResponse(method, responseBody); blocked {
			detail.PipelineStage = "injection_scan"
			detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
			// Try to collect detailed scan result if available
			if scanResult := e.injectionDetector.ScanResponseDetail(method, responseBody); scanResult != nil {
				detail.ScanResults = append(detail.ScanResults, *scanResult)
			}
			e.recordActiveOverrides(detail)
			return ResponseResult{Decision: Deny, Reason: reason, Details: detail}
		}
	}

	// Malware scanning — always blocks
	if e.malwareScanner != nil {
		if blocked, reason := e.malwareScanner.ScanResponse(responseBody); blocked {
			detail.PipelineStage = "malware_scan"
			detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
			// Try to collect detailed scan result if available
			if scanResult := e.malwareScanner.ScanResponseDetail(responseBody); scanResult != nil {
				detail.ScanResults = append(detail.ScanResults, *scanResult)
			}
			e.recordActiveOverrides(detail)
			return ResponseResult{Decision: Deny, Reason: reason, Details: detail}
		}
	}

	// Track redaction across scanners
	workingBody := responseBody
	wasRedacted := false
	var redactReasons []string
	var scanResults []types.ScanResult

	// Secrets scanning on responses
	if e.secretsScanner != nil {
		if detected, reason := e.secretsScanner.ScanResponse(method, workingBody); detected {
			// Collect detailed scan result if available
			if scanResult := e.secretsScanner.ScanResponseDetail(method, workingBody); scanResult != nil {
				scanResults = append(scanResults, *scanResult)
			}

			if e.secretsScanner.Action() == "redact" {
				redacted, found := e.secretsScanner.RedactSecrets(workingBody)
				if len(found) > 0 {
					workingBody = redacted
					wasRedacted = true
					redactReasons = append(redactReasons, fmt.Sprintf("secrets redacted: %v", found))
				}
			} else {
				detail.PipelineStage = "secrets_scan"
				detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
				detail.ScanResults = scanResults
				e.recordActiveOverrides(detail)
				return ResponseResult{Decision: Deny, Reason: reason, Details: detail}
			}
		}
	}

	// PII scanning on responses
	if e.piiScanner != nil {
		if detected, reason := e.piiScanner.ScanResponse(method, workingBody); detected {
			// Collect detailed scan result if available
			if scanResult := e.piiScanner.ScanResponseDetail(method, workingBody); scanResult != nil {
				scanResults = append(scanResults, *scanResult)
			}

			if e.piiScanner.Action() == "redact" {
				redacted, found := e.piiScanner.RedactPII(workingBody)
				if len(found) > 0 {
					workingBody = redacted
					wasRedacted = true
					redactReasons = append(redactReasons, fmt.Sprintf("PII redacted: %v", found))
				}
			} else {
				detail.PipelineStage = "pii_scan"
				detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
				detail.ScanResults = scanResults
				e.recordActiveOverrides(detail)
				return ResponseResult{Decision: Deny, Reason: reason, Details: detail}
			}
		}
	}

	if wasRedacted {
		reason := strings.Join(redactReasons, "; ")
		detail.PipelineStage = "response_redaction"
		detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
		detail.ScanResults = scanResults
		e.recordActiveOverrides(detail)
		return ResponseResult{
			Decision:     Allow,
			Reason:       "response redacted: " + reason,
			RedactedBody: workingBody,
			WasRedacted:  true,
			Details:      detail,
		}
	}

	detail.PipelineStage = "response_clean"
	detail.EvalDurationMs = time.Since(startTime).Seconds() * 1000
	e.recordActiveOverrides(detail)
	return ResponseResult{Decision: Allow, Reason: "response clean", Details: detail}
}

// EvaluateResponseSimple is a backward-compatible wrapper that returns only
// (decision, reason) for callers that don't need the redacted body.
func (e *Evaluator) EvaluateResponseSimple(ctx context.Context, method string, responseBody string) (string, string) {
	result := e.EvaluateResponse(ctx, method, responseBody)
	return result.Decision, result.Reason
}

// EvaluateAgentScope scans a response for cross-scope platform references.
// Returns (decision, reason). If the response references platforms not in
// agentScopes, it is blocked.
func (e *Evaluator) EvaluateAgentScope(responseBody string, agentScopes []string) (string, string) {
	if len(agentScopes) == 0 {
		return Allow, "no scope restrictions"
	}

	// Build set of allowed platforms for O(1) lookup
	allowed := make(map[string]bool, len(agentScopes))
	for _, s := range agentScopes {
		allowed[strings.ToLower(s)] = true
	}

	// Known platform action prefixes to scan for
	platformPrefixes := map[string]string{
		"slack":      "slack",
		"github":     "github",
		"jira":       "jira",
		"confluence":  "confluence",
		"google":     "google",
		"microsoft":  "microsoft",
		"gitlab":     "gitlab",
		"jsm":        "jsm",
	}

	lower := strings.ToLower(responseBody)
	for prefix, platform := range platformPrefixes {
		if allowed[platform] {
			continue // Agent has access to this platform
		}
		// Check for action key patterns: "slack-send-msg", "github-create-issue", etc.
		if strings.Contains(lower, prefix+"-") {
			// Verify it looks like an action directive (not just a mention)
			patterns := []string{
				"use " + prefix,
				"invoke " + prefix,
				"call " + prefix,
				prefix + "-send",
				prefix + "-create",
				prefix + "-delete",
				prefix + "-update",
				prefix + "-search",
				prefix + "-list",
				prefix + "-get",
			}
			for _, pat := range patterns {
				if strings.Contains(lower, pat) {
					return Deny, fmt.Sprintf("cross_scope: response references %s platform (agent lacks access)", platform)
				}
			}
		}
	}

	return Allow, "response within agent scope"
}

// EvaluateOpenClawAgent checks if an agent is permitted by the agent_allowlist.
// Returns true if allowed, false if denied.
func (e *Evaluator) EvaluateOpenClawAgent(agentID string) (string, string) {
	if e.policy.OpenClaw == nil || len(e.policy.OpenClaw.AgentAllowlist) == 0 {
		return Allow, "no agent allowlist configured"
	}
	for _, allowed := range e.policy.OpenClaw.AgentAllowlist {
		if strings.EqualFold(agentID, allowed) {
			return Allow, "agent in allowlist"
		}
	}
	return Deny, fmt.Sprintf("agent %q not in allowlist", agentID)
}

// EvaluateOpenClawChannel checks channel-specific tool restrictions.
// Returns (decision, reason). If no channel policy exists, defers to normal evaluation.
func (e *Evaluator) EvaluateOpenClawChannel(channel, tool string) (string, string) {
	if e.policy.OpenClaw == nil || len(e.policy.OpenClaw.ChannelPolicies) == 0 {
		return Allow, "no channel policies configured"
	}
	cp, exists := e.policy.OpenClaw.ChannelPolicies[channel]
	if !exists {
		return Allow, "no policy for channel"
	}
	// Check blocked tools first
	for _, blocked := range cp.BlockedTools {
		if tool == blocked {
			return Deny, fmt.Sprintf("tool %q blocked for channel %q", tool, channel)
		}
	}
	// Check allowed tools (if configured, acts as allowlist)
	if len(cp.AllowedTools) > 0 {
		for _, allowed := range cp.AllowedTools {
			if tool == allowed {
				return Allow, "tool allowed for channel"
			}
		}
		return Deny, fmt.Sprintf("tool %q not in allowed list for channel %q", tool, channel)
	}
	return Allow, "tool not restricted for channel"
}

// hasDuplicateKeys recursively checks for duplicate keys at every level of a
// JSON object tree. This prevents parser differential attacks where Go takes
// the last key but other languages take the first — including in nested objects
// like params, which the old top-level-only check missed.
func hasDuplicateKeys(data []byte) bool {
	var raw interface{}
	// First do a quick decode to see if it's valid JSON at all
	if err := json.Unmarshal(data, &raw); err != nil {
		return false
	}
	return hasDuplicateKeysRecursive(data)
}

// hasDuplicateKeysRecursive walks JSON tokens and checks every object level
// for duplicate keys, recursing into nested objects and arrays.
func hasDuplicateKeysRecursive(data []byte) bool {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	return checkTokenStream(dec)
}

// checkTokenStream reads tokens from the decoder and checks for duplicate keys
// at the current object nesting level, recursing into child objects/arrays.
func checkTokenStream(dec *json.Decoder) bool {
	t, err := dec.Token()
	if err != nil {
		return false
	}

	switch v := t.(type) {
	case json.Delim:
		if v == '{' {
			return checkObject(dec)
		}
		if v == '[' {
			return checkArray(dec)
		}
	}
	return false
}

// checkObject checks for duplicate keys in a single JSON object and recurses
// into any nested objects or arrays found in values.
func checkObject(dec *json.Decoder) bool {
	seen := make(map[string]bool)
	for dec.More() {
		// Read key
		keyTok, err := dec.Token()
		if err != nil {
			return false
		}
		key, ok := keyTok.(string)
		if !ok {
			return false
		}
		if seen[key] {
			return true
		}
		seen[key] = true

		// Read value — peek to see if it's a nested object/array
		valTok, err := dec.Token()
		if err != nil {
			return false
		}
		if delim, ok := valTok.(json.Delim); ok {
			if delim == '{' {
				if checkObject(dec) {
					return true
				}
			} else if delim == '[' {
				if checkArray(dec) {
					return true
				}
			}
		}
		// Primitive value — already consumed, continue
	}
	// Consume closing '}'
	dec.Token() // nolint:errcheck
	return false
}

// checkArray recurses into each element of a JSON array looking for duplicate
// keys in any nested objects.
func checkArray(dec *json.Decoder) bool {
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		if delim, ok := tok.(json.Delim); ok {
			if delim == '{' {
				if checkObject(dec) {
					return true
				}
			} else if delim == '[' {
				if checkArray(dec) {
					return true
				}
			}
		}
		// Primitive element — already consumed
	}
	// Consume closing ']'
	dec.Token() // nolint:errcheck
	return false
}

// decodeJSONStrings recursively decodes JSON and returns all string values
// concatenated. This normalizes unicode escapes like \u0070 -> "p" so that
// regex filters see the actual decoded content, not raw JSON bytes.
func decodeJSONStrings(data json.RawMessage) string {
	var result strings.Builder

	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return string(data)
	}
	collectStrings(&result, v)
	return result.String()
}

func collectStrings(b *strings.Builder, v interface{}) {
	switch val := v.(type) {
	case string:
		b.WriteString(val)
		b.WriteByte(' ')
	case map[string]interface{}:
		for k, mv := range val {
			b.WriteString(k)
			b.WriteByte(' ')
			collectStrings(b, mv)
		}
	case []interface{}:
		for _, av := range val {
			collectStrings(b, av)
		}
	}
}

// validateURLSafety rejects URLs with characters that cause parser differential
// attacks between Go's url.Parse and downstream HTTP clients.
func validateURLSafety(rawURL string) error {
	// Reject URLs with embedded credentials (@) that can confuse parsers
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	if u.User != nil {
		return fmt.Errorf("URL contains embedded credentials")
	}
	// Reject backslashes (parser differential between Go and browsers/curl)
	if strings.ContainsAny(rawURL, "\\") {
		return fmt.Errorf("URL contains backslash")
	}
	// Reject null bytes
	if strings.Contains(rawURL, "\x00") {
		return fmt.Errorf("URL contains null byte")
	}
	// Reject percent-encoded characters in the host portion
	if u.Host != u.Hostname() && strings.Contains(u.Host, "%") {
		return fmt.Errorf("URL host contains percent-encoded characters")
	}
	return nil
}

// matchDomain checks if domain matches an allowlist entry.
func matchDomain(domain, pattern string) bool {
	if domain == pattern {
		return true
	}
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}
	suffix := pattern[1:] // ".example.com"
	bare := pattern[2:]   // "example.com"
	return domain == bare || strings.HasSuffix(domain, suffix)
}

func extractDomain(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil || u.Host == "" {
		u, err = url.Parse("http://" + urlStr)
		if err != nil {
			return ""
		}
	}
	return u.Hostname()
}

// --- Cross-Layer Adaptive Override Methods ---

// SetSensitivityOverride temporarily elevates the injection detection sensitivity.
// The override expires at the given time, after which normal policy sensitivity resumes.
func (e *Evaluator) SetSensitivityOverride(level string, expiresAt time.Time) {
	e.overrideMu.Lock()
	defer e.overrideMu.Unlock()
	e.sensitivityOverride = level
	e.sensitivityOverrideExp = expiresAt
	log.Printf("Evaluator: injection sensitivity overridden to %q until %s", level, expiresAt.Format(time.RFC3339))
}

// SetDefaultActionOverride temporarily overrides the default policy action.
// Typically used to force deny-by-default when the adaptive controller detects elevated threat.
func (e *Evaluator) SetDefaultActionOverride(action string, expiresAt time.Time) {
	e.overrideMu.Lock()
	defer e.overrideMu.Unlock()
	e.defaultActionOverride = action
	e.defaultActionOverrideExp = expiresAt
	log.Printf("Evaluator: default action overridden to %q until %s", action, expiresAt.Format(time.RFC3339))
}

// ClearOverrides removes all active adaptive overrides.
func (e *Evaluator) ClearOverrides() {
	e.overrideMu.Lock()
	defer e.overrideMu.Unlock()
	e.sensitivityOverride = ""
	e.defaultActionOverride = ""
}

// effectiveDefaultAction returns the current default action, considering any active override.
func (e *Evaluator) effectiveDefaultAction() string {
	e.overrideMu.RLock()
	defer e.overrideMu.RUnlock()

	if e.defaultActionOverride != "" && time.Now().Before(e.defaultActionOverrideExp) {
		return e.defaultActionOverride
	}
	return e.policy.DefaultAction
}

// HasActiveOverrides returns true if any adaptive overrides are currently active.
func (e *Evaluator) HasActiveOverrides() bool {
	e.overrideMu.RLock()
	defer e.overrideMu.RUnlock()

	now := time.Now()
	return (e.sensitivityOverride != "" && now.Before(e.sensitivityOverrideExp)) ||
		(e.defaultActionOverride != "" && now.Before(e.defaultActionOverrideExp))
}

// Ensure types import is used
var _ = types.AdaptiveConfig{}
