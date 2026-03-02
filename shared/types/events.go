// Package types defines shared event structures for ClawShield audit logging.
package types

import (
	"encoding/json"
	"time"
)

type Decision struct {
	DecisionID      int64            `json:"decision_id"`
	Timestamp       time.Time        `json:"timestamp"`
	SessionID       string           `json:"session_id"`
	Tool            string           `json:"tool"`
	ArgumentsHash   string           `json:"arguments_hash"`
	Decision        string           `json:"decision"` // allow, deny, redacted
	Reason          string           `json:"reason,omitempty"`
	PolicyVersion   string           `json:"policy_version,omitempty"`
	ScannerType     string           `json:"scanner_type,omitempty"` // vuln, injection, malware (empty = policy engine)
	CorrelationID   string           `json:"correlation_id,omitempty"`
	Classification  string           `json:"classification,omitempty"`   // PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED
	Source          string           `json:"source,omitempty"`           // forge-bridge, direct, slack, telegram
	ResponseBlocked bool             `json:"response_blocked,omitempty"`
	AgentName       string           `json:"agent_name,omitempty"`       // Agent identity from X-Agent-Name header
	Details         *DecisionDetail  `json:"details,omitempty"`          // Structured forensic detail for explainability
}

// DecisionDetail captures structured forensic information about a security
// decision, enabling SOC analysts to understand exactly why a request was
// allowed, denied, or redacted without needing to reproduce the evaluation.
type DecisionDetail struct {
	// PipelineStage identifies where in the evaluation pipeline the decision
	// was made (e.g. "denylist", "allowlist", "arg_filter", "domain_allowlist",
	// "vuln_scan", "injection_scan", "secrets_scan", "pii_scan", "malware_scan",
	// "default_action", "timeout", "parse_error").
	PipelineStage string `json:"pipeline_stage"`

	// EvalDurationMs is the wall-clock time in milliseconds for the full
	// evaluation pipeline to reach a decision.
	EvalDurationMs float64 `json:"eval_duration_ms"`

	// ScanResults contains per-scanner forensic details. Only scanners that
	// produced a finding are included. Empty for policy-only decisions.
	ScanResults []ScanResult `json:"scan_results,omitempty"`

	// ActiveOverrides records any adaptive overrides that were in effect
	// at the time of evaluation (e.g. elevated sensitivity, forced deny).
	ActiveOverrides []string `json:"active_overrides,omitempty"`
}

// ScanResult captures the forensic output of a single security scanner.
//
// SECURITY: MatchExcerpt is truncated to MaxExcerptLen characters and
// sanitized to prevent sensitive data (secrets, PII) from leaking into
// audit logs. Scanners that detect secrets or PII must redact the excerpt
// before returning it.
type ScanResult struct {
	// Scanner identifies which scanner produced this result
	// (e.g. "vuln", "injection", "malware", "secrets", "pii").
	Scanner string `json:"scanner"`

	// RuleID is a stable, machine-readable identifier for the specific
	// detection rule that fired (e.g. "sqli", "ssrf", "aws_access_key",
	// "email", "reverse_shell_bash").
	RuleID string `json:"rule_id"`

	// Description is a human-readable explanation of what was detected.
	Description string `json:"description"`

	// MatchExcerpt is a safely truncated and sanitized excerpt of the
	// content that matched. For secrets/PII, the excerpt is redacted
	// (e.g. "AKIA****XXXX"). Never contains full sensitive values.
	MatchExcerpt string `json:"match_excerpt,omitempty"`

	// Confidence is a normalized score: "high", "medium", or "low".
	Confidence string `json:"confidence"`

	// Blocked indicates whether this scanner result caused a deny decision.
	// False for scanners that only redacted or logged.
	Blocked bool `json:"blocked"`

	// Metadata contains scanner-specific key-value pairs (e.g. entropy
	// score, compression ratio, CIDR block matched).
	Metadata map[string]string `json:"metadata,omitempty"`
}

// MaxExcerptLen is the maximum length of a MatchExcerpt in ScanResult.
// Excerpts longer than this are truncated with "..." appended.
// SECURITY: This limit prevents large payloads from being stored in audit
// logs, and reduces the risk of sensitive data exposure in forensic records.
const MaxExcerptLen = 100

// TruncateExcerpt safely truncates a string to MaxExcerptLen runes.
// If the input is longer, it is truncated and "..." is appended.
// SECURITY: Uses rune-based slicing to avoid splitting multi-byte UTF-8
// characters, which could produce invalid strings in audit logs.
func TruncateExcerpt(s string) string {
	runes := []rune(s)
	if len(runes) <= MaxExcerptLen {
		return s
	}
	return string(runes[:MaxExcerptLen]) + "..."
}

// RedactExcerpt returns a safely redacted version of a matched value
// for inclusion in audit logs. Shows the first 4 and last 2 characters
// with the middle replaced by asterisks. For values shorter than 8 chars,
// returns "****".
func RedactExcerpt(s string) string {
	if len(s) < 8 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-2:]
}

// MarshalDecisionDetail serializes a DecisionDetail to JSON for storage.
// Returns nil if detail is nil.
func MarshalDecisionDetail(d *DecisionDetail) (json.RawMessage, error) {
	if d == nil {
		return nil, nil
	}
	return json.Marshal(d)
}

// UnmarshalDecisionDetail deserializes a DecisionDetail from JSON.
// Returns nil if data is nil or empty.
func UnmarshalDecisionDetail(data []byte) (*DecisionDetail, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var d DecisionDetail
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

type ToolCall struct {
	CallID      int64  `json:"call_id"`
	DecisionID  int64  `json:"decision_id"`
	RequestJSON []byte `json:"request_json"`
	ResponseJSON []byte `json:"response_json,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

type Session struct {
	SessionID    string    `json:"session_id"`
	StartTime    time.Time `json:"start_time"`
	EndTime      *time.Time `json:"end_time,omitempty"`
	AgentVersion string    `json:"agent_version,omitempty"`
	NodeID       string    `json:"node_id,omitempty"`
	Context      []byte    `json:"context,omitempty"` // JSON-encoded extra context
}

type PolicyChange struct {
	ChangeID        int64     `json:"change_id"`
	Timestamp       time.Time `json:"timestamp"`
	SessionID       string    `json:"session_id,omitempty"`
	OldPolicyHash   string    `json:"old_policy_hash,omitempty"`
	NewPolicyHash   string    `json:"new_policy_hash"`
	ChangedBy       string    `json:"changed_by,omitempty"`
	Reason          string    `json:"reason,omitempty"`
}

type IntegrityCheckpoint struct {
	CheckpointID int64     `json:"checkpoint_id"`
	Timestamp    time.Time `json:"timestamp"`
	DBHash       string    `json:"db_hash"`
	Reason       string    `json:"reason"`
}

// DecisionLog is the full audit log entry with optional tool call data.
type DecisionLog struct {
	Decision   Decision  `json:"decision"`
	ToolCall   *ToolCall `json:"tool_call,omitempty"`
}