// Package types defines shared event structures for ClawShield audit logging.
package types

import "time"

type Decision struct {
	DecisionID      int64     `json:"decision_id"`
	Timestamp       time.Time `json:"timestamp"`
	SessionID       string    `json:"session_id"`
	Tool            string    `json:"tool"`
	ArgumentsHash   string    `json:"arguments_hash"`
	Decision        string    `json:"decision"` // allow, deny, redacted
	Reason          string    `json:"reason,omitempty"`
	PolicyVersion   string    `json:"policy_version,omitempty"`
	ScannerType     string    `json:"scanner_type,omitempty"` // vuln, injection, malware (empty = policy engine)
	CorrelationID   string    `json:"correlation_id,omitempty"`
	Classification  string    `json:"classification,omitempty"`   // PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED
	Source          string    `json:"source,omitempty"`           // forge-bridge, direct, slack, telegram
	ResponseBlocked bool      `json:"response_blocked,omitempty"`
	AgentName       string    `json:"agent_name,omitempty"`       // Agent identity from X-Agent-Name header
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