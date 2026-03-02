// Package types defines shared event structures for ClawShield cross-layer security integration.
package types

import (
	"encoding/json"
	"time"
)

// SecurityEvent is the unified event type exchanged between ClawShield security layers.
// Events flow between the proxy (Layer 1), firewall (Layer 2), and eBPF monitor (Layer 3)
// via Unix domain socket using JSON encoding.
type SecurityEvent struct {
	// EventType identifies the class of security event.
	EventType EventType `json:"event_type"`

	// Severity indicates the urgency of the event.
	Severity Severity `json:"severity"`

	// Source identifies which security layer produced the event.
	Source EventSource `json:"source"`

	// Timestamp is when the event occurred.
	Timestamp time.Time `json:"timestamp"`

	// SessionID links the event to an audit session (proxy events only).
	SessionID string `json:"session_id,omitempty"`

	// PID is the process ID associated with the event (eBPF events only).
	PID int `json:"pid,omitempty"`

	// Tool is the MCP tool or command name involved.
	Tool string `json:"tool,omitempty"`

	// Reason is a human-readable explanation of the event.
	Reason string `json:"reason"`

	// Details contains event-specific metadata as key-value pairs.
	Details map[string]string `json:"details,omitempty"`

	// Reaction records what adaptive action was taken in response (filled by the controller).
	Reaction string `json:"reaction,omitempty"`
}

// EventType identifies the class of security event.
type EventType string

const (
	// Proxy layer events (Layer 1)
	EventInjectionBlocked EventType = "injection_blocked"
	EventMalwareBlocked   EventType = "malware_blocked"
	EventVulnBlocked      EventType = "vuln_blocked"
	EventPolicyDeny       EventType = "policy_deny"
	EventArgFilterMatch   EventType = "arg_filter_match"

	// eBPF layer events (Layer 3)
	EventExecSuspicious EventType = "exec_suspicious"
	EventPortScan       EventType = "port_scan"
	EventFileAccess     EventType = "file_access"
	EventPrivesc        EventType = "privesc"

	// Firewall layer events (Layer 2)
	EventFirewallBlock EventType = "firewall_block"

	// Adaptive response events (cross-layer)
	EventSensitivityElevated EventType = "sensitivity_elevated"
	EventDefaultDenyActivated EventType = "default_deny_activated"
	EventSessionBlocked      EventType = "session_blocked"
	EventTempRuleAdded       EventType = "temp_rule_added"
)

// Severity indicates the urgency of a security event.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// SeverityWeight returns a numeric weight for severity comparison and threshold logic.
func (s Severity) Weight() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// EventSource identifies which ClawShield layer produced an event.
type EventSource string

const (
	SourceProxy    EventSource = "proxy"
	SourceFirewall EventSource = "firewall"
	SourceEBPF     EventSource = "ebpf"
	SourceAdaptive EventSource = "adaptive"
)

// AdaptiveConfig holds cross-layer adaptive response configuration,
// loaded from the policy YAML under the "adaptive" key.
type AdaptiveConfig struct {
	Enabled    bool            `yaml:"enabled" json:"enabled"`
	SocketPath string          `yaml:"socket_path" json:"socket_path"`
	Rules      []AdaptiveRule  `yaml:"rules" json:"rules"`
}

// AdaptiveRule defines a single cross-layer reaction rule.
type AdaptiveRule struct {
	Trigger AdaptiveTrigger `yaml:"trigger" json:"trigger"`
	Action  string          `yaml:"action" json:"action"`
	Params  map[string]int  `yaml:"params" json:"params"`
}

// AdaptiveTrigger defines the conditions that activate a rule.
type AdaptiveTrigger struct {
	Source        EventSource `yaml:"source" json:"source"`
	Type          EventType   `yaml:"type" json:"type"`
	MinSeverity   Severity    `yaml:"min_severity,omitempty" json:"min_severity,omitempty"`
	MinCount      int         `yaml:"min_count,omitempty" json:"min_count,omitempty"`
	WindowSeconds int         `yaml:"window_seconds,omitempty" json:"window_seconds,omitempty"`
}

// MarshalJSON implements custom JSON marshaling for SecurityEvent.
func (e *SecurityEvent) MarshalJSON() ([]byte, error) {
	type Alias SecurityEvent
	return json.Marshal(&struct {
		*Alias
		Timestamp string `json:"timestamp"`
	}{
		Alias:     (*Alias)(e),
		Timestamp: e.Timestamp.Format(time.RFC3339Nano),
	})
}

// UnmarshalJSON implements custom JSON unmarshaling for SecurityEvent.
func (e *SecurityEvent) UnmarshalJSON(data []byte) error {
	type Alias SecurityEvent
	aux := &struct {
		*Alias
		Timestamp string `json:"timestamp"`
	}{
		Alias: (*Alias)(e),
	}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	t, err := time.Parse(time.RFC3339Nano, aux.Timestamp)
	if err != nil {
		// Fall back to RFC3339 without nanos
		t, err = time.Parse(time.RFC3339, aux.Timestamp)
		if err != nil {
			return err
		}
	}
	e.Timestamp = t
	return nil
}
