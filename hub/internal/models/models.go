package models

import (
	"encoding/json"
	"time"
)

// Agent represents a registered ClawShield endpoint.
type Agent struct {
	AgentID           string    `json:"agent_id"`
	Hostname          string    `json:"hostname"`
	IPAddress         string    `json:"ip_address,omitempty"`
	ClawshieldVersion string    `json:"clawshield_version"`
	AgentVersion      string    `json:"agent_version"`
	PolicyHash        string    `json:"policy_hash"`
	PolicyVersion     string    `json:"policy_version"`
	EncryptionKeyID   string    `json:"encryption_key_id,omitempty"`
	Status            string    `json:"status"` // healthy, unhealthy, stale, unreachable
	Tags              []string  `json:"tags,omitempty"`
	LastCheckinAt     time.Time `json:"last_checkin_at"`
	RegisteredAt      time.Time `json:"registered_at"`
	PolicyGroupID     string    `json:"policy_group_id,omitempty"`
}

// AgentHealth contains health information from a check-in.
type AgentHealth struct {
	Status          string    `json:"status"` // healthy, degraded, unhealthy
	LastDecisionAt  time.Time `json:"last_decision_at,omitempty"`
	AuditDBSizeBytes int64    `json:"audit_db_size_bytes"`
	QueueDepth      int       `json:"queue_depth"`
}

// MetricsSummary contains aggregated metrics from a check-in period.
type MetricsSummary struct {
	DecisionsTotal    int            `json:"decisions_total"`
	DecisionsDenied   int            `json:"decisions_denied"`
	ScannerDetections map[string]int `json:"scanner_detections"`
	PeriodSeconds     int            `json:"period_seconds"`
}

// CheckinRequest is sent by the agent on each poll.
type CheckinRequest struct {
	AgentID           string         `json:"agent_id"`
	Hostname          string         `json:"hostname"`
	ClawshieldVersion string         `json:"clawshield_version"`
	AgentVersion      string         `json:"agent_version"`
	PolicyHash        string         `json:"policy_hash"`
	PolicyVersion     string         `json:"policy_version"`
	EncryptionKeyID   string         `json:"encryption_key_id,omitempty"`
	UptimeSeconds     int64          `json:"uptime_seconds"`
	Health            AgentHealth    `json:"health"`
	MetricsSummary    MetricsSummary `json:"metrics_summary"`
	Tags              []string       `json:"tags,omitempty"`
}

// Action represents a command from the Hub to an agent.
type Action struct {
	Type    string          `json:"type"` // update_policy, rotate_encryption_key, update_binary, emergency_lockdown
	Payload json.RawMessage `json:"payload,omitempty"`
}

// CheckinResponse is returned to the agent after a check-in.
type CheckinResponse struct {
	Actions            []Action  `json:"actions"`
	NextCheckinSeconds int       `json:"next_checkin_seconds"`
	ServerTime         time.Time `json:"server_time"`
}

// EnrollmentRequest is sent by a new agent to register.
type EnrollmentRequest struct {
	Token    string   `json:"token"`
	Hostname string   `json:"hostname"`
	Tags     []string `json:"tags,omitempty"`
}

// EnrollmentResponse is returned after successful enrollment.
type EnrollmentResponse struct {
	AgentID       string `json:"agent_id"`
	HubURL        string `json:"hub_url"`
	CheckinInterval int  `json:"checkin_interval_seconds"`
}

// AgentCheckin is a recorded check-in event.
type AgentCheckin struct {
	CheckinID        int64          `json:"checkin_id"`
	AgentID          string         `json:"agent_id"`
	Timestamp        time.Time      `json:"timestamp"`
	HealthStatus     string         `json:"health_status"`
	MetricsSummary   MetricsSummary `json:"metrics_summary"`
	AuditDBSizeBytes int64          `json:"audit_db_size_bytes"`
}

// AgentDetail represents detailed agent information with recent checkins.
type AgentDetail struct {
	Agent          *Agent         `json:"agent"`
	RecentCheckins []AgentCheckin `json:"recent_checkins"`
}

// HealthResponse is the response to health checks.
type HealthResponse struct {
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
}

// ErrorResponse is a standard error response.
type ErrorResponse struct {
	Error string `json:"error"`
}
