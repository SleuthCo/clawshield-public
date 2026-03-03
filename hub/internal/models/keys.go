package models

import "time"

// EncryptionKey represents a managed encryption key for audit log encryption.
type EncryptionKey struct {
	KeyID        string    `json:"key_id"`
	GroupID      string    `json:"group_id"` // policy group this key belongs to
	EncryptedKey string    `json:"encrypted_key,omitempty"` // hex-encoded encrypted key material
	Status       string    `json:"status"` // active, rotated, revoked
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	RotatedAt    time.Time `json:"rotated_at,omitempty"`
}

// KeyRotateAction is the payload for a rotate_encryption_key action.
type KeyRotateAction struct {
	KeyID       string `json:"key_id"`
	KeyMaterial string `json:"key_material"` // hex-encoded key (transmitted over mTLS)
	ExpiresAt   string `json:"expires_at,omitempty"`
}

// DashboardOverview contains fleet-wide summary statistics.
type DashboardOverview struct {
	TotalAgents         int                `json:"total_agents"`
	HealthyAgents       int                `json:"healthy_agents"`
	UnhealthyAgents     int                `json:"unhealthy_agents"`
	StaleAgents         int                `json:"stale_agents"`
	VersionDistribution map[string]int     `json:"version_distribution"`
	PolicyCompliance    PolicyCompliance   `json:"policy_compliance"`
}

// PolicyCompliance shows how many agents are running the latest policy.
type PolicyCompliance struct {
	Compliant    int `json:"compliant"`
	NonCompliant int `json:"non_compliant"`
	Unassigned   int `json:"unassigned"`
}

// SecuritySummary contains aggregated security metrics across the fleet.
type SecuritySummary struct {
	TotalDecisions    int64             `json:"total_decisions"`
	TotalDenied       int64             `json:"total_denied"`
	ScannerDetections map[string]int64  `json:"scanner_detections"`
	TopTriggeredRules []RuleCount       `json:"top_triggered_rules,omitempty"`
}

// RuleCount pairs a scanner/rule with its count.
type RuleCount struct {
	Scanner string `json:"scanner"`
	Count   int64  `json:"count"`
}
