package models

import "time"

// UpdateRelease represents a published ClawShield version available for deployment.
type UpdateRelease struct {
	ReleaseID    string    `json:"release_id"`
	Version      string    `json:"version"`
	BinaryHash   string    `json:"binary_hash"`   // SHA-256 hash of the binary
	Signature    string    `json:"signature"`     // RSA-SHA256 signature of the binary hash
	ReleaseNotes string    `json:"release_notes,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

// UpdateTask represents a pending update assignment for a specific agent.
type UpdateTask struct {
	TaskID        string    `json:"task_id"`
	AgentID       string    `json:"agent_id"`
	TargetVersion string    `json:"target_version"`
	BinaryHash    string    `json:"binary_hash"`
	Signature     string    `json:"signature"`
	Status        string    `json:"status"` // pending, in_progress, completed, failed, rolled_back
	Wave          string    `json:"wave"`   // canary, wave1, wave2, full
	ScheduledAt   time.Time `json:"scheduled_at"`
	CompletedAt   time.Time `json:"completed_at,omitempty"`
	ErrorMessage  string    `json:"error_message,omitempty"`
}

// UpdateRollout represents a fleet-wide rollout of a new version.
type UpdateRollout struct {
	RolloutID   string     `json:"rollout_id"`
	ReleaseID   string     `json:"release_id"`
	Status      string     `json:"status"` // active, paused, completed, rolled_back
	WaveConfig  WaveConfig `json:"wave_config"`
	CurrentWave string     `json:"current_wave"`
	CreatedAt   time.Time  `json:"created_at"`
}

// WaveConfig defines the rollout wave percentages.
type WaveConfig struct {
	CanaryPercent int `json:"canary_percent"` // e.g., 5
	Wave1Percent  int `json:"wave1_percent"`  // e.g., 25
	Wave2Percent  int `json:"wave2_percent"`  // e.g., 50
	// Remainder goes to 'full' wave
}

// UpdateBinaryAction is the payload for an update_binary action sent to agents.
type UpdateBinaryAction struct {
	Version    string `json:"version"`
	BinaryHash string `json:"binary_hash"`
	Signature  string `json:"signature"`
	DownloadURL string `json:"download_url"`
}
