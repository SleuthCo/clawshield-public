package models

import "time"

// PolicyGroup represents a collection of agents that share the same policy versions.
type PolicyGroup struct {
	GroupID       string    `json:"group_id"`
	Name          string    `json:"name"`
	ParentGroupID string    `json:"parent_group_id,omitempty"`
	Description   string    `json:"description,omitempty"`
	CurrentPolicyVersionID string `json:"current_policy_version_id,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// PolicyVersion represents a specific version of a policy with its lifecycle state.
type PolicyVersion struct {
	VersionID  string    `json:"version_id"`
	GroupID    string    `json:"group_id"`
	VersionLabel string `json:"version_label"`
	PolicyYAML string    `json:"policy_yaml"`
	PolicyHash string    `json:"policy_hash"`
	Signature  string    `json:"signature,omitempty"`
	Status     string    `json:"status"` // draft, approved, published, retired
	CreatedBy  string    `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	PublishedAt time.Time `json:"published_at,omitempty"`
}

// PolicyApproval represents an approval or rejection of a policy version.
type PolicyApproval struct {
	ApprovalID string    `json:"approval_id"`
	VersionID  string    `json:"version_id"`
	ApproverID string    `json:"approver_id"`
	Decision   string    `json:"decision"` // approved, rejected
	Comment    string    `json:"comment,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// PolicyUpdateAction is the payload for an update_policy action.
type PolicyUpdateAction struct {
	VersionID  string `json:"version_id"`
	PolicyYAML string `json:"policy_yaml"`
	Signature  string `json:"signature,omitempty"`
	PolicyHash string `json:"policy_hash"`
}
