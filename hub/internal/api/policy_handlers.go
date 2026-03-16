package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/SleuthCo/clawshield/hub/internal/models"
	"github.com/SleuthCo/clawshield/hub/internal/policy"
)

// RegisterPolicyRoutes registers all policy-related HTTP routes with the mux.
func (h *Hub) RegisterPolicyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/policy-groups", h.requireAPIKey(h.HandleCreatePolicyGroup))
	mux.HandleFunc("GET /api/v1/policy-groups", h.requireAPIKey(h.HandleListPolicyGroups))
	mux.HandleFunc("GET /api/v1/policy-groups/", h.requireAPIKey(h.HandleGetPolicyGroup))
	mux.HandleFunc("POST /api/v1/policy-versions", h.requireAPIKey(h.HandleCreatePolicyVersion))
	mux.HandleFunc("GET /api/v1/policy-versions/", h.requireAPIKey(h.HandleGetPolicyVersion))
	mux.HandleFunc("POST /api/v1/policy-versions/{id}/approve", h.requireAPIKey(h.HandleApprovePolicyVersion))
	mux.HandleFunc("POST /api/v1/policy-versions/{id}/publish", h.requireAPIKey(h.HandlePublishPolicyVersion))
	mux.HandleFunc("GET /api/v1/policy-versions/{id}/content", h.requireAPIKey(h.HandleGetPolicyContent))
	mux.HandleFunc("POST /api/v1/agents/{id}/assign-group", h.requireAPIKey(h.HandleAssignAgentToGroup))
}

// HandleCreatePolicyGroup handles POST /api/v1/policy-groups
func (h *Hub) HandleCreatePolicyGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		Name          string `json:"name"`
		ParentGroupID string `json:"parent_group_id"`
		Description   string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	group := models.PolicyGroup{
		GroupID:       uuid.New().String(),
		Name:          req.Name,
		ParentGroupID: req.ParentGroupID,
		Description:   req.Description,
	}

	if err := h.Store.CreatePolicyGroup(group); err != nil {
		log.Printf("error creating policy group: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusCreated, group)
}

// HandleListPolicyGroups handles GET /api/v1/policy-groups
func (h *Hub) HandleListPolicyGroups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	groups, err := h.Store.ListPolicyGroups()
	if err != nil {
		log.Printf("error listing policy groups: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if groups == nil {
		groups = []models.PolicyGroup{}
	}

	writeJSON(w, http.StatusOK, groups)
}

// HandleGetPolicyGroup handles GET /api/v1/policy-groups/{id}
func (h *Hub) HandleGetPolicyGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Extract group ID from path: /api/v1/policy-groups/{id}
	path := r.URL.Path
	const prefix = "/api/v1/policy-groups/"
	if !strings.HasPrefix(path, prefix) {
		writeError(w, http.StatusBadRequest, "invalid path")
		return
	}

	groupID := strings.TrimPrefix(path, prefix)
	if groupID == "" {
		writeError(w, http.StatusBadRequest, "group ID is required")
		return
	}

	// Validate group ID format
	if !validateID(groupID) {
		writeError(w, http.StatusBadRequest, "invalid ID format")
		return
	}

	group, err := h.Store.GetPolicyGroup(groupID)
	if err != nil {
		log.Printf("error retrieving policy group: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if group == nil {
		writeError(w, http.StatusNotFound, "policy group not found")
		return
	}

	writeJSON(w, http.StatusOK, group)
}

// HandleCreatePolicyVersion handles POST /api/v1/policy-versions
func (h *Hub) HandleCreatePolicyVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		GroupID    string `json:"group_id"`
		VersionLabel string `json:"version_label"`
		PolicyYAML string `json:"policy_yaml"`
		CreatedBy  string `json:"created_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if req.GroupID == "" || req.VersionLabel == "" || req.PolicyYAML == "" {
		writeError(w, http.StatusBadRequest, "group_id, version_label, and policy_yaml are required")
		return
	}

	policyHash := policy.ComputePolicyHash(req.PolicyYAML)

	version := models.PolicyVersion{
		VersionID:    uuid.New().String(),
		GroupID:      req.GroupID,
		VersionLabel: req.VersionLabel,
		PolicyYAML:   req.PolicyYAML,
		PolicyHash:   policyHash,
		Status:       "draft",
		CreatedBy:    req.CreatedBy,
	}

	if err := h.Store.CreatePolicyVersion(version); err != nil {
		log.Printf("error creating policy version: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusCreated, version)
}

// HandleGetPolicyVersion handles GET /api/v1/policy-versions/{id}
func (h *Hub) HandleGetPolicyVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Extract version ID from path: /api/v1/policy-versions/{id}
	path := r.URL.Path
	const prefix = "/api/v1/policy-versions/"
	if !strings.HasPrefix(path, prefix) {
		writeError(w, http.StatusBadRequest, "invalid path")
		return
	}

	versionID := strings.TrimPrefix(path, prefix)
	// Remove any trailing path components (e.g., /approve, /publish, /content)
	if idx := strings.Index(versionID, "/"); idx != -1 {
		versionID = versionID[:idx]
	}

	if versionID == "" {
		writeError(w, http.StatusBadRequest, "version ID is required")
		return
	}

	// Validate version ID format
	if !validateID(versionID) {
		writeError(w, http.StatusBadRequest, "invalid ID format")
		return
	}

	version, err := h.Store.GetPolicyVersion(versionID)
	if err != nil {
		log.Printf("error retrieving policy version: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if version == nil {
		writeError(w, http.StatusNotFound, "policy version not found")
		return
	}

	writeJSON(w, http.StatusOK, version)
}

// HandleApprovePolicyVersion handles POST /api/v1/policy-versions/{id}/approve
func (h *Hub) HandleApprovePolicyVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Extract version ID from path: /api/v1/policy-versions/{id}/approve
	versionID := extractIDFromPath(r.URL.Path, "/api/v1/policy-versions/", "/approve")
	if versionID == "" {
		writeError(w, http.StatusBadRequest, "version ID is required")
		return
	}

	// Validate version ID format
	if !validateID(versionID) {
		writeError(w, http.StatusBadRequest, "invalid ID format")
		return
	}

	var req struct {
		ApproverID string `json:"approver_id"`
		Decision   string `json:"decision"`
		Comment    string `json:"comment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if req.ApproverID == "" || req.Decision == "" {
		writeError(w, http.StatusBadRequest, "approver_id and decision are required")
		return
	}

	if req.Decision != "approved" && req.Decision != "rejected" {
		writeError(w, http.StatusBadRequest, "decision must be 'approved' or 'rejected'")
		return
	}

	approval := models.PolicyApproval{
		ApprovalID: uuid.New().String(),
		VersionID:  versionID,
		ApproverID: req.ApproverID,
		Decision:   req.Decision,
		Comment:    req.Comment,
	}

	if err := h.Store.CreatePolicyApproval(approval); err != nil {
		log.Printf("error creating policy approval: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// If approved, update version status
	if req.Decision == "approved" {
		if err := h.Store.UpdatePolicyVersionStatus(versionID, "approved"); err != nil {
			log.Printf("error updating policy version status: %v", err)
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
	}

	writeJSON(w, http.StatusOK, approval)
}

// HandlePublishPolicyVersion handles POST /api/v1/policy-versions/{id}/publish
func (h *Hub) HandlePublishPolicyVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Extract version ID from path: /api/v1/policy-versions/{id}/publish
	versionID := extractIDFromPath(r.URL.Path, "/api/v1/policy-versions/", "/publish")
	if versionID == "" {
		writeError(w, http.StatusBadRequest, "version ID is required")
		return
	}

	// Validate version ID format
	if !validateID(versionID) {
		writeError(w, http.StatusBadRequest, "invalid ID format")
		return
	}

	if err := h.Store.PublishPolicyVersion(versionID); err != nil {
		log.Printf("error publishing policy version: %v", err)
		// Return 400 for business rule violations (e.g., not approved yet)
		if strings.Contains(err.Error(), "cannot publish") || strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusBadRequest, err.Error())
		} else {
			writeError(w, http.StatusInternalServerError, "internal server error")
		}
		return
	}

	version, err := h.Store.GetPolicyVersion(versionID)
	if err != nil {
		log.Printf("error retrieving policy version: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, version)
}

// HandleGetPolicyContent handles GET /api/v1/policy-versions/{id}/content
func (h *Hub) HandleGetPolicyContent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Extract version ID from path: /api/v1/policy-versions/{id}/content
	versionID := extractIDFromPath(r.URL.Path, "/api/v1/policy-versions/", "/content")
	if versionID == "" {
		writeError(w, http.StatusBadRequest, "version ID is required")
		return
	}

	// Validate version ID format
	if !validateID(versionID) {
		writeError(w, http.StatusBadRequest, "invalid ID format")
		return
	}

	version, err := h.Store.GetPolicyVersion(versionID)
	if err != nil {
		log.Printf("error retrieving policy version: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if version == nil {
		writeError(w, http.StatusNotFound, "policy version not found")
		return
	}

	w.Header().Set("Content-Type", "text/x-yaml")
	w.Header().Set("X-Policy-Hash", version.PolicyHash)
	if version.Signature != "" {
		w.Header().Set("X-Policy-Signature", version.Signature)
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(version.PolicyYAML))
}

// HandleAssignAgentToGroup handles POST /api/v1/agents/{id}/assign-group
func (h *Hub) HandleAssignAgentToGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Extract agent ID from path: /api/v1/agents/{id}/assign-group
	agentID := extractIDFromPath(r.URL.Path, "/api/v1/agents/", "/assign-group")
	if agentID == "" {
		writeError(w, http.StatusBadRequest, "agent ID is required")
		return
	}

	// Validate agent ID format
	if !validateID(agentID) {
		writeError(w, http.StatusBadRequest, "invalid ID format")
		return
	}

	var req struct {
		GroupID string `json:"group_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if req.GroupID == "" {
		writeError(w, http.StatusBadRequest, "group_id is required")
		return
	}

	if err := h.Store.AssignAgentToGroup(agentID, req.GroupID); err != nil {
		log.Printf("error assigning agent to group: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	agent, err := h.Store.GetAgent(agentID)
	if err != nil {
		log.Printf("error retrieving agent: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, agent)
}

// BuildPolicyActions checks if an agent has a policy update and returns appropriate actions.
func (h *Hub) BuildPolicyActions(req *models.CheckinRequest) []models.Action {
	// Get the agent to find their policy group
	agent, err := h.Store.GetAgent(req.AgentID)
	if err != nil || agent == nil {
		return []models.Action{}
	}

	if agent.PolicyGroupID == "" {
		return []models.Action{}
	}

	// Get the policy group
	group, err := h.Store.GetPolicyGroup(agent.PolicyGroupID)
	if err != nil || group == nil || group.CurrentPolicyVersionID == "" {
		return []models.Action{}
	}

	// Get the current policy version
	version, err := h.Store.GetPolicyVersion(group.CurrentPolicyVersionID)
	if err != nil || version == nil {
		return []models.Action{}
	}

	// If agent's policy hash matches current, no update needed
	if req.PolicyHash == version.PolicyHash {
		return []models.Action{}
	}

	// Agent needs a policy update
	policyAction := models.PolicyUpdateAction{
		VersionID:  version.VersionID,
		PolicyYAML: version.PolicyYAML,
		Signature:  version.Signature,
		PolicyHash: version.PolicyHash,
	}

	payload, _ := json.Marshal(policyAction)

	return []models.Action{
		{
			Type:    "update_policy",
			Payload: payload,
		},
	}
}

// extractIDFromPath extracts an ID from a URL path between prefix and suffix.
// For example, extractIDFromPath("/api/v1/policy-versions/abc123/approve", "/api/v1/policy-versions/", "/approve") returns "abc123"
func extractIDFromPath(path, prefix, suffix string) string {
	if !strings.HasPrefix(path, prefix) {
		return ""
	}

	path = strings.TrimPrefix(path, prefix)
	if idx := strings.Index(path, suffix); idx != -1 {
		return path[:idx]
	}
	return ""
}
