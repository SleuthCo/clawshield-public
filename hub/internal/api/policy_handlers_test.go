package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SleuthCo/clawshield/hub/internal/models"
)

// authedRequest creates an httptest.Request with the test API key auth header.
func authedRequest(method, target string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, target, body)
	req.Header.Set("Authorization", "Bearer test-api-key")
	return req
}

func TestPolicyGroupCRUD_API(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	mux := http.NewServeMux()
	h.RegisterPolicyRoutes(mux)

	// Test: Create a policy group
	createReq := struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}{
		Name:        "Production",
		Description: "Production policy group",
	}
	body, _ := json.Marshal(createReq)
	req := authedRequest("POST", "/api/v1/policy-groups", bytes.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	var groupResp models.PolicyGroup
	json.Unmarshal(w.Body.Bytes(), &groupResp)
	groupID := groupResp.GroupID

	if groupResp.Name != "Production" {
		t.Errorf("expected name 'Production', got '%s'", groupResp.Name)
	}

	// Test: List policy groups
	req = authedRequest("GET", "/api/v1/policy-groups", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var groups []models.PolicyGroup
	json.Unmarshal(w.Body.Bytes(), &groups)

	if len(groups) != 1 {
		t.Errorf("expected 1 group, got %d", len(groups))
	}

	// Test: Get policy group by ID
	req = authedRequest("GET", "/api/v1/policy-groups/"+groupID, nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var getResp models.PolicyGroup
	json.Unmarshal(w.Body.Bytes(), &getResp)

	if getResp.GroupID != groupID {
		t.Errorf("expected group ID '%s', got '%s'", groupID, getResp.GroupID)
	}

	// Test: Get non-existent group
	req = authedRequest("GET", "/api/v1/policy-groups/nonexistent", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestPolicyVersionLifecycle_API(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	mux := http.NewServeMux()
	h.RegisterPolicyRoutes(mux)

	// Create a policy group first
	group := models.PolicyGroup{
		GroupID: "test-group",
		Name:    "Test Group",
	}
	h.Store.CreatePolicyGroup(group)

	// Test: Create a policy version
	versionReq := struct {
		GroupID      string `json:"group_id"`
		VersionLabel string `json:"version_label"`
		PolicyYAML   string `json:"policy_yaml"`
		CreatedBy    string `json:"created_by"`
	}{
		GroupID:      "test-group",
		VersionLabel: "v1.0",
		PolicyYAML:   "rules:\n  - allow: all",
		CreatedBy:    "admin",
	}
	body, _ := json.Marshal(versionReq)
	req := authedRequest("POST", "/api/v1/policy-versions", bytes.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	var versionResp models.PolicyVersion
	json.Unmarshal(w.Body.Bytes(), &versionResp)
	versionID := versionResp.VersionID

	if versionResp.Status != "draft" {
		t.Errorf("expected status 'draft', got '%s'", versionResp.Status)
	}

	// Test: Get policy version
	req = authedRequest("GET", "/api/v1/policy-versions/"+versionID, nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// Test: Approve policy version
	approveReq := struct {
		ApproverID string `json:"approver_id"`
		Decision   string `json:"decision"`
		Comment    string `json:"comment"`
	}{
		ApproverID: "approver1",
		Decision:   "approved",
		Comment:    "Looks good",
	}
	body, _ = json.Marshal(approveReq)
	req = authedRequest("POST", "/api/v1/policy-versions/"+versionID+"/approve", bytes.NewReader(body))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// Verify status was updated to approved
	version, _ := h.Store.GetPolicyVersion(versionID)
	if version.Status != "approved" {
		t.Errorf("expected status 'approved', got '%s'", version.Status)
	}

	// Test: Publish policy version
	req = authedRequest("POST", "/api/v1/policy-versions/"+versionID+"/publish", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var publishResp models.PolicyVersion
	json.Unmarshal(w.Body.Bytes(), &publishResp)

	if publishResp.Status != "published" {
		t.Errorf("expected status 'published', got '%s'", publishResp.Status)
	}

	// Test: Get policy content
	req = authedRequest("GET", "/api/v1/policy-versions/"+versionID+"/content", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	if w.Header().Get("Content-Type") != "text/x-yaml" {
		t.Errorf("expected Content-Type 'text/x-yaml', got '%s'", w.Header().Get("Content-Type"))
	}

	if string(w.Body.Bytes()) != "rules:\n  - allow: all" {
		t.Errorf("expected policy YAML in body, got '%s'", w.Body.String())
	}

	hash := w.Header().Get("X-Policy-Hash")
	if hash == "" {
		t.Error("expected X-Policy-Hash header")
	}
}

func TestAssignAgentToGroup_API(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	h.RegisterPolicyRoutes(mux)

	// Enroll an agent
	enrollReq := models.EnrollmentRequest{
		Token:    "test-token",
		Hostname: "test-host",
	}
	h.Store.CreateEnrollmentToken("test-token")
	body, _ := json.Marshal(enrollReq)
	req := httptest.NewRequest("POST", "/api/v1/enroll", bytes.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var enrollResp models.EnrollmentResponse
	json.Unmarshal(w.Body.Bytes(), &enrollResp)
	agentID := enrollResp.AgentID

	// Create a policy group
	group := models.PolicyGroup{
		GroupID: "test-group",
		Name:    "Test Group",
	}
	h.Store.CreatePolicyGroup(group)

	// Test: Assign agent to group
	assignReq := struct {
		GroupID string `json:"group_id"`
	}{
		GroupID: "test-group",
	}
	body, _ = json.Marshal(assignReq)
	req = authedRequest("POST", "/api/v1/agents/"+agentID+"/assign-group", bytes.NewReader(body))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var agentResp models.Agent
	json.Unmarshal(w.Body.Bytes(), &agentResp)

	if agentResp.PolicyGroupID != "test-group" {
		t.Errorf("expected policy_group_id 'test-group', got '%s'", agentResp.PolicyGroupID)
	}
}

func TestCheckinWithPolicyUpdate(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	h.RegisterPolicyRoutes(mux)

	// Enroll an agent
	enrollReq := models.EnrollmentRequest{
		Token:    "test-token",
		Hostname: "test-host",
	}
	h.Store.CreateEnrollmentToken("test-token")
	body, _ := json.Marshal(enrollReq)
	req := httptest.NewRequest("POST", "/api/v1/enroll", bytes.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var enrollResp models.EnrollmentResponse
	json.Unmarshal(w.Body.Bytes(), &enrollResp)
	agentID := enrollResp.AgentID

	// Create a policy group
	group := models.PolicyGroup{
		GroupID: "test-group",
		Name:    "Test Group",
	}
	h.Store.CreatePolicyGroup(group)

	// Assign agent to group
	h.Store.AssignAgentToGroup(agentID, "test-group")

	// Create and publish a policy version
	version := models.PolicyVersion{
		VersionID:    "v1",
		GroupID:      "test-group",
		VersionLabel: "v1.0",
		PolicyYAML:   "rules:\n  - allow: all",
		PolicyHash:   "abc123",
		Status:       "draft",
		CreatedBy:    "admin",
	}
	h.Store.CreatePolicyVersion(version)

	// Approve it
	approval := models.PolicyApproval{
		ApprovalID: "a1",
		VersionID:  "v1",
		ApproverID: "approver1",
		Decision:   "approved",
	}
	h.Store.CreatePolicyApproval(approval)
	h.Store.UpdatePolicyVersionStatus("v1", "approved")

	// Publish it
	h.Store.PublishPolicyVersion("v1")

	// Agent checkin with old policy hash
	checkinReq := models.CheckinRequest{
		AgentID:           agentID,
		Hostname:          "test-host",
		ClawshieldVersion: "1.0",
		AgentVersion:      "1.0",
		PolicyHash:        "old-hash", // Different from the published policy
		PolicyVersion:     "v0",
		Health:            models.AgentHealth{Status: "healthy"},
		MetricsSummary:    models.MetricsSummary{},
	}
	body, _ = json.Marshal(checkinReq)
	req = httptest.NewRequest("POST", "/api/v1/checkin", bytes.NewReader(body))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var checkinResp models.CheckinResponse
	json.Unmarshal(w.Body.Bytes(), &checkinResp)

	// Should have update_policy action
	if len(checkinResp.Actions) != 1 {
		t.Errorf("expected 1 action, got %d", len(checkinResp.Actions))
	}

	if checkinResp.Actions[0].Type != "update_policy" {
		t.Errorf("expected action type 'update_policy', got '%s'", checkinResp.Actions[0].Type)
	}

	var policyAction models.PolicyUpdateAction
	json.Unmarshal(checkinResp.Actions[0].Payload, &policyAction)

	if policyAction.VersionID != "v1" {
		t.Errorf("expected version_id 'v1', got '%s'", policyAction.VersionID)
	}

	if policyAction.PolicyYAML != "rules:\n  - allow: all" {
		t.Errorf("expected policy YAML to match")
	}

	// Agent checkin with matching policy hash (should have no actions)
	checkinReq.PolicyHash = "abc123"
	body, _ = json.Marshal(checkinReq)
	req = httptest.NewRequest("POST", "/api/v1/checkin", bytes.NewReader(body))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	json.Unmarshal(w.Body.Bytes(), &checkinResp)

	if len(checkinResp.Actions) != 0 {
		t.Errorf("expected 0 actions when policy hash matches, got %d", len(checkinResp.Actions))
	}
}

