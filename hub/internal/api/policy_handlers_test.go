package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SleuthCo/clawshield/hub/internal/models"
)

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
	req := httptest.NewRequest("POST", "/api/v1/policy-groups", bytes.NewReader(body))
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
	req = httptest.NewRequest("GET", "/api/v1/policy-groups", nil)
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
	req = httptest.NewRequest("GET", "/api/v1/policy-groups/"+groupID, nil)
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
	req = httptest.NewRequest("GET", "/api/v1/policy-groups/nonexistent", nil)
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
	req := httptest.NewRequest("POST", "/api/v1/policy-versions", bytes.NewReader(body))
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
	req = httptest.NewRequest("GET", "/api/v1/policy-versions/"+versionID, nil)
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
	req = httptest.NewRequest("POST", "/api/v1/policy-versions/"+versionID+"/approve", bytes.NewReader(body))
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
	req = httptest.NewRequest("POST", "/api/v1/policy-versions/"+versionID+"/publish", nil)
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
	req = httptest.NewRequest("GET", "/api/v1/policy-versions/"+versionID+"/content", nil)
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
	req = httptest.NewRequest("POST", "/api/v1/agents/"+agentID+"/assign-group", bytes.NewReader(body))
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

// TestCreatePolicyGroupWithBadJSON tests error handling with malformed JSON.
func TestCreatePolicyGroupWithBadJSON(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	mux := http.NewServeMux()
	h.RegisterPolicyRoutes(mux)

	req := httptest.NewRequest("POST", "/api/v1/policy-groups", bytes.NewReader([]byte("invalid json")))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestCreatePolicyGroupWithMissingName tests error handling with missing name field.
func TestCreatePolicyGroupWithMissingName(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	mux := http.NewServeMux()
	h.RegisterPolicyRoutes(mux)

	createReq := struct {
		Description string `json:"description"`
	}{
		Description: "A policy group without a name",
	}

	body, _ := json.Marshal(createReq)
	req := httptest.NewRequest("POST", "/api/v1/policy-groups", bytes.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestCreatePolicyVersionWithBadJSON tests error handling with malformed JSON.
func TestCreatePolicyVersionWithBadJSON(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	mux := http.NewServeMux()
	h.RegisterPolicyRoutes(mux)

	req := httptest.NewRequest("POST", "/api/v1/policy-versions", bytes.NewReader([]byte("invalid json")))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestCreatePolicyVersionWithMissingFields tests error handling with missing required fields.
func TestCreatePolicyVersionWithMissingFields(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	mux := http.NewServeMux()
	h.RegisterPolicyRoutes(mux)

	tests := []struct {
		name string
		req  interface{}
	}{
		{
			name: "missing group_id",
			req: struct {
				VersionLabel string `json:"version_label"`
				PolicyYAML   string `json:"policy_yaml"`
				CreatedBy    string `json:"created_by"`
			}{
				VersionLabel: "v1.0",
				PolicyYAML:   "rules:\n  - allow: all",
				CreatedBy:    "admin",
			},
		},
		{
			name: "missing version_label",
			req: struct {
				GroupID    string `json:"group_id"`
				PolicyYAML string `json:"policy_yaml"`
				CreatedBy  string `json:"created_by"`
			}{
				GroupID:    "group-1",
				PolicyYAML: "rules:\n  - allow: all",
				CreatedBy:  "admin",
			},
		},
		{
			name: "missing policy_yaml",
			req: struct {
				GroupID      string `json:"group_id"`
				VersionLabel string `json:"version_label"`
				CreatedBy    string `json:"created_by"`
			}{
				GroupID:      "group-1",
				VersionLabel: "v1.0",
				CreatedBy:    "admin",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.req)
			req := httptest.NewRequest("POST", "/api/v1/policy-versions", bytes.NewReader(body))
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected status 400, got %d", w.Code)
			}
		})
	}
}

// TestApprovePolicyVersionFlow tests the complete approval workflow.
func TestApprovePolicyVersionFlow(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	mux := http.NewServeMux()
	h.RegisterPolicyRoutes(mux)

	// Create a policy group
	group := models.PolicyGroup{
		GroupID: "test-group",
		Name:    "Test Group",
	}
	h.Store.CreatePolicyGroup(group)

	// Create a policy version
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
	req := httptest.NewRequest("POST", "/api/v1/policy-versions", bytes.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var versionResp models.PolicyVersion
	json.Unmarshal(w.Body.Bytes(), &versionResp)
	versionID := versionResp.VersionID

	// Verify status is draft
	if versionResp.Status != "draft" {
		t.Errorf("expected status 'draft', got '%s'", versionResp.Status)
	}

	// Approve the version
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
	req = httptest.NewRequest("POST", "/api/v1/policy-versions/"+versionID+"/approve", bytes.NewReader(body))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	// Verify version status is now approved
	version, _ := h.Store.GetPolicyVersion(versionID)
	if version.Status != "approved" {
		t.Errorf("expected status 'approved', got '%s'", version.Status)
	}
}

// TestPublishPolicyVersionAfterApproval tests publishing an approved policy version.
func TestPublishPolicyVersionAfterApproval(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	mux := http.NewServeMux()
	h.RegisterPolicyRoutes(mux)

	// Create a policy group
	group := models.PolicyGroup{
		GroupID: "test-group",
		Name:    "Test Group",
	}
	h.Store.CreatePolicyGroup(group)

	// Create a policy version
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
	req := httptest.NewRequest("POST", "/api/v1/policy-versions", bytes.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var versionResp models.PolicyVersion
	json.Unmarshal(w.Body.Bytes(), &versionResp)
	versionID := versionResp.VersionID

	// Approve the version
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
	req = httptest.NewRequest("POST", "/api/v1/policy-versions/"+versionID+"/approve", bytes.NewReader(body))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	// Publish the version
	req = httptest.NewRequest("POST", "/api/v1/policy-versions/"+versionID+"/publish", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var publishResp models.PolicyVersion
	json.Unmarshal(w.Body.Bytes(), &publishResp)

	if publishResp.Status != "published" {
		t.Errorf("expected status 'published', got '%s'", publishResp.Status)
	}
}

// TestGetPolicyContentForNonExistentVersion tests error handling for missing version.
func TestGetPolicyContentForNonExistentVersion(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	mux := http.NewServeMux()
	h.RegisterPolicyRoutes(mux)

	req := httptest.NewRequest("GET", "/api/v1/policy-versions/nonexistent-version/content", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", w.Code)
	}
}

// TestAssignAgentToGroupWithBadJSON tests error handling with malformed JSON.
func TestAssignAgentToGroupWithBadJSON(t *testing.T) {
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

	// Try to assign with bad JSON
	req = httptest.NewRequest("POST", "/api/v1/agents/"+agentID+"/assign-group", bytes.NewReader([]byte("invalid json")))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestAssignAgentToGroupWithMissingGroupID tests error handling with missing group_id field.
func TestAssignAgentToGroupWithMissingGroupID(t *testing.T) {
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

	// Try to assign with missing group_id
	assignReq := struct {
		GroupID string `json:"group_id"`
	}{
		GroupID: "",
	}
	body, _ = json.Marshal(assignReq)
	req = httptest.NewRequest("POST", "/api/v1/agents/"+agentID+"/assign-group", bytes.NewReader(body))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestHandleListPolicyGroupsWrongMethod tests that direct handler call with wrong method returns 405
func TestHandleListPolicyGroupsWrongMethod(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	// Call handler directly with wrong method
	req := httptest.NewRequest("POST", "/api/v1/policy-groups", nil)
	w := httptest.NewRecorder()
	h.HandleListPolicyGroups(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

// TestHandleListPolicyGroupsWithCreatedGroups tests listing returns created groups
func TestHandleListPolicyGroupsWithCreatedGroups(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	mux := http.NewServeMux()
	h.RegisterPolicyRoutes(mux)

	// Create a policy group
	groupBody := bytes.NewBufferString(`{"name":"test-group","description":"test desc"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policy-groups", groupBody)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	// List groups - should return the created group
	req = httptest.NewRequest("GET", "/api/v1/policy-groups", nil)
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

	if groups[0].Name != "test-group" {
		t.Errorf("expected name 'test-group', got '%s'", groups[0].Name)
	}
}

// TestHandleGetPolicyGroupWrongMethod tests POST to GET-only endpoint
func TestHandleGetPolicyGroupWrongMethod(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	mux := http.NewServeMux()
	h.RegisterPolicyRoutes(mux)

	// Try POST instead of GET
	req := httptest.NewRequest("POST", "/api/v1/policy-groups/test-id", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

// TestHandleGetPolicyGroupInvalidIDFormat tests ID validation with special characters
func TestHandleGetPolicyGroupInvalidIDFormat(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	// Call handler directly with invalid ID containing special chars
	req := httptest.NewRequest("GET", "/api/v1/policy-groups/id@with#special", nil)
	w := httptest.NewRecorder()
	h.HandleGetPolicyGroup(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestHandleGetPolicyGroupEmptyPath tests empty path without ID
func TestHandleGetPolicyGroupEmptyPath(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	mux := http.NewServeMux()
	h.RegisterPolicyRoutes(mux)

	// Request exactly to the base path without an ID
	req := httptest.NewRequest("GET", "/api/v1/policy-groups/", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestHandleGetPolicyGroupNotFound tests with valid but non-existent UUID
func TestHandleGetPolicyGroupNotFound(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	mux := http.NewServeMux()
	h.RegisterPolicyRoutes(mux)

	// Use a valid UUID format that doesn't exist
	validID := "550e8400-e29b-41d4-a716-446655440000"
	req := httptest.NewRequest("GET", "/api/v1/policy-groups/"+validID, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", w.Code)
	}
}

// TestHandleGetPolicyVersionWrongMethod tests POST to GET-only endpoint
func TestHandleGetPolicyVersionWrongMethod(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	mux := http.NewServeMux()
	h.RegisterPolicyRoutes(mux)

	// Try POST instead of GET
	req := httptest.NewRequest("POST", "/api/v1/policy-versions/test-id", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

// TestHandleGetPolicyVersionInvalidPath tests with invalid path prefix
func TestHandleGetPolicyVersionInvalidPath(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	// Call handler directly with wrong prefix
	req := httptest.NewRequest("GET", "/api/v2/policy-versions/test-id", nil)
	w := httptest.NewRecorder()
	h.HandleGetPolicyVersion(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestHandleGetPolicyVersionInvalidIDFormat tests ID validation
func TestHandleGetPolicyVersionInvalidIDFormat(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	mux := http.NewServeMux()
	h.RegisterPolicyRoutes(mux)

	// Try with ID containing special chars that fail validation
	req := httptest.NewRequest("GET", "/api/v1/policy-versions/bad@id#format", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestHandleGetPolicyVersionEmptyID tests with empty version ID
func TestHandleGetPolicyVersionEmptyID(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	mux := http.NewServeMux()
	h.RegisterPolicyRoutes(mux)

	// Request with no ID after prefix
	req := httptest.NewRequest("GET", "/api/v1/policy-versions/", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestHandleGetPolicyVersionNotFound tests with valid but non-existent UUID
func TestHandleGetPolicyVersionNotFound(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	mux := http.NewServeMux()
	h.RegisterPolicyRoutes(mux)

	// Use a valid UUID format that doesn't exist
	validID := "550e8400-e29b-41d4-a716-446655440000"
	req := httptest.NewRequest("GET", "/api/v1/policy-versions/"+validID, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", w.Code)
	}
}

// TestHandleApprovePolicyVersionWrongMethod tests GET to POST-only endpoint
func TestHandleApprovePolicyVersionWrongMethod(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	// Call handler directly with wrong method
	req := httptest.NewRequest("GET", "/api/v1/policy-versions/test-id/approve", nil)
	w := httptest.NewRecorder()
	h.HandleApprovePolicyVersion(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

// TestHandleApprovePolicyVersionEmptyVersionID tests bad path without version ID
func TestHandleApprovePolicyVersionEmptyVersionID(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	// Call handler directly with no ID before /approve
	approveReq := struct {
		ApproverID string `json:"approver_id"`
		Decision   string `json:"decision"`
	}{
		ApproverID: "admin",
		Decision:   "approved",
	}
	body, _ := json.Marshal(approveReq)
	req := httptest.NewRequest("POST", "/api/v1/policy-versions//approve", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleApprovePolicyVersion(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestHandleApprovePolicyVersionInvalidDecision tests with invalid decision value
func TestHandleApprovePolicyVersionInvalidDecision(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	mux := http.NewServeMux()
	h.RegisterPolicyRoutes(mux)

	// Create a policy group and version first
	group := models.PolicyGroup{
		GroupID: "test-group",
		Name:    "Test Group",
	}
	h.Store.CreatePolicyGroup(group)

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
	req := httptest.NewRequest("POST", "/api/v1/policy-versions", bytes.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var versionResp models.PolicyVersion
	json.Unmarshal(w.Body.Bytes(), &versionResp)
	versionID := versionResp.VersionID

	// Try to approve with invalid decision
	approveReq := struct {
		ApproverID string `json:"approver_id"`
		Decision   string `json:"decision"`
	}{
		ApproverID: "admin",
		Decision:   "maybe",
	}
	body, _ = json.Marshal(approveReq)
	req = httptest.NewRequest("POST", "/api/v1/policy-versions/"+versionID+"/approve", bytes.NewReader(body))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestHandleApprovePolicyVersionMissingApproverID tests with empty approver_id
func TestHandleApprovePolicyVersionMissingApproverID(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	mux := http.NewServeMux()
	h.RegisterPolicyRoutes(mux)

	// Create a policy group and version first
	group := models.PolicyGroup{
		GroupID: "test-group",
		Name:    "Test Group",
	}
	h.Store.CreatePolicyGroup(group)

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
	req := httptest.NewRequest("POST", "/api/v1/policy-versions", bytes.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var versionResp models.PolicyVersion
	json.Unmarshal(w.Body.Bytes(), &versionResp)
	versionID := versionResp.VersionID

	// Try to approve without approver_id
	approveReq := struct {
		ApproverID string `json:"approver_id"`
		Decision   string `json:"decision"`
	}{
		ApproverID: "",
		Decision:   "approved",
	}
	body, _ = json.Marshal(approveReq)
	req = httptest.NewRequest("POST", "/api/v1/policy-versions/"+versionID+"/approve", bytes.NewReader(body))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestHandlePublishPolicyVersionWrongMethod tests GET to POST-only endpoint
func TestHandlePublishPolicyVersionWrongMethod(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	// Call handler directly with wrong method
	req := httptest.NewRequest("GET", "/api/v1/policy-versions/test-id/publish", nil)
	w := httptest.NewRecorder()
	h.HandlePublishPolicyVersion(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

// TestHandlePublishPolicyVersionUnapproved tests publishing draft (unapproved) version
func TestHandlePublishPolicyVersionUnapproved(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	mux := http.NewServeMux()
	h.RegisterPolicyRoutes(mux)

	// Create a policy group and version
	group := models.PolicyGroup{
		GroupID: "test-group",
		Name:    "Test Group",
	}
	h.Store.CreatePolicyGroup(group)

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
	req := httptest.NewRequest("POST", "/api/v1/policy-versions", bytes.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var versionResp models.PolicyVersion
	json.Unmarshal(w.Body.Bytes(), &versionResp)
	versionID := versionResp.VersionID

	// Try to publish without approving first
	req = httptest.NewRequest("POST", "/api/v1/policy-versions/"+versionID+"/publish", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestHandleGetPolicyContentWrongMethod tests POST to GET-only endpoint
func TestHandleGetPolicyContentWrongMethod(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	mux := http.NewServeMux()
	h.RegisterPolicyRoutes(mux)

	// Try POST instead of GET
	req := httptest.NewRequest("POST", "/api/v1/policy-versions/test-id/content", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

// TestHandleAssignAgentToGroupInvalidAgentIDFormat tests invalid ID with special chars
func TestHandleAssignAgentToGroupInvalidAgentIDFormat(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	h.RegisterPolicyRoutes(mux)

	// Try with ID containing special chars
	assignReq := struct {
		GroupID string `json:"group_id"`
	}{
		GroupID: "test-group",
	}
	body, _ := json.Marshal(assignReq)
	req := httptest.NewRequest("POST", "/api/v1/agents/bad@id#format/assign-group", bytes.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestExtractIDFromPathBadPrefix tests extractIDFromPath with wrong prefix
func TestExtractIDFromPathBadPrefix(t *testing.T) {
	// Test extractIDFromPath with non-matching prefix
	result := extractIDFromPath("/api/v1/agents/123/assign-group", "/api/v2/agents/", "/assign-group")
	if result != "" {
		t.Errorf("expected empty string for non-matching prefix, got '%s'", result)
	}
}

// TestExtractIDFromPathNoSuffix tests extractIDFromPath with path that doesn't have suffix
func TestExtractIDFromPathNoSuffix(t *testing.T) {
	// Test extractIDFromPath where suffix is missing - should return empty string
	result := extractIDFromPath("/api/v1/agents/123/no-suffix", "/api/v1/agents/", "/assign-group")
	if result != "" {
		t.Errorf("expected empty string when suffix not found, got '%s'", result)
	}
}

// TestExtractIDFromPathEmptyPath tests extractIDFromPath with empty path
func TestExtractIDFromPathEmptyPath(t *testing.T) {
	// Test extractIDFromPath with empty remaining path
	result := extractIDFromPath("/api/v1/agents//assign-group", "/api/v1/agents/", "/assign-group")
	if result != "" {
		t.Errorf("expected empty string for empty ID, got '%s'", result)
	}
}

// TestGetPolicyContentSuccess covers lines 335-363 happy path
func TestGetPolicyContentSuccess(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	mux := http.NewServeMux()
	h.RegisterPolicyRoutes(mux)

	// Create group
	body := bytes.NewBufferString(`{"name":"content-group","description":"test"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policy-groups", body)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	var group struct{ GroupID string `json:"group_id"` }
	json.NewDecoder(w.Body).Decode(&group)

	// Create version
	vBody := bytes.NewBufferString(`{"group_id":"` + group.GroupID + `","version_label":"v1","policy_yaml":"rules:\n  - allow: true\n","created_by":"admin"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/policy-versions", vBody)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	var version struct{ VersionID string `json:"version_id"` }
	json.NewDecoder(w.Body).Decode(&version)

	// Get content
	req = httptest.NewRequest(http.MethodGet, "/api/v1/policy-versions/"+version.VersionID+"/content", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/x-yaml" {
		t.Errorf("expected Content-Type text/x-yaml, got %s", ct)
	}
	if ph := w.Header().Get("X-Policy-Hash"); ph == "" {
		t.Error("expected X-Policy-Hash header")
	}
	if w.Body.String() == "" {
		t.Error("expected non-empty policy YAML body")
	}
}

// TestGetPolicyContentNotFound covers lines 353-355
func TestGetPolicyContentNotFound(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	mux := http.NewServeMux()
	h.RegisterPolicyRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policy-versions/nonexistent-id/content", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// TestGetPolicyContentInvalidID covers line 341
func TestGetPolicyContentInvalidID(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policy-versions/bad!id/content", nil)
	w := httptest.NewRecorder()
	h.HandleGetPolicyContent(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// TestGetPolicyContentEmptyID covers line 335
func TestGetPolicyContentEmptyID(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policy-versions//content", nil)
	w := httptest.NewRecorder()
	h.HandleGetPolicyContent(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// TestApprovePolicyVersionInvalidID covers line 234
func TestApprovePolicyVersionInvalidID(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	body := bytes.NewBufferString(`{"approver_id":"admin","decision":"approved"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policy-versions/bad!id/approve", body)
	w := httptest.NewRecorder()
	h.HandleApprovePolicyVersion(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// TestApprovePolicyVersionBadJSON covers line 244
func TestApprovePolicyVersionBadJSON(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	body := bytes.NewBufferString(`not valid json`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policy-versions/valid-id/approve", body)
	w := httptest.NewRecorder()
	h.HandleApprovePolicyVersion(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// TestPublishPolicyVersionInvalidID covers line 300
func TestPublishPolicyVersionInvalidID(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policy-versions/bad!id/publish", nil)
	w := httptest.NewRecorder()
	h.HandlePublishPolicyVersion(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// TestPublishPolicyVersionEmptyID covers line 294
func TestPublishPolicyVersionEmptyID(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policy-versions//publish", nil)
	w := httptest.NewRecorder()
	h.HandlePublishPolicyVersion(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// TestPublishApprovedPolicyVersion covers lines 304-322 (full happy path)
func TestPublishApprovedPolicyVersion(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	mux := http.NewServeMux()
	h.RegisterPolicyRoutes(mux)

	// Create group
	groupBody := bytes.NewBufferString(`{"name":"publish-test","description":"test"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policy-groups", groupBody)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	var group struct{ GroupID string `json:"group_id"` }
	json.NewDecoder(w.Body).Decode(&group)

	// Create version
	vBody := bytes.NewBufferString(`{"group_id":"` + group.GroupID + `","version_label":"v1","policy_yaml":"rules:\n  - allow: true\n","created_by":"admin"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/policy-versions", vBody)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	var version struct{ VersionID string `json:"version_id"` }
	json.NewDecoder(w.Body).Decode(&version)

	// Approve version
	aBody := bytes.NewBufferString(`{"approver_id":"admin","decision":"approved"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/policy-versions/"+version.VersionID+"/approve", aBody)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("approve failed: expected 200, got %d", w.Code)
	}

	// Publish version
	req = httptest.NewRequest(http.MethodPost, "/api/v1/policy-versions/"+version.VersionID+"/publish", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("publish failed: expected 200, got %d", w.Code)
	}
	var result models.PolicyVersion
	json.NewDecoder(w.Body).Decode(&result)
	if result.Status != "published" {
		t.Errorf("expected status=published, got %s", result.Status)
	}
}

// TestAssignAgentToGroupSuccess covers lines 399-412
func TestAssignAgentToGroupSuccess(t *testing.T) {
	h := setupTestHub(t)
	defer h.Store.Close()
	h.Store.InitPolicySchema()

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	h.RegisterPolicyRoutes(mux)

	// Register an agent
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
	json.NewDecoder(w.Body).Decode(&enrollResp)
	agentID := enrollResp.AgentID

	// Create a policy group
	group := models.PolicyGroup{
		GroupID: "test-group",
		Name:    "Test Group",
	}
	h.Store.CreatePolicyGroup(group)

	// Assign agent to group
	assignReq := struct {
		GroupID string `json:"group_id"`
	}{
		GroupID: "test-group",
	}
	body, _ = json.Marshal(assignReq)
	req = httptest.NewRequest("POST", "/api/v1/agents/"+agentID+"/assign-group", bytes.NewReader(body))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var agentResp models.Agent
	json.NewDecoder(w.Body).Decode(&agentResp)
	if agentResp.PolicyGroupID != "test-group" {
		t.Errorf("expected policy_group_id=test-group, got %s", agentResp.PolicyGroupID)
	}
}
