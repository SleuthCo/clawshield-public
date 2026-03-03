package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SleuthCo/clawshield/hub/internal/models"
	"github.com/SleuthCo/clawshield/hub/internal/store"
)

// setupTestHub creates a test Hub with an in-memory SQLite database.
func setupTestHub(t *testing.T) *Hub {
	s, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}
	return NewHub(s)
}

// TestHandleHealth verifies the health endpoint returns 200 with status ok.
func TestHandleHealth(t *testing.T) {
	hub := setupTestHub(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()

	hub.HandleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp models.HealthResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Status != "ok" {
		t.Errorf("expected status 'ok', got '%s'", resp.Status)
	}

	if resp.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}
}

// TestHandleEnroll_Success verifies successful enrollment.
func TestHandleEnroll_Success(t *testing.T) {
	hub := setupTestHub(t)

	// Create an enrollment token
	testToken := "test-enrollment-token"
	if err := hub.Store.CreateEnrollmentToken(testToken); err != nil {
		t.Fatalf("failed to create enrollment token: %v", err)
	}

	// Enroll with the token
	reqBody := models.EnrollmentRequest{Token: testToken}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(body))
	w := httptest.NewRecorder()

	hub.HandleEnroll(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status 201, got %d", w.Code)
	}

	var resp models.EnrollmentResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.AgentID == "" {
		t.Error("expected non-empty agent_id")
	}

	if resp.CheckinInterval != 60 {
		t.Errorf("expected checkin_interval 60, got %d", resp.CheckinInterval)
	}
}

// TestHandleEnroll_InvalidToken verifies enrollment fails with invalid token.
func TestHandleEnroll_InvalidToken(t *testing.T) {
	hub := setupTestHub(t)

	reqBody := models.EnrollmentRequest{Token: "invalid-token"}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(body))
	w := httptest.NewRecorder()

	hub.HandleEnroll(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}

	var resp models.ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Error == "" {
		t.Error("expected error message")
	}
}

// TestHandleEnroll_BadJSON verifies enrollment fails with invalid JSON.
func TestHandleEnroll_BadJSON(t *testing.T) {
	hub := setupTestHub(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader([]byte("invalid json")))
	w := httptest.NewRecorder()

	hub.HandleEnroll(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}

	var resp models.ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Error == "" {
		t.Error("expected error message")
	}
}

// TestHandleCheckin_Success verifies successful check-in.
func TestHandleCheckin_Success(t *testing.T) {
	hub := setupTestHub(t)

	// First, enroll an agent
	testToken := "test-token"
	if err := hub.Store.CreateEnrollmentToken(testToken); err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	enrollReq := models.EnrollmentRequest{Token: testToken}
	body, _ := json.Marshal(enrollReq)
	enrollHTTPReq := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(body))
	enrollW := httptest.NewRecorder()
	hub.HandleEnroll(enrollW, enrollHTTPReq)

	var enrollResp models.EnrollmentResponse
	json.NewDecoder(enrollW.Body).Decode(&enrollResp)
	agentID := enrollResp.AgentID

	// Now check in
	checkinReq := models.CheckinRequest{
		AgentID:  agentID,
		Hostname: "test-host",
	}
	checkinBody, _ := json.Marshal(checkinReq)
	checkinHTTPReq := httptest.NewRequest(http.MethodPost, "/api/v1/checkin", bytes.NewReader(checkinBody))
	checkinW := httptest.NewRecorder()

	hub.HandleCheckin(checkinW, checkinHTTPReq)

	if checkinW.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", checkinW.Code)
	}

	var checkinResp models.CheckinResponse
	if err := json.NewDecoder(checkinW.Body).Decode(&checkinResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if checkinResp.NextCheckinSeconds != 60 {
		t.Errorf("expected next_checkin_seconds 60, got %d", checkinResp.NextCheckinSeconds)
	}

	if checkinResp.ServerTime.IsZero() {
		t.Error("expected non-zero server_time")
	}
}

// TestHandleCheckin_UnknownAgent verifies check-in fails for unknown agent.
func TestHandleCheckin_UnknownAgent(t *testing.T) {
	hub := setupTestHub(t)

	checkinReq := models.CheckinRequest{
		AgentID:  "unknown-agent",
		Hostname: "test-host",
	}
	body, _ := json.Marshal(checkinReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/checkin", bytes.NewReader(body))
	w := httptest.NewRecorder()

	hub.HandleCheckin(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", w.Code)
	}

	var resp models.ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Error == "" {
		t.Error("expected error message")
	}
}

// TestHandleListAgents verifies listing agents.
func TestHandleListAgents(t *testing.T) {
	hub := setupTestHub(t)

	// Enroll 2 agents
	for i := 0; i < 2; i++ {
		token := "token-" + string(rune(i))
		hub.Store.CreateEnrollmentToken(token)

		enrollReq := models.EnrollmentRequest{Token: token}
		body, _ := json.Marshal(enrollReq)
		enrollHTTPReq := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(body))
		enrollW := httptest.NewRecorder()
		hub.HandleEnroll(enrollW, enrollHTTPReq)
	}

	// List agents
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
	w := httptest.NewRecorder()

	hub.HandleListAgents(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var agents []models.Agent
	if err := json.NewDecoder(w.Body).Decode(&agents); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(agents) != 2 {
		t.Errorf("expected 2 agents, got %d", len(agents))
	}
}

// TestHandleListAgents_FilterByStatus verifies filtering agents by status.
func TestHandleListAgents_FilterByStatus(t *testing.T) {
	hub := setupTestHub(t)

	// Enroll 2 agents
	var agentIDs []string
	for i := 0; i < 2; i++ {
		token := "token-" + string(rune(i))
		hub.Store.CreateEnrollmentToken(token)

		enrollReq := models.EnrollmentRequest{Token: token}
		body, _ := json.Marshal(enrollReq)
		enrollHTTPReq := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(body))
		enrollW := httptest.NewRecorder()
		hub.HandleEnroll(enrollW, enrollHTTPReq)

		var enrollResp models.EnrollmentResponse
		json.NewDecoder(enrollW.Body).Decode(&enrollResp)
		agentIDs = append(agentIDs, enrollResp.AgentID)
	}

	// List agents with healthy status filter
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents?status=healthy", nil)
	w := httptest.NewRecorder()

	hub.HandleListAgents(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var agents []models.Agent
	if err := json.NewDecoder(w.Body).Decode(&agents); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(agents) != 2 {
		t.Errorf("expected 2 healthy agents, got %d", len(agents))
	}

	// Verify all returned agents have healthy status
	for _, agent := range agents {
		if agent.Status != "healthy" {
			t.Errorf("expected healthy status, got %s", agent.Status)
		}
	}
}

// TestHandleGetAgent_Success verifies retrieving a specific agent.
func TestHandleGetAgent_Success(t *testing.T) {
	hub := setupTestHub(t)

	// Enroll an agent
	testToken := "test-token"
	hub.Store.CreateEnrollmentToken(testToken)

	enrollReq := models.EnrollmentRequest{Token: testToken}
	body, _ := json.Marshal(enrollReq)
	enrollHTTPReq := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(body))
	enrollW := httptest.NewRecorder()
	hub.HandleEnroll(enrollW, enrollHTTPReq)

	var enrollResp models.EnrollmentResponse
	json.NewDecoder(enrollW.Body).Decode(&enrollResp)
	agentID := enrollResp.AgentID

	// Record a checkin
	checkinReq := models.CheckinRequest{
		AgentID:  agentID,
		Hostname: "test-host",
	}
	checkinBody, _ := json.Marshal(checkinReq)
	checkinHTTPReq := httptest.NewRequest(http.MethodPost, "/api/v1/checkin", bytes.NewReader(checkinBody))
	checkinW := httptest.NewRecorder()
	hub.HandleCheckin(checkinW, checkinHTTPReq)

	// Get agent details
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/"+agentID, nil)
	w := httptest.NewRecorder()

	hub.HandleGetAgent(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var detail models.AgentDetail
	if err := json.NewDecoder(w.Body).Decode(&detail); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if detail.Agent == nil {
		t.Fatal("expected non-nil agent")
	}

	if detail.Agent.AgentID != agentID {
		t.Errorf("expected agent_id %s, got %s", agentID, detail.Agent.AgentID)
	}

	if len(detail.RecentCheckins) != 1 {
		t.Errorf("expected 1 recent checkin, got %d", len(detail.RecentCheckins))
	}
}

// TestHandleGetAgent_NotFound verifies 404 when agent not found.
func TestHandleGetAgent_NotFound(t *testing.T) {
	hub := setupTestHub(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/unknown-id", nil)
	w := httptest.NewRecorder()

	hub.HandleGetAgent(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", w.Code)
	}

	var resp models.ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Error == "" {
		t.Error("expected error message")
	}
}

// TestHandleEnroll_WrongMethod verifies 405 when using wrong HTTP method.
func TestHandleEnroll_WrongMethod(t *testing.T) {
	hub := setupTestHub(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/enroll", nil)
	w := httptest.NewRecorder()

	hub.HandleEnroll(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}

	var resp models.ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Error == "" {
		t.Error("expected error message")
	}
}
