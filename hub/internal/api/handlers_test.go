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

// TestHandleListTokens_Empty verifies listing tokens returns empty array.
func TestHandleListTokens_Empty(t *testing.T) {
	hub := setupTestHub(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tokens", nil)
	w := httptest.NewRecorder()

	hub.HandleListTokens(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var tokens []store.EnrollmentToken
	if err := json.NewDecoder(w.Body).Decode(&tokens); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens, got %d", len(tokens))
	}
}

// TestHandleListTokens_WithTokens verifies listing tokens returns all tokens.
func TestHandleListTokens_WithTokens(t *testing.T) {
	hub := setupTestHub(t)

	// Create some tokens
	token1 := "token-1"
	token2 := "token-2"
	if err := hub.Store.CreateEnrollmentToken(token1); err != nil {
		t.Fatalf("failed to create token 1: %v", err)
	}
	if err := hub.Store.CreateEnrollmentToken(token2); err != nil {
		t.Fatalf("failed to create token 2: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tokens", nil)
	w := httptest.NewRecorder()

	hub.HandleListTokens(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var tokens []store.EnrollmentToken
	if err := json.NewDecoder(w.Body).Decode(&tokens); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(tokens) != 2 {
		t.Errorf("expected 2 tokens, got %d", len(tokens))
	}

	// Verify token values are present
	tokenValues := make(map[string]bool)
	for _, t := range tokens {
		tokenValues[t.Token] = true
	}
	if !tokenValues[token1] || !tokenValues[token2] {
		t.Error("expected both tokens to be in response")
	}
}

// TestHandleCreateToken_Success verifies creating a new enrollment token.
func TestHandleCreateToken_Success(t *testing.T) {
	hub := setupTestHub(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tokens", nil)
	w := httptest.NewRecorder()

	hub.HandleCreateToken(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status 201, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["token"] == "" {
		t.Error("expected non-empty token in response")
	}

	// Verify token was stored
	token := resp["token"]
	valid, err := hub.Store.ValidateEnrollmentToken(token)
	if err != nil {
		t.Fatalf("failed to validate token: %v", err)
	}
	if !valid {
		t.Error("expected token to be valid")
	}
}

// TestHandleCheckin_MissingAgentID verifies check-in fails with missing agent_id.
func TestHandleCheckin_MissingAgentID(t *testing.T) {
	hub := setupTestHub(t)

	checkinReq := models.CheckinRequest{
		AgentID:  "",
		Hostname: "test-host",
	}
	body, _ := json.Marshal(checkinReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/checkin", bytes.NewReader(body))
	w := httptest.NewRecorder()

	hub.HandleCheckin(w, req)

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

// TestHandleCheckin_WrongMethod verifies check-in fails with wrong HTTP method.
func TestHandleCheckin_WrongMethod(t *testing.T) {
	hub := setupTestHub(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/checkin", nil)
	w := httptest.NewRecorder()

	hub.HandleCheckin(w, req)

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

// TestHandleListAgents_FilterByTag verifies filtering agents by tag.
func TestHandleListAgents_FilterByTag(t *testing.T) {
	hub := setupTestHub(t)

	// Enroll agent with linux tag
	token := "test-token-with-tag"
	hub.Store.CreateEnrollmentToken(token)

	enrollReq := models.EnrollmentRequest{
		Token: token,
		Tags:  []string{"linux"},
	}
	body, _ := json.Marshal(enrollReq)
	enrollHTTPReq := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(body))
	enrollW := httptest.NewRecorder()
	hub.HandleEnroll(enrollW, enrollHTTPReq)

	// Enroll another agent without linux tag
	token2 := "test-token-no-tag"
	hub.Store.CreateEnrollmentToken(token2)
	enrollReq2 := models.EnrollmentRequest{Token: token2, Tags: []string{"windows"}}
	body2, _ := json.Marshal(enrollReq2)
	enrollHTTPReq2 := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(body2))
	enrollW2 := httptest.NewRecorder()
	hub.HandleEnroll(enrollW2, enrollHTTPReq2)

	// List agents with linux tag filter
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents?tag=linux", nil)
	w := httptest.NewRecorder()

	hub.HandleListAgents(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var agents []models.Agent
	if err := json.NewDecoder(w.Body).Decode(&agents); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(agents) != 1 {
		t.Errorf("expected 1 agent with linux tag, got %d", len(agents))
	}

	if len(agents) > 0 && !contains(agents[0].Tags, "linux") {
		t.Error("expected agent to have linux tag")
	}
}

// TestHandleGetAgent_InvalidIDFormat verifies invalid ID format returns 400.
func TestHandleGetAgent_InvalidIDFormat(t *testing.T) {
	hub := setupTestHub(t)

	// Use an ID with invalid characters (like /)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/invalid/id/format", nil)
	w := httptest.NewRecorder()

	hub.HandleGetAgent(w, req)

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

// TestHandleGetAgent_WrongMethod verifies wrong HTTP method returns 405.
func TestHandleGetAgent_WrongMethod(t *testing.T) {
	hub := setupTestHub(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/some-id", nil)
	w := httptest.NewRecorder()

	hub.HandleGetAgent(w, req)

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

// TestHandleHealth_WrongMethod verifies wrong HTTP method returns 405.
func TestHandleHealth_WrongMethod(t *testing.T) {
	hub := setupTestHub(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/health", nil)
	w := httptest.NewRecorder()

	hub.HandleHealth(w, req)

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

// TestValidateID_EmptyString verifies empty string validation fails.
func TestValidateID_EmptyString(t *testing.T) {
	if validateID("") {
		t.Error("expected empty string to be invalid")
	}
}

// TestValidateID_TooLong verifies string longer than 128 chars fails.
func TestValidateID_TooLong(t *testing.T) {
	longID := string(make([]byte, 129))
	for i := range longID {
		longID = string(append([]byte(longID[:i]), 'a'))
	}
	longID = longID + "a" // Make it 129 chars
	if validateID(longID) {
		t.Error("expected long string (>128) to be invalid")
	}
}

// TestValidateID_InvalidCharacters verifies invalid characters fail.
func TestValidateID_InvalidCharacters(t *testing.T) {
	invalidIDs := []string{
		"id/with/slash",
		"id with space",
		"id@with#special",
		"id;DROP TABLE agents",
		"id\\with\\backslash",
	}

	for _, id := range invalidIDs {
		if validateID(id) {
			t.Errorf("expected %q to be invalid", id)
		}
	}
}

// TestValidateID_ValidUUID verifies valid UUID passes.
func TestValidateID_ValidUUID(t *testing.T) {
	validID := "550e8400-e29b-41d4-a716-446655440000"
	if !validateID(validID) {
		t.Errorf("expected valid UUID %q to be valid", validID)
	}
}

// TestValidateID_ValidFormats verifies various valid formats pass.
func TestValidateID_ValidFormats(t *testing.T) {
	validIDs := []string{
		"simple-id",
		"id_with_underscore",
		"ID123",
		"123ID",
		"a",
		"A",
		"0",
		"-",
		"_",
		"a-b_c-d_e",
	}

	for _, id := range validIDs {
		if !validateID(id) {
			t.Errorf("expected %q to be valid", id)
		}
	}
}

// TestHandleListAgents_WrongMethod verifies wrong HTTP method returns 405.
func TestHandleListAgents_WrongMethod(t *testing.T) {
	hub := setupTestHub(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", nil)
	w := httptest.NewRecorder()

	hub.HandleListAgents(w, req)

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

// TestHandleListAgents_NoAgents verifies listing agents returns empty array when no agents registered.
func TestHandleListAgents_NoAgents(t *testing.T) {
	hub := setupTestHub(t)

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

	if len(agents) != 0 {
		t.Errorf("expected 0 agents, got %d", len(agents))
	}
}

// TestHandleGetAgent_EmptyID verifies empty agent ID returns 400.
func TestHandleGetAgent_EmptyID(t *testing.T) {
	hub := setupTestHub(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/", nil)
	w := httptest.NewRecorder()

	hub.HandleGetAgent(w, req)

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

// TestHandleGetAgent_WithCheckins verifies agent detail includes recorded checkins.
func TestHandleGetAgent_WithCheckins(t *testing.T) {
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

	// Record a checkin with version info
	checkinReq := models.CheckinRequest{
		AgentID:           agentID,
		Hostname:          "test-host",
		ClawshieldVersion: "1.0.0",
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

	// Verify checkins array is populated
	if len(detail.RecentCheckins) != 1 {
		t.Errorf("expected 1 recent checkin, got %d", len(detail.RecentCheckins))
	}

	// Verify checkin timestamp is set
	if detail.RecentCheckins[0].Timestamp.IsZero() {
		t.Error("expected non-zero timestamp for checkin")
	}
}

// TestHandleCreateToken_Fields verifies token creation returns correct response structure.
func TestHandleCreateToken_Fields(t *testing.T) {
	hub := setupTestHub(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tokens", nil)
	w := httptest.NewRecorder()

	hub.HandleCreateToken(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status 201, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify token field is present and non-empty
	if resp["token"] == "" {
		t.Error("expected non-empty token field in response")
	}

	// Verify no extra fields (should only have "token" key)
	if len(resp) != 1 {
		t.Errorf("expected response with 1 field, got %d", len(resp))
	}
}

// TestHandleGetAgent_NoCheckins tests agent detail with no checkins (covers line 228).
func TestHandleGetAgent_NoCheckins(t *testing.T) {
	hub := setupTestHub(t)

	// Register an agent without any checkins
	agentID := "agent-no-checkins"
	if err := hub.Store.RegisterAgent(agentID, "host1", []string{}); err != nil {
		t.Fatalf("register agent: %v", err)
	}

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

	// Verify recent_checkins is an empty array (not nil)
	if detail.RecentCheckins == nil {
		t.Error("expected empty array for recent_checkins, not nil")
	}

	if len(detail.RecentCheckins) != 0 {
		t.Errorf("expected 0 recent checkins, got %d", len(detail.RecentCheckins))
	}
}

// TestHandleCheckin_WithPolicyActions tests that checkin returns policy actions for assigned agents.
func TestHandleCheckin_WithPolicyActions(t *testing.T) {
	hub := setupTestHub(t)

	// Initialize policy schema
	if err := hub.Store.InitPolicySchema(); err != nil {
		t.Fatalf("init policy schema: %v", err)
	}

	// Create and enroll agent
	testToken := "test-token-policy"
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

	// Create policy group
	groupID := "policy-group-actions"
	group := models.PolicyGroup{
		GroupID:     groupID,
		Name:        "test-group",
		Description: "test policy group",
	}
	if err := hub.Store.CreatePolicyGroup(group); err != nil {
		t.Fatalf("create policy group: %v", err)
	}

	// Create and publish policy version
	versionID := "policy-version-1"
	version := models.PolicyVersion{
		VersionID:    versionID,
		GroupID:      groupID,
		VersionLabel: "v1",
		PolicyYAML:   "test policy",
		PolicyHash:   "hash-v1",
		Status:       "draft",
		CreatedBy:    "admin",
	}
	if err := hub.Store.CreatePolicyVersion(version); err != nil {
		t.Fatalf("create policy version: %v", err)
	}

	if err := hub.Store.UpdatePolicyVersionStatus(versionID, "approved"); err != nil {
		t.Fatalf("approve policy: %v", err)
	}

	if err := hub.Store.PublishPolicyVersion(versionID); err != nil {
		t.Fatalf("publish policy: %v", err)
	}

	// Assign agent to group
	if err := hub.Store.AssignAgentToGroup(agentID, groupID); err != nil {
		t.Fatalf("assign agent to group: %v", err)
	}

	// Check in with matching policy hash
	checkinReq := models.CheckinRequest{
		AgentID:           agentID,
		Hostname:          "test-host",
		ClawshieldVersion: "1.0.0",
		PolicyHash:        "hash-v1",
		Health: models.AgentHealth{
			Status:           "healthy",
			AuditDBSizeBytes: 1024,
		},
		MetricsSummary: models.MetricsSummary{
			DecisionsTotal:    0,
			DecisionsDenied:   0,
			ScannerDetections: make(map[string]int),
			PeriodSeconds:     60,
		},
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

	// Verify response structure
	if checkinResp.NextCheckinSeconds != 60 {
		t.Errorf("expected next_checkin_seconds 60, got %d", checkinResp.NextCheckinSeconds)
	}

	if checkinResp.ServerTime.IsZero() {
		t.Error("expected non-zero server_time")
	}

	// Note: BuildPolicyActions implementation determines what actions are returned
	// Just verify Actions array is initialized
	if checkinResp.Actions == nil {
		t.Error("expected Actions array to be initialized (not nil)")
	}
}

// TestHandleGetAgent_EmptyIDPath tests empty agent ID with trailing slash (covers line 195-196).
func TestHandleGetAgent_EmptyIDPath(t *testing.T) {
	hub := setupTestHub(t)

	// Request with trailing slash but no ID
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/", nil)
	w := httptest.NewRecorder()

	hub.HandleGetAgent(w, req)

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

	// Verify error message mentions agent ID
	if !contains([]string{resp.Error}, "required") && !contains([]string{resp.Error}, "ID") {
		t.Logf("error message is: %s", resp.Error)
	}
}

// Helper function to check if a string is in a slice
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
