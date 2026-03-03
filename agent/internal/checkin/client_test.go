package checkin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SleuthCo/clawshield/shared/models"
)

// TestEnroll_Success verifies successful enrollment.
func TestEnroll_Success(t *testing.T) {
	// Create a mock Hub server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/enroll" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		response := models.EnrollmentResponse{
			AgentID: "agent-12345",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewClient(server.URL)
	result, err := client.Enroll("token123", "hostname", []string{"tag1", "tag2"})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.AgentID != "agent-12345" {
		t.Errorf("expected agent ID agent-12345, got %s", result.AgentID)
	}
}

// TestEnroll_InvalidToken verifies error handling for 401 status.
func TestEnroll_InvalidToken(t *testing.T) {
	// Create a mock Hub server that returns 401
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("invalid token"))
	}))
	defer server.Close()

	client := NewClient(server.URL)
	result, err := client.Enroll("badtoken", "hostname", []string{})

	if err == nil {
		t.Error("expected error for 401 status")
	}
	if result != nil {
		t.Error("expected nil result on error")
	}
}

// TestEnroll_ServerError verifies error handling for 500 status.
func TestEnroll_ServerError(t *testing.T) {
	// Create a mock Hub server that returns 500
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	}))
	defer server.Close()

	client := NewClient(server.URL)
	result, err := client.Enroll("token123", "hostname", []string{})

	if err == nil {
		t.Error("expected error for 500 status")
	}
	if result != nil {
		t.Error("expected nil result on error")
	}
}

// TestCheckin_Success verifies successful check-in.
func TestCheckin_Success(t *testing.T) {
	// Create a mock Hub server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/checkin" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		response := models.CheckinResponse{
			Actions:            []models.Action{},
			NextCheckinSeconds: 60,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewClient(server.URL)
	health := models.AgentHealth{
		Status:           "healthy",
		AuditDBSizeBytes: 1024,
		QueueDepth:       0,
	}
	req := &models.CheckinRequest{
		AgentID:           "agent-12345",
		Hostname:          "test-host",
		ClawshieldVersion: "1.0.0",
		AgentVersion:      "1.0.0",
		Health:            health,
	}
	result, err := client.Checkin(req)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Actions) != 0 {
		t.Errorf("expected 0 actions, got %d", len(result.Actions))
	}
}

// TestCheckin_WithActions verifies that actions are parsed correctly.
func TestCheckin_WithActions(t *testing.T) {
	// Create a mock Hub server that returns actions
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := models.CheckinResponse{
			Actions: []models.Action{
				{
					Type: "update_policy",
				},
				{
					Type: "restart_proxy",
				},
			},
			NextCheckinSeconds: 60,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewClient(server.URL)
	health := models.AgentHealth{
		Status:           "healthy",
		AuditDBSizeBytes: 1024,
		QueueDepth:       0,
	}
	req := &models.CheckinRequest{
		AgentID:           "agent-12345",
		Hostname:          "test-host",
		ClawshieldVersion: "1.0.0",
		AgentVersion:      "1.0.0",
		Health:            health,
	}
	result, err := client.Checkin(req)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Actions) != 2 {
		t.Errorf("expected 2 actions, got %d", len(result.Actions))
	}
	if result.Actions[0].Type != "update_policy" {
		t.Errorf("expected action type update_policy, got %s", result.Actions[0].Type)
	}
}

// TestCheckin_HubUnreachable verifies error handling when hub is unreachable.
func TestCheckin_HubUnreachable(t *testing.T) {
	client := NewClient("http://invalid-host-that-does-not-exist:99999")
	health := models.AgentHealth{
		Status:           "healthy",
		AuditDBSizeBytes: 1024,
		QueueDepth:       0,
	}
	req := &models.CheckinRequest{
		AgentID:           "agent-12345",
		Hostname:          "test-host",
		ClawshieldVersion: "1.0.0",
		AgentVersion:      "1.0.0",
		Health:            health,
	}
	result, err := client.Checkin(req)

	if err == nil {
		t.Error("expected error for unreachable hub")
	}
	if result != nil {
		t.Error("expected nil result on error")
	}
}
