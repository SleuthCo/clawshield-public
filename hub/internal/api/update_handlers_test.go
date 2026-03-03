package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SleuthCo/clawshield/hub/internal/models"
)

// TestReleaseAndRollout_API tests creating a release and starting a rollout via API.
func TestReleaseAndRollout_API(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitUpdateSchema(); err != nil {
		t.Fatalf("InitUpdateSchema failed: %v", err)
	}

	// Create a release
	releasePayload := struct {
		Version      string `json:"version"`
		BinaryHash   string `json:"binary_hash"`
		Signature    string `json:"signature"`
		ReleaseNotes string `json:"release_notes,omitempty"`
	}{
		Version:      "1.5.0",
		BinaryHash:   "abc123",
		Signature:    "sig123",
		ReleaseNotes: "Bug fixes",
	}

	body, err := json.Marshal(releasePayload)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	req := httptest.NewRequest("POST", "/api/v1/releases", bytes.NewReader(body))
	w := httptest.NewRecorder()
	hub.HandleCreateRelease(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, w.Code)
	}

	var release models.UpdateRelease
	if err := json.NewDecoder(w.Body).Decode(&release); err != nil {
		t.Fatalf("json.Decode failed: %v", err)
	}

	if release.Version != "1.5.0" {
		t.Errorf("Expected version 1.5.0, got %s", release.Version)
	}
	if release.BinaryHash != "abc123" {
		t.Errorf("Expected binary_hash abc123, got %s", release.BinaryHash)
	}

	releaseID := release.ReleaseID

	// Register some agents for rollout
	for i := 1; i <= 10; i++ {
		agentID := "agent-00" + string(rune('0'+i))
		if err := hub.Store.RegisterAgent(agentID, "host"+string(rune('0'+i)), []string{}); err != nil {
			t.Fatalf("RegisterAgent failed: %v", err)
		}
	}

	// Create a rollout
	rolloutPayload := struct {
		ReleaseID  string                 `json:"release_id"`
		WaveConfig models.WaveConfig `json:"wave_config"`
	}{
		ReleaseID: releaseID,
		WaveConfig: models.WaveConfig{
			CanaryPercent: 20, // 2 out of 10
			Wave1Percent:  50,
			Wave2Percent:  80,
		},
	}

	body, err = json.Marshal(rolloutPayload)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	req = httptest.NewRequest("POST", "/api/v1/rollouts", bytes.NewReader(body))
	w = httptest.NewRecorder()
	hub.HandleCreateRollout(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, w.Code)
	}

	var rollout models.UpdateRollout
	if err := json.NewDecoder(w.Body).Decode(&rollout); err != nil {
		t.Fatalf("json.Decode failed: %v", err)
	}

	if rollout.Status != "active" {
		t.Errorf("Expected status active, got %s", rollout.Status)
	}
	if rollout.CurrentWave != "canary" {
		t.Errorf("Expected current_wave canary, got %s", rollout.CurrentWave)
	}

	rolloutID := rollout.RolloutID

	// Get rollout status with stats
	req = httptest.NewRequest("GET", "/api/v1/rollouts/"+rolloutID, nil)
	w = httptest.NewRecorder()
	hub.HandleGetRollout(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var rolloutResp struct {
		*models.UpdateRollout
		TaskStats struct {
			Total     int `json:"total"`
			Completed int `json:"completed"`
			Failed    int `json:"failed"`
		} `json:"task_stats"`
	}
	if err := json.NewDecoder(w.Body).Decode(&rolloutResp); err != nil {
		t.Fatalf("json.Decode failed: %v", err)
	}

	if rolloutResp.TaskStats.Total != 2 {
		t.Errorf("Expected 2 canary tasks, got %d", rolloutResp.TaskStats.Total)
	}
}
