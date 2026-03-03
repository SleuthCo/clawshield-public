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

// TestHandleListReleases tests listing all releases.
func TestHandleListReleases(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitUpdateSchema(); err != nil {
		t.Fatalf("InitUpdateSchema failed: %v", err)
	}

	// Create a release first
	releasePayload := struct {
		Version    string `json:"version"`
		BinaryHash string `json:"binary_hash"`
		Signature  string `json:"signature"`
	}{
		Version:    "1.0.0",
		BinaryHash: "hash1",
		Signature:  "sig1",
	}

	body, _ := json.Marshal(releasePayload)
	req := httptest.NewRequest("POST", "/api/v1/releases", bytes.NewReader(body))
	w := httptest.NewRecorder()
	hub.HandleCreateRelease(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("Failed to create release: %d", w.Code)
	}

	// Now list releases
	req = httptest.NewRequest("GET", "/api/v1/releases", nil)
	w = httptest.NewRecorder()
	hub.HandleListReleases(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var releases []models.UpdateRelease
	if err := json.NewDecoder(w.Body).Decode(&releases); err != nil {
		t.Fatalf("json.Decode failed: %v", err)
	}

	if len(releases) != 1 {
		t.Errorf("Expected 1 release, got %d", len(releases))
	}
}

// TestHandlePauseRollout tests pausing an active rollout.
func TestHandlePauseRollout(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitUpdateSchema(); err != nil {
		t.Fatalf("InitUpdateSchema failed: %v", err)
	}

	// Create release
	releasePayload := struct {
		Version    string `json:"version"`
		BinaryHash string `json:"binary_hash"`
		Signature  string `json:"signature"`
	}{
		Version:    "1.0.0",
		BinaryHash: "hash1",
		Signature:  "sig1",
	}

	body, _ := json.Marshal(releasePayload)
	req := httptest.NewRequest("POST", "/api/v1/releases", bytes.NewReader(body))
	w := httptest.NewRecorder()
	hub.HandleCreateRelease(w, req)

	var release models.UpdateRelease
	json.NewDecoder(w.Body).Decode(&release)
	releaseID := release.ReleaseID

	// Register agents
	for i := 1; i <= 5; i++ {
		agentID := "agent-pause-" + string(rune('0'+i))
		hub.Store.RegisterAgent(agentID, "host"+string(rune('0'+i)), []string{})
	}

	// Create rollout
	rolloutPayload := struct {
		ReleaseID  string                 `json:"release_id"`
		WaveConfig models.WaveConfig `json:"wave_config"`
	}{
		ReleaseID: releaseID,
		WaveConfig: models.WaveConfig{
			CanaryPercent: 20,
			Wave1Percent:  50,
			Wave2Percent:  80,
		},
	}

	body, _ = json.Marshal(rolloutPayload)
	req = httptest.NewRequest("POST", "/api/v1/rollouts", bytes.NewReader(body))
	w = httptest.NewRecorder()
	hub.HandleCreateRollout(w, req)

	var rollout models.UpdateRollout
	json.NewDecoder(w.Body).Decode(&rollout)
	rolloutID := rollout.RolloutID

	// Pause the rollout
	req = httptest.NewRequest("POST", "/api/v1/rollouts/"+rolloutID+"/pause", nil)
	w = httptest.NewRecorder()
	hub.HandlePauseRollout(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var pausedRollout models.UpdateRollout
	json.NewDecoder(w.Body).Decode(&pausedRollout)

	if pausedRollout.Status != "paused" {
		t.Errorf("Expected status 'paused', got %s", pausedRollout.Status)
	}
}

// TestCreateReleaseWithBadJSON tests error handling with malformed JSON.
func TestCreateReleaseWithBadJSON(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitUpdateSchema(); err != nil {
		t.Fatalf("InitUpdateSchema failed: %v", err)
	}

	req := httptest.NewRequest("POST", "/api/v1/releases", bytes.NewReader([]byte("invalid json")))
	w := httptest.NewRecorder()
	hub.HandleCreateRelease(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// TestCreateReleaseWithMissingFields tests error handling with missing required fields.
func TestCreateReleaseWithMissingFields(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitUpdateSchema(); err != nil {
		t.Fatalf("InitUpdateSchema failed: %v", err)
	}

	tests := []struct {
		name string
		req  interface{}
	}{
		{
			name: "missing version",
			req: struct {
				BinaryHash string `json:"binary_hash"`
				Signature  string `json:"signature"`
			}{
				BinaryHash: "hash1",
				Signature:  "sig1",
			},
		},
		{
			name: "missing binary_hash",
			req: struct {
				Version   string `json:"version"`
				Signature string `json:"signature"`
			}{
				Version:   "1.0.0",
				Signature: "sig1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.req)
			req := httptest.NewRequest("POST", "/api/v1/releases", bytes.NewReader(body))
			w := httptest.NewRecorder()
			hub.HandleCreateRelease(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
			}
		})
	}
}

// TestCreateRolloutWithInvalidReleaseID tests error handling with non-existent release.
func TestCreateRolloutWithInvalidReleaseID(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitUpdateSchema(); err != nil {
		t.Fatalf("InitUpdateSchema failed: %v", err)
	}

	rolloutPayload := struct {
		ReleaseID  string                 `json:"release_id"`
		WaveConfig models.WaveConfig `json:"wave_config"`
	}{
		ReleaseID: "nonexistent-release-id",
		WaveConfig: models.WaveConfig{
			CanaryPercent: 20,
			Wave1Percent:  50,
			Wave2Percent:  80,
		},
	}

	body, _ := json.Marshal(rolloutPayload)
	req := httptest.NewRequest("POST", "/api/v1/rollouts", bytes.NewReader(body))
	w := httptest.NewRecorder()
	hub.HandleCreateRollout(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

// TestGetRolloutWithNonExistentID tests error handling for non-existent rollout.
func TestGetRolloutWithNonExistentID(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitUpdateSchema(); err != nil {
		t.Fatalf("InitUpdateSchema failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/v1/rollouts/nonexistent-rollout-id", nil)
	w := httptest.NewRecorder()
	hub.HandleGetRollout(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

// TestHandleCreateReleaseWrongMethod tests that HandleCreateRelease rejects non-POST requests.
func TestHandleCreateReleaseWrongMethod(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitUpdateSchema(); err != nil {
		t.Fatalf("InitUpdateSchema failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/releases", nil)
	w := httptest.NewRecorder()
	hub.HandleCreateRelease(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

// TestHandleListReleasesWrongMethod tests that HandleListReleases rejects non-GET requests.
func TestHandleListReleasesWrongMethod(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitUpdateSchema(); err != nil {
		t.Fatalf("InitUpdateSchema failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/releases", bytes.NewBufferString(`{}`))
	w := httptest.NewRecorder()
	hub.HandleListReleases(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

// TestHandleListReleasesSuccessfulWithReleases tests listing releases after creating some.
func TestHandleListReleasesSuccessfulWithReleases(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitUpdateSchema(); err != nil {
		t.Fatalf("InitUpdateSchema failed: %v", err)
	}

	// Create two releases
	for i := 1; i <= 2; i++ {
		releasePayload := struct {
			Version    string `json:"version"`
			BinaryHash string `json:"binary_hash"`
			Signature  string `json:"signature"`
		}{
			Version:    "1.0." + string(rune('0'+i)),
			BinaryHash: "hash" + string(rune('0'+i)),
			Signature:  "sig" + string(rune('0'+i)),
		}

		body, _ := json.Marshal(releasePayload)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/releases", bytes.NewReader(body))
		w := httptest.NewRecorder()
		hub.HandleCreateRelease(w, req)

		if w.Code != http.StatusCreated {
			t.Fatalf("Failed to create release %d: %d", i, w.Code)
		}
	}

	// List releases
	req := httptest.NewRequest(http.MethodGet, "/api/v1/releases", nil)
	w := httptest.NewRecorder()
	hub.HandleListReleases(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var releases []models.UpdateRelease
	if err := json.NewDecoder(w.Body).Decode(&releases); err != nil {
		t.Fatalf("json.Decode failed: %v", err)
	}

	if len(releases) != 2 {
		t.Errorf("Expected 2 releases, got %d", len(releases))
	}
}

// TestHandleCreateRolloutWrongMethod tests that HandleCreateRollout rejects non-POST requests.
func TestHandleCreateRolloutWrongMethod(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitUpdateSchema(); err != nil {
		t.Fatalf("InitUpdateSchema failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rollouts", nil)
	w := httptest.NewRecorder()
	hub.HandleCreateRollout(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

// TestHandleCreateRolloutMissingReleaseID tests that HandleCreateRollout rejects empty release_id.
func TestHandleCreateRolloutMissingReleaseID(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitUpdateSchema(); err != nil {
		t.Fatalf("InitUpdateSchema failed: %v", err)
	}

	rolloutPayload := struct {
		ReleaseID  string                 `json:"release_id"`
		WaveConfig models.WaveConfig `json:"wave_config"`
	}{
		ReleaseID: "",
		WaveConfig: models.WaveConfig{
			CanaryPercent: 20,
			Wave1Percent:  50,
			Wave2Percent:  80,
		},
	}

	body, _ := json.Marshal(rolloutPayload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rollouts", bytes.NewReader(body))
	w := httptest.NewRecorder()
	hub.HandleCreateRollout(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// TestHandleCreateRolloutNonExistentRelease tests creating rollout with non-existent release_id.
func TestHandleCreateRolloutNonExistentRelease(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitUpdateSchema(); err != nil {
		t.Fatalf("InitUpdateSchema failed: %v", err)
	}

	rolloutPayload := struct {
		ReleaseID  string                 `json:"release_id"`
		WaveConfig models.WaveConfig `json:"wave_config"`
	}{
		ReleaseID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		WaveConfig: models.WaveConfig{
			CanaryPercent: 20,
			Wave1Percent:  50,
			Wave2Percent:  80,
		},
	}

	body, _ := json.Marshal(rolloutPayload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rollouts", bytes.NewReader(body))
	w := httptest.NewRecorder()
	hub.HandleCreateRollout(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

// TestHandleGetRolloutWrongMethod tests that HandleGetRollout rejects non-GET requests.
func TestHandleGetRolloutWrongMethod(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitUpdateSchema(); err != nil {
		t.Fatalf("InitUpdateSchema failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/rollouts/some-id", nil)
	w := httptest.NewRecorder()
	hub.HandleGetRollout(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

// TestHandleGetRolloutEmptyID tests that HandleGetRollout rejects requests with no ID.
func TestHandleGetRolloutEmptyID(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitUpdateSchema(); err != nil {
		t.Fatalf("InitUpdateSchema failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rollouts/", nil)
	w := httptest.NewRecorder()
	hub.HandleGetRollout(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// TestHandleGetRolloutInvalidIDFormat tests that HandleGetRollout rejects invalid ID formats.
func TestHandleGetRolloutInvalidIDFormat(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitUpdateSchema(); err != nil {
		t.Fatalf("InitUpdateSchema failed: %v", err)
	}

	// Test with path traversal attempt
	req := httptest.NewRequest(http.MethodGet, "/api/v1/rollouts/../etc/passwd", nil)
	w := httptest.NewRecorder()
	hub.HandleGetRollout(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d for path traversal, got %d", http.StatusBadRequest, w.Code)
	}

	// Test with special characters
	req = httptest.NewRequest(http.MethodGet, "/api/v1/rollouts/id@with$special", nil)
	w = httptest.NewRecorder()
	hub.HandleGetRollout(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d for special chars, got %d", http.StatusBadRequest, w.Code)
	}
}

// TestHandleGetRolloutSuccessfulWithTaskStats tests getting rollout with task statistics.
func TestHandleGetRolloutSuccessfulWithTaskStats(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitUpdateSchema(); err != nil {
		t.Fatalf("InitUpdateSchema failed: %v", err)
	}

	// Create a release
	releasePayload := struct {
		Version    string `json:"version"`
		BinaryHash string `json:"binary_hash"`
		Signature  string `json:"signature"`
	}{
		Version:    "2.0.0",
		BinaryHash: "hash2",
		Signature:  "sig2",
	}

	body, _ := json.Marshal(releasePayload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/releases", bytes.NewReader(body))
	w := httptest.NewRecorder()
	hub.HandleCreateRelease(w, req)

	var release models.UpdateRelease
	json.NewDecoder(w.Body).Decode(&release)
	releaseID := release.ReleaseID

	// Register agents
	for i := 1; i <= 8; i++ {
		agentID := "get-rollout-agent-" + string(rune('0'+i))
		hub.Store.RegisterAgent(agentID, "host"+string(rune('0'+i)), []string{})
	}

	// Create rollout
	rolloutPayload := struct {
		ReleaseID  string                 `json:"release_id"`
		WaveConfig models.WaveConfig `json:"wave_config"`
	}{
		ReleaseID: releaseID,
		WaveConfig: models.WaveConfig{
			CanaryPercent: 25,
			Wave1Percent:  50,
			Wave2Percent:  80,
		},
	}

	body, _ = json.Marshal(rolloutPayload)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/rollouts", bytes.NewReader(body))
	w = httptest.NewRecorder()
	hub.HandleCreateRollout(w, req)

	var rollout models.UpdateRollout
	json.NewDecoder(w.Body).Decode(&rollout)
	rolloutID := rollout.RolloutID

	// Get rollout with task stats
	req = httptest.NewRequest(http.MethodGet, "/api/v1/rollouts/"+rolloutID, nil)
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

	// Should have 2 canary tasks (25% of 8)
	if rolloutResp.TaskStats.Total != 2 {
		t.Errorf("Expected 2 canary tasks, got %d", rolloutResp.TaskStats.Total)
	}
}

// TestHandlePauseRolloutWrongMethod tests that HandlePauseRollout rejects non-POST requests.
func TestHandlePauseRolloutWrongMethod(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitUpdateSchema(); err != nil {
		t.Fatalf("InitUpdateSchema failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rollouts/some-id/pause", nil)
	w := httptest.NewRecorder()
	hub.HandlePauseRollout(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

// TestHandlePauseRolloutInvalidPath tests that HandlePauseRollout rejects paths without /pause suffix.
func TestHandlePauseRolloutInvalidPath(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitUpdateSchema(); err != nil {
		t.Fatalf("InitUpdateSchema failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/rollouts/some-id", nil)
	w := httptest.NewRecorder()
	hub.HandlePauseRollout(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// TestHandlePauseRolloutEmptyID tests that HandlePauseRollout rejects paths with empty ID.
func TestHandlePauseRolloutEmptyID(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitUpdateSchema(); err != nil {
		t.Fatalf("InitUpdateSchema failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/rollouts//pause", nil)
	w := httptest.NewRecorder()
	hub.HandlePauseRollout(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// TestHandlePauseRolloutNonExistent tests that HandlePauseRollout returns 404 for non-existent rollout.
func TestHandlePauseRolloutNonExistent(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitUpdateSchema(); err != nil {
		t.Fatalf("InitUpdateSchema failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/rollouts/nonexistent-rollout/pause", nil)
	w := httptest.NewRecorder()
	hub.HandlePauseRollout(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

// TestHandlePauseRolloutSuccessfulPause tests successfully pausing a rollout and verifying status.
func TestHandlePauseRolloutSuccessfulPause(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitUpdateSchema(); err != nil {
		t.Fatalf("InitUpdateSchema failed: %v", err)
	}

	// Create release
	releasePayload := struct {
		Version    string `json:"version"`
		BinaryHash string `json:"binary_hash"`
		Signature  string `json:"signature"`
	}{
		Version:    "3.0.0",
		BinaryHash: "hash3",
		Signature:  "sig3",
	}

	body, _ := json.Marshal(releasePayload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/releases", bytes.NewReader(body))
	w := httptest.NewRecorder()
	hub.HandleCreateRelease(w, req)

	var release models.UpdateRelease
	json.NewDecoder(w.Body).Decode(&release)
	releaseID := release.ReleaseID

	// Register agents
	for i := 1; i <= 5; i++ {
		agentID := "pause-agent-" + string(rune('0'+i))
		hub.Store.RegisterAgent(agentID, "host"+string(rune('0'+i)), []string{})
	}

	// Create rollout
	rolloutPayload := struct {
		ReleaseID  string                 `json:"release_id"`
		WaveConfig models.WaveConfig `json:"wave_config"`
	}{
		ReleaseID: releaseID,
		WaveConfig: models.WaveConfig{
			CanaryPercent: 20,
			Wave1Percent:  50,
			Wave2Percent:  80,
		},
	}

	body, _ = json.Marshal(rolloutPayload)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/rollouts", bytes.NewReader(body))
	w = httptest.NewRecorder()
	hub.HandleCreateRollout(w, req)

	var rollout models.UpdateRollout
	json.NewDecoder(w.Body).Decode(&rollout)
	rolloutID := rollout.RolloutID

	if rollout.Status != "active" {
		t.Fatalf("Expected initial status 'active', got '%s'", rollout.Status)
	}

	// Pause the rollout
	req = httptest.NewRequest(http.MethodPost, "/api/v1/rollouts/"+rolloutID+"/pause", nil)
	w = httptest.NewRecorder()
	hub.HandlePauseRollout(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var pausedRollout models.UpdateRollout
	if err := json.NewDecoder(w.Body).Decode(&pausedRollout); err != nil {
		t.Fatalf("json.Decode failed: %v", err)
	}

	if pausedRollout.Status != "paused" {
		t.Errorf("Expected status 'paused', got '%s'", pausedRollout.Status)
	}
}
