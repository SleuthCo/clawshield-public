package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/SleuthCo/clawshield/hub/internal/models"
)

// RegisterUpdateRoutes registers all update-related routes with the mux.
func (h *Hub) RegisterUpdateRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/releases", h.HandleCreateRelease)
	mux.HandleFunc("GET /api/v1/releases", h.HandleListReleases)
	mux.HandleFunc("POST /api/v1/rollouts", h.HandleCreateRollout)
	mux.HandleFunc("GET /api/v1/rollouts/", h.HandleGetRollout)
	mux.HandleFunc("POST /api/v1/rollouts/", h.HandlePauseRollout)
}

// HandleCreateRelease creates a new update release.
func (h *Hub) HandleCreateRelease(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		Version      string `json:"version"`
		BinaryHash   string `json:"binary_hash"`
		Signature    string `json:"signature"`
		ReleaseNotes string `json:"release_notes,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if req.Version == "" || req.BinaryHash == "" {
		writeError(w, http.StatusBadRequest, "version and binary_hash are required")
		return
	}

	// Generate release ID
	releaseID := uuid.New().String()

	release := models.UpdateRelease{
		ReleaseID:    releaseID,
		Version:      req.Version,
		BinaryHash:   req.BinaryHash,
		Signature:    req.Signature,
		ReleaseNotes: req.ReleaseNotes,
		CreatedAt:    time.Now().UTC(),
	}

	if err := h.Store.CreateRelease(release); err != nil {
		log.Printf("error creating release: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusCreated, release)
}

// HandleListReleases lists all available releases.
func (h *Hub) HandleListReleases(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	releases, err := h.Store.ListReleases()
	if err != nil {
		log.Printf("error listing releases: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if releases == nil {
		releases = []models.UpdateRelease{}
	}

	writeJSON(w, http.StatusOK, releases)
}

// HandleCreateRollout starts a new fleet-wide rollout.
func (h *Hub) HandleCreateRollout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		ReleaseID  string                 `json:"release_id"`
		WaveConfig models.WaveConfig `json:"wave_config"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if req.ReleaseID == "" {
		writeError(w, http.StatusBadRequest, "release_id is required")
		return
	}

	// Verify release exists
	release, err := h.Store.GetRelease(req.ReleaseID)
	if err != nil {
		log.Printf("error retrieving release: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if release == nil {
		writeError(w, http.StatusNotFound, "release not found")
		return
	}

	// Generate rollout ID
	rolloutID := uuid.New().String()

	rollout := models.UpdateRollout{
		RolloutID:   rolloutID,
		ReleaseID:   req.ReleaseID,
		Status:      "active",
		WaveConfig:  req.WaveConfig,
		CurrentWave: "canary",
		CreatedAt:   time.Now().UTC(),
	}

	if err := h.Store.CreateRollout(rollout); err != nil {
		log.Printf("error creating rollout: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Get all agents and create canary wave tasks
	agents, err := h.Store.ListAgents("", "")
	if err != nil {
		log.Printf("error listing agents: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Calculate canary count
	canaryCount := (len(agents) * req.WaveConfig.CanaryPercent) / 100
	if canaryCount == 0 && len(agents) > 0 && req.WaveConfig.CanaryPercent > 0 {
		canaryCount = 1
	}

	// Create canary tasks
	now := time.Now().UTC()
	for i := 0; i < canaryCount; i++ {
		task := models.UpdateTask{
			TaskID:        uuid.New().String(),
			AgentID:       agents[i].AgentID,
			TargetVersion: release.Version,
			BinaryHash:    release.BinaryHash,
			Signature:     release.Signature,
			Status:        "pending",
			Wave:          "canary",
			ScheduledAt:   now,
		}
		if err := h.Store.CreateUpdateTask(task); err != nil {
			log.Printf("error creating canary task: %v", err)
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
	}

	writeJSON(w, http.StatusCreated, rollout)
}

// HandleGetRollout retrieves rollout details with task stats.
func (h *Hub) HandleGetRollout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Extract rollout ID from path: /api/v1/rollouts/{id}
	path := r.URL.Path
	const prefix = "/api/v1/rollouts/"
	if !strings.HasPrefix(path, prefix) {
		writeError(w, http.StatusBadRequest, "invalid path")
		return
	}

	rolloutID := strings.TrimPrefix(path, prefix)
	// Remove any trailing /pause or similar
	if idx := strings.Index(rolloutID, "/"); idx != -1 {
		rolloutID = rolloutID[:idx]
	}

	if rolloutID == "" {
		writeError(w, http.StatusBadRequest, "rollout ID is required")
		return
	}

	// Validate rollout ID format
	if !validateID(rolloutID) {
		writeError(w, http.StatusBadRequest, "invalid ID format")
		return
	}

	// Get rollout
	rollout, err := h.Store.GetRollout(rolloutID)
	if err != nil {
		log.Printf("error retrieving rollout: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if rollout == nil {
		writeError(w, http.StatusNotFound, "rollout not found")
		return
	}

	// Get task stats
	total, completed, failed, err := h.Store.GetRolloutTaskStats(rolloutID)
	if err != nil {
		log.Printf("error getting task stats: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	resp := struct {
		*models.UpdateRollout
		TaskStats struct {
			Total     int `json:"total"`
			Completed int `json:"completed"`
			Failed    int `json:"failed"`
		} `json:"task_stats"`
	}{
		UpdateRollout: rollout,
	}
	resp.TaskStats.Total = total
	resp.TaskStats.Completed = completed
	resp.TaskStats.Failed = failed

	writeJSON(w, http.StatusOK, resp)
}

// HandlePauseRollout pauses an active rollout.
func (h *Hub) HandlePauseRollout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Extract rollout ID from path: /api/v1/rollouts/{id}/pause
	path := r.URL.Path
	const prefix = "/api/v1/rollouts/"
	const suffix = "/pause"

	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		writeError(w, http.StatusBadRequest, "invalid path")
		return
	}

	rolloutID := strings.TrimPrefix(path, prefix)
	rolloutID = strings.TrimSuffix(rolloutID, suffix)

	if rolloutID == "" {
		writeError(w, http.StatusBadRequest, "rollout ID is required")
		return
	}

	// Validate rollout ID format
	if !validateID(rolloutID) {
		writeError(w, http.StatusBadRequest, "invalid ID format")
		return
	}

	// Get rollout
	rollout, err := h.Store.GetRollout(rolloutID)
	if err != nil {
		log.Printf("error retrieving rollout: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if rollout == nil {
		writeError(w, http.StatusNotFound, "rollout not found")
		return
	}

	// Update rollout status to paused
	if err := h.Store.UpdateRolloutStatus(rolloutID, "paused", rollout.CurrentWave); err != nil {
		log.Printf("error pausing rollout: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Retrieve updated rollout
	updatedRollout, err := h.Store.GetRollout(rolloutID)
	if err != nil {
		log.Printf("error retrieving rollout: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, updatedRollout)
}
