package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/SleuthCo/clawshield/hub/internal/models"
	"github.com/SleuthCo/clawshield/hub/internal/store"
)

type Hub struct {
	Store *store.Store
}

func NewHub(s *store.Store) *Hub {
	return &Hub{Store: s}
}

// RegisterRoutes registers all HTTP routes with the mux.
func (h *Hub) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/enroll", h.HandleEnroll)
	mux.HandleFunc("POST /api/v1/checkin", h.HandleCheckin)
	mux.HandleFunc("GET /api/v1/agents", h.HandleListAgents)
	mux.HandleFunc("GET /api/v1/agents/", h.HandleGetAgent)
	mux.HandleFunc("GET /api/v1/health", h.HandleHealth)
}

// HandleEnroll handles agent enrollment requests.
func (h *Hub) HandleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req models.EnrollmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// Validate enrollment token
	valid, err := h.Store.ValidateEnrollmentToken(req.Token)
	if err != nil {
		log.Printf("error validating token: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if !valid {
		writeError(w, http.StatusUnauthorized, "invalid or already used token")
		return
	}

	// Generate agent ID
	agentID := uuid.New().String()

	// Register agent
	if err := h.Store.RegisterAgent(agentID, req.Hostname, req.Tags); err != nil {
		log.Printf("error registering agent: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	resp := models.EnrollmentResponse{
		AgentID:         agentID,
		CheckinInterval: 60,
	}

	writeJSON(w, http.StatusCreated, resp)
}

// HandleCheckin handles agent check-in requests.
func (h *Hub) HandleCheckin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req models.CheckinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// Validate agent ID format
	if !validateID(req.AgentID) {
		writeError(w, http.StatusBadRequest, "invalid ID format")
		return
	}

	// Verify agent exists
	agent, err := h.Store.GetAgent(req.AgentID)
	if err != nil {
		log.Printf("error retrieving agent: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if agent == nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	// Record the check-in
	if err := h.Store.RecordCheckin(&req); err != nil {
		log.Printf("error recording checkin: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Build policy actions based on agent's group assignment
	actions := h.BuildPolicyActions(&req)

	resp := models.CheckinResponse{
		Actions:            actions,
		NextCheckinSeconds: 60,
		ServerTime:         time.Now().UTC(),
	}

	writeJSON(w, http.StatusOK, resp)
}

// HandleListAgents handles listing agents with optional filters.
func (h *Hub) HandleListAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Parse query parameters
	status := r.URL.Query().Get("status")
	tag := r.URL.Query().Get("tag")

	// List agents from store
	agents, err := h.Store.ListAgents(status, tag)
	if err != nil {
		log.Printf("error listing agents: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if agents == nil {
		agents = []models.Agent{}
	}

	writeJSON(w, http.StatusOK, agents)
}

// HandleGetAgent handles retrieving a specific agent by ID.
func (h *Hub) HandleGetAgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Extract agent ID from path: /api/v1/agents/{id}
	path := r.URL.Path
	const prefix = "/api/v1/agents/"
	if !strings.HasPrefix(path, prefix) {
		writeError(w, http.StatusBadRequest, "invalid path")
		return
	}

	agentID := strings.TrimPrefix(path, prefix)
	if agentID == "" {
		writeError(w, http.StatusBadRequest, "agent ID is required")
		return
	}

	// Validate agent ID format
	if !validateID(agentID) {
		writeError(w, http.StatusBadRequest, "invalid ID format")
		return
	}

	// Get agent
	agent, err := h.Store.GetAgent(agentID)
	if err != nil {
		log.Printf("error retrieving agent: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if agent == nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	// Get recent checkins
	checkins, err := h.Store.GetRecentCheckins(agentID, 10)
	if err != nil {
		log.Printf("error retrieving checkins: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if checkins == nil {
		checkins = []models.AgentCheckin{}
	}

	detail := models.AgentDetail{
		Agent:          agent,
		RecentCheckins: checkins,
	}

	writeJSON(w, http.StatusOK, detail)
}

// HandleHealth handles health check requests.
func (h *Hub) HandleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	resp := models.HealthResponse{
		Status:    "ok",
		Timestamp: time.Now().UTC(),
	}

	writeJSON(w, http.StatusOK, resp)
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(models.ErrorResponse{Error: msg})
}

// validateID validates an ID string for security:
// - Must not be empty
// - Must be <= 128 characters
// - Must contain only alphanumeric, hyphens, and underscores
// - Must not contain path separators or traversal sequences
func validateID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
