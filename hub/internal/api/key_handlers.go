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

// RegisterKeyRoutes registers all encryption key management routes.
func (h *Hub) RegisterKeyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/keys", h.HandleCreateKey)
	mux.HandleFunc("GET /api/v1/keys", h.HandleListKeys)
	mux.HandleFunc("GET /api/v1/keys/", h.HandleGetKey)
	mux.HandleFunc("POST /api/v1/keys/", h.HandleRotateKeyOrRevoke)
}

// HandleCreateKey creates a new encryption key.
// POST /api/v1/keys
// Request body: {group_id, encrypted_key, expires_at}
func (h *Hub) HandleCreateKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		GroupID      string `json:"group_id"`
		EncryptedKey string `json:"encrypted_key"`
		ExpiresAt    string `json:"expires_at,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if req.GroupID == "" {
		writeError(w, http.StatusBadRequest, "group_id is required")
		return
	}

	// Generate key ID
	keyID := uuid.New().String()

	// Parse expires_at if provided
	var expiresAt time.Time
	if req.ExpiresAt != "" {
		var err error
		expiresAt, err = time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid expires_at format")
			return
		}
	}

	key := models.EncryptionKey{
		KeyID:        keyID,
		GroupID:      req.GroupID,
		EncryptedKey: req.EncryptedKey,
		Status:       "active",
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    expiresAt,
	}

	if err := h.Store.CreateKey(key); err != nil {
		log.Printf("error creating key: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusCreated, key)
}

// HandleListKeys lists encryption keys with optional group filter.
// GET /api/v1/keys?group_id=...
func (h *Hub) HandleListKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	groupID := r.URL.Query().Get("group_id")

	keys, err := h.Store.ListKeys(groupID)
	if err != nil {
		log.Printf("error listing keys: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if keys == nil {
		keys = []models.EncryptionKey{}
	}

	// Strip sensitive key material from list responses
	for i := range keys {
		keys[i].EncryptedKey = ""
	}

	writeJSON(w, http.StatusOK, keys)
}

// HandleGetKey retrieves a specific encryption key by ID.
// GET /api/v1/keys/{id}
func (h *Hub) HandleGetKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Extract key ID from path: /api/v1/keys/{id}
	path := r.URL.Path
	const prefix = "/api/v1/keys/"
	if !strings.HasPrefix(path, prefix) {
		writeError(w, http.StatusBadRequest, "invalid path")
		return
	}

	keyID := strings.TrimPrefix(path, prefix)
	if keyID == "" {
		writeError(w, http.StatusBadRequest, "key ID is required")
		return
	}

	// Remove any trailing path components (e.g., /rotate, /revoke)
	if idx := strings.Index(keyID, "/"); idx != -1 {
		keyID = keyID[:idx]
	}

	// Validate key ID format
	if !validateID(keyID) {
		writeError(w, http.StatusBadRequest, "invalid ID format")
		return
	}

	key, err := h.Store.GetKey(keyID)
	if err != nil {
		log.Printf("error retrieving key: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if key == nil {
		writeError(w, http.StatusNotFound, "key not found")
		return
	}

	// Strip sensitive key material from response
	key.EncryptedKey = ""

	writeJSON(w, http.StatusOK, key)
}

// HandleRotateKeyOrRevoke handles both rotate and revoke actions based on the path.
// POST /api/v1/keys/{id}/rotate - request body: {new_key_id}
// POST /api/v1/keys/{id}/revoke - no body required
func (h *Hub) HandleRotateKeyOrRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Extract path: /api/v1/keys/{id}/rotate or /api/v1/keys/{id}/revoke
	path := r.URL.Path
	const prefix = "/api/v1/keys/"
	if !strings.HasPrefix(path, prefix) {
		writeError(w, http.StatusBadRequest, "invalid path")
		return
	}

	remainder := strings.TrimPrefix(path, prefix)
	parts := strings.Split(remainder, "/")

	if len(parts) < 2 {
		writeError(w, http.StatusBadRequest, "invalid path")
		return
	}

	keyID := parts[0]
	action := parts[1]

	if action == "rotate" {
		h.handleRotateKey(w, r, keyID)
	} else if action == "revoke" {
		h.handleRevokeKey(w, r, keyID)
	} else {
		writeError(w, http.StatusBadRequest, "unknown action")
	}
}

// handleRotateKey rotates a key.
func (h *Hub) handleRotateKey(w http.ResponseWriter, r *http.Request, oldKeyID string) {
	// Validate key ID format
	if !validateID(oldKeyID) {
		writeError(w, http.StatusBadRequest, "invalid ID format")
		return
	}

	var req struct {
		NewKeyID string `json:"new_key_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if req.NewKeyID == "" {
		writeError(w, http.StatusBadRequest, "new_key_id is required")
		return
	}

	if err := h.Store.RotateKey(oldKeyID, req.NewKeyID); err != nil {
		log.Printf("error rotating key: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Return the rotated key
	key, err := h.Store.GetKey(oldKeyID)
	if err != nil {
		log.Printf("error retrieving rotated key: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Strip sensitive key material from response
	key.EncryptedKey = ""

	writeJSON(w, http.StatusOK, key)
}

// handleRevokeKey revokes a key.
func (h *Hub) handleRevokeKey(w http.ResponseWriter, r *http.Request, keyID string) {
	// Validate key ID format
	if !validateID(keyID) {
		writeError(w, http.StatusBadRequest, "invalid ID format")
		return
	}

	if err := h.Store.RevokeKey(keyID); err != nil {
		log.Printf("error revoking key: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Return the revoked key
	key, err := h.Store.GetKey(keyID)
	if err != nil {
		log.Printf("error retrieving revoked key: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Strip sensitive key material from response
	key.EncryptedKey = ""

	writeJSON(w, http.StatusOK, key)
}
