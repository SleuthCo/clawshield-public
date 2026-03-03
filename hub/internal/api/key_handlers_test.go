package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SleuthCo/clawshield/hub/internal/models"
)

// TestKeyLifecycle_API tests the complete key lifecycle through API endpoints.
func TestKeyLifecycle_API(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	groupID := "test-group-1"

	// Test: Create a key
	createReq := struct {
		GroupID      string `json:"group_id"`
		EncryptedKey string `json:"encrypted_key"`
		ExpiresAt    string `json:"expires_at,omitempty"`
	}{
		GroupID:      groupID,
		EncryptedKey: "aabbccdd",
		ExpiresAt:    "2025-12-31T23:59:59Z",
	}

	body, _ := json.Marshal(createReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()

	hub.HandleCreateKey(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("create key: expected status 201, got %d", w.Code)
	}

	var createdKey models.EncryptionKey
	if err := json.NewDecoder(w.Body).Decode(&createdKey); err != nil {
		t.Fatalf("decode created key: %v", err)
	}

	if createdKey.KeyID == "" {
		t.Error("expected key_id to be generated")
	}
	if createdKey.Status != "active" {
		t.Errorf("expected status 'active', got %q", createdKey.Status)
	}

	keyID := createdKey.KeyID

	// Test: Get the key
	req = httptest.NewRequest(http.MethodGet, "/api/v1/keys/"+keyID, nil)
	w = httptest.NewRecorder()

	hub.HandleGetKey(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("get key: expected status 200, got %d", w.Code)
	}

	var retrievedKey models.EncryptionKey
	if err := json.NewDecoder(w.Body).Decode(&retrievedKey); err != nil {
		t.Fatalf("decode retrieved key: %v", err)
	}

	if retrievedKey.KeyID != keyID {
		t.Errorf("expected key_id %q, got %q", keyID, retrievedKey.KeyID)
	}

	// Test: List keys with filter
	req = httptest.NewRequest(http.MethodGet, "/api/v1/keys?group_id="+groupID, nil)
	w = httptest.NewRecorder()

	hub.HandleListKeys(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("list keys: expected status 200, got %d", w.Code)
	}

	var keys []models.EncryptionKey
	if err := json.NewDecoder(w.Body).Decode(&keys); err != nil {
		t.Fatalf("decode keys list: %v", err)
	}

	if len(keys) < 1 {
		t.Error("expected at least 1 key in list")
	}

	// Test: Create a second key for rotation
	createReq2 := struct {
		GroupID      string `json:"group_id"`
		EncryptedKey string `json:"encrypted_key"`
	}{
		GroupID:      groupID,
		EncryptedKey: "eeff0011",
	}

	body2, _ := json.Marshal(createReq2)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body2))
	w = httptest.NewRecorder()

	hub.HandleCreateKey(w, req)

	var key2 models.EncryptionKey
	if err := json.NewDecoder(w.Body).Decode(&key2); err != nil {
		t.Fatalf("decode second key: %v", err)
	}

	// Test: Rotate the first key
	rotateReq := struct {
		NewKeyID string `json:"new_key_id"`
	}{
		NewKeyID: key2.KeyID,
	}

	body3, _ := json.Marshal(rotateReq)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/keys/"+keyID+"/rotate", bytes.NewReader(body3))
	w = httptest.NewRecorder()

	hub.HandleRotateKeyOrRevoke(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("rotate key: expected status 200, got %d", w.Code)
	}

	var rotatedKey models.EncryptionKey
	if err := json.NewDecoder(w.Body).Decode(&rotatedKey); err != nil {
		t.Fatalf("decode rotated key: %v", err)
	}

	if rotatedKey.Status != "rotated" {
		t.Errorf("expected status 'rotated', got %q", rotatedKey.Status)
	}
	if rotatedKey.RotatedAt.IsZero() {
		t.Error("expected RotatedAt to be set after rotation")
	}

	// Test: Revoke the second key
	req = httptest.NewRequest(http.MethodPost, "/api/v1/keys/"+key2.KeyID+"/revoke", nil)
	w = httptest.NewRecorder()

	hub.HandleRotateKeyOrRevoke(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("revoke key: expected status 200, got %d", w.Code)
	}

	var revokedKey models.EncryptionKey
	if err := json.NewDecoder(w.Body).Decode(&revokedKey); err != nil {
		t.Fatalf("decode revoked key: %v", err)
	}

	if revokedKey.Status != "revoked" {
		t.Errorf("expected status 'revoked', got %q", revokedKey.Status)
	}
}

// TestCreateKeyValidation tests input validation for key creation.
func TestCreateKeyValidation(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	tests := []struct {
		name           string
		req            interface{}
		expectedStatus int
	}{
		{
			name: "missing group_id",
			req: struct {
				EncryptedKey string `json:"encrypted_key"`
			}{
				EncryptedKey: "data",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "invalid expires_at format",
			req: struct {
				GroupID      string `json:"group_id"`
				EncryptedKey string `json:"encrypted_key"`
				ExpiresAt    string `json:"expires_at"`
			}{
				GroupID:      "group-1",
				EncryptedKey: "data",
				ExpiresAt:    "invalid-date",
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.req)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
			w := httptest.NewRecorder()

			hub.HandleCreateKey(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

// TestGetKeyNotFound tests 404 response for missing key.
func TestGetKeyNotFound(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/nonexistent-key", nil)
	w := httptest.NewRecorder()

	hub.HandleGetKey(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", w.Code)
	}
}
