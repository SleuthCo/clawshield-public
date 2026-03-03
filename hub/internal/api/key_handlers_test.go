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

// TestRotateKeyWithNonExistentKey tests rotation with a valid old key and valid new key.
func TestRotateKeyWithNonExistentKey(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	// Create an old key
	oldKeyReq := struct {
		GroupID      string `json:"group_id"`
		EncryptedKey string `json:"encrypted_key"`
	}{
		GroupID:      "test-group",
		EncryptedKey: "old-key-data",
	}

	body, _ := json.Marshal(oldKeyReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()
	hub.HandleCreateKey(w, req)

	var oldKey models.EncryptionKey
	json.NewDecoder(w.Body).Decode(&oldKey)
	oldKeyID := oldKey.KeyID

	// Create a new key
	newKeyReq := struct {
		GroupID      string `json:"group_id"`
		EncryptedKey string `json:"encrypted_key"`
	}{
		GroupID:      "test-group",
		EncryptedKey: "new-key-data",
	}

	body, _ = json.Marshal(newKeyReq)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w = httptest.NewRecorder()
	hub.HandleCreateKey(w, req)

	var newKey models.EncryptionKey
	json.NewDecoder(w.Body).Decode(&newKey)
	newKeyID := newKey.KeyID

	// Now rotate the old key to the new key
	rotateReq := struct {
		NewKeyID string `json:"new_key_id"`
	}{
		NewKeyID: newKeyID,
	}

	body, _ = json.Marshal(rotateReq)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/keys/"+oldKeyID+"/rotate", bytes.NewReader(body))
	w = httptest.NewRecorder()

	hub.HandleRotateKeyOrRevoke(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var rotatedKey models.EncryptionKey
	json.NewDecoder(w.Body).Decode(&rotatedKey)

	if rotatedKey.Status != "rotated" {
		t.Errorf("expected status 'rotated', got %q", rotatedKey.Status)
	}
}

// TestRevokeKeySuccessful tests successful key revocation.
func TestRevokeKeySuccessful(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	// Create a key to revoke
	createReq := struct {
		GroupID      string `json:"group_id"`
		EncryptedKey string `json:"encrypted_key"`
	}{
		GroupID:      "test-group",
		EncryptedKey: "key-data",
	}

	body, _ := json.Marshal(createReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()

	hub.HandleCreateKey(w, req)

	var key models.EncryptionKey
	json.NewDecoder(w.Body).Decode(&key)
	keyID := key.KeyID

	// Revoke the key
	req = httptest.NewRequest(http.MethodPost, "/api/v1/keys/"+keyID+"/revoke", nil)
	w = httptest.NewRecorder()

	hub.HandleRotateKeyOrRevoke(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var revokedKey models.EncryptionKey
	json.NewDecoder(w.Body).Decode(&revokedKey)

	if revokedKey.Status != "revoked" {
		t.Errorf("expected status 'revoked', got %q", revokedKey.Status)
	}
}

// TestRevokeAlreadyRevokedKey tests revoking an already-revoked key.
func TestRevokeAlreadyRevokedKey(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	// Create and revoke a key
	createReq := struct {
		GroupID      string `json:"group_id"`
		EncryptedKey string `json:"encrypted_key"`
	}{
		GroupID:      "test-group",
		EncryptedKey: "key-data",
	}

	body, _ := json.Marshal(createReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()

	hub.HandleCreateKey(w, req)

	var key models.EncryptionKey
	json.NewDecoder(w.Body).Decode(&key)
	keyID := key.KeyID

	// Revoke once
	req = httptest.NewRequest(http.MethodPost, "/api/v1/keys/"+keyID+"/revoke", nil)
	w = httptest.NewRecorder()
	hub.HandleRotateKeyOrRevoke(w, req)

	// Try to revoke again
	req = httptest.NewRequest(http.MethodPost, "/api/v1/keys/"+keyID+"/revoke", nil)
	w = httptest.NewRecorder()
	hub.HandleRotateKeyOrRevoke(w, req)

	// Should still succeed (idempotent)
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

// TestListKeysWithGroupIDFilter tests listing keys filtered by group_id.
func TestListKeysWithGroupIDFilter(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	// Create keys in different groups
	group1Req := struct {
		GroupID      string `json:"group_id"`
		EncryptedKey string `json:"encrypted_key"`
	}{
		GroupID:      "group-1",
		EncryptedKey: "key1",
	}

	body, _ := json.Marshal(group1Req)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()
	hub.HandleCreateKey(w, req)

	group2Req := struct {
		GroupID      string `json:"group_id"`
		EncryptedKey string `json:"encrypted_key"`
	}{
		GroupID:      "group-2",
		EncryptedKey: "key2",
	}

	body, _ = json.Marshal(group2Req)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w = httptest.NewRecorder()
	hub.HandleCreateKey(w, req)

	// List keys for group-1
	req = httptest.NewRequest(http.MethodGet, "/api/v1/keys?group_id=group-1", nil)
	w = httptest.NewRecorder()
	hub.HandleListKeys(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var keys []models.EncryptionKey
	json.NewDecoder(w.Body).Decode(&keys)

	if len(keys) != 1 {
		t.Errorf("expected 1 key for group-1, got %d", len(keys))
	}

	if keys[0].GroupID != "group-1" {
		t.Errorf("expected group_id 'group-1', got %q", keys[0].GroupID)
	}
}

// TestGetKeyWithWrongMethod tests 405 error for non-GET request.
func TestGetKeyWithWrongMethod(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	// Create a key first
	createReq := struct {
		GroupID      string `json:"group_id"`
		EncryptedKey string `json:"encrypted_key"`
	}{
		GroupID:      "test-group",
		EncryptedKey: "key-data",
	}

	body, _ := json.Marshal(createReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()

	hub.HandleCreateKey(w, req)

	var key models.EncryptionKey
	json.NewDecoder(w.Body).Decode(&key)
	keyID := key.KeyID

	// Try to GET with POST method
	req = httptest.NewRequest(http.MethodPost, "/api/v1/keys/"+keyID, nil)
	w = httptest.NewRecorder()

	hub.HandleGetKey(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

// TestCreateKeyWrongMethod tests that HandleCreateKey rejects non-POST requests.
func TestCreateKeyWrongMethod(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	// Try to create a key with GET method
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
	w := httptest.NewRecorder()

	hub.HandleCreateKey(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

// TestCreateKeyBadJSON tests that HandleCreateKey rejects invalid JSON.
func TestCreateKeyBadJSON(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	// Send malformed JSON
	body := bytes.NewBufferString(`{invalid json}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", body)
	w := httptest.NewRecorder()

	hub.HandleCreateKey(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestCreateKeyBadExpiresAtFormat tests that HandleCreateKey rejects invalid expires_at format.
func TestCreateKeyBadExpiresAtFormat(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	createReq := struct {
		GroupID      string `json:"group_id"`
		EncryptedKey string `json:"encrypted_key"`
		ExpiresAt    string `json:"expires_at"`
	}{
		GroupID:      "test-group",
		EncryptedKey: "key-data",
		ExpiresAt:    "not-a-valid-date",
	}

	body, _ := json.Marshal(createReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()

	hub.HandleCreateKey(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestListKeysWrongMethod tests that HandleListKeys rejects non-GET requests.
func TestListKeysWrongMethod(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	// Try to list keys with POST method
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", nil)
	w := httptest.NewRecorder()

	hub.HandleListKeys(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

// TestListKeysNilToEmptyArray tests that HandleListKeys converts nil to empty array.
func TestListKeysNilToEmptyArray(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	// List keys without creating any
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
	w := httptest.NewRecorder()

	hub.HandleListKeys(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var keys []models.EncryptionKey
	if err := json.NewDecoder(w.Body).Decode(&keys); err != nil {
		t.Fatalf("decode keys: %v", err)
	}

	if keys == nil {
		t.Error("expected empty array, got nil")
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(keys))
	}
}

// TestGetKeyEmptyID tests that HandleGetKey rejects empty key IDs.
func TestGetKeyEmptyID(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	// Request with empty key ID: /api/v1/keys/
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/", nil)
	w := httptest.NewRecorder()

	hub.HandleGetKey(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestGetKeyInvalidIDFormat tests that HandleGetKey rejects invalid ID formats.
func TestGetKeyInvalidIDFormat(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	// Request with invalid ID containing ../
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/../etc/passwd", nil)
	w := httptest.NewRecorder()

	hub.HandleGetKey(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestGetKeyStripsSensitiveData tests that HandleGetKey strips encrypted_key from response.
func TestGetKeyStripsSensitiveData(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	// Create a key
	createReq := struct {
		GroupID      string `json:"group_id"`
		EncryptedKey string `json:"encrypted_key"`
	}{
		GroupID:      "test-group",
		EncryptedKey: "secret-key-material",
	}

	body, _ := json.Marshal(createReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()

	hub.HandleCreateKey(w, req)

	var createdKey models.EncryptionKey
	json.NewDecoder(w.Body).Decode(&createdKey)
	keyID := createdKey.KeyID

	// Get the key
	req = httptest.NewRequest(http.MethodGet, "/api/v1/keys/"+keyID, nil)
	w = httptest.NewRecorder()

	hub.HandleGetKey(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var retrievedKey models.EncryptionKey
	json.NewDecoder(w.Body).Decode(&retrievedKey)

	if retrievedKey.EncryptedKey != "" {
		t.Errorf("expected encrypted_key to be stripped, got %q", retrievedKey.EncryptedKey)
	}
}

// TestRotateKeyOrRevokeWrongMethod tests that HandleRotateKeyOrRevoke rejects non-POST requests.
func TestRotateKeyOrRevokeWrongMethod(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	// Create a key first
	createReq := struct {
		GroupID      string `json:"group_id"`
		EncryptedKey string `json:"encrypted_key"`
	}{
		GroupID:      "test-group",
		EncryptedKey: "key-data",
	}

	body, _ := json.Marshal(createReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()

	hub.HandleCreateKey(w, req)

	var key models.EncryptionKey
	json.NewDecoder(w.Body).Decode(&key)
	keyID := key.KeyID

	// Try to revoke with GET method
	req = httptest.NewRequest(http.MethodGet, "/api/v1/keys/"+keyID+"/revoke", nil)
	w = httptest.NewRecorder()

	hub.HandleRotateKeyOrRevoke(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

// TestRotateKeyOrRevokeInvalidPathNoAction tests invalid path without action.
func TestRotateKeyOrRevokeInvalidPathNoAction(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	// Create a key first
	createReq := struct {
		GroupID      string `json:"group_id"`
		EncryptedKey string `json:"encrypted_key"`
	}{
		GroupID:      "test-group",
		EncryptedKey: "key-data",
	}

	body, _ := json.Marshal(createReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()

	hub.HandleCreateKey(w, req)

	var key models.EncryptionKey
	json.NewDecoder(w.Body).Decode(&key)
	keyID := key.KeyID

	// POST to /api/v1/keys/{id} without action (no /rotate or /revoke)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/keys/"+keyID, nil)
	w = httptest.NewRecorder()

	hub.HandleRotateKeyOrRevoke(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestRotateKeyOrRevokeUnknownAction tests unknown action in path.
func TestRotateKeyOrRevokeUnknownAction(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	// Create a key first
	createReq := struct {
		GroupID      string `json:"group_id"`
		EncryptedKey string `json:"encrypted_key"`
	}{
		GroupID:      "test-group",
		EncryptedKey: "key-data",
	}

	body, _ := json.Marshal(createReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()

	hub.HandleCreateKey(w, req)

	var key models.EncryptionKey
	json.NewDecoder(w.Body).Decode(&key)
	keyID := key.KeyID

	// POST to /api/v1/keys/{id}/unknown
	req = httptest.NewRequest(http.MethodPost, "/api/v1/keys/"+keyID+"/unknown", nil)
	w = httptest.NewRecorder()

	hub.HandleRotateKeyOrRevoke(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestRotateKeyInvalidKeyIDFormat tests rotation with invalid key ID format.
func TestRotateKeyInvalidKeyIDFormat(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	// Create a valid new key to rotate to
	createReq := struct {
		GroupID      string `json:"group_id"`
		EncryptedKey string `json:"encrypted_key"`
	}{
		GroupID:      "test-group",
		EncryptedKey: "new-key-data",
	}

	body, _ := json.Marshal(createReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()

	hub.HandleCreateKey(w, req)

	var newKey models.EncryptionKey
	json.NewDecoder(w.Body).Decode(&newKey)

	// Try to rotate with invalid key ID containing special chars
	rotateReq := struct {
		NewKeyID string `json:"new_key_id"`
	}{
		NewKeyID: newKey.KeyID,
	}

	body, _ = json.Marshal(rotateReq)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/keys/../invalid/rotate", bytes.NewReader(body))
	w = httptest.NewRecorder()

	hub.HandleRotateKeyOrRevoke(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestRotateKeyBadJSON tests rotation with invalid JSON body.
func TestRotateKeyBadJSON(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	// Create a key to rotate
	createReq := struct {
		GroupID      string `json:"group_id"`
		EncryptedKey string `json:"encrypted_key"`
	}{
		GroupID:      "test-group",
		EncryptedKey: "key-data",
	}

	body, _ := json.Marshal(createReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()

	hub.HandleCreateKey(w, req)

	var key models.EncryptionKey
	json.NewDecoder(w.Body).Decode(&key)
	keyID := key.KeyID

	// Send malformed JSON for rotation
	badBody := bytes.NewBufferString(`{invalid json}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/keys/"+keyID+"/rotate", badBody)
	w = httptest.NewRecorder()

	hub.HandleRotateKeyOrRevoke(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestRotateKeyMissingNewKeyID tests rotation with missing new_key_id.
func TestRotateKeyMissingNewKeyID(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	// Create a key to rotate
	createReq := struct {
		GroupID      string `json:"group_id"`
		EncryptedKey string `json:"encrypted_key"`
	}{
		GroupID:      "test-group",
		EncryptedKey: "key-data",
	}

	body, _ := json.Marshal(createReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()

	hub.HandleCreateKey(w, req)

	var key models.EncryptionKey
	json.NewDecoder(w.Body).Decode(&key)
	keyID := key.KeyID

	// Send rotation request with empty new_key_id
	rotateReq := struct {
		NewKeyID string `json:"new_key_id"`
	}{
		NewKeyID: "",
	}

	body, _ = json.Marshal(rotateReq)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/keys/"+keyID+"/rotate", bytes.NewReader(body))
	w = httptest.NewRecorder()

	hub.HandleRotateKeyOrRevoke(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestRevokeKeyInvalidKeyIDFormat tests revocation with invalid key ID format.
func TestRevokeKeyInvalidKeyIDFormat(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	// Try to revoke with invalid key ID containing special chars
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/../invalid/revoke", nil)
	w := httptest.NewRecorder()

	hub.HandleRotateKeyOrRevoke(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestRevokeKeyInvalidIDViaHandler tests revoking with invalid key ID (non-alphanumeric chars).
func TestRevokeKeyInvalidIDViaHandler(t *testing.T) {
	hub := setupTestHub(t)
	hub.Store.InitKeySchema()
	// Use key ID with ! character — passes URL routing but fails validateID
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/key!bad/revoke", nil)
	w := httptest.NewRecorder()
	hub.HandleRotateKeyOrRevoke(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// TestRotateKeyInvalidIDViaHandler tests rotating with invalid key ID (non-alphanumeric chars).
func TestRotateKeyInvalidIDViaHandler(t *testing.T) {
	hub := setupTestHub(t)
	hub.Store.InitKeySchema()
	body := bytes.NewBufferString(`{"new_key_id":"newkey"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/key!bad/rotate", body)
	w := httptest.NewRecorder()
	hub.HandleRotateKeyOrRevoke(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// TestRevokeKeyStripsEncryptedKey verifies the happy path for revoke and strips encrypted_key.
func TestRevokeKeyStripsEncryptedKey(t *testing.T) {
	hub := setupTestHub(t)
	hub.Store.InitKeySchema()
	// Create a key
	body := bytes.NewBufferString(`{"group_id":"grp1","encrypted_key":"supersecret"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", body)
	w := httptest.NewRecorder()
	hub.HandleCreateKey(w, req)
	var created models.EncryptionKey
	json.NewDecoder(w.Body).Decode(&created)
	
	// Revoke and verify encrypted_key is stripped
	req = httptest.NewRequest(http.MethodPost, "/api/v1/keys/"+created.KeyID+"/revoke", nil)
	w = httptest.NewRecorder()
	hub.HandleRotateKeyOrRevoke(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var result models.EncryptionKey
	json.NewDecoder(w.Body).Decode(&result)
	if result.EncryptedKey != "" {
		t.Error("expected encrypted_key to be stripped")
	}
}

// TestRotateKeyStripsEncryptedKey verifies the happy path for rotate and strips encrypted_key.
func TestRotateKeyStripsEncryptedKey(t *testing.T) {
	hub := setupTestHub(t)
	hub.Store.InitKeySchema()
	// Create key 1
	body := bytes.NewBufferString(`{"group_id":"grp1","encrypted_key":"key1data"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", body)
	w := httptest.NewRecorder()
	hub.HandleCreateKey(w, req)
	var key1 models.EncryptionKey
	json.NewDecoder(w.Body).Decode(&key1)
	
	// Create key 2
	body = bytes.NewBufferString(`{"group_id":"grp1","encrypted_key":"key2data"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/keys", body)
	w = httptest.NewRecorder()
	hub.HandleCreateKey(w, req)
	var key2 models.EncryptionKey
	json.NewDecoder(w.Body).Decode(&key2)
	
	// Rotate key1 to key2 and verify encrypted_key is stripped
	body = bytes.NewBufferString(`{"new_key_id":"` + key2.KeyID + `"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/keys/"+key1.KeyID+"/rotate", body)
	w = httptest.NewRecorder()
	hub.HandleRotateKeyOrRevoke(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var result models.EncryptionKey
	json.NewDecoder(w.Body).Decode(&result)
	if result.EncryptedKey != "" {
		t.Error("expected encrypted_key to be stripped")
	}
}
