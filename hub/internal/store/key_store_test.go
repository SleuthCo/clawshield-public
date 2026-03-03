package store

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/SleuthCo/clawshield/hub/internal/models"
)

func TestKeyCRUD(t *testing.T) {
	s := newTestStore(t)
	if err := s.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	// Create a key
	keyID := uuid.New().String()
	groupID := "group-1"
	key := models.EncryptionKey{
		KeyID:        keyID,
		GroupID:      groupID,
		EncryptedKey: "aabbccdd",
		Status:       "active",
		CreatedAt:    time.Now(),
	}

	if err := s.CreateKey(key); err != nil {
		t.Fatalf("create key: %v", err)
	}

	// Get the key
	retrieved, err := s.GetKey(keyID)
	if err != nil {
		t.Fatalf("get key: %v", err)
	}

	if retrieved == nil {
		t.Fatal("expected key, got nil")
	}
	if retrieved.KeyID != keyID {
		t.Errorf("expected key_id %q, got %q", keyID, retrieved.KeyID)
	}
	if retrieved.GroupID != groupID {
		t.Errorf("expected group_id %q, got %q", groupID, retrieved.GroupID)
	}
	if retrieved.Status != "active" {
		t.Errorf("expected status 'active', got %q", retrieved.Status)
	}

	// List keys for the group
	keys, err := s.ListKeys(groupID)
	if err != nil {
		t.Fatalf("list keys: %v", err)
	}

	if len(keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(keys))
	}
	if keys[0].KeyID != keyID {
		t.Errorf("expected key_id %q, got %q", keyID, keys[0].KeyID)
	}

	// List all keys (empty group filter)
	allKeys, err := s.ListKeys("")
	if err != nil {
		t.Fatalf("list all keys: %v", err)
	}
	if len(allKeys) < 1 {
		t.Error("expected at least 1 key in full list")
	}
}

func TestGetActiveKeyForGroup(t *testing.T) {
	s := newTestStore(t)
	if err := s.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	groupID := "group-1"

	// Create first key as active
	keyID1 := uuid.New().String()
	key1 := models.EncryptionKey{
		KeyID:        keyID1,
		GroupID:      groupID,
		EncryptedKey: "key1data",
		Status:       "active",
		CreatedAt:    time.Now().Add(-10 * time.Minute),
	}
	if err := s.CreateKey(key1); err != nil {
		t.Fatalf("create key1: %v", err)
	}

	// Create second key also as active (newer)
	keyID2 := uuid.New().String()
	key2 := models.EncryptionKey{
		KeyID:        keyID2,
		GroupID:      groupID,
		EncryptedKey: "key2data",
		Status:       "active",
		CreatedAt:    time.Now(),
	}
	if err := s.CreateKey(key2); err != nil {
		t.Fatalf("create key2: %v", err)
	}

	// Rotate the first key
	if err := s.RotateKey(keyID1, keyID2); err != nil {
		t.Fatalf("rotate key: %v", err)
	}

	// Get active key — should be key2
	active, err := s.GetActiveKeyForGroup(groupID)
	if err != nil {
		t.Fatalf("get active key: %v", err)
	}

	if active == nil {
		t.Fatal("expected active key, got nil")
	}
	if active.KeyID != keyID2 {
		t.Errorf("expected active key_id %q, got %q", keyID2, active.KeyID)
	}
	if active.Status != "active" {
		t.Errorf("expected status 'active', got %q", active.Status)
	}

	// Verify first key is now rotated
	rotated, err := s.GetKey(keyID1)
	if err != nil {
		t.Fatalf("get rotated key: %v", err)
	}
	if rotated.Status != "rotated" {
		t.Errorf("expected status 'rotated', got %q", rotated.Status)
	}
}

func TestRotateKey(t *testing.T) {
	s := newTestStore(t)
	if err := s.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	groupID := "group-1"

	// Create key A as active
	keyIDA := uuid.New().String()
	keyA := models.EncryptionKey{
		KeyID:        keyIDA,
		GroupID:      groupID,
		EncryptedKey: "keyAdata",
		Status:       "active",
		CreatedAt:    time.Now().Add(-5 * time.Minute),
	}
	if err := s.CreateKey(keyA); err != nil {
		t.Fatalf("create key A: %v", err)
	}

	// Create key B as active
	keyIDB := uuid.New().String()
	keyB := models.EncryptionKey{
		KeyID:        keyIDB,
		GroupID:      groupID,
		EncryptedKey: "keyBdata",
		Status:       "active",
		CreatedAt:    time.Now(),
	}
	if err := s.CreateKey(keyB); err != nil {
		t.Fatalf("create key B: %v", err)
	}

	// Rotate A -> B
	if err := s.RotateKey(keyIDA, keyIDB); err != nil {
		t.Fatalf("rotate key: %v", err)
	}

	// Verify A is rotated
	retrievedA, err := s.GetKey(keyIDA)
	if err != nil {
		t.Fatalf("get key A: %v", err)
	}
	if retrievedA.Status != "rotated" {
		t.Errorf("expected A status 'rotated', got %q", retrievedA.Status)
	}
	if retrievedA.RotatedAt.IsZero() {
		t.Error("expected RotatedAt to be set")
	}

	// Verify B is still active
	retrievedB, err := s.GetKey(keyIDB)
	if err != nil {
		t.Fatalf("get key B: %v", err)
	}
	if retrievedB.Status != "active" {
		t.Errorf("expected B status 'active', got %q", retrievedB.Status)
	}
}

func TestRevokeKey(t *testing.T) {
	s := newTestStore(t)
	if err := s.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	// Create key
	keyID := uuid.New().String()
	key := models.EncryptionKey{
		KeyID:        keyID,
		GroupID:      "group-1",
		EncryptedKey: "keydata",
		Status:       "active",
		CreatedAt:    time.Now(),
	}
	if err := s.CreateKey(key); err != nil {
		t.Fatalf("create key: %v", err)
	}

	// Revoke the key
	if err := s.RevokeKey(keyID); err != nil {
		t.Fatalf("revoke key: %v", err)
	}

	// Verify key is revoked
	retrieved, err := s.GetKey(keyID)
	if err != nil {
		t.Fatalf("get key: %v", err)
	}
	if retrieved.Status != "revoked" {
		t.Errorf("expected status 'revoked', got %q", retrieved.Status)
	}
}
