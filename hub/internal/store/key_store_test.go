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

func TestGetAggregatedMetrics(t *testing.T) {
	s := newTestStore(t)
	if err := s.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	// Register an agent and record checkins with metrics
	s.RegisterAgent("metrics-agent-1", "host1", nil)
	s.RegisterAgent("metrics-agent-2", "host2", nil)

	// Record checkins with different metrics
	checkins := []struct {
		agentID string
		decisions int
		denied int
		detections map[string]int
	}{
		{"metrics-agent-1", 100, 5, map[string]int{"injection_blocked": 2, "pii_detected": 1}},
		{"metrics-agent-1", 200, 10, map[string]int{"injection_blocked": 3, "sql_injection": 1}},
		{"metrics-agent-2", 150, 7, map[string]int{"injection_blocked": 1, "pii_detected": 2}},
	}

	for _, c := range checkins {
		req := &models.CheckinRequest{
			AgentID: c.agentID,
			Health:  models.AgentHealth{Status: "healthy"},
			MetricsSummary: models.MetricsSummary{
				DecisionsTotal:     c.decisions,
				DecisionsDenied:    c.denied,
				ScannerDetections: c.detections,
			},
		}
		if err := s.RecordCheckin(req); err != nil {
			t.Fatalf("record checkin for %s: %v", c.agentID, err)
		}
	}

	// Get aggregated metrics
	metrics, err := s.GetAggregatedMetrics()
	if err != nil {
		t.Fatalf("get aggregated metrics: %v", err)
	}

	if metrics == nil {
		t.Fatal("expected non-nil metrics")
	}

	// Verify aggregation
	expectedTotalDecisions := int64(100 + 200 + 150) // 450
	expectedTotalDenied := int64(5 + 10 + 7)        // 22
	if metrics.TotalDecisions != expectedTotalDecisions {
		t.Errorf("total decisions: got %d, want %d", metrics.TotalDecisions, expectedTotalDecisions)
	}
	if metrics.TotalDenied != expectedTotalDenied {
		t.Errorf("total denied: got %d, want %d", metrics.TotalDenied, expectedTotalDenied)
	}

	// Verify scanner detections aggregation
	if metrics.ScannerDetections["injection_blocked"] != 6 {
		t.Errorf("injection_blocked: got %d, want 6", metrics.ScannerDetections["injection_blocked"])
	}
	if metrics.ScannerDetections["pii_detected"] != 3 {
		t.Errorf("pii_detected: got %d, want 3", metrics.ScannerDetections["pii_detected"])
	}
	if metrics.ScannerDetections["sql_injection"] != 1 {
		t.Errorf("sql_injection: got %d, want 1", metrics.ScannerDetections["sql_injection"])
	}
}

func TestGetActiveKeyForGroup_NoKeys(t *testing.T) {
	s := newTestStore(t)
	if err := s.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	// Get active key for group with no keys
	key, err := s.GetActiveKeyForGroup("nonexistent-group")
	if err != nil {
		t.Fatalf("get active key: %v", err)
	}

	if key != nil {
		t.Fatal("expected nil for group with no keys")
	}
}

func TestListKeys_EmptyGroupID(t *testing.T) {
	s := newTestStore(t)
	if err := s.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	// Create keys in different groups
	keyID1 := uuid.New().String()
	key1 := models.EncryptionKey{
		KeyID:        keyID1,
		GroupID:      "group-a",
		EncryptedKey: "key1data",
		Status:       "active",
		CreatedAt:    time.Now().Add(-5 * time.Minute),
	}
	if err := s.CreateKey(key1); err != nil {
		t.Fatalf("create key1: %v", err)
	}

	keyID2 := uuid.New().String()
	key2 := models.EncryptionKey{
		KeyID:        keyID2,
		GroupID:      "group-b",
		EncryptedKey: "key2data",
		Status:       "active",
		CreatedAt:    time.Now(),
	}
	if err := s.CreateKey(key2); err != nil {
		t.Fatalf("create key2: %v", err)
	}

	// List all keys (empty groupID)
	allKeys, err := s.ListKeys("")
	if err != nil {
		t.Fatalf("list all keys: %v", err)
	}

	if len(allKeys) < 2 {
		t.Fatalf("expected at least 2 keys, got %d", len(allKeys))
	}

	// Verify both keys are present
	found1, found2 := false, false
	for _, k := range allKeys {
		if k.KeyID == keyID1 {
			found1 = true
		}
		if k.KeyID == keyID2 {
			found2 = true
		}
	}

	if !found1 || !found2 {
		t.Fatal("not all keys found in full list")
	}
}

func TestListKeys_NonexistentGroup(t *testing.T) {
	s := newTestStore(t)
	if err := s.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	// Create a key in one group
	keyID := uuid.New().String()
	key := models.EncryptionKey{
		KeyID:        keyID,
		GroupID:      "existing-group",
		EncryptedKey: "keydata",
		Status:       "active",
		CreatedAt:    time.Now(),
	}
	if err := s.CreateKey(key); err != nil {
		t.Fatalf("create key: %v", err)
	}

	// List keys for non-existent group
	keys, err := s.ListKeys("nonexistent-group")
	if err != nil {
		t.Fatalf("list keys: %v", err)
	}

	if len(keys) != 0 {
		t.Fatalf("expected 0 keys for nonexistent group, got %d", len(keys))
	}
}

func TestGetKey_EmptyKeyID(t *testing.T) {
	s := newTestStore(t)
	if err := s.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	// Get key with empty keyID
	key, err := s.GetKey("")
	if err != nil {
		t.Fatalf("get key: %v", err)
	}

	if key != nil {
		t.Fatal("expected nil for empty keyID")
	}
}
