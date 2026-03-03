package store

import (
	"testing"
	"time"

	"github.com/SleuthCo/clawshield/hub/internal/models"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestNewStore(t *testing.T) {
	s := newTestStore(t)
	// Verify tables exist by running queries that would fail if they don't
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM agents").Scan(&count); err != nil {
		t.Fatalf("agents table missing: %v", err)
	}
	if err := s.db.QueryRow("SELECT COUNT(*) FROM agent_checkins").Scan(&count); err != nil {
		t.Fatalf("agent_checkins table missing: %v", err)
	}
	if err := s.db.QueryRow("SELECT COUNT(*) FROM enrollment_tokens").Scan(&count); err != nil {
		t.Fatalf("enrollment_tokens table missing: %v", err)
	}
}

func TestEnrollmentTokenLifecycle(t *testing.T) {
	s := newTestStore(t)

	token := "test-token-abc123"

	// Create token
	if err := s.CreateEnrollmentToken(token); err != nil {
		t.Fatalf("create token: %v", err)
	}

	// Validate — should succeed
	valid, err := s.ValidateEnrollmentToken(token)
	if err != nil {
		t.Fatalf("validate token: %v", err)
	}
	if !valid {
		t.Fatal("expected token to be valid")
	}

	// Validate again — should fail (already used)
	valid, err = s.ValidateEnrollmentToken(token)
	if err != nil {
		t.Fatalf("validate used token: %v", err)
	}
	if valid {
		t.Fatal("expected token to be invalid after use")
	}

	// Validate non-existent token
	valid, err = s.ValidateEnrollmentToken("nonexistent")
	if err != nil {
		t.Fatalf("validate nonexistent: %v", err)
	}
	if valid {
		t.Fatal("expected nonexistent token to be invalid")
	}
}

func TestRegisterAgent(t *testing.T) {
	s := newTestStore(t)

	err := s.RegisterAgent("agent-001", "host1.example.com", []string{"prod", "us-west"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	agent, err := s.GetAgent("agent-001")
	if err != nil {
		t.Fatalf("get agent: %v", err)
	}
	if agent == nil {
		t.Fatal("expected non-nil agent")
	}
	if agent.AgentID != "agent-001" {
		t.Errorf("agent_id: got %q, want %q", agent.AgentID, "agent-001")
	}
	if agent.Hostname != "host1.example.com" {
		t.Errorf("hostname: got %q, want %q", agent.Hostname, "host1.example.com")
	}
	if agent.Status != "healthy" {
		t.Errorf("status: got %q, want %q", agent.Status, "healthy")
	}
	if len(agent.Tags) != 2 || agent.Tags[0] != "prod" || agent.Tags[1] != "us-west" {
		t.Errorf("tags: got %v, want [prod us-west]", agent.Tags)
	}
}

func TestRegisterAgentDuplicate(t *testing.T) {
	s := newTestStore(t)

	if err := s.RegisterAgent("agent-dup", "host1", nil); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if err := s.RegisterAgent("agent-dup", "host2", nil); err == nil {
		t.Fatal("expected error on duplicate registration")
	}
}

func TestGetAgent_NotFound(t *testing.T) {
	s := newTestStore(t)

	agent, err := s.GetAgent("nonexistent")
	if err != nil {
		t.Fatalf("get agent: %v", err)
	}
	if agent != nil {
		t.Fatal("expected nil for nonexistent agent")
	}
}

func TestListAgents(t *testing.T) {
	s := newTestStore(t)

	s.RegisterAgent("a1", "host1", []string{"prod", "engineering"})
	s.RegisterAgent("a2", "host2", []string{"staging", "engineering"})
	s.RegisterAgent("a3", "host3", []string{"prod", "finance"})

	// List all
	agents, err := s.ListAgents("", "")
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(agents) != 3 {
		t.Fatalf("expected 3 agents, got %d", len(agents))
	}

	// Filter by status
	agents, err = s.ListAgents("healthy", "")
	if err != nil {
		t.Fatalf("filter by status: %v", err)
	}
	if len(agents) != 3 {
		t.Fatalf("expected 3 healthy agents, got %d", len(agents))
	}

	// Filter by tag
	agents, err = s.ListAgents("", "prod")
	if err != nil {
		t.Fatalf("filter by tag: %v", err)
	}
	if len(agents) != 2 {
		t.Fatalf("expected 2 prod agents, got %d", len(agents))
	}

	// Filter by tag + status
	agents, err = s.ListAgents("healthy", "finance")
	if err != nil {
		t.Fatalf("filter by tag+status: %v", err)
	}
	if len(agents) != 1 {
		t.Fatalf("expected 1 healthy+finance agent, got %d", len(agents))
	}
}

func TestRecordCheckin(t *testing.T) {
	s := newTestStore(t)
	s.RegisterAgent("a1", "host1", nil)

	req := &models.CheckinRequest{
		AgentID:           "a1",
		Hostname:          "host1-updated",
		ClawshieldVersion: "1.4.2",
		AgentVersion:      "1.0.0",
		PolicyHash:        "sha256:abc123",
		PolicyVersion:     "v2.1",
		EncryptionKeyID:   "key-2026-03",
		Health: models.AgentHealth{
			Status:           "healthy",
			AuditDBSizeBytes: 52428800,
		},
		MetricsSummary: models.MetricsSummary{
			DecisionsTotal:  100,
			DecisionsDenied: 5,
			ScannerDetections: map[string]int{
				"injection": 2,
				"pii":       3,
			},
			PeriodSeconds: 60,
		},
	}

	if err := s.RecordCheckin(req); err != nil {
		t.Fatalf("record checkin: %v", err)
	}

	// Verify agent was updated
	agent, _ := s.GetAgent("a1")
	if agent.Hostname != "host1-updated" {
		t.Errorf("hostname not updated: got %q", agent.Hostname)
	}
	if agent.ClawshieldVersion != "1.4.2" {
		t.Errorf("version not updated: got %q", agent.ClawshieldVersion)
	}
	if agent.PolicyHash != "sha256:abc123" {
		t.Errorf("policy_hash not updated: got %q", agent.PolicyHash)
	}

	// Verify checkin row was created
	checkins, err := s.GetRecentCheckins("a1", 10)
	if err != nil {
		t.Fatalf("get checkins: %v", err)
	}
	if len(checkins) != 1 {
		t.Fatalf("expected 1 checkin, got %d", len(checkins))
	}
	if checkins[0].HealthStatus != "healthy" {
		t.Errorf("health_status: got %q", checkins[0].HealthStatus)
	}
	if checkins[0].AuditDBSizeBytes != 52428800 {
		t.Errorf("audit_db_size: got %d", checkins[0].AuditDBSizeBytes)
	}
}

func TestGetRecentCheckins_Ordering(t *testing.T) {
	s := newTestStore(t)
	s.RegisterAgent("a1", "host1", nil)

	// Record multiple checkins
	for i := 0; i < 5; i++ {
		req := &models.CheckinRequest{
			AgentID: "a1",
			Health:  models.AgentHealth{Status: "healthy"},
		}
		if err := s.RecordCheckin(req); err != nil {
			t.Fatalf("checkin %d: %v", i, err)
		}
	}

	// Get with limit
	checkins, err := s.GetRecentCheckins("a1", 3)
	if err != nil {
		t.Fatalf("get checkins: %v", err)
	}
	if len(checkins) != 3 {
		t.Fatalf("expected 3 checkins, got %d", len(checkins))
	}

	// Verify descending order (most recent first)
	for i := 1; i < len(checkins); i++ {
		if checkins[i].CheckinID > checkins[i-1].CheckinID {
			t.Error("checkins not in descending order")
		}
	}
}

func TestMarkStaleAgents(t *testing.T) {
	s := newTestStore(t)

	s.RegisterAgent("fresh", "host1", nil)
	s.RegisterAgent("old", "host2", nil)

	// Make "fresh" agent's last checkin very recent (Go time, not DB time)
	s.db.Exec("UPDATE agents SET last_checkin_at = ? WHERE agent_id = ?",
		time.Now(), "fresh")

	// Make "old" agent's last checkin very old
	s.db.Exec("UPDATE agents SET last_checkin_at = ? WHERE agent_id = ?",
		time.Now().Add(-2*time.Hour), "old")

	// Mark stale with 1-hour threshold
	n, err := s.MarkStaleAgents(1 * time.Hour)
	if err != nil {
		t.Fatalf("mark stale: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 stale agent, got %d", n)
	}

	// Verify
	old, _ := s.GetAgent("old")
	if old.Status != "stale" {
		t.Errorf("old agent should be stale, got %q", old.Status)
	}
	fresh, _ := s.GetAgent("fresh")
	if fresh.Status != "healthy" {
		t.Errorf("fresh agent should still be healthy, got %q", fresh.Status)
	}

	// Running again should mark 0 (already stale)
	n, _ = s.MarkStaleAgents(1 * time.Hour)
	if n != 0 {
		t.Fatalf("expected 0 newly stale, got %d", n)
	}
}
