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

func TestListEnrollmentTokens(t *testing.T) {
	s := newTestStore(t)

	// Create several tokens
	token1 := "token-001"
	token2 := "token-002"
	token3 := "token-003"
	if err := s.CreateEnrollmentToken(token1); err != nil {
		t.Fatalf("create token1: %v", err)
	}
	if err := s.CreateEnrollmentToken(token2); err != nil {
		t.Fatalf("create token2: %v", err)
	}
	if err := s.CreateEnrollmentToken(token3); err != nil {
		t.Fatalf("create token3: %v", err)
	}

	// Use one token
	if _, err := s.ValidateEnrollmentToken(token2); err != nil {
		t.Fatalf("validate token2: %v", err)
	}

	// List all tokens
	tokens, err := s.ListEnrollmentTokens()
	if err != nil {
		t.Fatalf("list tokens: %v", err)
	}

	if len(tokens) != 3 {
		t.Fatalf("expected 3 tokens, got %d", len(tokens))
	}

	// Verify tokens are ordered by created_at DESC
	foundToken1, foundToken2, foundToken3 := false, false, false
	for _, tok := range tokens {
		switch tok.Token {
		case token1:
			if tok.Used {
				t.Error("token1 should not be used")
			}
			foundToken1 = true
		case token2:
			if !tok.Used {
				t.Error("token2 should be used")
			}
			foundToken2 = true
		case token3:
			if tok.Used {
				t.Error("token3 should not be used")
			}
			foundToken3 = true
		}
	}

	if !foundToken1 || !foundToken2 || !foundToken3 {
		t.Fatal("not all tokens found in list")
	}
}

func TestSetPolicyVersionSignature(t *testing.T) {
	s := newTestStore(t)
	if err := s.InitPolicySchema(); err != nil {
		t.Fatalf("init policy schema: %v", err)
	}

	// Create policy group
	group := models.PolicyGroup{
		GroupID:     "group-sig-test",
		Name:        "Signature Test Group",
		Description: "Testing signature functionality",
	}
	if err := s.CreatePolicyGroup(group); err != nil {
		t.Fatalf("create group: %v", err)
	}

	// Create policy version
	version := models.PolicyVersion{
		VersionID:  "v1-sig-test",
		GroupID:    "group-sig-test",
		VersionLabel: "1.0.0",
		PolicyYAML: "default_action: deny\nallowlist:\n  - web_search\n",
		PolicyHash: "sha256:test123",
		Status:     "draft",
		CreatedBy:  "test-user",
	}
	if err := s.CreatePolicyVersion(version); err != nil {
		t.Fatalf("create version: %v", err)
	}

	// Set signature
	testSig := "signature-test-value-abc123def456"
	if err := s.SetPolicyVersionSignature("v1-sig-test", testSig); err != nil {
		t.Fatalf("set signature: %v", err)
	}

	// Verify signature was set
	retrieved, err := s.GetPolicyVersion("v1-sig-test")
	if err != nil {
		t.Fatalf("get version: %v", err)
	}
	if retrieved.Signature != testSig {
		t.Errorf("signature: got %q, want %q", retrieved.Signature, testSig)
	}
}

func TestRecordCheckin_NilMetrics(t *testing.T) {
	s := newTestStore(t)
	s.RegisterAgent("agent-nil-metrics", "host1", nil)

	// Record checkin with nil metrics map (should be handled gracefully)
	req := &models.CheckinRequest{
		AgentID:           "agent-nil-metrics",
		Hostname:          "host1",
		ClawshieldVersion: "1.0.0",
		AgentVersion:      "1.0.0",
		Health:            models.AgentHealth{Status: "healthy"},
		MetricsSummary:    models.MetricsSummary{}, // Empty metrics
	}

	if err := s.RecordCheckin(req); err != nil {
		t.Fatalf("record checkin with empty metrics: %v", err)
	}

	// Verify checkin was recorded
	checkins, err := s.GetRecentCheckins("agent-nil-metrics", 10)
	if err != nil {
		t.Fatalf("get checkins: %v", err)
	}
	if len(checkins) != 1 {
		t.Fatalf("expected 1 checkin, got %d", len(checkins))
	}
}

func TestRecordCheckin_MultipleCheckins(t *testing.T) {
	s := newTestStore(t)
	s.RegisterAgent("agent-multiple", "host1", nil)

	// Record multiple checkins for the same agent
	for i := 0; i < 5; i++ {
		req := &models.CheckinRequest{
			AgentID:           "agent-multiple",
			Hostname:          "host1",
			ClawshieldVersion: "1.0.0",
			Health: models.AgentHealth{
				Status:           "healthy",
				AuditDBSizeBytes: int64(1000 * (i + 1)),
			},
			MetricsSummary: models.MetricsSummary{
				DecisionsTotal:  100 + i*10,
				DecisionsDenied: 5 + i,
			},
		}
		if err := s.RecordCheckin(req); err != nil {
			t.Fatalf("checkin %d: %v", i, err)
		}
	}

	// Verify all checkins are recorded
	checkins, err := s.GetRecentCheckins("agent-multiple", 10)
	if err != nil {
		t.Fatalf("get checkins: %v", err)
	}
	if len(checkins) != 5 {
		t.Fatalf("expected 5 checkins, got %d", len(checkins))
	}

	// Verify they're in descending order by checkin_id (most recent first)
	for i := 1; i < len(checkins); i++ {
		if checkins[i].CheckinID > checkins[i-1].CheckinID {
			t.Error("checkins not in descending order")
		}
	}
}

func TestGetRecentCheckins_LimitZero(t *testing.T) {
	s := newTestStore(t)
	s.RegisterAgent("agent-limit-zero", "host1", nil)

	// Record a checkin
	req := &models.CheckinRequest{
		AgentID: "agent-limit-zero",
		Health:  models.AgentHealth{Status: "healthy"},
	}
	if err := s.RecordCheckin(req); err != nil {
		t.Fatalf("record checkin: %v", err)
	}

	// Get with limit of 0
	checkins, err := s.GetRecentCheckins("agent-limit-zero", 0)
	if err != nil {
		t.Fatalf("get checkins with limit 0: %v", err)
	}
	if len(checkins) != 0 {
		t.Fatalf("expected 0 checkins with limit 0, got %d", len(checkins))
	}
}

func TestGetRecentCheckins_NoCheckins(t *testing.T) {
	s := newTestStore(t)
	s.RegisterAgent("agent-no-checkins", "host1", nil)

	// Get checkins for agent with no checkins
	checkins, err := s.GetRecentCheckins("agent-no-checkins", 10)
	if err != nil {
		t.Fatalf("get checkins: %v", err)
	}
	if len(checkins) != 0 {
		t.Fatalf("expected 0 checkins, got %d", len(checkins))
	}
}

func TestPublishPolicyVersion_Unapproved(t *testing.T) {
	s := newTestStore(t)
	if err := s.InitPolicySchema(); err != nil {
		t.Fatalf("init policy schema: %v", err)
	}

	// Create policy group and version
	group := models.PolicyGroup{
		GroupID: "group-unapproved",
		Name:    "Unapproved Test",
	}
	if err := s.CreatePolicyGroup(group); err != nil {
		t.Fatalf("create group: %v", err)
	}

	version := models.PolicyVersion{
		VersionID:     "v-unapproved",
		GroupID:       "group-unapproved",
		VersionLabel:  "1.0.0",
		PolicyYAML:    "default_action: deny\n",
		PolicyHash:    "sha256:test",
		Status:        "draft", // Still in draft
		CreatedBy:     "test-user",
	}
	if err := s.CreatePolicyVersion(version); err != nil {
		t.Fatalf("create version: %v", err)
	}

	// Try to publish draft version — should fail
	err := s.PublishPolicyVersion("v-unapproved")
	if err == nil {
		t.Fatal("expected error when publishing unapproved version")
	}
}

func TestPublishPolicyVersion_Nonexistent(t *testing.T) {
	s := newTestStore(t)
	if err := s.InitPolicySchema(); err != nil {
		t.Fatalf("init policy schema: %v", err)
	}

	// Try to publish non-existent version
	err := s.PublishPolicyVersion("nonexistent-version")
	if err == nil {
		t.Fatal("expected error when publishing nonexistent version")
	}
}

func TestRegisterAgent_EmptyTags(t *testing.T) {
	s := newTestStore(t)

	// Register agent with empty tags slice
	err := s.RegisterAgent("agent-empty-tags", "host1.example.com", []string{})
	if err != nil {
		t.Fatalf("register with empty tags: %v", err)
	}

	// Retrieve and verify
	agent, err := s.GetAgent("agent-empty-tags")
	if err != nil {
		t.Fatalf("get agent: %v", err)
	}
	if agent == nil {
		t.Fatal("expected non-nil agent")
	}
	if agent.AgentID != "agent-empty-tags" {
		t.Errorf("agent_id: got %q, want %q", agent.AgentID, "agent-empty-tags")
	}
	if len(agent.Tags) != 0 {
		t.Errorf("expected empty tags, got %v", agent.Tags)
	}
}
