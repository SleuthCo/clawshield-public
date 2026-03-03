package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/SleuthCo/clawshield/hub/internal/models"
)

// TestDashboardOverview tests the fleet overview endpoint.
func TestDashboardOverview(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitPolicySchema(); err != nil {
		t.Fatalf("init policy schema: %v", err)
	}

	// Register 3 agents with different statuses and versions
	agent1ID := uuid.New().String()
	if err := hub.Store.RegisterAgent(agent1ID, "host1", []string{"prod"}); err != nil {
		t.Fatalf("register agent1: %v", err)
	}

	// Record checkin for agent1 (healthy, version 1.0.0)
	checkin1 := models.CheckinRequest{
		AgentID:           agent1ID,
		Hostname:          "host1",
		ClawshieldVersion: "1.0.0",
		AgentVersion:      "1.0.0",
		PolicyHash:        "hash1",
		PolicyVersion:     "v1",
		Health: models.AgentHealth{
			Status:           "healthy",
			AuditDBSizeBytes: 1024,
		},
		MetricsSummary: models.MetricsSummary{
			DecisionsTotal:    0,
			DecisionsDenied:   0,
			ScannerDetections: make(map[string]int),
			PeriodSeconds:     60,
		},
	}
	if err := hub.Store.RecordCheckin(&checkin1); err != nil {
		t.Fatalf("record checkin1: %v", err)
	}

	agent2ID := uuid.New().String()
	if err := hub.Store.RegisterAgent(agent2ID, "host2", []string{"staging"}); err != nil {
		t.Fatalf("register agent2: %v", err)
	}

	// Record checkin for agent2 (unhealthy, version 1.0.0)
	checkin2 := models.CheckinRequest{
		AgentID:           agent2ID,
		Hostname:          "host2",
		ClawshieldVersion: "1.0.0",
		AgentVersion:      "1.0.0",
		PolicyHash:        "hash1",
		PolicyVersion:     "v1",
		Health: models.AgentHealth{
			Status:           "unhealthy",
			AuditDBSizeBytes: 1024,
		},
		MetricsSummary: models.MetricsSummary{
			DecisionsTotal:    0,
			DecisionsDenied:   0,
			ScannerDetections: make(map[string]int),
			PeriodSeconds:     60,
		},
	}
	if err := hub.Store.RecordCheckin(&checkin2); err != nil {
		t.Fatalf("record checkin2: %v", err)
	}

	agent3ID := uuid.New().String()
	if err := hub.Store.RegisterAgent(agent3ID, "host3", []string{"dev"}); err != nil {
		t.Fatalf("register agent3: %v", err)
	}

	// Record checkin for agent3 (stale, version 0.9.0)
	checkin3 := models.CheckinRequest{
		AgentID:           agent3ID,
		Hostname:          "host3",
		ClawshieldVersion: "0.9.0",
		AgentVersion:      "0.9.0",
		PolicyHash:        "hash1",
		PolicyVersion:     "v1",
		Health: models.AgentHealth{
			Status:           "stale",
			AuditDBSizeBytes: 1024,
		},
		MetricsSummary: models.MetricsSummary{
			DecisionsTotal:    0,
			DecisionsDenied:   0,
			ScannerDetections: make(map[string]int),
			PeriodSeconds:     60,
		},
	}
	if err := hub.Store.RecordCheckin(&checkin3); err != nil {
		t.Fatalf("record checkin3: %v", err)
	}

	// Make a GET request to the overview endpoint
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/overview", nil)
	w := httptest.NewRecorder()

	hub.HandleDashboardOverview(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var overview models.DashboardOverview
	if err := json.NewDecoder(w.Body).Decode(&overview); err != nil {
		t.Fatalf("decode overview: %v", err)
	}

	// Verify totals
	if overview.TotalAgents != 3 {
		t.Errorf("expected total_agents 3, got %d", overview.TotalAgents)
	}

	if overview.HealthyAgents != 1 {
		t.Errorf("expected healthy_agents 1, got %d", overview.HealthyAgents)
	}

	if overview.UnhealthyAgents != 1 {
		t.Errorf("expected unhealthy_agents 1, got %d", overview.UnhealthyAgents)
	}

	if overview.StaleAgents != 1 {
		t.Errorf("expected stale_agents 1, got %d", overview.StaleAgents)
	}

	// Verify version distribution
	if overview.VersionDistribution["1.0.0"] != 2 {
		t.Errorf("expected version 1.0.0 count 2, got %d", overview.VersionDistribution["1.0.0"])
	}

	if overview.VersionDistribution["0.9.0"] != 1 {
		t.Errorf("expected version 0.9.0 count 1, got %d", overview.VersionDistribution["0.9.0"])
	}

	// Verify unassigned agents
	if overview.PolicyCompliance.Unassigned != 3 {
		t.Errorf("expected unassigned 3, got %d", overview.PolicyCompliance.Unassigned)
	}
}

// TestDashboardOverview_WithPolicies tests policy compliance calculation.
func TestDashboardOverview_WithPolicies(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitPolicySchema(); err != nil {
		t.Fatalf("init policy schema: %v", err)
	}

	// Create a policy group with a version
	groupID := uuid.New().String()
	group := models.PolicyGroup{
		GroupID:     groupID,
		Name:        "test-group",
		Description: "test policy group",
	}
	if err := hub.Store.CreatePolicyGroup(group); err != nil {
		t.Fatalf("create policy group: %v", err)
	}

	// Create a policy version
	versionID := uuid.New().String()
	version := models.PolicyVersion{
		VersionID:   versionID,
		GroupID:     groupID,
		VersionLabel: "v1",
		PolicyYAML:  "test policy yaml",
		PolicyHash:  "hash123",
		Status:      "draft",
		CreatedBy:   "admin",
	}
	if err := hub.Store.CreatePolicyVersion(version); err != nil {
		t.Fatalf("create policy version: %v", err)
	}

	// Approve and publish the version
	if err := hub.Store.UpdatePolicyVersionStatus(versionID, "approved"); err != nil {
		t.Fatalf("approve policy: %v", err)
	}
	if err := hub.Store.PublishPolicyVersion(versionID); err != nil {
		t.Fatalf("publish policy: %v", err)
	}

	// Register 2 agents and assign to group
	agent1ID := uuid.New().String()
	if err := hub.Store.RegisterAgent(agent1ID, "host1", nil); err != nil {
		t.Fatalf("register agent1: %v", err)
	}
	hub.Store.AssignAgentToGroup(agent1ID, groupID)

	agent2ID := uuid.New().String()
	if err := hub.Store.RegisterAgent(agent2ID, "host2", nil); err != nil {
		t.Fatalf("register agent2: %v", err)
	}
	hub.Store.AssignAgentToGroup(agent2ID, groupID)

	// Record checkin for agent1 with matching policy hash (compliant)
	checkinA := models.CheckinRequest{
		AgentID:           agent1ID,
		Hostname:          "host1",
		ClawshieldVersion: "1.0.0",
		AgentVersion:      "1.0.0",
		PolicyHash:        "hash123",
		PolicyVersion:     "v1",
		Health: models.AgentHealth{
			Status:           "healthy",
			AuditDBSizeBytes: 1024,
		},
		MetricsSummary: models.MetricsSummary{
			DecisionsTotal:    0,
			DecisionsDenied:   0,
			ScannerDetections: make(map[string]int),
			PeriodSeconds:     60,
		},
	}
	if err := hub.Store.RecordCheckin(&checkinA); err != nil {
		t.Fatalf("record checkinA: %v", err)
	}

	// Record checkin for agent2 with different policy hash (non-compliant)
	checkinB := models.CheckinRequest{
		AgentID:           agent2ID,
		Hostname:          "host2",
		ClawshieldVersion: "1.0.0",
		AgentVersion:      "1.0.0",
		PolicyHash:        "hash456",
		PolicyVersion:     "v1",
		Health: models.AgentHealth{
			Status:           "healthy",
			AuditDBSizeBytes: 1024,
		},
		MetricsSummary: models.MetricsSummary{
			DecisionsTotal:    0,
			DecisionsDenied:   0,
			ScannerDetections: make(map[string]int),
			PeriodSeconds:     60,
		},
	}
	if err := hub.Store.RecordCheckin(&checkinB); err != nil {
		t.Fatalf("record checkinB: %v", err)
	}

	// Request overview
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/overview", nil)
	w := httptest.NewRecorder()

	hub.HandleDashboardOverview(w, req)

	var overview models.DashboardOverview
	if err := json.NewDecoder(w.Body).Decode(&overview); err != nil {
		t.Fatalf("decode overview: %v", err)
	}

	// Verify policy compliance
	if overview.PolicyCompliance.Compliant != 1 {
		t.Errorf("expected compliant 1, got %d", overview.PolicyCompliance.Compliant)
	}

	if overview.PolicyCompliance.NonCompliant != 1 {
		t.Errorf("expected non_compliant 1, got %d", overview.PolicyCompliance.NonCompliant)
	}

	if overview.PolicyCompliance.Unassigned != 0 {
		t.Errorf("expected unassigned 0, got %d", overview.PolicyCompliance.Unassigned)
	}
}

// TestSecuritySummary tests the security metrics aggregation endpoint.
func TestSecuritySummary(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	// Register an agent
	agentID := uuid.New().String()
	if err := hub.Store.RegisterAgent(agentID, "host1", nil); err != nil {
		t.Fatalf("register agent: %v", err)
	}

	// Record checkins with metrics
	checkin1 := models.CheckinRequest{
		AgentID:           agentID,
		Hostname:          "host1",
		ClawshieldVersion: "1.0.0",
		AgentVersion:      "1.0.0",
		PolicyHash:        "hash1",
		PolicyVersion:     "v1",
		Health: models.AgentHealth{
			Status:           "healthy",
			AuditDBSizeBytes: 1024,
		},
		MetricsSummary: models.MetricsSummary{
			DecisionsTotal:   100,
			DecisionsDenied:  5,
			ScannerDetections: map[string]int{
				"osquery": 10,
				"auditd":  3,
			},
			PeriodSeconds: 60,
		},
	}

	if err := hub.Store.RecordCheckin(&checkin1); err != nil {
		t.Fatalf("record checkin1: %v", err)
	}

	// Record another checkin to test aggregation
	checkin2 := models.CheckinRequest{
		AgentID:           agentID,
		Hostname:          "host1",
		ClawshieldVersion: "1.0.0",
		AgentVersion:      "1.0.0",
		PolicyHash:        "hash1",
		PolicyVersion:     "v1",
		Health: models.AgentHealth{
			Status:           "healthy",
			AuditDBSizeBytes: 2048,
		},
		MetricsSummary: models.MetricsSummary{
			DecisionsTotal:   50,
			DecisionsDenied:  2,
			ScannerDetections: map[string]int{
				"osquery": 5,
				"auditd":  1,
			},
			PeriodSeconds: 60,
		},
	}

	if err := hub.Store.RecordCheckin(&checkin2); err != nil {
		t.Fatalf("record checkin2: %v", err)
	}

	// Request security summary
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/security", nil)
	w := httptest.NewRecorder()

	hub.HandleSecuritySummary(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var summary models.SecuritySummary
	if err := json.NewDecoder(w.Body).Decode(&summary); err != nil {
		t.Fatalf("decode summary: %v", err)
	}

	// Verify aggregated metrics
	if summary.TotalDecisions != 150 {
		t.Errorf("expected total_decisions 150, got %d", summary.TotalDecisions)
	}

	if summary.TotalDenied != 7 {
		t.Errorf("expected total_denied 7, got %d", summary.TotalDenied)
	}

	// Verify scanner detections
	if summary.ScannerDetections["osquery"] != 15 {
		t.Errorf("expected osquery 15, got %d", summary.ScannerDetections["osquery"])
	}

	if summary.ScannerDetections["auditd"] != 4 {
		t.Errorf("expected auditd 4, got %d", summary.ScannerDetections["auditd"])
	}
}

// TestSecuritySummary_EmptyMetrics tests security summary with no checkins.
func TestSecuritySummary_EmptyMetrics(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	// Request security summary without any checkins
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/security", nil)
	w := httptest.NewRecorder()

	hub.HandleSecuritySummary(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var summary models.SecuritySummary
	if err := json.NewDecoder(w.Body).Decode(&summary); err != nil {
		t.Fatalf("decode summary: %v", err)
	}

	// Verify zero metrics
	if summary.TotalDecisions != 0 {
		t.Errorf("expected total_decisions 0, got %d", summary.TotalDecisions)
	}

	if summary.TotalDenied != 0 {
		t.Errorf("expected total_denied 0, got %d", summary.TotalDenied)
	}

	if summary.ScannerDetections == nil {
		t.Error("expected scanner_detections to be initialized")
	}
}
