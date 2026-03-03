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

// TestHandleDashboardOverview_WrongMethod verifies wrong HTTP method returns 405.
func TestHandleDashboardOverview_WrongMethod(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitPolicySchema(); err != nil {
		t.Fatalf("init policy schema: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/dashboard/overview", nil)
	w := httptest.NewRecorder()

	hub.HandleDashboardOverview(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}

	var resp models.ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Error == "" {
		t.Error("expected error message")
	}
}

// TestHandleDashboardOverview_VersionsAndStatus verifies version distribution and health counts.
func TestHandleDashboardOverview_VersionsAndStatus(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitPolicySchema(); err != nil {
		t.Fatalf("init policy schema: %v", err)
	}

	// Register agent 1 with version 1.1.0
	agent1ID := uuid.New().String()
	if err := hub.Store.RegisterAgent(agent1ID, "host1", nil); err != nil {
		t.Fatalf("register agent1: %v", err)
	}

	checkin1 := models.CheckinRequest{
		AgentID:           agent1ID,
		Hostname:          "host1",
		ClawshieldVersion: "1.1.0",
		AgentVersion:      "1.1.0",
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

	// Register agent 2 with version 1.1.0 but unhealthy
	agent2ID := uuid.New().String()
	if err := hub.Store.RegisterAgent(agent2ID, "host2", nil); err != nil {
		t.Fatalf("register agent2: %v", err)
	}

	checkin2 := models.CheckinRequest{
		AgentID:           agent2ID,
		Hostname:          "host2",
		ClawshieldVersion: "1.1.0",
		AgentVersion:      "1.1.0",
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

	// Register agent 3 with version 1.0.0
	agent3ID := uuid.New().String()
	if err := hub.Store.RegisterAgent(agent3ID, "host3", nil); err != nil {
		t.Fatalf("register agent3: %v", err)
	}

	checkin3 := models.CheckinRequest{
		AgentID:           agent3ID,
		Hostname:          "host3",
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
	if err := hub.Store.RecordCheckin(&checkin3); err != nil {
		t.Fatalf("record checkin3: %v", err)
	}

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

	// Verify health counts
	if overview.HealthyAgents != 2 {
		t.Errorf("expected healthy_agents 2, got %d", overview.HealthyAgents)
	}

	if overview.UnhealthyAgents != 1 {
		t.Errorf("expected unhealthy_agents 1, got %d", overview.UnhealthyAgents)
	}

	// Verify version distribution
	if overview.VersionDistribution["1.1.0"] != 2 {
		t.Errorf("expected version 1.1.0 count 2, got %d", overview.VersionDistribution["1.1.0"])
	}

	if overview.VersionDistribution["1.0.0"] != 1 {
		t.Errorf("expected version 1.0.0 count 1, got %d", overview.VersionDistribution["1.0.0"])
	}
}

// TestHandleDashboardOverview_PolicyCompliance tests policy compliance scenarios.
func TestHandleDashboardOverview_PolicyCompliance(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitPolicySchema(); err != nil {
		t.Fatalf("init policy schema: %v", err)
	}

	// Register agent 1: no policy group (unassigned)
	agent1ID := uuid.New().String()
	if err := hub.Store.RegisterAgent(agent1ID, "host1", nil); err != nil {
		t.Fatalf("register agent1: %v", err)
	}

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

	// Create a policy group with published policy
	groupID := uuid.New().String()
	group := models.PolicyGroup{
		GroupID:     groupID,
		Name:        "policy-group",
		Description: "test group",
	}
	if err := hub.Store.CreatePolicyGroup(group); err != nil {
		t.Fatalf("create policy group: %v", err)
	}

	// Create and publish a policy version
	versionID := uuid.New().String()
	version := models.PolicyVersion{
		VersionID:     versionID,
		GroupID:       groupID,
		VersionLabel:  "v1",
		PolicyYAML:    "test policy",
		PolicyHash:    "policy-hash-123",
		Status:        "draft",
		CreatedBy:     "admin",
	}
	if err := hub.Store.CreatePolicyVersion(version); err != nil {
		t.Fatalf("create policy version: %v", err)
	}

	if err := hub.Store.UpdatePolicyVersionStatus(versionID, "approved"); err != nil {
		t.Fatalf("approve policy: %v", err)
	}

	if err := hub.Store.PublishPolicyVersion(versionID); err != nil {
		t.Fatalf("publish policy: %v", err)
	}

	// Register agent 2: assigned to group, matching policy hash (compliant)
	agent2ID := uuid.New().String()
	if err := hub.Store.RegisterAgent(agent2ID, "host2", nil); err != nil {
		t.Fatalf("register agent2: %v", err)
	}
	if err := hub.Store.AssignAgentToGroup(agent2ID, groupID); err != nil {
		t.Fatalf("assign agent2 to group: %v", err)
	}

	checkin2 := models.CheckinRequest{
		AgentID:           agent2ID,
		Hostname:          "host2",
		ClawshieldVersion: "1.0.0",
		AgentVersion:      "1.0.0",
		PolicyHash:        "policy-hash-123",
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
	if err := hub.Store.RecordCheckin(&checkin2); err != nil {
		t.Fatalf("record checkin2: %v", err)
	}

	// Register agent 3: assigned to group, mismatched policy hash (non-compliant)
	agent3ID := uuid.New().String()
	if err := hub.Store.RegisterAgent(agent3ID, "host3", nil); err != nil {
		t.Fatalf("register agent3: %v", err)
	}
	if err := hub.Store.AssignAgentToGroup(agent3ID, groupID); err != nil {
		t.Fatalf("assign agent3 to group: %v", err)
	}

	checkin3 := models.CheckinRequest{
		AgentID:           agent3ID,
		Hostname:          "host3",
		ClawshieldVersion: "1.0.0",
		AgentVersion:      "1.0.0",
		PolicyHash:        "different-hash-456",
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
	if err := hub.Store.RecordCheckin(&checkin3); err != nil {
		t.Fatalf("record checkin3: %v", err)
	}

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

	// Verify policy compliance counts
	if overview.PolicyCompliance.Unassigned != 1 {
		t.Errorf("expected unassigned 1, got %d", overview.PolicyCompliance.Unassigned)
	}

	if overview.PolicyCompliance.Compliant != 1 {
		t.Errorf("expected compliant 1, got %d", overview.PolicyCompliance.Compliant)
	}

	if overview.PolicyCompliance.NonCompliant != 1 {
		t.Errorf("expected non_compliant 1, got %d", overview.PolicyCompliance.NonCompliant)
	}
}

// TestHandleSecuritySummary_WrongMethod verifies wrong HTTP method returns 405.
func TestHandleSecuritySummary_WrongMethod(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitKeySchema(); err != nil {
		t.Fatalf("init key schema: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/dashboard/security", nil)
	w := httptest.NewRecorder()

	hub.HandleSecuritySummary(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}

	var resp models.ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Error == "" {
		t.Error("expected error message")
	}
}

// TestDashboardOverview_EmptyFleet tests overview with no agents (covers line 32: agents == nil).
func TestDashboardOverview_EmptyFleet(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitPolicySchema(); err != nil {
		t.Fatalf("init policy schema: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/overview", nil)
	w := httptest.NewRecorder()

	hub.HandleDashboardOverview(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var overview models.DashboardOverview
	if err := json.NewDecoder(w.Body).Decode(&overview); err != nil {
		t.Fatalf("decode overview: %v", err)
	}

	if overview.TotalAgents != 0 {
		t.Errorf("expected 0 total agents, got %d", overview.TotalAgents)
	}

	if overview.PolicyCompliance.Unassigned != 0 {
		t.Errorf("expected 0 unassigned agents, got %d", overview.PolicyCompliance.Unassigned)
	}
}

// TestDashboardOverview_AgentWithGroupNoVersion tests agent assigned to group with no published policy version (covers line 80).
func TestDashboardOverview_AgentWithGroupNoVersion(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitPolicySchema(); err != nil {
		t.Fatalf("init policy schema: %v", err)
	}

	// Register agent
	agentID := "agent-no-version"
	if err := hub.Store.RegisterAgent(agentID, "host1", []string{}); err != nil {
		t.Fatalf("register agent: %v", err)
	}

	// Create policy group with no published version
	groupID := "group-no-version"
	group := models.PolicyGroup{
		GroupID:     groupID,
		Name:        "test-group-no-version",
		Description: "group with no published policy",
	}
	if err := hub.Store.CreatePolicyGroup(group); err != nil {
		t.Fatalf("create policy group: %v", err)
	}

	// Assign agent to group
	if err := hub.Store.AssignAgentToGroup(agentID, groupID); err != nil {
		t.Fatalf("assign agent to group: %v", err)
	}

	// Request overview
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/overview", nil)
	w := httptest.NewRecorder()

	hub.HandleDashboardOverview(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var overview models.DashboardOverview
	if err := json.NewDecoder(w.Body).Decode(&overview); err != nil {
		t.Fatalf("decode overview: %v", err)
	}

	// Agent has group but no published version, so should be unassigned
	if overview.PolicyCompliance.Unassigned != 1 {
		t.Errorf("expected 1 unassigned (no published version), got %d", overview.PolicyCompliance.Unassigned)
	}

	if overview.TotalAgents != 1 {
		t.Errorf("expected 1 total agent, got %d", overview.TotalAgents)
	}
}

// TestDashboardOverview_AgentCompliant tests agent with matching policy hash (covers lines 84-96).
func TestDashboardOverview_AgentCompliant(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitPolicySchema(); err != nil {
		t.Fatalf("init policy schema: %v", err)
	}

	// Register agent
	agentID := "agent-compliant"
	if err := hub.Store.RegisterAgent(agentID, "host1", []string{}); err != nil {
		t.Fatalf("register agent: %v", err)
	}

	// Create policy group
	groupID := "group-with-version"
	group := models.PolicyGroup{
		GroupID:     groupID,
		Name:        "test-group",
		Description: "group with published policy",
	}
	if err := hub.Store.CreatePolicyGroup(group); err != nil {
		t.Fatalf("create policy group: %v", err)
	}

	// Create policy version
	versionID := "version-1"
	policyHash := "policy-hash-abc123"
	version := models.PolicyVersion{
		VersionID:    versionID,
		GroupID:      groupID,
		VersionLabel: "v1",
		PolicyYAML:   "test policy yaml",
		PolicyHash:   policyHash,
		Status:       "draft",
		CreatedBy:    "admin",
	}
	if err := hub.Store.CreatePolicyVersion(version); err != nil {
		t.Fatalf("create policy version: %v", err)
	}

	// Approve and publish version
	if err := hub.Store.UpdatePolicyVersionStatus(versionID, "approved"); err != nil {
		t.Fatalf("approve policy: %v", err)
	}
	if err := hub.Store.PublishPolicyVersion(versionID); err != nil {
		t.Fatalf("publish policy: %v", err)
	}

	// Assign agent to group
	if err := hub.Store.AssignAgentToGroup(agentID, groupID); err != nil {
		t.Fatalf("assign agent to group: %v", err)
	}

	// Record checkin with matching policy hash
	checkin := models.CheckinRequest{
		AgentID:           agentID,
		Hostname:          "host1",
		ClawshieldVersion: "1.0.0",
		PolicyHash:        policyHash,
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
	if err := hub.Store.RecordCheckin(&checkin); err != nil {
		t.Fatalf("record checkin: %v", err)
	}

	// Request overview
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/overview", nil)
	w := httptest.NewRecorder()

	hub.HandleDashboardOverview(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var overview models.DashboardOverview
	if err := json.NewDecoder(w.Body).Decode(&overview); err != nil {
		t.Fatalf("decode overview: %v", err)
	}

	// Agent has matching policy hash, so should be compliant
	if overview.PolicyCompliance.Compliant != 1 {
		t.Errorf("expected 1 compliant agent, got %d", overview.PolicyCompliance.Compliant)
	}

	if overview.PolicyCompliance.NonCompliant != 0 {
		t.Errorf("expected 0 non-compliant agents, got %d", overview.PolicyCompliance.NonCompliant)
	}

	if overview.PolicyCompliance.Unassigned != 0 {
		t.Errorf("expected 0 unassigned agents, got %d", overview.PolicyCompliance.Unassigned)
	}
}

// TestDashboardOverview_AgentNonCompliant tests agent with non-matching policy hash (covers line 94).
func TestDashboardOverview_AgentNonCompliant(t *testing.T) {
	hub := setupTestHub(t)
	if err := hub.Store.InitPolicySchema(); err != nil {
		t.Fatalf("init policy schema: %v", err)
	}

	// Register agent
	agentID := "agent-non-compliant"
	if err := hub.Store.RegisterAgent(agentID, "host1", []string{}); err != nil {
		t.Fatalf("register agent: %v", err)
	}

	// Create policy group
	groupID := "group-strict"
	group := models.PolicyGroup{
		GroupID:     groupID,
		Name:        "strict-group",
		Description: "strict policy group",
	}
	if err := hub.Store.CreatePolicyGroup(group); err != nil {
		t.Fatalf("create policy group: %v", err)
	}

	// Create policy version
	versionID := "version-strict"
	policyHash := "policy-hash-xyz789"
	version := models.PolicyVersion{
		VersionID:    versionID,
		GroupID:      groupID,
		VersionLabel: "v1",
		PolicyYAML:   "strict policy",
		PolicyHash:   policyHash,
		Status:       "draft",
		CreatedBy:    "admin",
	}
	if err := hub.Store.CreatePolicyVersion(version); err != nil {
		t.Fatalf("create policy version: %v", err)
	}

	// Approve and publish version
	if err := hub.Store.UpdatePolicyVersionStatus(versionID, "approved"); err != nil {
		t.Fatalf("approve policy: %v", err)
	}
	if err := hub.Store.PublishPolicyVersion(versionID); err != nil {
		t.Fatalf("publish policy: %v", err)
	}

	// Assign agent to group
	if err := hub.Store.AssignAgentToGroup(agentID, groupID); err != nil {
		t.Fatalf("assign agent to group: %v", err)
	}

	// Record checkin with DIFFERENT policy hash
	checkin := models.CheckinRequest{
		AgentID:           agentID,
		Hostname:          "host1",
		ClawshieldVersion: "1.0.0",
		PolicyHash:        "different-hash-123",
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
	if err := hub.Store.RecordCheckin(&checkin); err != nil {
		t.Fatalf("record checkin: %v", err)
	}

	// Request overview
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/overview", nil)
	w := httptest.NewRecorder()

	hub.HandleDashboardOverview(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var overview models.DashboardOverview
	if err := json.NewDecoder(w.Body).Decode(&overview); err != nil {
		t.Fatalf("decode overview: %v", err)
	}

	// Agent has non-matching policy hash, so should be non-compliant
	if overview.PolicyCompliance.NonCompliant != 1 {
		t.Errorf("expected 1 non-compliant agent, got %d", overview.PolicyCompliance.NonCompliant)
	}

	if overview.PolicyCompliance.Compliant != 0 {
		t.Errorf("expected 0 compliant agents, got %d", overview.PolicyCompliance.Compliant)
	}

	if overview.PolicyCompliance.Unassigned != 0 {
		t.Errorf("expected 0 unassigned agents, got %d", overview.PolicyCompliance.Unassigned)
	}
}
