package store

import (
	"testing"
	"time"

	"github.com/SleuthCo/clawshield/hub/internal/models"
)

// TestReleaseCRUD tests create, get, and list releases.
func TestReleaseCRUD(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	if err := s.InitUpdateSchema(); err != nil {
		t.Fatalf("InitUpdateSchema failed: %v", err)
	}

	// Create a release
	release := models.UpdateRelease{
		ReleaseID:    "rel-001",
		Version:      "1.5.0",
		BinaryHash:   "abc123",
		Signature:    "sig123",
		ReleaseNotes: "Bug fixes and improvements",
		CreatedAt:    time.Now().UTC(),
	}

	if err := s.CreateRelease(release); err != nil {
		t.Fatalf("CreateRelease failed: %v", err)
	}

	// Get the release
	retrieved, err := s.GetRelease("rel-001")
	if err != nil {
		t.Fatalf("GetRelease failed: %v", err)
	}
	if retrieved == nil {
		t.Fatal("Expected release, got nil")
	}
	if retrieved.Version != "1.5.0" {
		t.Errorf("Expected version 1.5.0, got %s", retrieved.Version)
	}
	if retrieved.BinaryHash != "abc123" {
		t.Errorf("Expected hash abc123, got %s", retrieved.BinaryHash)
	}

	// Create another release
	release2 := models.UpdateRelease{
		ReleaseID:    "rel-002",
		Version:      "1.6.0",
		BinaryHash:   "def456",
		Signature:    "sig456",
		ReleaseNotes: "New features",
		CreatedAt:    time.Now().UTC().Add(1 * time.Second),
	}
	if err := s.CreateRelease(release2); err != nil {
		t.Fatalf("CreateRelease failed: %v", err)
	}

	// List releases
	releases, err := s.ListReleases()
	if err != nil {
		t.Fatalf("ListReleases failed: %v", err)
	}
	if len(releases) != 2 {
		t.Errorf("Expected 2 releases, got %d", len(releases))
	}
	// Should be ordered by created_at DESC (rel-002 first)
	if releases[0].Version != "1.6.0" {
		t.Errorf("Expected first release version 1.6.0, got %s", releases[0].Version)
	}
}

// TestRolloutLifecycle tests create rollout, update status, and get.
func TestRolloutLifecycle(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	if err := s.InitUpdateSchema(); err != nil {
		t.Fatalf("InitUpdateSchema failed: %v", err)
	}

	// Create a release first
	release := models.UpdateRelease{
		ReleaseID:  "rel-001",
		Version:    "1.5.0",
		BinaryHash: "abc123",
		Signature:  "sig123",
		CreatedAt:  time.Now().UTC(),
	}
	if err := s.CreateRelease(release); err != nil {
		t.Fatalf("CreateRelease failed: %v", err)
	}

	// Create a rollout
	rollout := models.UpdateRollout{
		RolloutID: "roll-001",
		ReleaseID: "rel-001",
		Status:    "active",
		WaveConfig: models.WaveConfig{
			CanaryPercent: 5,
			Wave1Percent:  25,
			Wave2Percent:  50,
		},
		CurrentWave: "canary",
		CreatedAt:   time.Now().UTC(),
	}

	if err := s.CreateRollout(rollout); err != nil {
		t.Fatalf("CreateRollout failed: %v", err)
	}

	// Get the rollout
	retrieved, err := s.GetRollout("roll-001")
	if err != nil {
		t.Fatalf("GetRollout failed: %v", err)
	}
	if retrieved == nil {
		t.Fatal("Expected rollout, got nil")
	}
	if retrieved.Status != "active" {
		t.Errorf("Expected status active, got %s", retrieved.Status)
	}
	if retrieved.CurrentWave != "canary" {
		t.Errorf("Expected current_wave canary, got %s", retrieved.CurrentWave)
	}
	if retrieved.WaveConfig.CanaryPercent != 5 {
		t.Errorf("Expected canary percent 5, got %d", retrieved.WaveConfig.CanaryPercent)
	}

	// Update rollout status
	if err := s.UpdateRolloutStatus("roll-001", "completed", "full"); err != nil {
		t.Fatalf("UpdateRolloutStatus failed: %v", err)
	}

	// Verify update
	retrieved, err = s.GetRollout("roll-001")
	if err != nil {
		t.Fatalf("GetRollout after update failed: %v", err)
	}
	if retrieved.Status != "completed" {
		t.Errorf("Expected status completed, got %s", retrieved.Status)
	}
	if retrieved.CurrentWave != "full" {
		t.Errorf("Expected current_wave full, got %s", retrieved.CurrentWave)
	}
}

// TestUpdateTaskLifecycle tests create task, get pending, and update status.
func TestUpdateTaskLifecycle(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	if err := s.InitUpdateSchema(); err != nil {
		t.Fatalf("InitUpdateSchema failed: %v", err)
	}

	// Register an agent first
	if err := s.RegisterAgent("agent-001", "host1", []string{}); err != nil {
		t.Fatalf("RegisterAgent failed: %v", err)
	}

	// Create an update task
	task := models.UpdateTask{
		TaskID:        "task-001",
		AgentID:       "agent-001",
		TargetVersion: "1.5.0",
		BinaryHash:    "abc123",
		Signature:     "sig123",
		Status:        "pending",
		Wave:          "canary",
		ScheduledAt:   time.Now().UTC(),
	}

	if err := s.CreateUpdateTask(task); err != nil {
		t.Fatalf("CreateUpdateTask failed: %v", err)
	}

	// Get pending update for agent
	pending, err := s.GetPendingUpdateForAgent("agent-001")
	if err != nil {
		t.Fatalf("GetPendingUpdateForAgent failed: %v", err)
	}
	if pending == nil {
		t.Fatal("Expected pending task, got nil")
	}
	if pending.TaskID != "task-001" {
		t.Errorf("Expected task_id task-001, got %s", pending.TaskID)
	}
	if pending.Status != "pending" {
		t.Errorf("Expected status pending, got %s", pending.Status)
	}

	// Update task status to in_progress
	if err := s.UpdateTaskStatus("task-001", "in_progress", ""); err != nil {
		t.Fatalf("UpdateTaskStatus failed: %v", err)
	}

	// Verify no pending task now
	pending, err = s.GetPendingUpdateForAgent("agent-001")
	if err != nil {
		t.Fatalf("GetPendingUpdateForAgent after update failed: %v", err)
	}
	if pending != nil {
		t.Fatal("Expected no pending task, got one")
	}

	// Update task status to completed (terminal)
	if err := s.UpdateTaskStatus("task-001", "completed", ""); err != nil {
		t.Fatalf("UpdateTaskStatus to completed failed: %v", err)
	}

	// Update task status to failed (terminal)
	task2 := models.UpdateTask{
		TaskID:        "task-002",
		AgentID:       "agent-001",
		TargetVersion: "1.6.0",
		BinaryHash:    "def456",
		Signature:     "sig456",
		Status:        "pending",
		Wave:          "wave1",
		ScheduledAt:   time.Now().UTC(),
	}
	if err := s.CreateUpdateTask(task2); err != nil {
		t.Fatalf("CreateUpdateTask failed: %v", err)
	}

	if err := s.UpdateTaskStatus("task-002", "failed", "download failed"); err != nil {
		t.Fatalf("UpdateTaskStatus to failed failed: %v", err)
	}
}

// TestGetRolloutTaskStats tests task counting for a rollout.
func TestGetRolloutTaskStats(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	if err := s.InitUpdateSchema(); err != nil {
		t.Fatalf("InitUpdateSchema failed: %v", err)
	}

	// Create a release
	release := models.UpdateRelease{
		ReleaseID:  "rel-001",
		Version:    "1.5.0",
		BinaryHash: "abc123",
		Signature:  "sig123",
		CreatedAt:  time.Now().UTC(),
	}
	if err := s.CreateRelease(release); err != nil {
		t.Fatalf("CreateRelease failed: %v", err)
	}

	// Create a rollout
	rollout := models.UpdateRollout{
		RolloutID: "roll-001",
		ReleaseID: "rel-001",
		Status:    "active",
		WaveConfig: models.WaveConfig{
			CanaryPercent: 5,
			Wave1Percent:  25,
			Wave2Percent:  50,
		},
		CurrentWave: "canary",
		CreatedAt:   time.Now().UTC(),
	}
	if err := s.CreateRollout(rollout); err != nil {
		t.Fatalf("CreateRollout failed: %v", err)
	}

	// Register agents
	for i := 1; i <= 4; i++ {
		agentID := "agent-" + string(rune('0'+i))
		if err := s.RegisterAgent(agentID, "host"+string(rune('0'+i)), []string{}); err != nil {
			t.Fatalf("RegisterAgent failed: %v", err)
		}
	}

	// Create tasks with mixed statuses
	statuses := []string{"pending", "completed", "completed", "failed"}
	for i, status := range statuses {
		task := models.UpdateTask{
			TaskID:        "task-00" + string(rune('1'+i)),
			AgentID:       "agent-" + string(rune('1'+i)),
			TargetVersion: "1.5.0",
			BinaryHash:    "abc123",
			Signature:     "sig123",
			Status:        status,
			Wave:          "canary",
			ScheduledAt:   time.Now().UTC(),
		}
		if err := s.CreateUpdateTask(task); err != nil {
			t.Fatalf("CreateUpdateTask failed: %v", err)
		}
		if status != "pending" {
			if err := s.UpdateTaskStatus(task.TaskID, status, ""); err != nil {
				t.Fatalf("UpdateTaskStatus failed: %v", err)
			}
		}
	}

	// Get rollout task stats
	total, completed, failed, err := s.GetRolloutTaskStats("roll-001")
	if err != nil {
		t.Fatalf("GetRolloutTaskStats failed: %v", err)
	}

	if total != 4 {
		t.Errorf("Expected total 4, got %d", total)
	}
	if completed != 2 {
		t.Errorf("Expected completed 2, got %d", completed)
	}
	if failed != 1 {
		t.Errorf("Expected failed 1, got %d", failed)
	}
}
