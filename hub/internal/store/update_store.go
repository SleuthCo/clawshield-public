package store

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/SleuthCo/clawshield/hub/internal/models"
)

// InitUpdateSchema creates the update_releases, update_tasks, and update_rollouts tables.
func (s *Store) InitUpdateSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS update_releases (
		release_id TEXT PRIMARY KEY,
		version TEXT NOT NULL,
		binary_hash TEXT NOT NULL,
		signature TEXT DEFAULT '',
		release_notes TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS update_rollouts (
		rollout_id TEXT PRIMARY KEY,
		release_id TEXT NOT NULL,
		status TEXT DEFAULT 'active',
		wave_config TEXT DEFAULT '{}',
		current_wave TEXT DEFAULT 'canary',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(release_id) REFERENCES update_releases(release_id)
	);
	CREATE TABLE IF NOT EXISTS update_tasks (
		task_id TEXT PRIMARY KEY,
		agent_id TEXT NOT NULL,
		target_version TEXT NOT NULL,
		binary_hash TEXT NOT NULL,
		signature TEXT DEFAULT '',
		status TEXT DEFAULT 'pending',
		wave TEXT DEFAULT '',
		scheduled_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		completed_at DATETIME,
		error_message TEXT DEFAULT '',
		FOREIGN KEY(agent_id) REFERENCES agents(agent_id)
	);`

	_, err := s.db.Exec(schema)
	return err
}

// CreateRelease stores a new update release.
func (s *Store) CreateRelease(r models.UpdateRelease) error {
	_, err := s.db.Exec(
		`INSERT INTO update_releases (release_id, version, binary_hash, signature, release_notes, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		r.ReleaseID, r.Version, r.BinaryHash, r.Signature, r.ReleaseNotes, r.CreatedAt)
	return err
}

// GetRelease retrieves a release by ID. Returns nil if not found.
func (s *Store) GetRelease(releaseID string) (*models.UpdateRelease, error) {
	var r models.UpdateRelease
	err := s.db.QueryRow(
		`SELECT release_id, version, binary_hash, signature, release_notes, created_at
		 FROM update_releases WHERE release_id = ?`, releaseID).Scan(
		&r.ReleaseID, &r.Version, &r.BinaryHash, &r.Signature, &r.ReleaseNotes, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// ListReleases returns all releases ordered by created_at DESC.
func (s *Store) ListReleases() ([]models.UpdateRelease, error) {
	rows, err := s.db.Query(
		`SELECT release_id, version, binary_hash, signature, release_notes, created_at
		 FROM update_releases ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var releases []models.UpdateRelease
	for rows.Next() {
		var r models.UpdateRelease
		if err := rows.Scan(&r.ReleaseID, &r.Version, &r.BinaryHash, &r.Signature, &r.ReleaseNotes, &r.CreatedAt); err != nil {
			return nil, err
		}
		releases = append(releases, r)
	}
	return releases, rows.Err()
}

// CreateRollout stores a new update rollout.
func (s *Store) CreateRollout(r models.UpdateRollout) error {
	waveConfigJSON, err := json.Marshal(r.WaveConfig)
	if err != nil {
		return fmt.Errorf("marshal wave_config: %w", err)
	}
	_, err = s.db.Exec(
		`INSERT INTO update_rollouts (rollout_id, release_id, status, wave_config, current_wave, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		r.RolloutID, r.ReleaseID, r.Status, string(waveConfigJSON), r.CurrentWave, r.CreatedAt)
	return err
}

// GetRollout retrieves a rollout by ID. Returns nil if not found.
func (s *Store) GetRollout(rolloutID string) (*models.UpdateRollout, error) {
	var r models.UpdateRollout
	var waveConfigJSON string
	err := s.db.QueryRow(
		`SELECT rollout_id, release_id, status, wave_config, current_wave, created_at
		 FROM update_rollouts WHERE rollout_id = ?`, rolloutID).Scan(
		&r.RolloutID, &r.ReleaseID, &r.Status, &waveConfigJSON, &r.CurrentWave, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(waveConfigJSON), &r.WaveConfig)
	return &r, nil
}

// UpdateRolloutStatus updates the status and currentWave of a rollout.
func (s *Store) UpdateRolloutStatus(rolloutID, status, currentWave string) error {
	_, err := s.db.Exec(
		`UPDATE update_rollouts SET status = ?, current_wave = ? WHERE rollout_id = ?`,
		status, currentWave, rolloutID)
	return err
}

// CreateUpdateTask stores a new update task.
func (s *Store) CreateUpdateTask(t models.UpdateTask) error {
	_, err := s.db.Exec(
		`INSERT INTO update_tasks (task_id, agent_id, target_version, binary_hash, signature, status, wave, scheduled_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		t.TaskID, t.AgentID, t.TargetVersion, t.BinaryHash, t.Signature, t.Status, t.Wave, t.ScheduledAt)
	return err
}

// GetPendingUpdateForAgent returns the first pending update task for an agent, or nil if none.
func (s *Store) GetPendingUpdateForAgent(agentID string) (*models.UpdateTask, error) {
	var t models.UpdateTask
	var completedAt sql.NullTime
	err := s.db.QueryRow(
		`SELECT task_id, agent_id, target_version, binary_hash, signature, status, wave, scheduled_at, completed_at, error_message
		 FROM update_tasks WHERE agent_id = ? AND status = 'pending' ORDER BY scheduled_at LIMIT 1`,
		agentID).Scan(
		&t.TaskID, &t.AgentID, &t.TargetVersion, &t.BinaryHash, &t.Signature, &t.Status, &t.Wave, &t.ScheduledAt, &completedAt, &t.ErrorMessage)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if completedAt.Valid {
		t.CompletedAt = completedAt.Time
	}
	return &t, nil
}

// UpdateTaskStatus updates the status of an update task and sets completed_at if terminal.
func (s *Store) UpdateTaskStatus(taskID, status, errorMsg string) error {
	isTerminal := status == "completed" || status == "failed" || status == "rolled_back"
	if isTerminal {
		_, err := s.db.Exec(
			`UPDATE update_tasks SET status = ?, error_message = ?, completed_at = CURRENT_TIMESTAMP WHERE task_id = ?`,
			status, errorMsg, taskID)
		return err
	}
	_, err := s.db.Exec(
		`UPDATE update_tasks SET status = ?, error_message = ? WHERE task_id = ?`,
		status, errorMsg, taskID)
	return err
}

// GetRolloutTaskStats returns total, completed, and failed task counts for a rollout.
func (s *Store) GetRolloutTaskStats(rolloutID string) (total, completed, failed int, err error) {
	// Get the release_id for this rollout
	var releaseID string
	err = s.db.QueryRow(`SELECT release_id FROM update_rollouts WHERE rollout_id = ?`, rolloutID).Scan(&releaseID)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("get release_id: %w", err)
	}

	// Get the version from the release
	var version string
	err = s.db.QueryRow(`SELECT version FROM update_releases WHERE release_id = ?`, releaseID).Scan(&version)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("get version: %w", err)
	}

	// Count tasks by status for this rollout's release
	err = s.db.QueryRow(
		`SELECT COUNT(*), 
		        COALESCE(SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END), 0),
		        COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0)
		 FROM update_tasks WHERE target_version = ?`, version).Scan(&total, &completed, &failed)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("get stats: %w", err)
	}
	return total, completed, failed, nil
}
