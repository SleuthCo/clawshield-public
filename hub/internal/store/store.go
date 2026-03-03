// Package store provides SQLite-backed persistence for the ClawShield
// management hub. It manages fleet registration, agent check-ins,
// enrollment tokens, and fleet status tracking.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/SleuthCo/clawshield/hub/internal/models"
	_ "github.com/mattn/go-sqlite3"
)

// Store manages the hub's persistent data.
type Store struct {
	db *sql.DB
}

// NewStore creates a new Store with the given database file path.
// If dbPath is ":memory:", an in-memory SQLite database is used.
func NewStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}

	store := &Store{db: db}
	if err := store.initSchema(); err != nil {
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return store, nil
}

func (s *Store) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS agents (
		agent_id TEXT PRIMARY KEY,
		hostname TEXT NOT NULL DEFAULT '',
		ip_address TEXT DEFAULT '',
		clawshield_version TEXT DEFAULT '',
		agent_version TEXT DEFAULT '',
		policy_hash TEXT DEFAULT '',
		policy_version TEXT DEFAULT '',
		encryption_key_id TEXT DEFAULT '',
		status TEXT DEFAULT 'healthy',
		tags TEXT DEFAULT '[]',
		last_checkin_at DATETIME,
		registered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		policy_group_id TEXT DEFAULT ''
	);

	CREATE TABLE IF NOT EXISTS agent_checkins (
		checkin_id INTEGER PRIMARY KEY AUTOINCREMENT,
		agent_id TEXT NOT NULL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		health_status TEXT,
		metrics_summary TEXT,
		audit_db_size_bytes INTEGER DEFAULT 0,
		FOREIGN KEY(agent_id) REFERENCES agents(agent_id)
	);

	CREATE TABLE IF NOT EXISTS enrollment_tokens (
		token TEXT PRIMARY KEY,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		used INTEGER DEFAULT 0,
		used_by TEXT,
		used_at DATETIME
	);`

	_, err := s.db.Exec(schema)
	return err
}

// InitPolicySchema initializes the policy-related tables.
func (s *Store) InitPolicySchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS policy_groups (
		group_id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		parent_group_id TEXT DEFAULT '',
		description TEXT DEFAULT '',
		current_policy_version_id TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS policy_versions (
		version_id TEXT PRIMARY KEY,
		group_id TEXT NOT NULL,
		version_label TEXT NOT NULL,
		policy_yaml TEXT NOT NULL,
		policy_hash TEXT NOT NULL,
		signature TEXT DEFAULT '',
		status TEXT DEFAULT 'draft',
		created_by TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		published_at DATETIME,
		FOREIGN KEY(group_id) REFERENCES policy_groups(group_id)
	);

	CREATE TABLE IF NOT EXISTS policy_approvals (
		approval_id TEXT PRIMARY KEY,
		version_id TEXT NOT NULL,
		approver_id TEXT NOT NULL,
		decision TEXT NOT NULL,
		comment TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(version_id) REFERENCES policy_versions(version_id)
	);

	CREATE INDEX IF NOT EXISTS idx_policy_versions_group ON policy_versions(group_id);
	CREATE INDEX IF NOT EXISTS idx_policy_approvals_version ON policy_approvals(version_id);`

	_, err := s.db.Exec(schema)
	return err
}

// EnrollmentToken represents a stored enrollment token.
type EnrollmentToken struct {
	Token     string `json:"token"`
	CreatedAt string `json:"created_at"`
	Used      bool   `json:"used"`
	UsedBy    string `json:"used_by,omitempty"`
	UsedAt    string `json:"used_at,omitempty"`
}

// ListEnrollmentTokens returns all enrollment tokens.
func (s *Store) ListEnrollmentTokens() ([]EnrollmentToken, error) {
	rows, err := s.db.Query(
		`SELECT token, created_at, used, COALESCE(used_by,''), COALESCE(used_at,'')
		 FROM enrollment_tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []EnrollmentToken
	for rows.Next() {
		var t EnrollmentToken
		var used int
		if err := rows.Scan(&t.Token, &t.CreatedAt, &used, &t.UsedBy, &t.UsedAt); err != nil {
			return nil, err
		}
		t.Used = used != 0
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// CreateEnrollmentToken stores a new enrollment token.
func (s *Store) CreateEnrollmentToken(token string) error {
	_, err := s.db.Exec(
		"INSERT INTO enrollment_tokens (token) VALUES (?)", token)
	return err
}

// ValidateEnrollmentToken checks if a token is valid (exists and unused)
// and marks it as used. Returns (true, nil) if valid, (false, nil) if
// invalid or already used, or (false, err) on database error.
func (s *Store) ValidateEnrollmentToken(token string) (bool, error) {
	var used int
	err := s.db.QueryRow(
		"SELECT used FROM enrollment_tokens WHERE token = ?", token,
	).Scan(&used)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if used != 0 {
		return false, nil
	}

	_, err = s.db.Exec(
		"UPDATE enrollment_tokens SET used = 1, used_at = CURRENT_TIMESTAMP WHERE token = ?",
		token)
	if err != nil {
		return false, err
	}
	return true, nil
}

// RegisterAgent registers a new agent with the given ID, hostname, and tags.
func (s *Store) RegisterAgent(agentID, hostname string, tags []string) error {
	tagsJSON, err := json.Marshal(tags)
	if err != nil {
		return fmt.Errorf("marshal tags: %w", err)
	}
	_, err = s.db.Exec(
		`INSERT INTO agents (agent_id, hostname, tags, status, registered_at, last_checkin_at)
		 VALUES (?, ?, ?, 'healthy', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		agentID, hostname, string(tagsJSON))
	return err
}

// GetAgent retrieves a single agent by ID. Returns nil if not found.
func (s *Store) GetAgent(agentID string) (*models.Agent, error) {
	var a models.Agent
	var tagsJSON string
	err := s.db.QueryRow(
		`SELECT agent_id, hostname, ip_address, clawshield_version,
		        agent_version, policy_hash, policy_version,
		        encryption_key_id, status, tags, last_checkin_at,
		        registered_at, policy_group_id
		 FROM agents WHERE agent_id = ?`, agentID,
	).Scan(
		&a.AgentID, &a.Hostname, &a.IPAddress,
		&a.ClawshieldVersion, &a.AgentVersion,
		&a.PolicyHash, &a.PolicyVersion,
		&a.EncryptionKeyID, &a.Status, &tagsJSON,
		&a.LastCheckinAt, &a.RegisteredAt, &a.PolicyGroupID,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(tagsJSON), &a.Tags)
	return &a, nil
}

// ListAgents returns all agents, optionally filtered by status and/or tag.
func (s *Store) ListAgents(statusFilter, tagFilter string) ([]models.Agent, error) {
	query := `SELECT agent_id, hostname, ip_address, clawshield_version,
	                 agent_version, policy_hash, policy_version,
	                 encryption_key_id, status, tags, last_checkin_at,
	                 registered_at, policy_group_id
	          FROM agents WHERE 1=1`
	var args []interface{}

	if statusFilter != "" {
		query += " AND status = ?"
		args = append(args, statusFilter)
	}
	if tagFilter != "" {
		// Tags stored as JSON array — LIKE match for the value
		query += ` AND tags LIKE ?`
		args = append(args, fmt.Sprintf(`%%"%s"%%`, tagFilter))
	}
	query += " ORDER BY agent_id"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []models.Agent
	for rows.Next() {
		var a models.Agent
		var tagsJSON string
		if err := rows.Scan(
			&a.AgentID, &a.Hostname, &a.IPAddress,
			&a.ClawshieldVersion, &a.AgentVersion,
			&a.PolicyHash, &a.PolicyVersion,
			&a.EncryptionKeyID, &a.Status, &tagsJSON,
			&a.LastCheckinAt, &a.RegisteredAt, &a.PolicyGroupID,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(tagsJSON), &a.Tags)
		agents = append(agents, a)
	}
	return agents, rows.Err()
}

// RecordCheckin updates the agent's status fields and records a check-in row.
func (s *Store) RecordCheckin(req *models.CheckinRequest) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Update agent fields
	_, err = tx.Exec(
		`UPDATE agents SET
			hostname = ?, clawshield_version = ?, agent_version = ?,
			policy_hash = ?, policy_version = ?, encryption_key_id = ?,
			status = ?, last_checkin_at = CURRENT_TIMESTAMP
		 WHERE agent_id = ?`,
		req.Hostname, req.ClawshieldVersion, req.AgentVersion,
		req.PolicyHash, req.PolicyVersion, req.EncryptionKeyID,
		req.Health.Status, req.AgentID)
	if err != nil {
		return fmt.Errorf("update agent: %w", err)
	}

	// Serialize metrics
	metricsJSON, _ := json.Marshal(req.MetricsSummary)

	// Insert checkin row
	_, err = tx.Exec(
		`INSERT INTO agent_checkins (agent_id, health_status, metrics_summary, audit_db_size_bytes)
		 VALUES (?, ?, ?, ?)`,
		req.AgentID, req.Health.Status, string(metricsJSON), req.Health.AuditDBSizeBytes)
	if err != nil {
		return fmt.Errorf("insert checkin: %w", err)
	}

	return tx.Commit()
}

// GetRecentCheckins returns the last N check-ins for an agent.
func (s *Store) GetRecentCheckins(agentID string, limit int) ([]models.AgentCheckin, error) {
	rows, err := s.db.Query(
		`SELECT checkin_id, agent_id, timestamp, health_status,
		        COALESCE(metrics_summary, '{}'), COALESCE(audit_db_size_bytes, 0)
		 FROM agent_checkins
		 WHERE agent_id = ?
		 ORDER BY checkin_id DESC LIMIT ?`,
		agentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var checkins []models.AgentCheckin
	for rows.Next() {
		var c models.AgentCheckin
		var metricsJSON string
		if err := rows.Scan(&c.CheckinID, &c.AgentID, &c.Timestamp,
			&c.HealthStatus, &metricsJSON, &c.AuditDBSizeBytes); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(metricsJSON), &c.MetricsSummary)
		checkins = append(checkins, c)
	}
	return checkins, rows.Err()
}

// MarkStaleAgents marks agents as 'stale' if their last check-in is older
// than the given threshold. Returns the number of agents marked.
func (s *Store) MarkStaleAgents(threshold time.Duration) (int, error) {
	cutoff := time.Now().Add(-threshold)
	result, err := s.db.Exec(
		`UPDATE agents SET status = 'stale'
		 WHERE status != 'stale' AND last_checkin_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	n, _ := result.RowsAffected()
	return int(n), nil
}

// CreatePolicyGroup creates a new policy group.
func (s *Store) CreatePolicyGroup(group models.PolicyGroup) error {
	_, err := s.db.Exec(
		`INSERT INTO policy_groups (group_id, name, parent_group_id, description, created_at, updated_at)
		 VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		group.GroupID, group.Name, group.ParentGroupID, group.Description)
	return err
}

// GetPolicyGroup retrieves a policy group by ID. Returns nil if not found.
func (s *Store) GetPolicyGroup(groupID string) (*models.PolicyGroup, error) {
	var g models.PolicyGroup
	err := s.db.QueryRow(
		`SELECT group_id, name, parent_group_id, description, current_policy_version_id, created_at, updated_at
		 FROM policy_groups WHERE group_id = ?`, groupID,
	).Scan(&g.GroupID, &g.Name, &g.ParentGroupID, &g.Description, &g.CurrentPolicyVersionID, &g.CreatedAt, &g.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// ListPolicyGroups returns all policy groups.
func (s *Store) ListPolicyGroups() ([]models.PolicyGroup, error) {
	rows, err := s.db.Query(
		`SELECT group_id, name, parent_group_id, description, current_policy_version_id, created_at, updated_at
		 FROM policy_groups ORDER BY group_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []models.PolicyGroup
	for rows.Next() {
		var g models.PolicyGroup
		if err := rows.Scan(&g.GroupID, &g.Name, &g.ParentGroupID, &g.Description, &g.CurrentPolicyVersionID, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

// CreatePolicyVersion creates a new policy version.
func (s *Store) CreatePolicyVersion(version models.PolicyVersion) error {
	_, err := s.db.Exec(
		`INSERT INTO policy_versions (version_id, group_id, version_label, policy_yaml, policy_hash, status, created_by, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		version.VersionID, version.GroupID, version.VersionLabel, version.PolicyYAML, version.PolicyHash, version.Status, version.CreatedBy)
	return err
}

// GetPolicyVersion retrieves a policy version by ID. Returns nil if not found.
func (s *Store) GetPolicyVersion(versionID string) (*models.PolicyVersion, error) {
	var v models.PolicyVersion
	var publishedAt sql.NullTime
	err := s.db.QueryRow(
		`SELECT version_id, group_id, version_label, policy_yaml, policy_hash, signature, status, created_by, created_at, updated_at, published_at
		 FROM policy_versions WHERE version_id = ?`, versionID,
	).Scan(&v.VersionID, &v.GroupID, &v.VersionLabel, &v.PolicyYAML, &v.PolicyHash, &v.Signature, &v.Status, &v.CreatedBy, &v.CreatedAt, &v.UpdatedAt, &publishedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if publishedAt.Valid {
		v.PublishedAt = publishedAt.Time
	}
	return &v, nil
}

// ListPolicyVersions returns all policy versions for a group.
func (s *Store) ListPolicyVersions(groupID string) ([]models.PolicyVersion, error) {
	rows, err := s.db.Query(
		`SELECT version_id, group_id, version_label, policy_yaml, policy_hash, signature, status, created_by, created_at, updated_at, published_at
		 FROM policy_versions WHERE group_id = ? ORDER BY created_at DESC`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var versions []models.PolicyVersion
	for rows.Next() {
		var v models.PolicyVersion
		var publishedAt sql.NullTime
		if err := rows.Scan(&v.VersionID, &v.GroupID, &v.VersionLabel, &v.PolicyYAML, &v.PolicyHash, &v.Signature, &v.Status, &v.CreatedBy, &v.CreatedAt, &v.UpdatedAt, &publishedAt); err != nil {
			return nil, err
		}
		if publishedAt.Valid {
			v.PublishedAt = publishedAt.Time
		}
		versions = append(versions, v)
	}
	return versions, rows.Err()
}

// UpdatePolicyVersionStatus updates the status of a policy version.
// Valid transitions: draft → approved, draft → rejected, approved → published, published → superseded.
func (s *Store) UpdatePolicyVersionStatus(versionID, status string) error {
	// Get current status
	var currentStatus string
	err := s.db.QueryRow(`SELECT status FROM policy_versions WHERE version_id = ?`, versionID).Scan(&currentStatus)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("version not found")
		}
		return fmt.Errorf("query status: %w", err)
	}

	// Validate transition
	validTransitions := map[string]map[string]bool{
		"draft": {
			"approved": true,
			"rejected": true,
		},
		"approved": {
			"published": true,
			"rejected":  true,
		},
		"published": {
			"superseded": true,
		},
	}

	if allowed, exists := validTransitions[currentStatus]; !exists || !allowed[status] {
		return fmt.Errorf("invalid status transition from %q to %q", currentStatus, status)
	}

	_, err = s.db.Exec(
		`UPDATE policy_versions SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE version_id = ?`,
		status, versionID)
	return err
}

// SetPolicyVersionSignature sets the signature for a policy version.
func (s *Store) SetPolicyVersionSignature(versionID, signature string) error {
	_, err := s.db.Exec(
		`UPDATE policy_versions SET signature = ?, updated_at = CURRENT_TIMESTAMP WHERE version_id = ?`,
		signature, versionID)
	return err
}

// PublishPolicyVersion publishes a policy version and sets it as current for the group.
func (s *Store) PublishPolicyVersion(versionID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Get current status and validate it's approved
	var currentStatus string
	var groupID string
	err = tx.QueryRow(`SELECT status, group_id FROM policy_versions WHERE version_id = ?`, versionID).Scan(&currentStatus, &groupID)
	if err != nil {
		return fmt.Errorf("query version: %w", err)
	}

	if currentStatus != "approved" {
		return fmt.Errorf("cannot publish version with status %q: must be approved first", currentStatus)
	}

	// Update version status and published_at
	_, err = tx.Exec(
		`UPDATE policy_versions SET status = 'published', published_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
		 WHERE version_id = ?`, versionID)
	if err != nil {
		return fmt.Errorf("update version: %w", err)
	}

	// Update the group's current_policy_version_id
	_, err = tx.Exec(
		`UPDATE policy_groups SET current_policy_version_id = ?, updated_at = CURRENT_TIMESTAMP WHERE group_id = ?`,
		versionID, groupID)
	if err != nil {
		return fmt.Errorf("update group: %w", err)
	}

	return tx.Commit()
}

// CreatePolicyApproval creates a policy approval record.
func (s *Store) CreatePolicyApproval(approval models.PolicyApproval) error {
	_, err := s.db.Exec(
		`INSERT INTO policy_approvals (approval_id, version_id, approver_id, decision, comment, created_at)
		 VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		approval.ApprovalID, approval.VersionID, approval.ApproverID, approval.Decision, approval.Comment)
	return err
}

// GetPolicyApprovals returns all approvals for a policy version.
func (s *Store) GetPolicyApprovals(versionID string) ([]models.PolicyApproval, error) {
	rows, err := s.db.Query(
		`SELECT approval_id, version_id, approver_id, decision, comment, created_at
		 FROM policy_approvals WHERE version_id = ? ORDER BY created_at DESC`, versionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var approvals []models.PolicyApproval
	for rows.Next() {
		var a models.PolicyApproval
		if err := rows.Scan(&a.ApprovalID, &a.VersionID, &a.ApproverID, &a.Decision, &a.Comment, &a.CreatedAt); err != nil {
			return nil, err
		}
		approvals = append(approvals, a)
	}
	return approvals, rows.Err()
}

// AssignAgentToGroup assigns an agent to a policy group.
func (s *Store) AssignAgentToGroup(agentID, groupID string) error {
	_, err := s.db.Exec(
		`UPDATE agents SET policy_group_id = ? WHERE agent_id = ?`,
		groupID, agentID)
	return err
}

// GetAgentsByGroup returns all agents assigned to a policy group.
func (s *Store) GetAgentsByGroup(groupID string) ([]models.Agent, error) {
	rows, err := s.db.Query(
		`SELECT agent_id, hostname, ip_address, clawshield_version,
		        agent_version, policy_hash, policy_version,
		        encryption_key_id, status, tags, last_checkin_at,
		        registered_at, policy_group_id
		 FROM agents WHERE policy_group_id = ? ORDER BY agent_id`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []models.Agent
	for rows.Next() {
		var a models.Agent
		var tagsJSON string
		if err := rows.Scan(
			&a.AgentID, &a.Hostname, &a.IPAddress,
			&a.ClawshieldVersion, &a.AgentVersion,
			&a.PolicyHash, &a.PolicyVersion,
			&a.EncryptionKeyID, &a.Status, &tagsJSON,
			&a.LastCheckinAt, &a.RegisteredAt, &a.PolicyGroupID,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(tagsJSON), &a.Tags)
		agents = append(agents, a)
	}
	return agents, rows.Err()
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}
