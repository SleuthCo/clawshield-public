package store

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/SleuthCo/clawshield/hub/internal/models"
)

// InitKeySchema initializes the encryption key management tables.
func (s *Store) InitKeySchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS encryption_keys (
		key_id TEXT PRIMARY KEY,
		group_id TEXT NOT NULL,
		encrypted_key TEXT,
		status TEXT DEFAULT 'active',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME,
		rotated_at DATETIME
	);

	CREATE INDEX IF NOT EXISTS idx_encryption_keys_group ON encryption_keys(group_id);
	CREATE INDEX IF NOT EXISTS idx_encryption_keys_status ON encryption_keys(status);`

	_, err := s.db.Exec(schema)
	return err
}

// CreateKey stores a new encryption key.
func (s *Store) CreateKey(key models.EncryptionKey) error {
	_, err := s.db.Exec(
		`INSERT INTO encryption_keys (key_id, group_id, encrypted_key, status, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		key.KeyID, key.GroupID, key.EncryptedKey, key.Status, key.CreatedAt, nullTime(key.ExpiresAt))
	return err
}

// GetKey retrieves a single encryption key by ID. Returns nil if not found.
func (s *Store) GetKey(keyID string) (*models.EncryptionKey, error) {
	var k models.EncryptionKey
	var expiresAt, rotatedAt sql.NullTime

	err := s.db.QueryRow(
		`SELECT key_id, group_id, encrypted_key, status, created_at, expires_at, rotated_at
		 FROM encryption_keys WHERE key_id = ?`, keyID).Scan(
		&k.KeyID, &k.GroupID, &k.EncryptedKey, &k.Status, &k.CreatedAt, &expiresAt, &rotatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if expiresAt.Valid {
		k.ExpiresAt = expiresAt.Time
	}
	if rotatedAt.Valid {
		k.RotatedAt = rotatedAt.Time
	}

	return &k, nil
}

// GetActiveKeyForGroup returns the active encryption key for a group.
// Returns nil if no active key exists for the group.
func (s *Store) GetActiveKeyForGroup(groupID string) (*models.EncryptionKey, error) {
	var k models.EncryptionKey
	var expiresAt, rotatedAt sql.NullTime

	err := s.db.QueryRow(
		`SELECT key_id, group_id, encrypted_key, status, created_at, expires_at, rotated_at
		 FROM encryption_keys WHERE group_id = ? AND status = 'active'
		 ORDER BY created_at DESC LIMIT 1`, groupID).Scan(
		&k.KeyID, &k.GroupID, &k.EncryptedKey, &k.Status, &k.CreatedAt, &expiresAt, &rotatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if expiresAt.Valid {
		k.ExpiresAt = expiresAt.Time
	}
	if rotatedAt.Valid {
		k.RotatedAt = rotatedAt.Time
	}

	return &k, nil
}

// ListKeys returns all encryption keys for a group.
// If groupID is empty, returns all keys.
func (s *Store) ListKeys(groupID string) ([]models.EncryptionKey, error) {
	query := `SELECT key_id, group_id, encrypted_key, status, created_at, expires_at, rotated_at
	          FROM encryption_keys`
	var args []interface{}

	if groupID != "" {
		query += ` WHERE group_id = ?`
		args = append(args, groupID)
	}

	query += ` ORDER BY created_at DESC`

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []models.EncryptionKey
	for rows.Next() {
		var k models.EncryptionKey
		var expiresAt, rotatedAt sql.NullTime
		if err := rows.Scan(&k.KeyID, &k.GroupID, &k.EncryptedKey, &k.Status,
			&k.CreatedAt, &expiresAt, &rotatedAt); err != nil {
			return nil, err
		}
		if expiresAt.Valid {
			k.ExpiresAt = expiresAt.Time
		}
		if rotatedAt.Valid {
			k.RotatedAt = rotatedAt.Time
		}
		keys = append(keys, k)
	}

	return keys, rows.Err()
}

// RotateKey marks an old key as 'rotated' and sets the rotated_at timestamp.
// The new key should already exist with status 'active'.
func (s *Store) RotateKey(oldKeyID, newKeyID string) error {
	_, err := s.db.Exec(
		`UPDATE encryption_keys SET status = 'rotated', rotated_at = CURRENT_TIMESTAMP WHERE key_id = ?`,
		oldKeyID)
	return err
}

// RevokeKey marks a key as 'revoked'.
func (s *Store) RevokeKey(keyID string) error {
	_, err := s.db.Exec(
		`UPDATE encryption_keys SET status = 'revoked' WHERE key_id = ?`, keyID)
	return err
}

// GetAggregatedMetrics returns aggregated security metrics from recent checkins (last 24 hours).
func (s *Store) GetAggregatedMetrics() (*models.SecuritySummary, error) {
	// Query checkins from the last 24 hours
	cutoff := time.Now().Add(-24 * time.Hour)

	rows, err := s.db.Query(
		`SELECT COALESCE(metrics_summary, '{}') FROM agent_checkins
		 WHERE timestamp > ?`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	summary := &models.SecuritySummary{
		ScannerDetections: make(map[string]int64),
	}

	for rows.Next() {
		var metricsJSON string
		if err := rows.Scan(&metricsJSON); err != nil {
			return nil, err
		}

		var metrics models.MetricsSummary
		if err := unmarshalMetrics(metricsJSON, &metrics); err != nil {
			// Skip malformed metrics
			continue
		}

		summary.TotalDecisions += int64(metrics.DecisionsTotal)
		summary.TotalDenied += int64(metrics.DecisionsDenied)

		// Aggregate scanner detections
		for scanner, count := range metrics.ScannerDetections {
			summary.ScannerDetections[scanner] += int64(count)
		}
	}

	return summary, rows.Err()
}

// Helper functions

// nullTime returns a sql.NullTime for optional time.Time values.
func nullTime(t time.Time) sql.NullTime {
	return sql.NullTime{Time: t, Valid: !t.IsZero()}
}

// unmarshalMetrics unmarshals JSON metrics safely.
func unmarshalMetrics(metricsJSON string, metrics *models.MetricsSummary) error {
	if metricsJSON == "" || metricsJSON == "{}" {
		return nil
	}
	return json.Unmarshal([]byte(metricsJSON), metrics)
}
