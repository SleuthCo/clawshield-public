// Package sqlite provides a query interface for ClawShield audit logs.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/SleuthCo/clawshield/proxy/internal/audit/crypto"
	"github.com/SleuthCo/clawshield/shared/types"
)

// Reader provides a query interface for ClawShield audit logs.
type Reader struct {
	db        *sql.DB
	encryptor *crypto.FieldEncryptor
}

// NewReader creates a new audit log reader without decryption.
func NewReader(db *sql.DB) *Reader {
	return &Reader{db: db}
}

// NewReaderWithEncryptor creates a new audit log reader with decryption support.
// When set, encrypted fields are transparently decrypted on read.
// Unencrypted (legacy) data is returned as-is for migration compatibility.
func NewReaderWithEncryptor(db *sql.DB, enc *crypto.FieldEncryptor) *Reader {
	return &Reader{db: db, encryptor: enc}
}

// decryptField attempts to decrypt a byte slice if it appears encrypted.
// Returns the original data unchanged if no encryptor is set or if the
// data does not have the encryption version prefix (plaintext/legacy data).
// This enables graceful migration from unencrypted to encrypted storage.
func (r *Reader) decryptField(data []byte) ([]byte, error) {
	if r.encryptor == nil || len(data) == 0 {
		return data, nil
	}
	if !crypto.IsEncrypted(data) {
		return data, nil
	}
	return r.encryptor.Decrypt(data)
}

// decryptStringField attempts to decrypt a string field stored as raw bytes.
// Returns the original string if no encryptor is set or if the data is plaintext.
func (r *Reader) decryptStringField(s string) (string, error) {
	if r.encryptor == nil || s == "" {
		return s, nil
	}
	data := []byte(s)
	if !crypto.IsEncrypted(data) {
		return s, nil
	}
	decrypted, err := r.encryptor.Decrypt(data)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

// QueryDecisions queries decisions based on filters.
// Returns a slice of DecisionLog objects with optional tool_calls.
func (r *Reader) QueryDecisions(ctx context.Context, opts ...QueryOption) ([]*types.DecisionLog, error) {
	q := &query{
		db:     r.db,
		reader: r,
	}

	for _, opt := range opts {
		opt(q)
	}

	return q.execute(ctx)
}

type QueryOption func(*query)

// WithTimeRange filters decisions by time range.
func WithTimeRange(from, to time.Time) QueryOption {
	return func(q *query) {
		q.from = from
		q.to = to
	}
}

// WithDecision filters by decision type (allow/deny/redacted).
func WithDecision(decision string) QueryOption {
	return func(q *query) {
		q.decision = decision
	}
}

// WithTool filters by tool name.
func WithTool(tool string) QueryOption {
	return func(q *query) {
		q.tool = tool
	}
}

// WithArgumentsHashPrefix filters by hash prefix (e.g., for partial matches).
func WithArgumentsHashPrefix(prefix string) QueryOption {
	return func(q *query) {
		q.argsHashPrefix = prefix
	}
}

// WithIncludeToolCall includes full tool_call data in results.
func WithIncludeToolCall() QueryOption {
	return func(q *query) {
		q.includeToolCall = true
	}
}

// WithScannerType filters by scanner_type.
func WithScannerType(scannerType string) QueryOption {
	return func(q *query) {
		q.scannerType = scannerType
	}
}

// WithRuleID filters by rule_id in decision_details JSON.
func WithRuleID(ruleID string) QueryOption {
	return func(q *query) {
		q.ruleID = ruleID
	}
}

type query struct {
	db              *sql.DB
	reader          *Reader
	from            time.Time
	to              time.Time
	decision        string
	tool            string
	argsHashPrefix  string
	includeToolCall bool
	scannerType     string
	ruleID          string
}

func (q *query) execute(ctx context.Context) ([]*types.DecisionLog, error) {
	var where []string
	var args []interface{}

	if !q.from.IsZero() {
		where = append(where, "timestamp >= ?")
		args = append(args, q.from)
	}
	if !q.to.IsZero() {
		where = append(where, "timestamp <= ?")
		args = append(args, q.to)
	}
	if q.decision != "" {
		where = append(where, "decision = ?")
		args = append(args, q.decision)
	}
	if q.tool != "" {
		where = append(where, "tool LIKE ?")
		args = append(args, "%"+q.tool+"%")
	}
	if q.argsHashPrefix != "" {
		where = append(where, "arguments_hash LIKE ?")
		args = append(args, q.argsHashPrefix+"%")
	}
	if q.scannerType != "" {
		where = append(where, "scanner_type = ?")
		args = append(args, q.scannerType)
	}
	if q.ruleID != "" {
		// SECURITY: Escape LIKE wildcards in user-provided ruleID to prevent
		// unintended pattern matching. The value is parameterized (safe from SQL
		// injection) but wildcards could match broader than intended.
		escapedRuleID := strings.NewReplacer("%", "\\%", "_", "\\_").Replace(q.ruleID)
		where = append(where, "decision_details LIKE ? ESCAPE '\\'")
		args = append(args, "%\"rule_id\":\""+escapedRuleID+"\"%")
	}

	queryStr := `SELECT d.decision_id, d.timestamp, d.session_id, d.tool, d.arguments_hash, d.decision, d.reason, d.policy_version, d.decision_details`
	if q.includeToolCall {
		queryStr += ", tc.request_json, tc.response_json"
	}

	queryStr += " FROM decisions d"
	if q.includeToolCall {
		queryStr += " LEFT JOIN tool_calls tc ON d.decision_id = tc.decision_id"
	}

	if len(where) > 0 {
		queryStr += " WHERE " + strings.Join(where, " AND ")
	}

	queryStr += " ORDER BY d.timestamp DESC"

	rows, err := q.db.QueryContext(ctx, queryStr, args...)
	if err != nil {
		return nil, fmt.Errorf("execute query: %w", err)
	}
	defer rows.Close()

	var logs []*types.DecisionLog
	for rows.Next() {
		var decision types.Decision
		var toolCallPtr *types.ToolCall

		if q.includeToolCall {
			var call types.ToolCall
			var reqJSON, respJSON sql.NullString
			var detailsRaw sql.NullString
			err := rows.Scan(
				&decision.DecisionID,
				&decision.Timestamp,
				&decision.SessionID,
				&decision.Tool,
				&decision.ArgumentsHash,
				&decision.Decision,
				&decision.Reason,
				&decision.PolicyVersion,
				&detailsRaw,
				&reqJSON,
				&respJSON,
			)
			if err != nil {
				return nil, fmt.Errorf("scan decision with tool call: %w", err)
			}

			// SECURITY: Decrypt arguments_hash if encrypted
			if decision.ArgumentsHash != "" {
				decryptedHash, err := q.reader.decryptStringField(decision.ArgumentsHash)
				if err != nil {
					log.Printf("WARNING: failed to decrypt arguments_hash for decision_id=%d: %v", decision.DecisionID, err)
				} else {
					decision.ArgumentsHash = decryptedHash
				}
			}

			// SECURITY: Decrypt and unmarshal decision_details
			if detailsRaw.Valid {
				detailsBytes := []byte(detailsRaw.String)
				detailsBytes, err := q.reader.decryptField(detailsBytes)
				if err != nil {
					log.Printf("WARNING: failed to decrypt decision_details for decision_id=%d: %v", decision.DecisionID, err)
				} else {
					details, err := types.UnmarshalDecisionDetail(detailsBytes)
					if err != nil {
						// SECURITY: Gracefully handle corrupt JSON rather than failing
						// the entire query — a single corrupt row shouldn't block forensics.
						log.Printf("WARNING: corrupt decision_details JSON for decision_id=%d: %v", decision.DecisionID, err)
					} else {
						decision.Details = details
					}
				}
			}

			// SECURITY: Decrypt tool call request/response JSON
			if reqJSON.Valid {
				reqBytes, err := q.reader.decryptField([]byte(reqJSON.String))
				if err != nil {
					log.Printf("WARNING: failed to decrypt request_json for decision_id=%d: %v", decision.DecisionID, err)
					call.RequestJSON = []byte(reqJSON.String)
				} else {
					call.RequestJSON = reqBytes
				}
			}
			if respJSON.Valid {
				respBytes, err := q.reader.decryptField([]byte(respJSON.String))
				if err != nil {
					log.Printf("WARNING: failed to decrypt response_json for decision_id=%d: %v", decision.DecisionID, err)
					call.ResponseJSON = []byte(respJSON.String)
				} else {
					call.ResponseJSON = respBytes
				}
			}
			call.DecisionID = decision.DecisionID
			call.CreatedAt = decision.Timestamp
			toolCallPtr = &call
		} else {
			var detailsRaw sql.NullString
			err := rows.Scan(
				&decision.DecisionID,
				&decision.Timestamp,
				&decision.SessionID,
				&decision.Tool,
				&decision.ArgumentsHash,
				&decision.Decision,
				&decision.Reason,
				&decision.PolicyVersion,
				&detailsRaw,
			)
			if err != nil {
				return nil, fmt.Errorf("scan decision: %w", err)
			}

			// SECURITY: Decrypt arguments_hash if encrypted
			if decision.ArgumentsHash != "" {
				decryptedHash, err := q.reader.decryptStringField(decision.ArgumentsHash)
				if err != nil {
					log.Printf("WARNING: failed to decrypt arguments_hash for decision_id=%d: %v", decision.DecisionID, err)
				} else {
					decision.ArgumentsHash = decryptedHash
				}
			}

			// SECURITY: Decrypt and unmarshal decision_details
			if detailsRaw.Valid {
				detailsBytes := []byte(detailsRaw.String)
				detailsBytes, err := q.reader.decryptField(detailsBytes)
				if err != nil {
					log.Printf("WARNING: failed to decrypt decision_details for decision_id=%d: %v", decision.DecisionID, err)
				} else {
					details, err := types.UnmarshalDecisionDetail(detailsBytes)
					if err != nil {
						log.Printf("WARNING: corrupt decision_details JSON for decision_id=%d: %v", decision.DecisionID, err)
					} else {
						decision.Details = details
					}
				}
			}
		}

		logs = append(logs, &types.DecisionLog{
			Decision: decision,
			ToolCall: toolCallPtr,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return logs, nil
}

// QueryPolicyChanges returns all policy changes.
func (r *Reader) QueryPolicyChanges(ctx context.Context, from, to time.Time) ([]*types.PolicyChange, error) {
	var where string
	var args []interface{}

	if !from.IsZero() || !to.IsZero() {
		where = "WHERE timestamp >= ? AND timestamp <= ?"
		args = []interface{}{from, to}
	}

	rows, err := r.db.QueryContext(ctx, fmt.Sprintf(`
	SELECT change_id, timestamp, session_id, old_policy_hash, new_policy_hash, changed_by, reason
	FROM policy_changes %s ORDER BY timestamp DESC`, where), args...)
	if err != nil {
		return nil, fmt.Errorf("query policy changes: %w", err)
	}
	defer rows.Close()

	var changes []*types.PolicyChange
	for rows.Next() {
		var pc types.PolicyChange
		var sessionID, oldHash, changedBy, reason sql.NullString
		err := rows.Scan(
			&pc.ChangeID,
			&pc.Timestamp,
			&sessionID,
			&oldHash,
			&pc.NewPolicyHash,
			&changedBy,
			&reason,
		)
		if err != nil {
			return nil, fmt.Errorf("scan policy change: %w", err)
		}
		pc.SessionID = sessionID.String
		pc.OldPolicyHash = oldHash.String
		pc.ChangedBy = changedBy.String
		pc.Reason = reason.String
		changes = append(changes, &pc)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return changes, nil
}

// QuerySessions returns active and historical sessions.
func (r *Reader) QuerySessions(ctx context.Context, from, to time.Time) ([]*types.Session, error) {
	var where string
	var args []interface{}

	if !from.IsZero() || !to.IsZero() {
		where = "WHERE start_time >= ? AND start_time <= ?"
		args = []interface{}{from, to}
	}

	rows, err := r.db.QueryContext(ctx, fmt.Sprintf(`
	SELECT session_id, start_time, end_time, agent_version, node_id, context
	FROM sessions %s ORDER BY start_time DESC`, where), args...)
	if err != nil {
		return nil, fmt.Errorf("query sessions: %w", err)
	}
	defer rows.Close()

	var sessions []*types.Session
	for rows.Next() {
		var s types.Session
		var endTime sql.NullTime
		var nodeID sql.NullString
		var ctx []byte
		err := rows.Scan(
			&s.SessionID,
			&s.StartTime,
			&endTime,
			&s.AgentVersion,
			&nodeID,
			&ctx,
		)
		if err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		if endTime.Valid {
			s.EndTime = &endTime.Time
		}
		s.NodeID = nodeID.String
		s.Context = ctx
		sessions = append(sessions, &s)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return sessions, nil
}

// QueryIntegrityCheckpoints returns all integrity checkpoints.
func (r *Reader) QueryIntegrityCheckpoints(ctx context.Context) ([]*types.IntegrityCheckpoint, error) {
	rows, err := r.db.QueryContext(ctx, `
	SELECT checkpoint_id, timestamp, db_hash, reason
	FROM integrity_checkpoints ORDER BY timestamp DESC`)
	if err != nil {
		return nil, fmt.Errorf("query checkpoints: %w", err)
	}
	defer rows.Close()

	var checks []*types.IntegrityCheckpoint
	for rows.Next() {
		var c types.IntegrityCheckpoint
		err := rows.Scan(
			&c.CheckpointID,
			&c.Timestamp,
			&c.DBHash,
			&c.Reason,
		)
		if err != nil {
			return nil, fmt.Errorf("scan checkpoint: %w", err)
		}
		checks = append(checks, &c)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return checks, nil
}
