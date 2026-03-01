// Package sqlite provides a query interface for ClawShield audit logs.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/SleuthCo/clawshield/shared/types"
)

type Reader struct {
	db *sql.DB
}

func NewReader(db *sql.DB) *Reader {
	return &Reader{db: db}
}

// QueryDecisions queries decisions based on filters.
// Returns a slice of DecisionLog objects with optional tool_calls.
func (r *Reader) QueryDecisions(ctx context.Context, opts ...QueryOption) ([]*types.DecisionLog, error) {
	q := &query{
		db: r.db,
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

type query struct {
	db              *sql.DB
	from            time.Time
	to              time.Time
	decision        string
	tool            string
	argsHashPrefix  string
	includeToolCall bool
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

	queryStr := `SELECT d.decision_id, d.timestamp, d.session_id, d.tool, d.arguments_hash, d.decision, d.reason, d.policy_version`
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
			err := rows.Scan(
				&decision.DecisionID,
				&decision.Timestamp,
				&decision.SessionID,
				&decision.Tool,
				&decision.ArgumentsHash,
				&decision.Decision,
				&decision.Reason,
				&decision.PolicyVersion,
				&reqJSON,
				&respJSON,
			)
			if err != nil {
				return nil, fmt.Errorf("scan decision with tool call: %w", err)
			}
			if reqJSON.Valid {
				call.RequestJSON = []byte(reqJSON.String)
			}
			if respJSON.Valid {
				call.ResponseJSON = []byte(respJSON.String)
			}
			call.DecisionID = decision.DecisionID
			call.CreatedAt = decision.Timestamp
			toolCallPtr = &call
		} else {
			err := rows.Scan(
				&decision.DecisionID,
				&decision.Timestamp,
				&decision.SessionID,
				&decision.Tool,
				&decision.ArgumentsHash,
				&decision.Decision,
				&decision.Reason,
				&decision.PolicyVersion,
			)
			if err != nil {
				return nil, fmt.Errorf("scan decision: %w", err)
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
