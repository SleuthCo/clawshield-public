// Package sqlite_test contains unit tests for the SQLite audit writer and reader.
package sqlite_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/SleuthCo/clawshield/proxy/internal/audit/hashlined"
	"github.com/SleuthCo/clawshield/proxy/internal/audit/sqlite"
	"github.com/SleuthCo/clawshield/shared/types"
	_ "github.com/mattn/go-sqlite3"
)

var testDB *sql.DB

func TestMain(m *testing.M) {
	dbFile := "./test_audit.db"
	if err := os.RemoveAll(dbFile); err != nil {
		panic(err)
	}

	var err error
	testDB, err = sql.Open("sqlite3", dbFile)
	if err != nil {
		panic(fmt.Sprintf("failed to open test DB: %v", err))
	}

	schema, err := os.ReadFile("schema.sql")
	if err != nil {
		panic(err)
	}
	if _, err = testDB.Exec(string(schema)); err != nil {
		panic(fmt.Sprintf("failed to apply schema: %v", err))
	}

	code := m.Run()

	testDB.Close()
	os.Remove(dbFile)
	os.Exit(code)
}

func TestWriter_WriteAndRead(t *testing.T) {
	w, err := sqlite.NewWriter(testDB)
	if err != nil {
		t.Fatalf("failed to create writer: %v", err)
	}

	desc := &types.Decision{
		Timestamp:     time.Now(),
		SessionID:     "session-123",
		Tool:          "file.read",
		ArgumentsHash: `{"path":"/etc/passwd","user":"alice"}`,
		Decision:      "allow",
		Reason:        "Policy allows read for alice",
		PolicyVersion: "v1.2",
	}

	err = w.Write(desc)
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// Close to flush all pending writes before querying
	if err := w.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	r := sqlite.NewReader(testDB)
	logs, err := r.QueryDecisions(context.Background(), sqlite.WithTool("file.read"))
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}

	if len(logs) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(logs))
	}
	got := logs[0].Decision
	if got.Tool != "file.read" || got.Decision != "allow" || got.PolicyVersion != "v1.2" {
		t.Errorf("unexpected decision: %+v", got)
	}
}

func TestHashArguments(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{
			`{"api_key":"secret123","query":"hello"}`,
			`{"api_key":"[REDACTED]","query":"hello"}`,
		},
	}

	for _, tc := range testCases {
		hash, err := hashlined.HashArguments(tc.input)
		if err != nil {
			t.Fatalf("hash failed: %v", err)
		}
		if len(hash) != 64 {
			t.Errorf("hash length mismatch: got %d, want 64", len(hash))
		}

		redacted, err := hashlined.RedactArguments(tc.input)
		if err != nil {
			t.Fatalf("redact failed: %v", err)
		}
		if !strings.Contains(redacted, "[REDACTED]") {
			t.Errorf("expected redaction, got: %s", redacted)
		}
	}
}

func TestQueryPolicyChanges(t *testing.T) {
	r := sqlite.NewReader(testDB)

	stmt, err := testDB.Prepare(`INSERT INTO policy_changes (timestamp, new_policy_hash, changed_by, reason) VALUES (?, ?, ?, ?)`)
	if err != nil {
		t.Fatal(err)
	}
	defer stmt.Close()
	_, err = stmt.Exec(time.Now(), "hash123", "admin", "test change")
	if err != nil {
		t.Fatal(err)
	}

	changes, err := r.QueryPolicyChanges(context.Background(), time.Time{}, time.Now())
	if err != nil {
		t.Fatalf("query policy changes failed: %v", err)
	}

	if len(changes) == 0 {
		t.Error("expected at least one change")
	}
}

func TestReader_Sessions(t *testing.T) {
	r := sqlite.NewReader(testDB)

	stmt, err := testDB.Prepare(`INSERT INTO sessions (session_id, start_time, agent_version) VALUES (?, ?, ?)`)
	if err != nil {
		t.Fatal(err)
	}
	defer stmt.Close()
	_, err = stmt.Exec("sess-001", time.Now(), "v1.0")
	if err != nil {
		t.Fatal(err)
	}

	sessions, err := r.QuerySessions(context.Background(), time.Time{}, time.Now())
	if err != nil {
		t.Fatalf("query sessions failed: %v", err)
	}

	if len(sessions) == 0 {
		t.Error("expected at least one session")
	}
}

// =============================================================================
// CRITICAL-4: Comprehensive reader.go tests
// =============================================================================

func TestReader_QueryDecisions_NoFilters(t *testing.T) {
	// Use a fresh DB to avoid interference from other tests
	dbFile := "./test_reader_nofilter.db"
	os.RemoveAll(dbFile)
	defer os.Remove(dbFile)

	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	schema, _ := os.ReadFile("schema.sql")
	db.Exec(string(schema))

	w, _ := sqlite.NewWriter(db)
	for i := 0; i < 5; i++ {
		w.Write(&types.Decision{
			Timestamp:     time.Now(),
			SessionID:     fmt.Sprintf("sess-%d", i),
			Tool:          "read",
			ArgumentsHash: "hash",
			Decision:      "allow",
			Reason:        "ok",
			PolicyVersion: "1.0",
		})
	}
	w.Close()

	r := sqlite.NewReader(db)
	logs, err := r.QueryDecisions(context.Background())
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if len(logs) != 5 {
		t.Errorf("expected 5 decisions, got %d", len(logs))
	}
}

func TestReader_QueryDecisions_WithDecisionFilter(t *testing.T) {
	dbFile := "./test_reader_decision.db"
	os.RemoveAll(dbFile)
	defer os.Remove(dbFile)

	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	schema, _ := os.ReadFile("schema.sql")
	db.Exec(string(schema))

	w, _ := sqlite.NewWriter(db)
	w.Write(&types.Decision{Timestamp: time.Now(), SessionID: "s1", Tool: "read", ArgumentsHash: "h", Decision: "allow", PolicyVersion: "1.0"})
	w.Write(&types.Decision{Timestamp: time.Now(), SessionID: "s2", Tool: "write", ArgumentsHash: "h", Decision: "deny", PolicyVersion: "1.0"})
	w.Write(&types.Decision{Timestamp: time.Now(), SessionID: "s3", Tool: "exec", ArgumentsHash: "h", Decision: "deny", PolicyVersion: "1.0"})
	w.Close()

	r := sqlite.NewReader(db)
	logs, err := r.QueryDecisions(context.Background(), sqlite.WithDecision("deny"))
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if len(logs) != 2 {
		t.Errorf("expected 2 deny decisions, got %d", len(logs))
	}
	for _, l := range logs {
		if l.Decision.Decision != "deny" {
			t.Errorf("expected decision=deny, got %s", l.Decision.Decision)
		}
	}
}

func TestReader_QueryDecisions_WithToolFilter(t *testing.T) {
	dbFile := "./test_reader_tool.db"
	os.RemoveAll(dbFile)
	defer os.Remove(dbFile)

	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	schema, _ := os.ReadFile("schema.sql")
	db.Exec(string(schema))

	w, _ := sqlite.NewWriter(db)
	w.Write(&types.Decision{Timestamp: time.Now(), SessionID: "s1", Tool: "file.read", ArgumentsHash: "h", Decision: "allow", PolicyVersion: "1.0"})
	w.Write(&types.Decision{Timestamp: time.Now(), SessionID: "s2", Tool: "file.write", ArgumentsHash: "h", Decision: "allow", PolicyVersion: "1.0"})
	w.Write(&types.Decision{Timestamp: time.Now(), SessionID: "s3", Tool: "shell.exec", ArgumentsHash: "h", Decision: "deny", PolicyVersion: "1.0"})
	w.Close()

	r := sqlite.NewReader(db)
	// Tool filter uses LIKE %tool% so "file" should match both file.read and file.write
	logs, err := r.QueryDecisions(context.Background(), sqlite.WithTool("file"))
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if len(logs) != 2 {
		t.Errorf("expected 2 file.* decisions, got %d", len(logs))
	}
}

func TestReader_QueryDecisions_WithTimeRange(t *testing.T) {
	dbFile := "./test_reader_time.db"
	os.RemoveAll(dbFile)
	defer os.Remove(dbFile)

	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	schema, _ := os.ReadFile("schema.sql")
	db.Exec(string(schema))

	now := time.Now()
	old := now.Add(-2 * time.Hour)
	recent := now.Add(-10 * time.Minute)

	w, _ := sqlite.NewWriter(db)
	w.Write(&types.Decision{Timestamp: old, SessionID: "s1", Tool: "read", ArgumentsHash: "h", Decision: "allow", PolicyVersion: "1.0"})
	w.Write(&types.Decision{Timestamp: recent, SessionID: "s2", Tool: "read", ArgumentsHash: "h", Decision: "allow", PolicyVersion: "1.0"})
	w.Write(&types.Decision{Timestamp: now, SessionID: "s3", Tool: "read", ArgumentsHash: "h", Decision: "allow", PolicyVersion: "1.0"})
	w.Close()

	r := sqlite.NewReader(db)
	// Query only decisions from the last 30 minutes
	logs, err := r.QueryDecisions(context.Background(), sqlite.WithTimeRange(now.Add(-30*time.Minute), now.Add(time.Minute)))
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if len(logs) != 2 {
		t.Errorf("expected 2 recent decisions, got %d", len(logs))
	}
}

func TestReader_QueryDecisions_WithIncludeToolCall(t *testing.T) {
	dbFile := "./test_reader_toolcall.db"
	os.RemoveAll(dbFile)
	defer os.Remove(dbFile)

	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	schema, _ := os.ReadFile("schema.sql")
	db.Exec(string(schema))

	// Write a decision, then manually insert tool_call data since
	// WriteDecision currently does NOT persist tool call data (known bug —
	// it delegates to Write() which drops the toolCall parameter).
	w, _ := sqlite.NewWriter(db)
	w.Write(&types.Decision{
		Timestamp:     time.Now(),
		SessionID:     "s1",
		Tool:          "read",
		ArgumentsHash: "h",
		Decision:      "allow",
		PolicyVersion: "1.0",
	})
	w.Close()

	// Manually insert tool_call data for the decision we just wrote
	var decisionID int64
	db.QueryRow("SELECT decision_id FROM decisions WHERE session_id = 's1'").Scan(&decisionID)
	db.Exec(`INSERT INTO tool_calls (decision_id, request_json, response_json) VALUES (?, ?, ?)`,
		decisionID, `{"method":"read"}`, `{"result":"ok"}`)

	r := sqlite.NewReader(db)
	logs, err := r.QueryDecisions(context.Background(), sqlite.WithIncludeToolCall())
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if len(logs) == 0 {
		t.Fatal("expected at least 1 log")
	}
	if logs[0].ToolCall == nil {
		t.Error("expected tool call data to be included")
	}
	if logs[0].ToolCall != nil && string(logs[0].ToolCall.RequestJSON) != `{"method":"read"}` {
		t.Errorf("unexpected request JSON: %s", logs[0].ToolCall.RequestJSON)
	}
}

func TestReader_QueryDecisions_EmptyDB(t *testing.T) {
	dbFile := "./test_reader_empty.db"
	os.RemoveAll(dbFile)
	defer os.Remove(dbFile)

	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	schema, _ := os.ReadFile("schema.sql")
	db.Exec(string(schema))

	r := sqlite.NewReader(db)
	logs, err := r.QueryDecisions(context.Background())
	if err != nil {
		t.Fatalf("query on empty DB should not error: %v", err)
	}
	if len(logs) != 0 {
		t.Errorf("expected 0 decisions from empty DB, got %d", len(logs))
	}
}

func TestReader_QueryDecisions_CombinedFilters(t *testing.T) {
	dbFile := "./test_reader_combined.db"
	os.RemoveAll(dbFile)
	defer os.Remove(dbFile)

	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	schema, _ := os.ReadFile("schema.sql")
	db.Exec(string(schema))

	now := time.Now()
	w, _ := sqlite.NewWriter(db)
	w.Write(&types.Decision{Timestamp: now, SessionID: "s1", Tool: "file.read", ArgumentsHash: "h", Decision: "allow", PolicyVersion: "1.0"})
	w.Write(&types.Decision{Timestamp: now, SessionID: "s2", Tool: "file.read", ArgumentsHash: "h", Decision: "deny", PolicyVersion: "1.0"})
	w.Write(&types.Decision{Timestamp: now, SessionID: "s3", Tool: "shell.exec", ArgumentsHash: "h", Decision: "deny", PolicyVersion: "1.0"})
	w.Close()

	r := sqlite.NewReader(db)
	// Combine tool + decision filter
	logs, err := r.QueryDecisions(context.Background(), sqlite.WithTool("file"), sqlite.WithDecision("deny"))
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if len(logs) != 1 {
		t.Errorf("expected 1 deny+file decision, got %d", len(logs))
	}
}

func TestReader_QueryDecisions_OrderByTimestampDesc(t *testing.T) {
	dbFile := "./test_reader_order.db"
	os.RemoveAll(dbFile)
	defer os.Remove(dbFile)

	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	schema, _ := os.ReadFile("schema.sql")
	db.Exec(string(schema))

	w, _ := sqlite.NewWriter(db)
	t1 := time.Now().Add(-2 * time.Hour)
	t2 := time.Now().Add(-1 * time.Hour)
	t3 := time.Now()
	w.Write(&types.Decision{Timestamp: t1, SessionID: "oldest", Tool: "read", ArgumentsHash: "h", Decision: "allow", PolicyVersion: "1.0"})
	w.Write(&types.Decision{Timestamp: t3, SessionID: "newest", Tool: "read", ArgumentsHash: "h", Decision: "allow", PolicyVersion: "1.0"})
	w.Write(&types.Decision{Timestamp: t2, SessionID: "middle", Tool: "read", ArgumentsHash: "h", Decision: "allow", PolicyVersion: "1.0"})
	w.Close()

	r := sqlite.NewReader(db)
	logs, err := r.QueryDecisions(context.Background())
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if len(logs) != 3 {
		t.Fatalf("expected 3 decisions, got %d", len(logs))
	}
	// Should be ordered newest first
	if logs[0].Decision.SessionID != "newest" {
		t.Errorf("expected first result to be 'newest', got %q", logs[0].Decision.SessionID)
	}
	if logs[2].Decision.SessionID != "oldest" {
		t.Errorf("expected last result to be 'oldest', got %q", logs[2].Decision.SessionID)
	}
}

func TestReader_QueryIntegrityCheckpoints(t *testing.T) {
	dbFile := "./test_reader_checkpoints.db"
	os.RemoveAll(dbFile)
	defer os.Remove(dbFile)

	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	schema, _ := os.ReadFile("schema.sql")
	db.Exec(string(schema))

	// Insert checkpoints directly
	db.Exec(`INSERT INTO integrity_checkpoints (timestamp, db_hash, reason) VALUES (?, ?, ?)`, time.Now(), "abc123", "startup")
	db.Exec(`INSERT INTO integrity_checkpoints (timestamp, db_hash, reason) VALUES (?, ?, ?)`, time.Now(), "def456", "batch flush")

	r := sqlite.NewReader(db)
	checks, err := r.QueryIntegrityCheckpoints(context.Background())
	if err != nil {
		t.Fatalf("query checkpoints failed: %v", err)
	}
	if len(checks) != 2 {
		t.Errorf("expected 2 checkpoints, got %d", len(checks))
	}
}

func TestReader_QueryPolicyChanges_EmptyTimeRange(t *testing.T) {
	dbFile := "./test_reader_policy_empty.db"
	os.RemoveAll(dbFile)
	defer os.Remove(dbFile)

	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	schema, _ := os.ReadFile("schema.sql")
	db.Exec(string(schema))

	r := sqlite.NewReader(db)
	// Both zero times — should return all (none in empty DB)
	changes, err := r.QueryPolicyChanges(context.Background(), time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if len(changes) != 0 {
		t.Errorf("expected 0 changes from empty DB, got %d", len(changes))
	}
}

func TestReader_QuerySessions_EmptyDB(t *testing.T) {
	dbFile := "./test_reader_sessions_empty.db"
	os.RemoveAll(dbFile)
	defer os.Remove(dbFile)

	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	schema, _ := os.ReadFile("schema.sql")
	db.Exec(string(schema))

	r := sqlite.NewReader(db)
	sessions, err := r.QuerySessions(context.Background(), time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("query sessions on empty DB should not error: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(sessions))
	}
}
