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
