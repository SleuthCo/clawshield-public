package sqlite_test

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	"github.com/SleuthCo/clawshield/proxy/internal/audit/sqlite"
	"github.com/SleuthCo/clawshield/shared/types"
	_ "github.com/mattn/go-sqlite3"
)

func createSchema(t *testing.T, db *sql.DB) {
	schema := `
	CREATE TABLE IF NOT EXISTS decisions (
		decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME,
		session_id TEXT,
		tool TEXT,
		arguments_hash TEXT,
		decision TEXT,
		reason TEXT,
		policy_version TEXT,
		scanner_type TEXT,
		correlation_id TEXT,
		classification TEXT,
		source TEXT,
		response_blocked INTEGER DEFAULT 0,
		decision_details JSON
	);

	CREATE TABLE IF NOT EXISTS integrity_checkpoints (
		checkpoint_id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		db_hash TEXT,
		reason TEXT
	);

	CREATE TABLE IF NOT EXISTS tool_calls (
		call_id INTEGER PRIMARY KEY AUTOINCREMENT,
		decision_id INTEGER,
		request_json TEXT,
		response_json TEXT,
		FOREIGN KEY(decision_id) REFERENCES decisions(decision_id)
	);
	`

	_, err := db.Exec(schema)
	if err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}
}

func TestWriter_ConcurrentWrites(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:?_busy_timeout=5000&_journal_mode=WAL")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	createSchema(t, db)

	w, err := sqlite.NewWriter(db)
	if err != nil {
		t.Fatalf("failed to create writer: %v", err)
	}

	const numGoroutines = 10
	const decisionsPerGoroutine = 50

	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < decisionsPerGoroutine; j++ {
				d := &types.Decision{
					Timestamp:     time.Now(),
					SessionID:     "session-test",
					Tool:          "test-tool",
					ArgumentsHash: `{"key": "value"}`,
					Decision:      "allow",
					Reason:        "test reason",
					PolicyVersion: "1.0",
				}
				if err := w.Write(d); err != nil {
					t.Logf("write failed for goroutine %d decision %d: %v", id, j, err)
				}
			}
		}(i)
	}

	wg.Wait()

	// Close to flush all remaining
	if err := w.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}

	var count int
	err = db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM decisions").Scan(&count)
	if err != nil {
		t.Fatalf("failed to query count: %v", err)
	}

	expected := numGoroutines * decisionsPerGoroutine
	if count != expected {
		t.Errorf("expected %d decisions, got %d", expected, count)
	}
}
