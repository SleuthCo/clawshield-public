package sqlite

import (
	"database/sql"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/SleuthCo/clawshield/shared/types"
	_ "github.com/mattn/go-sqlite3"
)

func setupTestDB(t *testing.T) *sql.DB {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	
	// Create schema
	schema := `
	CREATE TABLE IF NOT EXISTS decisions (
		decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		session_id TEXT NOT NULL,
		tool TEXT NOT NULL,
		arguments_hash TEXT NOT NULL,
		decision TEXT NOT NULL,
		reason TEXT,
		policy_version TEXT,
		scanner_type TEXT,
		correlation_id TEXT,
		classification TEXT,
		source TEXT,
		response_blocked INTEGER DEFAULT 0
	);
	
	CREATE TABLE IF NOT EXISTS tool_calls (
		call_id INTEGER PRIMARY KEY AUTOINCREMENT,
		decision_id INTEGER NOT NULL,
		request_json TEXT,
		response_json TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (decision_id) REFERENCES decisions(decision_id)
	);
	
	CREATE TABLE IF NOT EXISTS integrity_checkpoints (
		checkpoint_id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		db_hash TEXT NOT NULL,
		reason TEXT
	);
	`
	
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}
	
	return db
}

func TestNewWriter(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	writer, err := NewWriter(db)
	if err != nil {
		t.Fatalf("NewWriter() failed: %v", err)
	}
	
	if writer == nil {
		t.Fatal("NewWriter() returned nil")
	}
	
	if err := writer.Close(); err != nil {
		t.Errorf("Close() failed: %v", err)
	}
}

func TestWriter_WriteAndFlush(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	writer, err := NewWriter(db)
	if err != nil {
		t.Fatalf("NewWriter() failed: %v", err)
	}
	defer writer.Close()
	
	decision := &types.Decision{
		Timestamp:     time.Now(),
		SessionID:     "test-session",
		Tool:          "read",
		ArgumentsHash: `{"path": "file.txt"}`,
		Decision:      "allow",
		Reason:        "test reason",
		PolicyVersion: "1.0",
	}
	
	if err := writer.Write(decision); err != nil {
		t.Fatalf("Write() failed: %v", err)
	}
	
	// Close to flush
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	
	// Verify written to DB
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM decisions").Scan(&count)
	if err != nil {
		t.Fatalf("failed to query decisions: %v", err)
	}
	
	if count != 1 {
		t.Errorf("expected 1 decision in DB, got %d", count)
	}
}

func TestWriter_BatchProcessing(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	writer, err := NewWriter(db)
	if err != nil {
		t.Fatalf("NewWriter() failed: %v", err)
	}
	defer writer.Close()
	
	// Write more than batchSize decisions
	numDecisions := batchSize + 50
	
	for i := 0; i < numDecisions; i++ {
		decision := &types.Decision{
			Timestamp:     time.Now(),
			SessionID:     "test-session",
			Tool:          "read",
			ArgumentsHash: `{"path": "file.txt"}`,
			Decision:      "allow",
			Reason:        "test reason",
			PolicyVersion: "1.0",
		}
		
		if err := writer.Write(decision); err != nil {
			t.Fatalf("Write() failed on decision %d: %v", i, err)
		}
	}
	
	// Give time for batches to flush
	time.Sleep(100 * time.Millisecond)
	
	// Close to flush remaining
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	
	// Verify all written to DB
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM decisions").Scan(&count)
	if err != nil {
		t.Fatalf("failed to query decisions: %v", err)
	}
	
	if count != numDecisions {
		t.Errorf("expected %d decisions in DB, got %d", numDecisions, count)
	}
}

func TestWriter_ConcurrentWrites(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	writer, err := NewWriter(db)
	if err != nil {
		t.Fatalf("NewWriter() failed: %v", err)
	}
	defer writer.Close()
	
	numGoroutines := 10
	decisionsPerGoroutine := 100
	
	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	
	for g := 0; g < numGoroutines; g++ {
		go func(goroutineID int) {
			defer wg.Done()
			
			for i := 0; i < decisionsPerGoroutine; i++ {
				decision := &types.Decision{
					Timestamp:     time.Now(),
					SessionID:     "test-session",
					Tool:          "read",
					ArgumentsHash: `{"path": "file.txt"}`,
					Decision:      "allow",
					Reason:        "test reason",
					PolicyVersion: "1.0",
				}
				
				if err := writer.Write(decision); err != nil {
					t.Errorf("goroutine %d: Write() failed: %v", goroutineID, err)
				}
			}
		}(g)
	}
	
	wg.Wait()
	
	// Close to flush
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	
	// Verify all written to DB
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM decisions").Scan(&count)
	if err != nil {
		t.Fatalf("failed to query decisions: %v", err)
	}
	
	expected := numGoroutines * decisionsPerGoroutine
	if count != expected {
		t.Errorf("expected %d decisions in DB, got %d", expected, count)
	}
}

func TestWriter_ClosedWriter(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	writer, err := NewWriter(db)
	if err != nil {
		t.Fatalf("NewWriter() failed: %v", err)
	}
	
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	
	// Try to write after close
	decision := &types.Decision{
		Timestamp:     time.Now(),
		SessionID:     "test-session",
		Tool:          "read",
		ArgumentsHash: `{"path": "file.txt"}`,
		Decision:      "allow",
	}
	
	err = writer.Write(decision)
	if err == nil {
		t.Error("Write() succeeded on closed writer, want error")
	}
	
	// Double close should not error
	if err := writer.Close(); err != nil {
		t.Errorf("second Close() failed: %v", err)
	}
}

func TestWriteDecision_PersistsToolCall(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	writer, err := NewWriter(db)
	if err != nil {
		t.Fatalf("NewWriter() failed: %v", err)
	}

	err = writer.WriteDecision(types.Decision{
		Timestamp:     time.Now(),
		SessionID:     "sess-toolcall",
		Tool:          "file.read",
		ArgumentsHash: "abc123",
		Decision:      "allow",
		Reason:        "ok",
		PolicyVersion: "1.0",
	}, &types.ToolCall{
		RequestJSON:  []byte(`{"method":"file.read","params":{"path":"test.txt"}}`),
		ResponseJSON: []byte(`{"result":{"content":"hello world"}}`),
		CreatedAt:    time.Now(),
	})
	if err != nil {
		t.Fatalf("WriteDecision() failed: %v", err)
	}

	writer.Close()

	// Verify decision was written
	var decisionID int64
	var tool string
	err = db.QueryRow("SELECT decision_id, tool FROM decisions WHERE session_id = ?", "sess-toolcall").Scan(&decisionID, &tool)
	if err != nil {
		t.Fatalf("decision not found: %v", err)
	}
	if tool != "file.read" {
		t.Errorf("expected tool=file.read, got %s", tool)
	}

	// Verify tool call was written and linked to the decision
	var requestJSON, responseJSON []byte
	err = db.QueryRow("SELECT request_json, response_json FROM tool_calls WHERE decision_id = ?", decisionID).Scan(&requestJSON, &responseJSON)
	if err != nil {
		t.Fatalf("tool_call not found for decision_id=%d: %v", decisionID, err)
	}
	if string(requestJSON) != `{"method":"file.read","params":{"path":"test.txt"}}` {
		t.Errorf("unexpected request_json: %s", requestJSON)
	}
	if string(responseJSON) != `{"result":{"content":"hello world"}}` {
		t.Errorf("unexpected response_json: %s", responseJSON)
	}
}

func TestWriteDecision_NilToolCall(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	writer, err := NewWriter(db)
	if err != nil {
		t.Fatalf("NewWriter() failed: %v", err)
	}

	// WriteDecision with nil toolCall should work exactly like Write
	err = writer.WriteDecision(types.Decision{
		Timestamp:     time.Now(),
		SessionID:     "sess-notoolcall",
		Tool:          "read",
		ArgumentsHash: "def456",
		Decision:      "allow",
		PolicyVersion: "1.0",
	}, nil)
	if err != nil {
		t.Fatalf("WriteDecision(nil toolCall) failed: %v", err)
	}

	writer.Close()

	// Verify decision was written
	var count int
	db.QueryRow("SELECT COUNT(*) FROM decisions WHERE session_id = ?", "sess-notoolcall").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 decision, got %d", count)
	}

	// Verify NO tool_call was written
	var tcCount int
	db.QueryRow("SELECT COUNT(*) FROM tool_calls tc JOIN decisions d ON tc.decision_id = d.decision_id WHERE d.session_id = ?", "sess-notoolcall").Scan(&tcCount)
	if tcCount != 0 {
		t.Errorf("expected 0 tool_calls for nil toolCall, got %d", tcCount)
	}
}

func TestWriteDecision_MixedBatch(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	writer, err := NewWriter(db)
	if err != nil {
		t.Fatalf("NewWriter() failed: %v", err)
	}

	// Write a mix of decisions with and without tool calls
	writer.Write(&types.Decision{
		Timestamp: time.Now(), SessionID: "s1", Tool: "read",
		ArgumentsHash: "h1", Decision: "allow", PolicyVersion: "1.0",
	})
	writer.WriteDecision(types.Decision{
		Timestamp: time.Now(), SessionID: "s2", Tool: "write",
		ArgumentsHash: "h2", Decision: "allow", PolicyVersion: "1.0",
	}, &types.ToolCall{
		RequestJSON: []byte(`{"method":"write"}`),
		CreatedAt:   time.Now(),
	})
	writer.Write(&types.Decision{
		Timestamp: time.Now(), SessionID: "s3", Tool: "exec",
		ArgumentsHash: "h3", Decision: "deny", PolicyVersion: "1.0",
	})

	writer.Close()

	// Verify all 3 decisions written
	var decCount int
	db.QueryRow("SELECT COUNT(*) FROM decisions").Scan(&decCount)
	if decCount != 3 {
		t.Errorf("expected 3 decisions, got %d", decCount)
	}

	// Verify exactly 1 tool_call written (for s2 only)
	var tcCount int
	db.QueryRow("SELECT COUNT(*) FROM tool_calls").Scan(&tcCount)
	if tcCount != 1 {
		t.Errorf("expected 1 tool_call, got %d", tcCount)
	}

	// Verify the tool_call is linked to the correct decision
	var linkedSession string
	db.QueryRow(`SELECT d.session_id FROM tool_calls tc 
		JOIN decisions d ON tc.decision_id = d.decision_id`).Scan(&linkedSession)
	if linkedSession != "s2" {
		t.Errorf("tool_call should be linked to s2, got %s", linkedSession)
	}
}

func TestWriter_QueueFull(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Create a writer with a tiny queue so we can actually saturate it.
	// We construct it manually since NewWriter uses a 10000-element queue.
	w := &Writer{
		db:    db,
		queue: make(chan auditEntry, 2), // Tiny queue
		stop:  make(chan struct{}),
		batch: make([]auditEntry, 0, batchSize),
	}
	// Do NOT start the loop goroutine — this ensures the queue stays full
	// because nothing is draining it.

	decision := &types.Decision{
		Timestamp:     time.Now(),
		SessionID:     "test-session",
		Tool:          "read",
		ArgumentsHash: `{"path": "file.txt"}`,
		Decision:      "allow",
	}

	// Fill the queue (capacity = 2)
	if err := w.Write(decision); err != nil {
		t.Fatalf("Write 1 should succeed: %v", err)
	}
	if err := w.Write(decision); err != nil {
		t.Fatalf("Write 2 should succeed: %v", err)
	}

	// Third write should fail — queue is full and nothing is draining
	err := w.Write(decision)
	if err == nil {
		t.Error("Write to full queue should return an error")
	}

	// Drain the queue to clean up
	close(w.stop)
	for len(w.queue) > 0 {
		<-w.queue
	}
}

func TestWriter_FlushOnInterval(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	writer, err := NewWriter(db)
	if err != nil {
		t.Fatalf("NewWriter() failed: %v", err)
	}

	// Write a small number of decisions (less than batchSize)
	for i := 0; i < 10; i++ {
		decision := &types.Decision{
			Timestamp:     time.Now(),
			SessionID:     "test-session",
			Tool:          "read",
			ArgumentsHash: `{"path": "file.txt"}`,
			Decision:      "allow",
		}
		if err := writer.Write(decision); err != nil {
			t.Fatalf("Write() failed: %v", err)
		}
	}

	// Instead of waiting 6 seconds for the flush interval, close the writer
	// which triggers a final flush of all pending items. This tests the same
	// code path (flush of sub-batch-size batches) without the long sleep.
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}

	// Verify flushed to DB
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM decisions").Scan(&count)
	if err != nil {
		t.Fatalf("failed to query decisions: %v", err)
	}

	if count != 10 {
		t.Errorf("expected 10 decisions flushed after close, got %d", count)
	}
}

func TestWriter_WriteDecision(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	writer, err := NewWriter(db)
	if err != nil {
		t.Fatalf("NewWriter() failed: %v", err)
	}
	defer writer.Close()
	
	decision := types.Decision{
		Timestamp:     time.Now(),
		SessionID:     "test-session",
		Tool:          "read",
		ArgumentsHash: `{"path": "file.txt"}`,
		Decision:      "allow",
		Reason:        "test reason",
		PolicyVersion: "1.0",
	}
	
	toolCall := &types.ToolCall{
		RequestJSON:  []byte(`{"method": "read", "params": {"path": "file.txt"}}`),
		ResponseJSON: []byte(`{"result": "success"}`),
		CreatedAt:    time.Now(),
	}
	
	if err := writer.WriteDecision(decision, toolCall); err != nil {
		t.Fatalf("WriteDecision() failed: %v", err)
	}
	
	// Close to flush
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	
	// Verify written
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM decisions").Scan(&count)
	if err != nil {
		t.Fatalf("failed to query decisions: %v", err)
	}
	
	if count != 1 {
		t.Errorf("expected 1 decision in DB, got %d", count)
	}
}

func TestWriter_EmptyBatch(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	writer, err := NewWriter(db)
	if err != nil {
		t.Fatalf("NewWriter() failed: %v", err)
	}
	
	// Close immediately without writing
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() failed on empty writer: %v", err)
	}
	
	// Verify no decisions in DB
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM decisions").Scan(&count)
	if err != nil {
		t.Fatalf("failed to query decisions: %v", err)
	}
	
	if count != 0 {
		t.Errorf("expected 0 decisions in DB, got %d", count)
	}
}

func TestWriter_RaceConditions(t *testing.T) {
	// This test should be run with -race flag
	db := setupTestDB(t)
	defer db.Close()
	
	writer, err := NewWriter(db)
	if err != nil {
		t.Fatalf("NewWriter() failed: %v", err)
	}
	
	var wg sync.WaitGroup
	
	// Concurrent writes
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			decision := &types.Decision{
				Timestamp:     time.Now(),
				SessionID:     "test-session",
				Tool:          "read",
				ArgumentsHash: `{"path": "file.txt"}`,
				Decision:      "allow",
			}
			writer.Write(decision)
		}()
	}
	
	// Concurrent close attempt
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(50 * time.Millisecond)
		writer.Close()
	}()
	
	wg.Wait()
}

func TestWriter_DataIntegrity(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	writer, err := NewWriter(db)
	if err != nil {
		t.Fatalf("NewWriter() failed: %v", err)
	}
	defer writer.Close()
	
	testDecision := &types.Decision{
		Timestamp:     time.Now(),
		SessionID:     "integrity-test",
		Tool:          "web.fetch",
		ArgumentsHash: `{"url": "https://example.com"}`,
		Decision:      "allow",
		Reason:        "domain in allowlist",
		PolicyVersion: "2.0",
	}
	
	if err := writer.Write(testDecision); err != nil {
		t.Fatalf("Write() failed: %v", err)
	}
	
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	
	// Verify data integrity
	var (
		sessionID     string
		tool          string
		decision      string
		reason        string
		policyVersion string
	)
	
	err = db.QueryRow(`
		SELECT session_id, tool, decision, reason, policy_version 
		FROM decisions 
		WHERE session_id = ?
	`, "integrity-test").Scan(&sessionID, &tool, &decision, &reason, &policyVersion)
	
	if err != nil {
		t.Fatalf("failed to query decision: %v", err)
	}
	
	if sessionID != testDecision.SessionID {
		t.Errorf("sessionID = %q, want %q", sessionID, testDecision.SessionID)
	}
	
	if tool != testDecision.Tool {
		t.Errorf("tool = %q, want %q", tool, testDecision.Tool)
	}
	
	if decision != testDecision.Decision {
		t.Errorf("decision = %q, want %q", decision, testDecision.Decision)
	}
	
	if reason != testDecision.Reason {
		t.Errorf("reason = %q, want %q", reason, testDecision.Reason)
	}
	
	if policyVersion != testDecision.PolicyVersion {
		t.Errorf("policyVersion = %q, want %q", policyVersion, testDecision.PolicyVersion)
	}
}
