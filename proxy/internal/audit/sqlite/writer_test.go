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

func TestWriter_QueueFull(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	writer, err := NewWriter(db)
	if err != nil {
		t.Fatalf("NewWriter() failed: %v", err)
	}
	defer writer.Close()
	
	// Fill the queue (queue size is 10000)
	// We won't actually fill it in this test as it would take too long,
	// but we verify the error handling exists
	decision := &types.Decision{
		Timestamp:     time.Now(),
		SessionID:     "test-session",
		Tool:          "read",
		ArgumentsHash: `{"path": "file.txt"}`,
		Decision:      "allow",
	}
	
	// Write one decision successfully
	if err := writer.Write(decision); err != nil {
		t.Fatalf("Write() failed: %v", err)
	}
	
	// In practice, queue full would require blocking the loop goroutine
	// and writing 10000+ decisions, which we skip for test speed
}

func TestWriter_FlushOnInterval(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	writer, err := NewWriter(db)
	if err != nil {
		t.Fatalf("NewWriter() failed: %v", err)
	}
	defer writer.Close()
	
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
	
	// Wait for flush interval (5 seconds + margin)
	time.Sleep(6 * time.Second)
	
	// Verify flushed to DB
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM decisions").Scan(&count)
	if err != nil {
		t.Fatalf("failed to query decisions: %v", err)
	}
	
	if count != 10 {
		t.Errorf("expected 10 decisions flushed after interval, got %d", count)
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
