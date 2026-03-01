// +build integration

package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SleuthCo/clawshield/proxy/internal/audit/sqlite"
	"github.com/SleuthCo/clawshield/proxy/internal/config"
	"github.com/SleuthCo/clawshield/proxy/internal/engine"
	"github.com/SleuthCo/clawshield/shared/types"
	_ "github.com/mattn/go-sqlite3"
)

func TestProxyFullFlow(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policy.yaml")
	policyContent := `
default_action: allow
allowlist:
  - read
  - write
denylist:
  - exec
`
	if err := os.WriteFile(policyFile, []byte(policyContent), 0644); err != nil {
		t.Fatalf("failed to create policy file: %v", err)
	}
	policy, err := config.Load(policyFile)
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}
	evaluator := engine.NewEvaluator(policy)
	testCases := []struct {
		name            string
		message         string
		expectedDecision string
	}{
		{
			name:            "allowed tool",
			message:         `{"method": "read", "params": {"path": "file.txt"}}`,
			expectedDecision: "allow",
		},
		{
			name:            "denied tool",
			message:         `{"method": "exec", "params": {"command": "ls"}}`,
			expectedDecision: "deny",
		},
		{
			name:            "invalid JSON",
			message:         `{not valid}`,
			expectedDecision: "deny",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			decision, reason := evaluator.EvaluateWithContext(ctx, tc.message)
			if decision != tc.expectedDecision {
				t.Errorf("decision = %s, want %s (reason: %s)", decision, tc.expectedDecision, reason)
			}
		})
	}
}

func TestAuditLogIntegrity(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "audit.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()
	schema := `
	CREATE TABLE decisions (
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
	CREATE TABLE tool_calls (
		call_id INTEGER PRIMARY KEY AUTOINCREMENT,
		decision_id INTEGER NOT NULL,
		request_json TEXT,
		response_json TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE integrity_checkpoints (
		checkpoint_id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		db_hash TEXT NOT NULL,
		reason TEXT
	);
	`
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}
	writer, err := sqlite.NewWriter(db)
	if err != nil {
		t.Fatalf("NewWriter() failed: %v", err)
	}
	testDecisions := []*types.Decision{
		{
			Timestamp:     time.Now(),
			SessionID:     "integration-test-1",
			Tool:          "read",
			ArgumentsHash: `{"path": "file1.txt"}`,
			Decision:      "allow",
			Reason:        "in allowlist",
			PolicyVersion: "1.0",
		},
		{
			Timestamp:     time.Now(),
			SessionID:     "integration-test-1",
			Tool:          "exec",
			ArgumentsHash: `{"command": "ls"}`,
			Decision:      "deny",
			Reason:        "in denylist",
			PolicyVersion: "1.0",
		},
		{
			Timestamp:     time.Now(),
			SessionID:     "integration-test-1",
			Tool:          "write",
			ArgumentsHash: `{"path": "file2.txt", "content": "data"}`,
			Decision:      "allow",
			Reason:        "in allowlist",
			PolicyVersion: "1.0",
		},
	}
	for _, dec := range testDecisions {
		if err := writer.Write(dec); err != nil {
			t.Fatalf("Write() failed: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	rows, err := db.Query("SELECT session_id, tool, decision, reason FROM decisions ORDER BY decision_id")
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	defer rows.Close()
	readDecisions := []*types.Decision{}
	for rows.Next() {
		var dec types.Decision
		if err := rows.Scan(&dec.SessionID, &dec.Tool, &dec.Decision, &dec.Reason); err != nil {
			t.Fatalf("scan failed: %v", err)
		}
		readDecisions = append(readDecisions, &dec)
	}
	if len(readDecisions) != len(testDecisions) {
		t.Fatalf("read %d decisions, want %d", len(readDecisions), len(testDecisions))
	}
	for i, read := range readDecisions {
		want := testDecisions[i]
		if read.SessionID != want.SessionID {
			t.Errorf("decision %d: sessionID = %s, want %s", i, read.SessionID, want.SessionID)
		}
		if read.Tool != want.Tool {
			t.Errorf("decision %d: tool = %s, want %s", i, read.Tool, want.Tool)
		}
		if read.Decision != want.Decision {
			t.Errorf("decision %d: decision = %s, want %s", i, read.Decision, want.Decision)
		}
		if read.Reason != want.Reason {
			t.Errorf("decision %d: reason = %s, want %s", i, read.Reason, want.Reason)
		}
	}
}

func TestEndToEnd_ProxyAuditIntegration(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policy.yaml")
	policyContent := `
default_action: deny
allowlist:
  - read
  - web.fetch
domain_allowlist:
  - example.com
arg_filters:
  - tool: read
    regex: "secret"
`
	if err := os.WriteFile(policyFile, []byte(policyContent), 0644); err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}
	policy, err := config.Load(policyFile)
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}
	evaluator := engine.NewEvaluator(policy)
	dbPath := filepath.Join(tmpDir, "audit.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()
	schema := `
	CREATE TABLE decisions (
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
	CREATE TABLE tool_calls (
		call_id INTEGER PRIMARY KEY AUTOINCREMENT,
		decision_id INTEGER NOT NULL,
		request_json TEXT,
		response_json TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE integrity_checkpoints (
		checkpoint_id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		db_hash TEXT NOT NULL,
		reason TEXT
	);
	`
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}
	writer, err := sqlite.NewWriter(db)
	if err != nil {
		t.Fatalf("NewWriter() failed: %v", err)
	}
	defer writer.Close()
	testMessages := []struct {
		message          string
		expectedDecision string
		expectedReason   string
	}{
		{
			message:          `{"method": "read", "params": {"path": "file.txt"}}`,
			expectedDecision: "allow",
			expectedReason:   "default allowed",
		},
		{
			message:          `{"method": "read", "params": {"path": "secret.txt"}}`,
			expectedDecision: "deny",
			expectedReason:   "sensitive data detected",
		},
		{
			message:          `{"method": "write", "params": {"path": "file.txt"}}`,
			expectedDecision: "deny",
			expectedReason:   "default denied",
		},
		{
			message:          `{"method": "web.fetch", "params": {"url": "https://example.com"}}`,
			expectedDecision: "allow",
			expectedReason:   "default allowed",
		},
		{
			message:          `{"method": "web.fetch", "params": {"url": "https://evil.com"}}`,
			expectedDecision: "deny",
			expectedReason:   "domain not in allowlist",
		},
	}
	ctx := context.Background()
	sessionID := "e2e-test-session"
	for i, tm := range testMessages {
		decision, reason := evaluator.EvaluateWithContext(ctx, tm.message)
		if decision != tm.expectedDecision {
			t.Errorf("message %d: decision = %s, want %s", i, decision, tm.expectedDecision)
		}
		if !strings.Contains(reason, tm.expectedReason) {
			t.Errorf("message %d: reason = %q, want to contain %q", i, reason, tm.expectedReason)
		}
		auditDecision := &types.Decision{
			Timestamp:     time.Now(),
			SessionID:     sessionID,
			Tool:          extractMethod(tm.message),
			ArgumentsHash: tm.message,
			Decision:      decision,
			Reason:        reason,
			PolicyVersion: "1.0",
		}
		if err := writer.Write(auditDecision); err != nil {
			t.Fatalf("message %d: Write() failed: %v", i, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM decisions WHERE session_id = ?", sessionID).Scan(&count)
	if err != nil {
		t.Fatalf("count query failed: %v", err)
	}
	if count != len(testMessages) {
		t.Errorf("audited %d decisions, want %d", count, len(testMessages))
	}
	var allowCount, denyCount int
	err = db.QueryRow("SELECT COUNT(*) FROM decisions WHERE session_id = ? AND decision = 'allow'", sessionID).Scan(&allowCount)
	if err != nil {
		t.Fatalf("allow count query failed: %v", err)
	}
	err = db.QueryRow("SELECT COUNT(*) FROM decisions WHERE session_id = ? AND decision = 'deny'", sessionID).Scan(&denyCount)
	if err != nil {
		t.Fatalf("deny count query failed: %v", err)
	}
	expectedAllow := 2
	expectedDeny := 3
	if allowCount != expectedAllow {
		t.Errorf("allow count = %d, want %d", allowCount, expectedAllow)
	}
	if denyCount != expectedDeny {
		t.Errorf("deny count = %d, want %d", denyCount, expectedDeny)
	}
}

func extractMethod(message string) string {
	var rpc struct {
		Method string `json:"method"`
	}
	if err := json.Unmarshal([]byte(message), &rpc); err != nil {
		return "unknown"
	}
	if rpc.Method == "" {
		return "unknown"
	}
	return rpc.Method
}
