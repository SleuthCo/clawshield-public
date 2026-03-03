package crypto_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"sync"
	"testing"
	"time"

	"github.com/SleuthCo/clawshield/proxy/internal/audit/crypto"
	"github.com/SleuthCo/clawshield/proxy/internal/audit/sqlite"
	"github.com/SleuthCo/clawshield/shared/types"
	_ "github.com/mattn/go-sqlite3"
)

// ---------- helpers ----------

func genKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, crypto.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:?_busy_timeout=5000&_journal_mode=WAL")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	createSchema(t, db)
	return db
}

func createSchema(t *testing.T, db *sql.DB) {
	t.Helper()
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
		created_at DATETIME,
		FOREIGN KEY(decision_id) REFERENCES decisions(decision_id)
	);
	CREATE TABLE IF NOT EXISTS policy_changes (
		change_id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		session_id TEXT,
		old_policy_hash TEXT,
		new_policy_hash TEXT,
		changed_by TEXT,
		reason TEXT
	);
	CREATE TABLE IF NOT EXISTS sessions (
		session_id TEXT PRIMARY KEY,
		start_time DATETIME,
		end_time DATETIME,
		agent_version TEXT,
		node_id TEXT,
		context JSON
	);`
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
}

func newEncryptor(t *testing.T, key []byte) *crypto.FieldEncryptor {
	t.Helper()
	enc, err := crypto.NewFieldEncryptor(key)
	if err != nil {
		t.Fatalf("create encryptor: %v", err)
	}
	return enc
}

func sampleDecision() types.Decision {
	return types.Decision{
		Timestamp:     time.Now().UTC().Truncate(time.Millisecond),
		SessionID:     "sess-001",
		Tool:          "web_search",
		ArgumentsHash: `e3b0c44298fc1c149afbf4c8996fb924`,
		Decision:      "deny",
		Reason:        "injection detected",
		PolicyVersion: "v2.1",
		ScannerType:   "injection",
		CorrelationID: "corr-abc-123",
		Classification: "CONFIDENTIAL",
		Source:         "forge-bridge",
		Details: &types.DecisionDetail{
			PipelineStage:  "injection_scan",
			EvalDurationMs: 3.14,
			ScanResults: []types.ScanResult{
				{
					Scanner:      "injection",
					RuleID:       "prompt_override",
					Description:  "Role override attempt detected",
					MatchExcerpt: "ignore previous instructions",
					Confidence:   "high",
					Blocked:      true,
				},
			},
		},
	}
}

func sampleToolCall() *types.ToolCall {
	return &types.ToolCall{
		RequestJSON:  []byte(`{"method":"tools/call","params":{"name":"web_search","arguments":{"query":"SSN 123-45-6789"}}}`),
		ResponseJSON: []byte(`{"result":{"content":[{"type":"text","text":"Found sensitive data: CC 4111-1111-1111-1111"}]}}`),
		CreatedAt:    time.Now().UTC().Truncate(time.Millisecond),
	}
}

func writeAndFlush(t *testing.T, w *sqlite.Writer, dec types.Decision, tc *types.ToolCall) {
	t.Helper()
	if err := w.WriteDecision(dec, tc); err != nil {
		t.Fatalf("write decision: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
}

// ---------- tests ----------

// TestEncryptedWriteDecryptedRead verifies the full round-trip: write with
// encryption, read with decryption — all sensitive fields should be recovered.
func TestEncryptedWriteDecryptedRead(t *testing.T) {
	db := openDB(t)
	key := genKey(t)
	enc := newEncryptor(t, key)

	// Write with encryption
	w, err := sqlite.NewWriter(db)
	if err != nil {
		t.Fatalf("create writer: %v", err)
	}
	w.SetEncryptor(enc)

	dec := sampleDecision()
	tc := sampleToolCall()
	writeAndFlush(t, w, dec, tc)

	// Read with decryption
	reader := sqlite.NewReaderWithEncryptor(db, enc)
	logs, err := reader.QueryDecisions(context.Background(), sqlite.WithIncludeToolCall())
	if err != nil {
		t.Fatalf("query: %v", err)
	}

	if len(logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(logs))
	}

	got := logs[0]

	// Verify all decrypted fields match originals
	if got.Decision.ArgumentsHash != dec.ArgumentsHash {
		t.Errorf("arguments_hash: got %q, want %q", got.Decision.ArgumentsHash, dec.ArgumentsHash)
	}
	if got.Decision.Details == nil {
		t.Fatal("expected non-nil details")
	}
	if got.Decision.Details.PipelineStage != "injection_scan" {
		t.Errorf("pipeline_stage: got %q, want %q", got.Decision.Details.PipelineStage, "injection_scan")
	}
	if len(got.Decision.Details.ScanResults) != 1 {
		t.Fatalf("expected 1 scan result, got %d", len(got.Decision.Details.ScanResults))
	}
	if got.Decision.Details.ScanResults[0].RuleID != "prompt_override" {
		t.Errorf("rule_id: got %q, want %q", got.Decision.Details.ScanResults[0].RuleID, "prompt_override")
	}

	// Verify tool call data decrypted correctly
	if got.ToolCall == nil {
		t.Fatal("expected non-nil tool call")
	}
	if string(got.ToolCall.RequestJSON) != string(tc.RequestJSON) {
		t.Errorf("request_json: got %q, want %q", got.ToolCall.RequestJSON, tc.RequestJSON)
	}
	if string(got.ToolCall.ResponseJSON) != string(tc.ResponseJSON) {
		t.Errorf("response_json: got %q, want %q", got.ToolCall.ResponseJSON, tc.ResponseJSON)
	}

	// Verify non-sensitive fields are unchanged
	if got.Decision.Tool != "web_search" {
		t.Errorf("tool: got %q, want %q", got.Decision.Tool, "web_search")
	}
	if got.Decision.Decision != "deny" {
		t.Errorf("decision: got %q, want %q", got.Decision.Decision, "deny")
	}
	// Note: scanner_type is used for filtering but is not included in the
	// Reader's SELECT output columns, so it won't be populated on read.
	// This is pre-existing Reader behavior, not an encryption concern.
}

// TestUnencryptedWriteDecryptedRead verifies that a reader with decryption
// enabled gracefully handles plaintext (unencrypted) data — the migration
// scenario where encryption is enabled on an existing database.
func TestUnencryptedWriteDecryptedRead(t *testing.T) {
	db := openDB(t)
	key := genKey(t)
	enc := newEncryptor(t, key)

	// Write WITHOUT encryption
	w, err := sqlite.NewWriter(db)
	if err != nil {
		t.Fatalf("create writer: %v", err)
	}

	dec := sampleDecision()
	tc := sampleToolCall()
	writeAndFlush(t, w, dec, tc)

	// Read WITH decryption — should gracefully return plaintext data
	reader := sqlite.NewReaderWithEncryptor(db, enc)
	logs, err := reader.QueryDecisions(context.Background(), sqlite.WithIncludeToolCall())
	if err != nil {
		t.Fatalf("query: %v", err)
	}

	if len(logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(logs))
	}

	got := logs[0]

	// Plaintext data should come through unchanged
	if got.Decision.ArgumentsHash != dec.ArgumentsHash {
		t.Errorf("arguments_hash: got %q, want %q", got.Decision.ArgumentsHash, dec.ArgumentsHash)
	}
	if got.Decision.Details == nil {
		t.Fatal("expected non-nil details")
	}
	if got.Decision.Details.PipelineStage != "injection_scan" {
		t.Errorf("pipeline_stage: got %q, want %q", got.Decision.Details.PipelineStage, "injection_scan")
	}
	if string(got.ToolCall.RequestJSON) != string(tc.RequestJSON) {
		t.Errorf("request_json: got %q, want %q", got.ToolCall.RequestJSON, tc.RequestJSON)
	}
}

// TestEncryptedWritePlaintextRead verifies that reading encrypted data
// without a decryptor returns raw ciphertext without errors — this is the
// safe failure mode (data is protected, reader just can't interpret it).
func TestEncryptedWritePlaintextRead(t *testing.T) {
	db := openDB(t)
	key := genKey(t)
	enc := newEncryptor(t, key)

	// Write WITH encryption
	w, err := sqlite.NewWriter(db)
	if err != nil {
		t.Fatalf("create writer: %v", err)
	}
	w.SetEncryptor(enc)

	dec := sampleDecision()
	tc := sampleToolCall()
	writeAndFlush(t, w, dec, tc)

	// Read WITHOUT decryption
	reader := sqlite.NewReader(db)
	logs, err := reader.QueryDecisions(context.Background(), sqlite.WithIncludeToolCall())
	if err != nil {
		t.Fatalf("query: %v", err)
	}

	if len(logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(logs))
	}

	got := logs[0]

	// Sensitive fields should NOT match the originals (they're ciphertext)
	if got.Decision.ArgumentsHash == dec.ArgumentsHash {
		t.Error("arguments_hash should be encrypted, but matches plaintext")
	}
	// Details should be nil because the encrypted blob can't be parsed as JSON
	if got.Decision.Details != nil {
		t.Error("expected nil details when reading encrypted data without decryptor")
	}
	// Tool call JSON should be ciphertext (not matching original)
	if got.ToolCall != nil && string(got.ToolCall.RequestJSON) == string(tc.RequestJSON) {
		t.Error("request_json should be encrypted, but matches plaintext")
	}

	// Non-sensitive fields should still be readable
	if got.Decision.Tool != "web_search" {
		t.Errorf("tool: got %q, want %q", got.Decision.Tool, "web_search")
	}
	if got.Decision.Decision != "deny" {
		t.Errorf("decision: got %q, want %q", got.Decision.Decision, "deny")
	}
}

// TestMixedEncryptedPlaintextData verifies that a database containing both
// encrypted and unencrypted rows is handled correctly — the migration scenario.
func TestMixedEncryptedPlaintextData(t *testing.T) {
	db := openDB(t)
	key := genKey(t)
	enc := newEncryptor(t, key)

	// Write first entry WITHOUT encryption
	w1, err := sqlite.NewWriter(db)
	if err != nil {
		t.Fatalf("create writer 1: %v", err)
	}
	plainDec := sampleDecision()
	plainDec.Tool = "plaintext_tool"
	plainDec.ArgumentsHash = "plain_hash_abc"
	writeAndFlush(t, w1, plainDec, nil)

	// Write second entry WITH encryption
	w2, err := sqlite.NewWriter(db)
	if err != nil {
		t.Fatalf("create writer 2: %v", err)
	}
	w2.SetEncryptor(enc)
	encDec := sampleDecision()
	encDec.Tool = "encrypted_tool"
	encDec.ArgumentsHash = "encrypted_hash_xyz"
	writeAndFlush(t, w2, encDec, nil)

	// Read with decryption — both rows should be readable
	reader := sqlite.NewReaderWithEncryptor(db, enc)
	logs, err := reader.QueryDecisions(context.Background())
	if err != nil {
		t.Fatalf("query: %v", err)
	}

	if len(logs) != 2 {
		t.Fatalf("expected 2 logs, got %d", len(logs))
	}

	// Results are DESC by timestamp, so encrypted entry is first
	for _, log := range logs {
		switch log.Decision.Tool {
		case "plaintext_tool":
			if log.Decision.ArgumentsHash != "plain_hash_abc" {
				t.Errorf("plaintext args_hash: got %q, want %q", log.Decision.ArgumentsHash, "plain_hash_abc")
			}
		case "encrypted_tool":
			if log.Decision.ArgumentsHash != "encrypted_hash_xyz" {
				t.Errorf("encrypted args_hash: got %q, want %q", log.Decision.ArgumentsHash, "encrypted_hash_xyz")
			}
		default:
			t.Errorf("unexpected tool: %q", log.Decision.Tool)
		}
	}
}

// TestWrongKeyDecryption verifies that reading with the wrong key produces
// graceful warnings rather than crashes — fields fall back to raw values.
func TestWrongKeyDecryption(t *testing.T) {
	db := openDB(t)
	writeKey := genKey(t)
	readKey := genKey(t)

	writeEnc := newEncryptor(t, writeKey)
	readEnc := newEncryptor(t, readKey)

	// Write with key A
	w, err := sqlite.NewWriter(db)
	if err != nil {
		t.Fatalf("create writer: %v", err)
	}
	w.SetEncryptor(writeEnc)

	dec := sampleDecision()
	writeAndFlush(t, w, dec, nil)

	// Read with key B — should not crash, should log warnings
	reader := sqlite.NewReaderWithEncryptor(db, readEnc)
	logs, err := reader.QueryDecisions(context.Background())
	if err != nil {
		t.Fatalf("query should not fail: %v", err)
	}

	if len(logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(logs))
	}

	// Non-sensitive fields should still be readable
	if logs[0].Decision.Tool != "web_search" {
		t.Errorf("tool: got %q, want %q", logs[0].Decision.Tool, "web_search")
	}
}

// TestNonSensitiveFieldsRemainQueryable verifies that filtering by
// non-sensitive fields (tool, decision, scanner_type, time range)
// still works correctly when encryption is enabled.
func TestNonSensitiveFieldsRemainQueryable(t *testing.T) {
	db := openDB(t)
	key := genKey(t)
	enc := newEncryptor(t, key)

	w, err := sqlite.NewWriter(db)
	if err != nil {
		t.Fatalf("create writer: %v", err)
	}
	w.SetEncryptor(enc)

	// Write two decisions with different tools
	dec1 := sampleDecision()
	dec1.Tool = "code_execute"
	dec1.Decision = "allow"
	dec1.ScannerType = ""
	if err := w.WriteDecision(dec1, nil); err != nil {
		t.Fatalf("write 1: %v", err)
	}

	dec2 := sampleDecision()
	dec2.Tool = "web_search"
	dec2.Decision = "deny"
	dec2.ScannerType = "injection"
	if err := w.WriteDecision(dec2, nil); err != nil {
		t.Fatalf("write 2: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reader := sqlite.NewReaderWithEncryptor(db, enc)

	// Filter by tool
	logs, err := reader.QueryDecisions(context.Background(), sqlite.WithTool("code_execute"))
	if err != nil {
		t.Fatalf("query by tool: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("expected 1 result for tool filter, got %d", len(logs))
	}
	if logs[0].Decision.Tool != "code_execute" {
		t.Errorf("tool: got %q, want %q", logs[0].Decision.Tool, "code_execute")
	}

	// Filter by decision
	logs, err = reader.QueryDecisions(context.Background(), sqlite.WithDecision("deny"))
	if err != nil {
		t.Fatalf("query by decision: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("expected 1 result for decision filter, got %d", len(logs))
	}

	// Filter by scanner_type
	logs, err = reader.QueryDecisions(context.Background(), sqlite.WithScannerType("injection"))
	if err != nil {
		t.Fatalf("query by scanner: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("expected 1 result for scanner filter, got %d", len(logs))
	}
}

// TestConcurrentEncryptedWrites verifies thread safety of encrypted writes.
func TestConcurrentEncryptedWrites(t *testing.T) {
	db := openDB(t)
	key := genKey(t)
	enc := newEncryptor(t, key)

	w, err := sqlite.NewWriter(db)
	if err != nil {
		t.Fatalf("create writer: %v", err)
	}
	w.SetEncryptor(enc)

	const goroutines = 10
	const perGoroutine = 20

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				dec := sampleDecision()
				dec.SessionID = "concurrent-test"
				tc := sampleToolCall()
				if err := w.WriteDecision(dec, tc); err != nil {
					t.Logf("write goroutine %d/%d: %v", id, j, err)
				}
			}
		}(i)
	}
	wg.Wait()

	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Verify all were written and can be decrypted
	reader := sqlite.NewReaderWithEncryptor(db, enc)
	logs, err := reader.QueryDecisions(context.Background(), sqlite.WithIncludeToolCall())
	if err != nil {
		t.Fatalf("query: %v", err)
	}

	expected := goroutines * perGoroutine
	if len(logs) != expected {
		t.Errorf("expected %d logs, got %d", expected, len(logs))
	}

	// Verify at least one entry decrypts correctly
	if len(logs) > 0 {
		got := logs[0]
		if got.Decision.Details == nil {
			t.Error("expected non-nil details after decryption")
		}
		if got.ToolCall == nil {
			t.Error("expected non-nil tool call")
		} else if len(got.ToolCall.RequestJSON) == 0 {
			t.Error("expected non-empty request_json after decryption")
		}
	}
}

// TestSIEMReceivesUnencryptedData verifies that the SIEM forwarder receives
// unencrypted data even when storage encryption is enabled.
type mockSIEMForwarder struct {
	mu        sync.Mutex
	forwarded []*types.Decision
}

func (m *mockSIEMForwarder) Forward(dec *types.Decision) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.forwarded = append(m.forwarded, dec)
}

func TestSIEMReceivesUnencryptedData(t *testing.T) {
	db := openDB(t)
	key := genKey(t)
	enc := newEncryptor(t, key)

	w, err := sqlite.NewWriter(db)
	if err != nil {
		t.Fatalf("create writer: %v", err)
	}
	w.SetEncryptor(enc)

	siem := &mockSIEMForwarder{}
	w.SetSIEMForwarder(siem)

	dec := sampleDecision()
	writeAndFlush(t, w, dec, nil)

	// SIEM should have received the original unencrypted data
	siem.mu.Lock()
	defer siem.mu.Unlock()
	if len(siem.forwarded) != 1 {
		t.Fatalf("expected 1 SIEM forward, got %d", len(siem.forwarded))
	}

	fwd := siem.forwarded[0]
	if fwd.ArgumentsHash != dec.ArgumentsHash {
		t.Errorf("SIEM got encrypted args_hash %q, want plaintext %q", fwd.ArgumentsHash, dec.ArgumentsHash)
	}
	if fwd.Details == nil {
		t.Error("SIEM should receive unencrypted details")
	}
	if fwd.Details != nil && fwd.Details.PipelineStage != "injection_scan" {
		t.Errorf("SIEM pipeline_stage: got %q, want %q", fwd.Details.PipelineStage, "injection_scan")
	}
}

// TestEncryptionWithNilDetails verifies that nil/empty optional fields
// are handled correctly when encryption is enabled.
func TestEncryptionWithNilDetails(t *testing.T) {
	db := openDB(t)
	key := genKey(t)
	enc := newEncryptor(t, key)

	w, err := sqlite.NewWriter(db)
	if err != nil {
		t.Fatalf("create writer: %v", err)
	}
	w.SetEncryptor(enc)

	dec := types.Decision{
		Timestamp:     time.Now().UTC(),
		SessionID:     "sess-nil",
		Tool:          "test_tool",
		ArgumentsHash: "",
		Decision:      "allow",
		Reason:        "allowed by policy",
		PolicyVersion: "v1.0",
		Details:       nil, // no details
	}

	writeAndFlush(t, w, dec, nil)

	reader := sqlite.NewReaderWithEncryptor(db, enc)
	logs, err := reader.QueryDecisions(context.Background())
	if err != nil {
		t.Fatalf("query: %v", err)
	}

	if len(logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(logs))
	}

	if logs[0].Decision.Details != nil {
		t.Error("expected nil details")
	}
	if logs[0].Decision.ArgumentsHash != "" {
		t.Errorf("expected empty args_hash, got %q", logs[0].Decision.ArgumentsHash)
	}
}

// TestRawStorageIsEncrypted verifies that sensitive fields in the database
// are actually stored as ciphertext, not plaintext — the core security property.
func TestRawStorageIsEncrypted(t *testing.T) {
	db := openDB(t)
	key := genKey(t)
	enc := newEncryptor(t, key)

	w, err := sqlite.NewWriter(db)
	if err != nil {
		t.Fatalf("create writer: %v", err)
	}
	w.SetEncryptor(enc)

	dec := sampleDecision()
	tc := sampleToolCall()
	writeAndFlush(t, w, dec, tc)

	// Query the raw database directly (bypassing the Reader's decryption)
	var rawArgsHash, rawDetails string
	err = db.QueryRow("SELECT arguments_hash, decision_details FROM decisions LIMIT 1").Scan(&rawArgsHash, &rawDetails)
	if err != nil {
		t.Fatalf("raw query decisions: %v", err)
	}

	// arguments_hash should NOT be plaintext
	if rawArgsHash == dec.ArgumentsHash {
		t.Error("arguments_hash is stored as plaintext — encryption not applied!")
	}

	// decision_details should NOT be valid JSON (it's ciphertext)
	if rawDetails == "" {
		t.Fatal("expected non-empty decision_details")
	}
	// The raw bytes should start with the version prefix when cast to bytes
	rawDetailBytes := []byte(rawDetails)
	if !crypto.IsEncrypted(rawDetailBytes) {
		t.Error("decision_details does not appear encrypted (missing version prefix)")
	}

	// Check tool_calls
	var rawReqJSON, rawRespJSON string
	err = db.QueryRow("SELECT request_json, response_json FROM tool_calls LIMIT 1").Scan(&rawReqJSON, &rawRespJSON)
	if err != nil {
		t.Fatalf("raw query tool_calls: %v", err)
	}

	if rawReqJSON == string(tc.RequestJSON) {
		t.Error("request_json is stored as plaintext — encryption not applied!")
	}
	if rawRespJSON == string(tc.ResponseJSON) {
		t.Error("response_json is stored as plaintext — encryption not applied!")
	}
}
