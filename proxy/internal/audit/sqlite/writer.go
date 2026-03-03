// Package sqlite implements an async, batched SQLite writer for ClawShield audit logs.
package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SleuthCo/clawshield/proxy/internal/audit/crypto"
	"github.com/SleuthCo/clawshield/shared/types"
)

const (
	batchSize     = 100
	flushInterval = 5 * time.Second
)

// auditEntry pairs a decision with an optional tool call so both can be
// carried through the async channel and persisted atomically in the same
// transaction.
type auditEntry struct {
	decision *types.Decision
	toolCall *types.ToolCall
}

// SIEMForwarder is the interface for forwarding decisions to a SIEM system.
// This interface is defined here to avoid circular imports with the siem package.
type SIEMForwarder interface {
	Forward(dec *types.Decision)
}

// Writer is an async, batched SQLite writer for audit logs.
type Writer struct {
	db             *sql.DB
	dbPath         string
	mu             sync.Mutex
	queue          chan auditEntry
	stop           chan struct{}
	wg             sync.WaitGroup
	batch          []auditEntry
	closed         atomic.Bool
	flushed        int64
	dropped        atomic.Int64
	siemForwarder  SIEMForwarder
	encryptor      *crypto.FieldEncryptor
}

// NewWriter creates a new async SQLite writer.
func NewWriter(db *sql.DB) (*Writer, error) {
	return NewWriterWithPath(db, "")
}

// NewWriterWithPath creates a new async SQLite writer with a known DB file path
// for integrity checkpointing.
func NewWriterWithPath(db *sql.DB, dbPath string) (*Writer, error) {
	w := &Writer{
		db:    db,
		dbPath: dbPath,
		queue: make(chan auditEntry, 10000),
		stop:  make(chan struct{}),
		batch: make([]auditEntry, 0, batchSize),
	}

	w.wg.Add(1)
	go w.loop()

	// SECURITY: Write an integrity checkpoint at startup so we can detect
	// if the DB was tampered with while the proxy was offline.
	if dbPath != "" {
		if err := w.writeIntegrityCheckpoint("startup"); err != nil {
			log.Printf("WARNING: Failed to write startup integrity checkpoint: %v", err)
		}
	}

	return w, nil
}

// Write enqueues a decision for async logging.
func (w *Writer) Write(dec *types.Decision) error {
	return w.enqueue(auditEntry{decision: dec})
}

// enqueue sends an audit entry (decision + optional tool call) to the async queue.
func (w *Writer) enqueue(entry auditEntry) error {
	if w.closed.Load() {
		return fmt.Errorf("writer is closed")
	}

	// Forward to SIEM in real-time (before SQLite batching)
	if w.siemForwarder != nil && entry.decision != nil {
		w.siemForwarder.Forward(entry.decision)
	}

	select {
	case w.queue <- entry:
		return nil
	default:
		w.dropped.Add(1)
		dropped := w.dropped.Load()
		if dropped == 1 || dropped%100 == 0 {
			log.Printf("WARNING: audit queue full, %d decisions dropped total", dropped)
		}
		return fmt.Errorf("write queue full, dropping decision (%d dropped total)", dropped)
	}
}

// Close closes the writer and waits for pending writes.
func (w *Writer) Close() error {
	if w.closed.Swap(true) {
		return nil // already closed
	}
	close(w.stop)
	w.wg.Wait()
	// Drain remaining queue items and do a final flush
	w.mu.Lock()
	defer w.mu.Unlock()
	for {
		select {
		case entry := <-w.queue:
			w.batch = append(w.batch, entry)
		default:
			return w.flushBatch()
		}
	}
}

// SetSIEMForwarder attaches a SIEM forwarder to the writer.
// When set, every decision written to the audit log is also forwarded
// to the SIEM system in real-time (before batching to SQLite).
func (w *Writer) SetSIEMForwarder(forwarder SIEMForwarder) {
	w.siemForwarder = forwarder
}

// SetEncryptor attaches a field encryptor to the writer.
// When set, sensitive fields (decision_details, arguments_hash,
// tool_calls.request_json, tool_calls.response_json) are encrypted
// with AES-256-GCM before being written to SQLite.
//
// SECURITY: Encryption is applied at the storage layer only. SIEM
// forwarding receives unencrypted data so SOC analysts can process
// events in real-time without needing the encryption key.
func (w *Writer) SetEncryptor(enc *crypto.FieldEncryptor) {
	w.encryptor = enc
}

// Dropped returns the number of dropped audit entries.
func (w *Writer) Dropped() int64 {
	return w.dropped.Load()
}

// loop runs the async writer goroutine.
func (w *Writer) loop() {
	defer w.wg.Done()

	flushTicker := time.NewTicker(flushInterval)
	defer flushTicker.Stop()

	for {
		select {
		case entry, ok := <-w.queue:
			if !ok {
				break
			}
			w.mu.Lock()
			w.batch = append(w.batch, entry)
			if len(w.batch) >= batchSize {
				if err := w.flushBatch(); err != nil {
					log.Printf("ERROR: audit flush failed: %v", err)
				}
			}
			w.mu.Unlock()

		case <-flushTicker.C:
			w.mu.Lock()
			if len(w.batch) > 0 {
				if err := w.flushBatch(); err != nil {
					log.Printf("ERROR: audit flush failed: %v", err)
				}
			}
			w.mu.Unlock()

		case <-w.stop:
			// Drain remaining queue items
			w.mu.Lock()
			for {
				select {
				case entry := <-w.queue:
					w.batch = append(w.batch, entry)
				default:
					if len(w.batch) > 0 {
						if err := w.flushBatch(); err != nil {
							log.Printf("ERROR: audit flush failed on shutdown: %v", err)
						}
					}
					w.mu.Unlock()
					return
				}
			}
		}
	}
}

// flushBatch writes the current batch to SQLite.
// Must be called only when mutex is held.
// ArgumentsHash is expected to be pre-hashed by the caller - stored directly.
// Tool call data (if present) is inserted in the same transaction as its decision.
func (w *Writer) flushBatch() error {
	if len(w.batch) == 0 {
		return nil
	}

	batch := make([]auditEntry, len(w.batch))
	copy(batch, w.batch)
	w.batch = w.batch[:0]

	tx, err := w.db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	defer tx.Rollback() // nolint:errcheck

	decStmt, err := tx.PrepareContext(context.Background(), `
	INSERT INTO decisions (timestamp, session_id, tool, arguments_hash, decision, reason, policy_version, scanner_type, correlation_id, classification, source, response_blocked, decision_details)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare decision insert: %w", err)
	}
	defer decStmt.Close()

	// Prepare tool_calls insert lazily — only if any entries have tool call data
	var tcStmt *sql.Stmt
	defer func() {
		if tcStmt != nil {
			tcStmt.Close()
		}
	}()

	for _, entry := range batch {
		dec := entry.decision
		// Store ArgumentsHash directly - caller is responsible for hashing
		respBlocked := 0
		if dec.ResponseBlocked {
			respBlocked = 1
		}
		// Serialize decision details
		detailsJSON, err := types.MarshalDecisionDetail(dec.Details)
		if err != nil {
			return fmt.Errorf("marshal decision details: %w", err)
		}
		var detailsBytes []byte
		if detailsJSON != nil {
			detailsBytes = []byte(detailsJSON)
		}

		// SECURITY: Encrypt sensitive fields before storage.
		// Non-sensitive fields (timestamp, session_id, tool, decision, reason,
		// policy_version, scanner_type, correlation_id, classification, source)
		// remain plaintext for queryability.
		argsHashForStorage := dec.ArgumentsHash
		if w.encryptor != nil {
			if detailsBytes != nil {
				detailsBytes, err = w.encryptor.Encrypt(detailsBytes)
				if err != nil {
					return fmt.Errorf("encrypt decision_details: %w", err)
				}
			}
			if argsHashForStorage != "" {
				encArgHash, err := w.encryptor.EncryptString(argsHashForStorage)
				if err != nil {
					return fmt.Errorf("encrypt arguments_hash: %w", err)
				}
				argsHashForStorage = string(encArgHash)
			}
		}

		result, err := decStmt.ExecContext(context.Background(),
			dec.Timestamp,
			dec.SessionID,
			dec.Tool,
			argsHashForStorage,
			dec.Decision,
			dec.Reason,
			dec.PolicyVersion,
			dec.ScannerType,
			dec.CorrelationID,
			dec.Classification,
			dec.Source,
			respBlocked,
			detailsBytes)
		if err != nil {
			return fmt.Errorf("insert decision: %w", err)
		}

		// If this entry has tool call data, insert it linked to the decision
		if entry.toolCall != nil {
			if tcStmt == nil {
				tcStmt, err = tx.PrepareContext(context.Background(), `
				INSERT INTO tool_calls (decision_id, request_json, response_json, created_at)
				VALUES (?, ?, ?, ?)`)
				if err != nil {
					return fmt.Errorf("prepare tool_call insert: %w", err)
				}
			}

			decisionID, err := result.LastInsertId()
			if err != nil {
				return fmt.Errorf("get decision_id for tool_call: %w", err)
			}

			createdAt := entry.toolCall.CreatedAt
			if createdAt.IsZero() {
				createdAt = dec.Timestamp
			}

			// SECURITY: Encrypt tool call request/response JSON before storage.
			// These fields contain the full MCP request and response bodies,
			// which may include secrets, PII, and credentials detected by scanners.
			reqJSON := entry.toolCall.RequestJSON
			respJSON := entry.toolCall.ResponseJSON
			if w.encryptor != nil {
				if reqJSON != nil {
					reqJSON, err = w.encryptor.Encrypt(reqJSON)
					if err != nil {
						return fmt.Errorf("encrypt request_json: %w", err)
					}
				}
				if respJSON != nil {
					respJSON, err = w.encryptor.Encrypt(respJSON)
					if err != nil {
						return fmt.Errorf("encrypt response_json: %w", err)
					}
				}
			}

			_, err = tcStmt.ExecContext(context.Background(),
				decisionID,
				reqJSON,
				respJSON,
				createdAt)
			if err != nil {
				return fmt.Errorf("insert tool_call: %w", err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	w.flushed += int64(len(batch))

	// SECURITY: Write integrity checkpoint every 1000 decisions (down from 10k)
	// to reduce the tamper window. Each checkpoint stores a SHA-256 hash of the
	// entire DB file, allowing detection of any modifications between checkpoints.
	if w.dbPath != "" && w.flushed%1000 < int64(len(batch)) && w.flushed >= 1000 {
		if err := w.writeIntegrityCheckpoint("batch flush"); err != nil {
			log.Printf("ERROR: Failed to write integrity checkpoint: %v", err)
		}
	}

	return nil
}

func (w *Writer) writeIntegrityCheckpoint(reason string) error {
	hash, err := w.computeDBHash()
	if err != nil {
		return fmt.Errorf("compute db hash: %w", err)
	}

	_, err = w.db.ExecContext(context.Background(), `
	INSERT INTO integrity_checkpoints (db_hash, reason)
	VALUES (?, ?)`, hash, reason)
	if err != nil {
		return fmt.Errorf("insert integrity checkpoint: %w", err)
	}
	return nil
}

// computeDBHash computes a SHA-256 hash of the database file for tamper detection.
// Requires dbPath to be set - refuses to generate forgeable fallback hashes.
func (w *Writer) computeDBHash() (string, error) {
	if w.dbPath == "" {
		return "", fmt.Errorf("dbPath not set; cannot compute reliable integrity hash")
	}

	// Force WAL checkpoint before hashing for consistency
	if _, err := w.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		log.Printf("WARNING: WAL checkpoint failed before integrity hash: %v", err)
	}

	f, err := os.Open(w.dbPath)
	if err != nil {
		return "", fmt.Errorf("open db file: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash db file: %w", err)
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// WriteDecision writes a decision and optionally its associated tool call data.
// Both the decision and tool call are persisted atomically in the same transaction.
func (w *Writer) WriteDecision(decision types.Decision, toolCall *types.ToolCall) error {
	return w.enqueue(auditEntry{decision: &decision, toolCall: toolCall})
}
