// Package sqlite implements an async, batched SQLite writer for ClawShield audit logs.
package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SleuthCo/clawshield/shared/types"
)

const (
	batchSize          = 100
	flushInterval      = 5 * time.Second
	maxRetries         = 3
	retryDelay         = 100 * time.Millisecond
	checkpointInterval = 100 // Write external checkpoint every 100 entries
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

// flushBatch writes the current batch to SQLite with retry logic.
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

	return w.flushWithRetry(batch)
}

// flushWithRetry attempts to flush entries to SQLite with exponential backoff retry logic.
// If all retries fail, writes entries to a fallback JSONL file for later recovery.
func (w *Writer) flushWithRetry(batch []auditEntry) error {
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if err := w.flush(batch); err != nil {
			lastErr = err
			log.Printf("ERROR: audit write failed (attempt %d/%d): %v", attempt+1, maxRetries, err)
			time.Sleep(retryDelay * time.Duration(attempt+1))
			continue
		}
		// Success
		return nil
	}

	// After all retries failed, write to a fallback file
	w.writeFallback(batch)
	return lastErr
}

// flush writes a batch of entries to SQLite in a single transaction.
func (w *Writer) flush(batch []auditEntry) error {
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
		result, err := decStmt.ExecContext(context.Background(),
			dec.Timestamp,
			dec.SessionID,
			dec.Tool,
			dec.ArgumentsHash,
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
			_, err = tcStmt.ExecContext(context.Background(),
				decisionID,
				entry.toolCall.RequestJSON,
				entry.toolCall.ResponseJSON,
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

	// SECURITY: Write external checkpoint every N entries to prevent tampering
	// with both data and checksums stored in the same DB.
	if w.dbPath != "" && w.flushed%checkpointInterval < int64(len(batch)) && w.flushed >= checkpointInterval {
		lastHash, err := w.computeDBHash()
		if err != nil {
			log.Printf("ERROR: Failed to compute DB hash for checkpoint: %v", err)
		} else {
			if err := w.writeExternalCheckpoint(int(w.flushed), lastHash); err != nil {
				log.Printf("ERROR: Failed to write external checkpoint: %v", err)
			}
		}
	}

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

// writeFallback writes failed entries to a local JSONL file for later recovery.
func (w *Writer) writeFallback(batch []auditEntry) {
	f, err := os.OpenFile("audit_fallback.jsonl", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Printf("CRITICAL: cannot write audit fallback: %v", err)
		return
	}
	defer f.Close()

	for _, entry := range batch {
		if entry.decision != nil {
			data, err := json.Marshal(entry.decision)
			if err != nil {
				log.Printf("ERROR: failed to marshal decision for fallback: %v", err)
				continue
			}
			if _, err := f.Write(append(data, '\n')); err != nil {
				log.Printf("ERROR: failed to write fallback entry: %v", err)
			}
		}
	}

	log.Printf("WARNING: %d audit entries written to fallback file", len(batch))
}

// writeExternalCheckpoint writes checkpoint data to an external file outside the DB.
// This allows integrity detection even if the DB file is tampered with.
func (w *Writer) writeExternalCheckpoint(entryCount int, lastHash string) error {
	checkpointFile := w.dbPath + ".checkpoint"
	data := fmt.Sprintf("%d:%s:%s\n", entryCount, time.Now().UTC().Format(time.RFC3339), lastHash)
	return os.WriteFile(checkpointFile, []byte(data), 0600)
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
