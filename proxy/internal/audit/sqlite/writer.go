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

	"github.com/SleuthCo/clawshield/shared/types"
)

const (
	batchSize     = 100
	flushInterval = 5 * time.Second
)

// Writer is an async, batched SQLite writer for audit logs.
type Writer struct {
	db       *sql.DB
	dbPath   string
	mu       sync.Mutex
	queue    chan *types.Decision
	stop     chan struct{}
	wg       sync.WaitGroup
	batch    []*types.Decision
	closed   atomic.Bool
	flushed  int64
	dropped  atomic.Int64
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
		queue: make(chan *types.Decision, 10000),
		stop:  make(chan struct{}),
		batch: make([]*types.Decision, 0, batchSize),
	}

	w.wg.Add(1)
	go w.loop()

	return w, nil
}

// Write enqueues a decision for async logging.
func (w *Writer) Write(dec *types.Decision) error {
	if w.closed.Load() {
		return fmt.Errorf("writer is closed")
	}

	select {
	case w.queue <- dec:
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
		case dec := <-w.queue:
			w.batch = append(w.batch, dec)
		default:
			return w.flushBatch()
		}
	}
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
		case dec, ok := <-w.queue:
			if !ok {
				break
			}
			w.mu.Lock()
			w.batch = append(w.batch, dec)
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
				case dec := <-w.queue:
					w.batch = append(w.batch, dec)
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
func (w *Writer) flushBatch() error {
	if len(w.batch) == 0 {
		return nil
	}

	batch := make([]*types.Decision, len(w.batch))
	copy(batch, w.batch)
	w.batch = w.batch[:0]

	tx, err := w.db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	defer tx.Rollback() // nolint:errcheck

	stmt, err := tx.PrepareContext(context.Background(), `
	INSERT INTO decisions (timestamp, session_id, tool, arguments_hash, decision, reason, policy_version, scanner_type, correlation_id, classification, source, response_blocked)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close()

	for _, dec := range batch {
		// Store ArgumentsHash directly - caller is responsible for hashing
		respBlocked := 0
		if dec.ResponseBlocked {
			respBlocked = 1
		}
		_, err = stmt.ExecContext(context.Background(),
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
			respBlocked)
		if err != nil {
			return fmt.Errorf("insert decision: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	w.flushed += int64(len(batch))

	// Write integrity checkpoint every 10k decisions (only when dbPath is set)
	if w.dbPath != "" && w.flushed%10000 < int64(len(batch)) && w.flushed >= 10000 {
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

// WriteDecision writes a decision and optionally its tool call.
func (w *Writer) WriteDecision(decision types.Decision, toolCall *types.ToolCall) error {
	return w.Write(&decision)
}
