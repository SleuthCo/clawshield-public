package config

import (
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SleuthCo/clawshield/proxy/internal/engine"
)

// ReloaderOption is a functional option for configuring a PolicyReloader.
type ReloaderOption func(*PolicyReloader)

// WithInterval sets the poll interval for checking policy file changes.
// Default is 5 seconds.
func WithInterval(d time.Duration) ReloaderOption {
	return func(r *PolicyReloader) {
		if d > 0 {
			r.interval = d
		}
	}
}

// WithShadowMode enables shadow/canary mode where new policies are loaded
// and evaluated in parallel (log-only) but not enforced.
func WithShadowMode(enabled bool) ReloaderOption {
	return func(r *PolicyReloader) {
		r.shadowMode = enabled
	}
}

// WithOnReload sets a callback invoked after a successful policy reload.
// The callback receives the old and new version hashes.
func WithOnReload(fn func(oldVersion, newVersion string)) ReloaderOption {
	return func(r *PolicyReloader) {
		r.onReload = fn
	}
}

// WithOnError sets a callback invoked when a policy reload attempt fails.
// The old policy remains active.
func WithOnError(fn func(err error)) ReloaderOption {
	return func(r *PolicyReloader) {
		r.onError = fn
	}
}

// PolicyReloader watches a policy file for changes and performs hot-reload
// of the evaluator without proxy restart. It uses an atomic pointer swap
// to ensure in-flight requests continue using the old evaluator while new
// requests use the new one.
//
// SECURITY: Includes debouncing to prevent DoS via rapid policy file changes.
// Consecutive reloads must be separated by at least 1 second.
//
// Usage:
//
//	reloader := NewPolicyReloader(path, eval, version)
//	reloader.Start()
//	defer reloader.Stop()
//
//	// In request handlers:
//	eval := reloader.GetEvaluator()
//	decision, reason := eval.EvaluateWithContext(ctx, msg)
type PolicyReloader struct {
	policyPath     string
	interval       time.Duration
	currentVersion atomic.Value // stores string
	evalPtr        atomic.Value // stores *engine.Evaluator

	// Shadow mode: load new policy but don't enforce it
	shadowMode     bool
	shadowEvalPtr  atomic.Value // stores *engine.Evaluator (shadow only)

	// Callbacks
	onReload func(oldVersion, newVersion string)
	onError  func(err error)

	// File modification tracking
	lastModTime time.Time
	lastSize    int64

	// Debounce: prevent DoS from rapid policy file changes (e.g., attacker rewriting file constantly)
	lastReloadTime time.Time
	minReloadInterval time.Duration // default: 1 second

	// Lifecycle
	stopCh  chan struct{}
	stopWg  sync.WaitGroup
	started atomic.Bool

	// Reload stats
	reloadCount  atomic.Int64
	errorCount   atomic.Int64
}

// NewPolicyReloader creates a new PolicyReloader.
func NewPolicyReloader(path string, initialEval *engine.Evaluator, initialVersion string, opts ...ReloaderOption) *PolicyReloader {
	r := &PolicyReloader{
		policyPath:        path,
		interval:          5 * time.Second,
		minReloadInterval: 1 * time.Second, // Minimum 1 second between reloads to prevent DoS
		stopCh:            make(chan struct{}),
	}

	r.evalPtr.Store(initialEval)
	r.currentVersion.Store(initialVersion)

	// Get initial file stat
	if info, err := os.Stat(path); err == nil {
		r.lastModTime = info.ModTime()
		r.lastSize = info.Size()
	}

	for _, opt := range opts {
		opt(r)
	}

	return r
}

// Start begins the background file-watching goroutine.
func (r *PolicyReloader) Start() {
	if r.started.Swap(true) {
		return // already started
	}

	r.stopWg.Add(1)
	go r.watchLoop()

	mode := "enforce"
	if r.shadowMode {
		mode = "shadow"
	}
	log.Printf("Policy reloader started: path=%s interval=%s mode=%s version=%s",
		r.policyPath, r.interval, mode, r.currentVersion.Load())
}

// Stop stops the background file-watching goroutine.
// Safe to call multiple times.
func (r *PolicyReloader) Stop() {
	if !r.started.Swap(false) {
		return
	}
	close(r.stopCh)
	r.stopWg.Wait()
	log.Printf("Policy reloader stopped: reloads=%d errors=%d",
		r.reloadCount.Load(), r.errorCount.Load())
}

// GetEvaluator returns the currently active evaluator via atomic load.
// This is safe to call from any goroutine and returns immediately.
func (r *PolicyReloader) GetEvaluator() *engine.Evaluator {
	return r.evalPtr.Load().(*engine.Evaluator)
}

// GetShadowEvaluator returns the shadow evaluator (if shadow mode is enabled).
// Returns nil if shadow mode is disabled or no shadow policy has been loaded.
func (r *PolicyReloader) GetShadowEvaluator() *engine.Evaluator {
	if !r.shadowMode {
		return nil
	}
	v := r.shadowEvalPtr.Load()
	if v == nil {
		return nil
	}
	return v.(*engine.Evaluator)
}

// Version returns the current policy version hash.
func (r *PolicyReloader) Version() string {
	v := r.currentVersion.Load()
	if v == nil {
		return ""
	}
	return v.(string)
}

// ForceReload manually triggers a policy reload regardless of file changes.
// Returns the new version hash and any error.
func (r *PolicyReloader) ForceReload() (string, error) {
	return r.tryReload()
}

// Stats returns reload statistics.
func (r *PolicyReloader) Stats() (reloads, errors int64) {
	return r.reloadCount.Load(), r.errorCount.Load()
}

// watchLoop polls the policy file for changes at the configured interval.
func (r *PolicyReloader) watchLoop() {
	defer r.stopWg.Done()

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			if r.fileChanged() {
				if _, err := r.tryReload(); err != nil {
					log.Printf("ERROR: policy reload failed: %v (keeping current policy version %s)",
						err, r.currentVersion.Load())
				}
			}
		}
	}
}

// fileChanged checks if the policy file has been modified since the last check.
func (r *PolicyReloader) fileChanged() bool {
	info, err := os.Stat(r.policyPath)
	if err != nil {
		// File disappeared — don't reload, keep current policy
		return false
	}

	if info.ModTime() != r.lastModTime || info.Size() != r.lastSize {
		return true
	}

	return false
}

// tryReload attempts to load the new policy, validate it, create a new
// evaluator, and atomically swap it in. On failure, the old evaluator
// remains active.
//
// SECURITY: Enforces minReloadInterval debouncing to prevent DoS from
// attackers who rapidly rewrite the policy file.
func (r *PolicyReloader) tryReload() (string, error) {
	// SECURITY: Debounce rapid reloads to prevent DoS
	// If the last reload was too recent, skip this one
	if time.Since(r.lastReloadTime) < r.minReloadInterval {
		return r.Version(), fmt.Errorf("reload rate-limited: too soon (min interval: %v)", r.minReloadInterval)
	}

	// Load and validate new policy
	newPolicy, newVersion, err := LoadWithVersion(r.policyPath)
	if err != nil {
		r.errorCount.Add(1)
		if r.onError != nil {
			r.onError(err)
		}
		return "", fmt.Errorf("load policy: %w", err)
	}

	// Check if content actually changed (mtime can change without content change)
	oldVersion := r.Version()
	if newVersion == oldVersion {
		// Update file stat but don't reload — content unchanged
		if info, err := os.Stat(r.policyPath); err == nil {
			r.lastModTime = info.ModTime()
			r.lastSize = info.Size()
		}
		return oldVersion, nil
	}

	// Compute diff for logging
	oldEval := r.GetEvaluator()
	diffSummary := ComputeEffectiveDiff(oldEval.GetPolicy(), newPolicy)

	// Create new evaluator
	newEval := engine.NewEvaluator(newPolicy)
	newEval.SetPolicyVersion(newVersion)

	if r.shadowMode {
		// Shadow mode: load but don't enforce
		r.shadowEvalPtr.Store(newEval)
		log.Printf("SHADOW POLICY loaded: version %s → %s (diff: %s)",
			oldVersion, newVersion, diffSummary)
	} else {
		// Enforce mode: atomic swap
		r.evalPtr.Store(newEval)
		r.currentVersion.Store(newVersion)
		log.Printf("POLICY RELOADED: version %s → %s (diff: %s)",
			oldVersion, newVersion, diffSummary)
	}

	// Update file stat
	if info, err := os.Stat(r.policyPath); err == nil {
		r.lastModTime = info.ModTime()
		r.lastSize = info.Size()
	}

	r.lastReloadTime = time.Now() // Record reload time for debouncing
	r.reloadCount.Add(1)

	if r.onReload != nil {
		r.onReload(oldVersion, newVersion)
	}

	return newVersion, nil
}
