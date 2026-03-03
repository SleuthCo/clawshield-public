package config

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SleuthCo/clawshield/proxy/internal/engine"
)

func writePolicy(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

func TestReloader_DetectsFileChange(t *testing.T) {
	dir := t.TempDir()
	path := writePolicy(t, dir, "default_action: allow\n")

	policy, version, err := LoadWithVersion(path)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	eval := engine.NewEvaluator(policy)
	eval.SetPolicyVersion(version)

	var reloaded atomic.Bool
	reloader := NewPolicyReloader(path, eval, version,
		WithInterval(100*time.Millisecond),
		WithOnReload(func(old, new string) {
			reloaded.Store(true)
		}),
	)
	reloader.Start()
	defer reloader.Stop()

	// Verify initial evaluator
	initialEval := reloader.GetEvaluator()
	if initialEval == nil {
		t.Fatal("expected non-nil initial evaluator")
	}

	// Modify the policy file
	time.Sleep(50 * time.Millisecond) // ensure mtime differs
	writePolicy(t, dir, "default_action: deny\n")

	// Wait for reload
	time.Sleep(300 * time.Millisecond)

	if !reloaded.Load() {
		t.Fatal("expected reloader to detect file change")
	}

	newVersion := reloader.Version()
	if newVersion == version {
		t.Fatalf("expected version to change, got %s", newVersion)
	}
}

func TestReloader_InvalidPolicyRejected(t *testing.T) {
	dir := t.TempDir()
	path := writePolicy(t, dir, "default_action: allow\n")

	policy, version, err := LoadWithVersion(path)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	eval := engine.NewEvaluator(policy)

	var gotError atomic.Bool
	reloader := NewPolicyReloader(path, eval, version,
		WithInterval(100*time.Millisecond),
		WithOnError(func(err error) {
			gotError.Store(true)
		}),
	)
	reloader.Start()
	defer reloader.Stop()

	// Write invalid YAML
	time.Sleep(50 * time.Millisecond)
	writePolicy(t, dir, ": invalid: yaml: {{{{\n")

	time.Sleep(300 * time.Millisecond)

	if !gotError.Load() {
		t.Fatal("expected error callback for invalid policy")
	}

	// Original evaluator should still be active
	if reloader.Version() != version {
		t.Fatal("version should not change on invalid reload")
	}
}

func TestReloader_ForceReload(t *testing.T) {
	dir := t.TempDir()
	path := writePolicy(t, dir, "default_action: allow\n")

	policy, version, err := LoadWithVersion(path)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	eval := engine.NewEvaluator(policy)

	reloader := NewPolicyReloader(path, eval, version)

	// Modify file and force reload (without starting the watcher)
	writePolicy(t, dir, "default_action: deny\n")

	newVersion, err := reloader.ForceReload()
	if err != nil {
		t.Fatalf("force reload failed: %v", err)
	}

	if newVersion == version {
		t.Fatal("expected new version after force reload")
	}

	reloads, errors := reloader.Stats()
	if reloads != 1 {
		t.Fatalf("expected 1 reload, got %d", reloads)
	}
	if errors != 0 {
		t.Fatalf("expected 0 errors, got %d", errors)
	}
}

func TestReloader_ShadowMode(t *testing.T) {
	dir := t.TempDir()
	path := writePolicy(t, dir, "default_action: allow\n")

	policy, version, err := LoadWithVersion(path)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	eval := engine.NewEvaluator(policy)

	reloader := NewPolicyReloader(path, eval, version,
		WithInterval(100*time.Millisecond),
		WithShadowMode(true),
	)
	reloader.Start()
	defer reloader.Stop()

	// Modify policy
	time.Sleep(50 * time.Millisecond)
	writePolicy(t, dir, "default_action: deny\n")
	time.Sleep(300 * time.Millisecond)

	// Active evaluator should still be the original
	if reloader.Version() != version {
		t.Fatal("active version should not change in shadow mode")
	}

	// Shadow evaluator should be loaded
	shadow := reloader.GetShadowEvaluator()
	if shadow == nil {
		t.Fatal("expected shadow evaluator to be loaded")
	}
}

func TestReloader_VersionHash(t *testing.T) {
	dir := t.TempDir()

	// Same content produces same hash
	path1 := filepath.Join(dir, "p1.yaml")
	path2 := filepath.Join(dir, "p2.yaml")
	content := "default_action: allow\n"
	os.WriteFile(path1, []byte(content), 0644)
	os.WriteFile(path2, []byte(content), 0644)

	v1, _ := ComputePolicyVersion(path1)
	v2, _ := ComputePolicyVersion(path2)
	if v1 != v2 {
		t.Fatalf("same content should produce same hash: %s != %s", v1, v2)
	}

	// Different content produces different hash
	os.WriteFile(path2, []byte("default_action: deny\n"), 0644)
	v3, _ := ComputePolicyVersion(path2)
	if v1 == v3 {
		t.Fatalf("different content should produce different hash: %s == %s", v1, v3)
	}

	// Version is 8 hex chars
	if len(v1) != 8 {
		t.Fatalf("expected 8 char version, got %d: %s", len(v1), v1)
	}
}

func TestReloader_Stop(t *testing.T) {
	dir := t.TempDir()
	path := writePolicy(t, dir, "default_action: allow\n")

	policy, version, _ := LoadWithVersion(path)
	eval := engine.NewEvaluator(policy)

	reloader := NewPolicyReloader(path, eval, version,
		WithInterval(50*time.Millisecond),
	)
	reloader.Start()
	reloader.Stop()

	// Should not panic on double stop
	reloader.Stop()
}
