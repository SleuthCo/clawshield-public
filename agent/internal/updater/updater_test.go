package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// TestVerifyHash_Match tests hash verification with matching hash.
func TestVerifyHash_Match(t *testing.T) {
	// Create a temporary file
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.bin")

	content := []byte("test content")
	if err := os.WriteFile(filePath, content, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Compute expected hash
	hash := sha256.Sum256(content)
	expectedHash := hex.EncodeToString(hash[:])

	updater := NewUpdater(tmpDir + "/current.bin")
	if err := updater.VerifyHash(filePath, expectedHash); err != nil {
		t.Errorf("VerifyHash failed: %v", err)
	}
}

// TestVerifyHash_Mismatch tests hash verification with mismatched hash.
func TestVerifyHash_Mismatch(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.bin")

	content := []byte("test content")
	if err := os.WriteFile(filePath, content, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	updater := NewUpdater(tmpDir + "/current.bin")
	if err := updater.VerifyHash(filePath, "wrong_hash"); err == nil {
		t.Error("Expected VerifyHash to fail, but it succeeded")
	}
}

// TestApply_Success tests successful application of an update.
func TestApply_Success(t *testing.T) {
	tmpDir := t.TempDir()
	currentPath := filepath.Join(tmpDir, "current.bin")
	downloadPath := filepath.Join(tmpDir, "download.bin")
	backupPath := currentPath + ".backup"

	// Create fake current binary
	currentContent := []byte("version 1.0")
	if err := os.WriteFile(currentPath, currentContent, 0755); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Create fake downloaded binary
	newContent := []byte("version 1.1")
	if err := os.WriteFile(downloadPath, newContent, 0755); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Compute hash of new content
	hash := sha256.Sum256(newContent)
	expectedHash := hex.EncodeToString(hash[:])

	updater := NewUpdater(currentPath)
	if err := updater.Apply(downloadPath, expectedHash); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	// Verify current binary was replaced
	current, err := os.ReadFile(currentPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(current) != "version 1.1" {
		t.Errorf("Expected 'version 1.1', got %q", string(current))
	}

	// Verify backup was created
	backup, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("ReadFile backup failed: %v", err)
	}
	if string(backup) != "version 1.0" {
		t.Errorf("Expected backup 'version 1.0', got %q", string(backup))
	}
}

// TestApply_BadHash tests apply with wrong hash verification.
func TestApply_BadHash(t *testing.T) {
	tmpDir := t.TempDir()
	currentPath := filepath.Join(tmpDir, "current.bin")
	downloadPath := filepath.Join(tmpDir, "download.bin")
	backupPath := currentPath + ".backup"

	// Create fake current binary
	currentContent := []byte("version 1.0")
	if err := os.WriteFile(currentPath, currentContent, 0755); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Create fake downloaded binary
	newContent := []byte("version 1.1")
	if err := os.WriteFile(downloadPath, newContent, 0755); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	updater := NewUpdater(currentPath)
	if err := updater.Apply(downloadPath, "wrong_hash"); err == nil {
		t.Error("Expected Apply to fail with wrong hash, but it succeeded")
	}

	// Verify current binary was NOT replaced
	current, err := os.ReadFile(currentPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(current) != "version 1.0" {
		t.Errorf("Expected 'version 1.0', got %q", string(current))
	}

	// Verify backup was NOT created
	if _, err := os.ReadFile(backupPath); err == nil {
		t.Error("Expected backup to not exist, but it does")
	}
}

// TestRollback tests rollback after a successful apply.
func TestRollback(t *testing.T) {
	tmpDir := t.TempDir()
	currentPath := filepath.Join(tmpDir, "current.bin")
	downloadPath := filepath.Join(tmpDir, "download.bin")

	// Create fake current binary
	currentContent := []byte("version 1.0")
	if err := os.WriteFile(currentPath, currentContent, 0755); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Create fake downloaded binary
	newContent := []byte("version 1.1")
	if err := os.WriteFile(downloadPath, newContent, 0755); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Compute hash of new content
	hash := sha256.Sum256(newContent)
	expectedHash := hex.EncodeToString(hash[:])

	updater := NewUpdater(currentPath)

	// Apply the update
	if err := updater.Apply(downloadPath, expectedHash); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	// Verify update was applied
	current, _ := os.ReadFile(currentPath)
	if string(current) != "version 1.1" {
		t.Errorf("Expected 'version 1.1', got %q", string(current))
	}

	// Rollback
	if err := updater.Rollback(); err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}

	// Verify original binary was restored
	current, err := os.ReadFile(currentPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(current) != "version 1.0" {
		t.Errorf("Expected 'version 1.0', got %q", string(current))
	}

	// Verify backup was deleted
	backupPath := currentPath + ".backup"
	if _, err := os.ReadFile(backupPath); err == nil {
		t.Error("Expected backup to be deleted, but it exists")
	}
}
