package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
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

// TestDownload_Success tests successful file download with 200 status code.
func TestDownload_Success(t *testing.T) {
	tmpDir := t.TempDir()
	destPath := filepath.Join(tmpDir, "downloaded.bin")

	// Create a test server that returns a file
	fileContent := []byte("downloaded binary content")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(fileContent)
	}))
	defer server.Close()

	updater := NewUpdater(tmpDir + "/current.bin")
	if err := updater.Download(server.URL, destPath); err != nil {
		t.Fatalf("Download failed: %v", err)
	}

	// Verify file was written correctly
	downloaded, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(downloaded) != string(fileContent) {
		t.Errorf("Expected '%s', got '%s'", string(fileContent), string(downloaded))
	}
}

// TestDownload_NonOKStatus tests download failure with non-200 status code.
func TestDownload_NonOKStatus(t *testing.T) {
	tmpDir := t.TempDir()
	destPath := filepath.Join(tmpDir, "downloaded.bin")

	// Create a test server that returns 404
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	updater := NewUpdater(tmpDir + "/current.bin")
	err := updater.Download(server.URL, destPath)
	if err == nil {
		t.Fatal("Expected Download to fail with 404 status, but it succeeded")
	}

	// Verify file was not created
	if _, err := os.ReadFile(destPath); err == nil {
		t.Error("Expected file not to exist after failed download")
	}
}

// TestDownload_WriteFailure tests download failure when writing to destination.
func TestDownload_WriteFailure(t *testing.T) {
	// Create a test server that returns a file
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("content"))
	}))
	defer server.Close()

	updater := NewUpdater("/nonexistent/path/current.bin")
	err := updater.Download(server.URL, "/nonexistent/dir/file.bin")
	if err == nil {
		t.Fatal("Expected Download to fail when writing to bad path, but it succeeded")
	}
}

// TestCurrentBinaryHash tests getting the hash of the current binary.
func TestCurrentBinaryHash(t *testing.T) {
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "current.bin")

	// Create a fake binary file
	binaryContent := []byte("binary content v1")
	if err := os.WriteFile(binaryPath, binaryContent, 0755); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Compute expected hash
	hash := sha256.Sum256(binaryContent)
	expectedHash := hex.EncodeToString(hash[:])

	updater := NewUpdater(binaryPath)
	actualHash, err := updater.CurrentBinaryHash()
	if err != nil {
		t.Fatalf("CurrentBinaryHash failed: %v", err)
	}

	if actualHash != expectedHash {
		t.Errorf("Expected hash '%s', got '%s'", expectedHash, actualHash)
	}
}

// TestHashFile_NonExistent tests hashFile error path with non-existent file.
func TestHashFile_NonExistent(t *testing.T) {
	tmpDir := t.TempDir()
	updater := NewUpdater(tmpDir + "/current.bin")

	_, err := updater.hashFile(filepath.Join(tmpDir, "nonexistent.bin"))
	if err == nil {
		t.Fatal("Expected hashFile to fail with non-existent file, but it succeeded")
	}
}

// TestApply_BackupCreationFails tests Apply when backup creation fails.
func TestApply_BackupCreationFails(t *testing.T) {
	tmpDir := t.TempDir()
	currentPath := filepath.Join(tmpDir, "current.bin")
	downloadPath := filepath.Join(tmpDir, "download.bin")

	// Create only the download file, NOT the current file
	// This makes os.Rename fail when trying to back up the non-existent current file
	newContent := []byte("version 1.1")
	if err := os.WriteFile(downloadPath, newContent, 0755); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Compute hash of new content
	hash := sha256.Sum256(newContent)
	expectedHash := hex.EncodeToString(hash[:])

	updater := NewUpdater(currentPath)
	err := updater.Apply(downloadPath, expectedHash)
	if err == nil {
		t.Fatal("Expected Apply to fail when current binary doesn't exist, but it succeeded")
	}

	// Verify download file still exists (should not have been renamed)
	if _, err := os.ReadFile(downloadPath); err != nil {
		t.Error("Expected download file to still exist after failed Apply")
	}
}

// TestRollback_BackupNotExist tests Rollback error path when backup file doesn't exist.
func TestRollback_BackupNotExist(t *testing.T) {
	tmpDir := t.TempDir()
	currentPath := filepath.Join(tmpDir, "current.bin")

	// Create only the current file, NOT the backup file
	currentContent := []byte("current binary")
	if err := os.WriteFile(currentPath, currentContent, 0755); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	updater := NewUpdater(currentPath)
	err := updater.Rollback()
	if err == nil {
		t.Fatal("Expected Rollback to fail when backup doesn't exist, but it succeeded")
	}

	// Verify current file is unchanged
	current, err := os.ReadFile(currentPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(current) != string(currentContent) {
		t.Errorf("Expected current file to be unchanged, but it was modified")
	}
}
