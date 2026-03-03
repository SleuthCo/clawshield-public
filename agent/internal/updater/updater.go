package updater

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Updater handles downloading and applying binary updates.
type Updater struct {
	CurrentBinaryPath string
	BackupPath        string
	Client            *http.Client
}

// NewUpdater creates a new Updater for the given binary path.
func NewUpdater(binaryPath string) *Updater {
	return &Updater{
		CurrentBinaryPath: binaryPath,
		BackupPath:        binaryPath + ".backup",
		Client:            &http.Client{Timeout: 5 * time.Minute},
	}
}

// VerifyHash computes the SHA-256 hash of a file and compares it to the expected hash
// using a timing-safe comparison to prevent timing attacks.
func (u *Updater) VerifyHash(filePath, expectedHash string) error {
	actualHash, err := u.hashFile(filePath)
	if err != nil {
		return fmt.Errorf("hash file: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(actualHash), []byte(expectedHash)) != 1 {
		return fmt.Errorf("hash mismatch: expected %s, got %s", expectedHash, actualHash)
	}
	return nil
}

// Download downloads a file from a URL and saves it to destPath.
func (u *Updater) Download(url, destPath string) error {
	resp, err := u.Client.Get(url)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: unexpected status code %d", resp.StatusCode)
	}

	out, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer out.Close()

	if _, err := io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	return nil
}

// Apply verifies the downloaded binary, backs up the current binary, and replaces it.
// If any step fails, it restores the backup and returns an error.
// Uses atomic operations (os.Rename) to prevent TOCTOU vulnerabilities.
func (u *Updater) Apply(downloadPath, expectedHash string) error {
	// Verify the hash of the downloaded file
	if err := u.VerifyHash(downloadPath, expectedHash); err != nil {
		return fmt.Errorf("verify hash: %w", err)
	}

	// Back up the current binary using atomic rename
	if err := os.Rename(u.CurrentBinaryPath, u.BackupPath); err != nil {
		return fmt.Errorf("backup current binary: %w", err)
	}

	// Replace the current binary with the downloaded one using atomic rename
	if err := os.Rename(downloadPath, u.CurrentBinaryPath); err != nil {
		// Restore backup if rename fails
		_ = os.Rename(u.BackupPath, u.CurrentBinaryPath)
		return fmt.Errorf("replace current binary: %w", err)
	}

	return nil
}

// Rollback restores the backup binary as the current binary.
func (u *Updater) Rollback() error {
	backupData, err := os.ReadFile(u.BackupPath)
	if err != nil {
		return fmt.Errorf("read backup: %w", err)
	}

	if err := os.WriteFile(u.CurrentBinaryPath, backupData, 0755); err != nil {
		return fmt.Errorf("write current binary: %w", err)
	}

	if err := os.Remove(u.BackupPath); err != nil {
		return fmt.Errorf("remove backup: %w", err)
	}

	return nil
}

// CurrentBinaryHash returns the SHA-256 hash of the current binary.
func (u *Updater) CurrentBinaryHash() (string, error) {
	return u.hashFile(u.CurrentBinaryPath)
}

// hashFile computes the SHA-256 hash of a file and returns it as a hex string.
func (u *Updater) hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("read file: %w", err)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}
