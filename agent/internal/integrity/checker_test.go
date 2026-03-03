package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// TestCheck_AllOK tests integrity check with all components matching.
func TestCheck_AllOK(t *testing.T) {
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "agent.bin")
	policyPath := filepath.Join(tmpDir, "policy.yaml")

	// Create binary with known content
	binaryContent := []byte("agent binary v1.0")
	if err := os.WriteFile(binaryPath, binaryContent, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	binaryHash := sha256.Sum256(binaryContent)
	expectedBinaryHash := hex.EncodeToString(binaryHash[:])

	// Create policy with known content
	policyContent := []byte("rules:\n  - name: test")
	if err := os.WriteFile(policyPath, policyContent, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	policyHash := sha256.Sum256(policyContent)
	expectedPolicyHash := hex.EncodeToString(policyHash[:])

	// Check with matching hashes
	checker := NewChecker(binaryPath, policyPath)
	checker.SetExpectedHashes(expectedBinaryHash, expectedPolicyHash)
	result := checker.Check()

	if !result.BinaryOK {
		t.Error("Expected binary to be OK")
	}
	if !result.PolicyOK {
		t.Error("Expected policy to be OK")
	}
	if len(result.TamperedItems) != 0 {
		t.Errorf("Expected no tampered items, got %v", result.TamperedItems)
	}
	if result.BinaryHash != expectedBinaryHash {
		t.Errorf("Expected binary hash %s, got %s", expectedBinaryHash, result.BinaryHash)
	}
	if result.PolicyHash != expectedPolicyHash {
		t.Errorf("Expected policy hash %s, got %s", expectedPolicyHash, result.PolicyHash)
	}
}

// TestCheck_TamperedBinary tests detection of binary tampering.
func TestCheck_TamperedBinary(t *testing.T) {
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "agent.bin")
	policyPath := filepath.Join(tmpDir, "policy.yaml")

	// Create binary with known content
	binaryContent := []byte("agent binary v1.0")
	if err := os.WriteFile(binaryPath, binaryContent, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	binaryHash := sha256.Sum256(binaryContent)
	expectedBinaryHash := hex.EncodeToString(binaryHash[:])

	// Create policy with known content
	policyContent := []byte("rules:\n  - name: test")
	if err := os.WriteFile(policyPath, policyContent, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	policyHash := sha256.Sum256(policyContent)
	expectedPolicyHash := hex.EncodeToString(policyHash[:])

	// Set checker with correct hashes
	checker := NewChecker(binaryPath, policyPath)
	checker.SetExpectedHashes(expectedBinaryHash, expectedPolicyHash)

	// Tamper with the binary
	if err := os.WriteFile(binaryPath, []byte("tampered content"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	result := checker.Check()

	if result.BinaryOK {
		t.Error("Expected binary to be tampered (not OK)")
	}
	if !result.PolicyOK {
		t.Error("Expected policy to still be OK")
	}
	if len(result.TamperedItems) == 0 {
		t.Error("Expected tampered items to be detected")
	}
}

// TestCheck_TamperedPolicy tests detection of policy tampering.
func TestCheck_TamperedPolicy(t *testing.T) {
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "agent.bin")
	policyPath := filepath.Join(tmpDir, "policy.yaml")

	// Create binary with known content
	binaryContent := []byte("agent binary v1.0")
	if err := os.WriteFile(binaryPath, binaryContent, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	binaryHash := sha256.Sum256(binaryContent)
	expectedBinaryHash := hex.EncodeToString(binaryHash[:])

	// Create policy with known content
	policyContent := []byte("rules:\n  - name: test")
	if err := os.WriteFile(policyPath, policyContent, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	policyHash := sha256.Sum256(policyContent)
	expectedPolicyHash := hex.EncodeToString(policyHash[:])

	// Set checker with correct hashes
	checker := NewChecker(binaryPath, policyPath)
	checker.SetExpectedHashes(expectedBinaryHash, expectedPolicyHash)

	// Tamper with the policy
	if err := os.WriteFile(policyPath, []byte("tampered policy content"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	result := checker.Check()

	if !result.BinaryOK {
		t.Error("Expected binary to still be OK")
	}
	if result.PolicyOK {
		t.Error("Expected policy to be tampered (not OK)")
	}
	if len(result.TamperedItems) == 0 {
		t.Error("Expected tampered items to be detected")
	}
}

// TestCheck_MissingFiles tests graceful handling of missing files.
func TestCheck_MissingFiles(t *testing.T) {
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "agent.bin")
	policyPath := filepath.Join(tmpDir, "policy.yaml")

	// Don't create the files, leaving them missing

	checker := NewChecker(binaryPath, policyPath)
	checker.SetExpectedHashes("somehash", "otherhash")
	result := checker.Check()

	// Both should fail gracefully
	if result.BinaryOK {
		t.Error("Expected binary check to fail for missing file")
	}
	if result.PolicyOK {
		t.Error("Expected policy check to fail for missing file")
	}
	if len(result.TamperedItems) == 0 {
		t.Error("Expected errors in tampered items")
	}
}
