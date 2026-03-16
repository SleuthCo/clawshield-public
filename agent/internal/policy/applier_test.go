package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	sharedpolicy "github.com/SleuthCo/clawshield/shared/policy"
)

func TestApply_Success(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policy.yaml")

	applier := NewApplier(policyFile, nil)

	policyYAML := "rules:\n  - allow: all"
	if err := applier.Apply(policyYAML, ""); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	// Verify file was written
	data, err := os.ReadFile(policyFile)
	if err != nil {
		t.Fatalf("read policy file failed: %v", err)
	}

	if string(data) != policyYAML {
		t.Errorf("expected policy '%s', got '%s'", policyYAML, string(data))
	}
}

func TestApply_WithSignatureVerification(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policy.yaml")

	// Generate key pair
	privateKey, publicKey, err := sharedpolicy.GenerateSigningKeyPair(2048)
	if err != nil {
		t.Fatalf("generate key pair failed: %v", err)
	}

	// Sign policy
	policyYAML := "rules:\n  - allow: all"
	signature, err := sharedpolicy.SignPolicy(policyYAML, privateKey)
	if err != nil {
		t.Fatalf("sign policy failed: %v", err)
	}

	applier := NewApplier(policyFile, publicKey)

	if err := applier.Apply(policyYAML, signature); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	// Verify file was written
	data, err := os.ReadFile(policyFile)
	if err != nil {
		t.Fatalf("read policy file failed: %v", err)
	}

	if string(data) != policyYAML {
		t.Errorf("expected policy '%s', got '%s'", policyYAML, string(data))
	}
}

func TestApply_BadSignature(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policy.yaml")

	// Generate key pair
	_, publicKey, err := sharedpolicy.GenerateSigningKeyPair(2048)
	if err != nil {
		t.Fatalf("generate key pair failed: %v", err)
	}

	applier := NewApplier(policyFile, publicKey)

	policyYAML := "rules:\n  - allow: all"
	badSignature := "invalid-signature-data"

	err = applier.Apply(policyYAML, badSignature)
	if err == nil {
		t.Fatalf("expected error for bad signature, got nil")
	}

	// Verify file was not written
	if _, err := os.ReadFile(policyFile); err == nil {
		t.Error("expected file not to exist after failed signature verification")
	}
}

func TestApply_EmptySignatureWithKey(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policy.yaml")

	// Generate key pair
	_, publicKey, err := sharedpolicy.GenerateSigningKeyPair(2048)
	if err != nil {
		t.Fatalf("generate key pair failed: %v", err)
	}

	applier := NewApplier(policyFile, publicKey)

	policyYAML := "rules:\n  - allow: all"
	emptySignature := ""

	err = applier.Apply(policyYAML, emptySignature)
	if err == nil {
		t.Fatalf("expected error for empty signature with key set, got nil")
	}

	// Verify the error message is correct
	expectedMsg := "policy signature required but not provided"
	if err.Error() != expectedMsg {
		t.Errorf("expected error message '%s', got '%s'", expectedMsg, err.Error())
	}

	// Verify file was not written
	if _, err := os.ReadFile(policyFile); err == nil {
		t.Error("expected file not to exist after missing signature")
	}
}

func TestApply_NoSignatureCheck(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policy.yaml")

	// No public key set
	applier := NewApplier(policyFile, nil)

	policyYAML := "rules:\n  - allow: all"
	if err := applier.Apply(policyYAML, ""); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	// Verify file was written
	data, err := os.ReadFile(policyFile)
	if err != nil {
		t.Fatalf("read policy file failed: %v", err)
	}

	if string(data) != policyYAML {
		t.Errorf("expected policy '%s', got '%s'", policyYAML, string(data))
	}
}

func TestCurrentHash(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policy.yaml")

	// Write a policy file
	policyYAML := "rules:\n  - allow: all"
	if err := os.WriteFile(policyFile, []byte(policyYAML), 0644); err != nil {
		t.Fatalf("write policy file failed: %v", err)
	}

	applier := NewApplier(policyFile, nil)
	hash, err := applier.CurrentHash()
	if err != nil {
		t.Fatalf("current hash failed: %v", err)
	}

	expectedHash := sharedpolicy.ComputePolicyHash(policyYAML)
	if hash != expectedHash {
		t.Errorf("expected hash '%s', got '%s'", expectedHash, hash)
	}
}

func TestCurrentHash_FileNotExist(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "nonexistent.yaml")

	applier := NewApplier(policyFile, nil)
	hash, err := applier.CurrentHash()
	if err != nil {
		t.Fatalf("current hash failed: %v", err)
	}

	if hash != "" {
		t.Errorf("expected empty string for missing file, got '%s'", hash)
	}
}

func TestApply_CreateDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "subdir", "policy.yaml")

	applier := NewApplier(policyFile, nil)

	policyYAML := "rules:\n  - allow: all"
	if err := applier.Apply(policyYAML, ""); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	// Verify file was written
	data, err := os.ReadFile(policyFile)
	if err != nil {
		t.Fatalf("read policy file failed: %v", err)
	}

	if string(data) != policyYAML {
		t.Errorf("expected policy '%s', got '%s'", policyYAML, string(data))
	}
}

func TestApply_Atomic(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policy.yaml")

	// Write an initial policy
	initialPolicy := "initial: policy"
	if err := os.WriteFile(policyFile, []byte(initialPolicy), 0644); err != nil {
		t.Fatalf("write initial policy failed: %v", err)
	}

	// Generate key pair for second policy
	privateKey, publicKey, err := sharedpolicy.GenerateSigningKeyPair(2048)
	if err != nil {
		t.Fatalf("generate key pair failed: %v", err)
	}

	newPolicyYAML := "new: policy"
	signature, err := sharedpolicy.SignPolicy(newPolicyYAML, privateKey)
	if err != nil {
		t.Fatalf("sign policy failed: %v", err)
	}

	applier := NewApplier(policyFile, publicKey)

	if err := applier.Apply(newPolicyYAML, signature); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	// Verify file contains new policy
	data, err := os.ReadFile(policyFile)
	if err != nil {
		t.Fatalf("read policy file failed: %v", err)
	}

	if string(data) != newPolicyYAML {
		t.Errorf("expected policy '%s', got '%s'", newPolicyYAML, string(data))
	}
}

// TestApply_EmptyPolicy tests Apply with empty policy YAML.
func TestApply_EmptyPolicy(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policy.yaml")

	applier := NewApplier(policyFile, nil)

	emptyPolicy := ""
	if err := applier.Apply(emptyPolicy, ""); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	// Verify file was written (even though it's empty)
	data, err := os.ReadFile(policyFile)
	if err != nil {
		t.Fatalf("read policy file failed: %v", err)
	}

	if string(data) != emptyPolicy {
		t.Errorf("expected empty policy, got '%s'", string(data))
	}
}

// TestApply_VeryLargePolicy tests Apply with very large policy YAML.
func TestApply_VeryLargePolicy(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policy.yaml")

	applier := NewApplier(policyFile, nil)

	// Create a very large policy
	largePolicy := "rules:\n"
	for i := 0; i < 10000; i++ {
		largePolicy += "  - allow: resource" + string(rune(i)) + "\n"
	}

	if err := applier.Apply(largePolicy, ""); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	// Verify file was written correctly
	data, err := os.ReadFile(policyFile)
	if err != nil {
		t.Fatalf("read policy file failed: %v", err)
	}

	if string(data) != largePolicy {
		t.Errorf("large policy not written correctly")
	}
}

// TestCurrentHash_UnreadableFile tests CurrentHash with unreadable file (permissions issue).
func TestCurrentHash_UnreadableFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping permission test on Windows (no Unix file permissions)")
	}
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policy.yaml")

	// Write a policy file
	policyYAML := "rules:\n  - allow: all"
	if err := os.WriteFile(policyFile, []byte(policyYAML), 0644); err != nil {
		t.Fatalf("write policy file failed: %v", err)
	}

	// Remove read permissions
	if err := os.Chmod(policyFile, 0000); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}
	defer os.Chmod(policyFile, 0644) // Restore for cleanup

	applier := NewApplier(policyFile, nil)
	_, err := applier.CurrentHash()
	if err == nil {
		t.Fatal("expected CurrentHash to fail with unreadable file, but it succeeded")
	}
}

// TestCurrentHash_EmptyFile tests CurrentHash with an empty policy file.
func TestCurrentHash_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policy.yaml")

	// Write an empty policy file
	if err := os.WriteFile(policyFile, []byte(""), 0644); err != nil {
		t.Fatalf("write policy file failed: %v", err)
	}

	applier := NewApplier(policyFile, nil)
	hash, err := applier.CurrentHash()
	if err != nil {
		t.Fatalf("current hash failed: %v", err)
	}

	// Compute expected hash for empty string
	expectedHash := sharedpolicy.ComputePolicyHash("")
	if hash != expectedHash {
		t.Errorf("expected hash '%s', got '%s'", expectedHash, hash)
	}
}
