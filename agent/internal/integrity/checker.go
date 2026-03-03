package integrity

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// CheckResult contains the results of an integrity check.
type CheckResult struct {
	BinaryOK      bool     `json:"binary_ok"`
	BinaryHash    string   `json:"binary_hash"`
	PolicyOK      bool     `json:"policy_ok"`
	PolicyHash    string   `json:"policy_hash"`
	TamperedItems []string `json:"tampered_items,omitempty"`
}

// Checker performs integrity verification of the agent binary and policy.
type Checker struct {
	BinaryPath         string
	PolicyPath         string
	ExpectedBinaryHash string // set by Hub during enrollment or update
	ExpectedPolicyHash string // set from signed policy
}

// NewChecker creates a new Checker for the given binary and policy paths.
func NewChecker(binaryPath, policyPath string) *Checker {
	return &Checker{
		BinaryPath: binaryPath,
		PolicyPath: policyPath,
	}
}

// SetExpectedHashes sets the expected hashes for binary and policy.
func (c *Checker) SetExpectedHashes(binaryHash, policyHash string) {
	c.ExpectedBinaryHash = binaryHash
	c.ExpectedPolicyHash = policyHash
}

// Check performs integrity verification and returns a CheckResult.
func (c *Checker) Check() *CheckResult {
	result := &CheckResult{
		TamperedItems: []string{},
	}

	// Check binary integrity
	binaryHash, err := hashFile(c.BinaryPath)
	if err != nil {
		result.BinaryOK = false
		result.TamperedItems = append(result.TamperedItems, "binary (error: "+err.Error()+")")
	} else {
		result.BinaryHash = binaryHash
		result.BinaryOK = subtle.ConstantTimeCompare([]byte(binaryHash), []byte(c.ExpectedBinaryHash)) == 1
		if !result.BinaryOK {
			result.TamperedItems = append(result.TamperedItems, "binary (hash mismatch)")
		}
	}

	// Check policy integrity
	policyHash, err := hashFile(c.PolicyPath)
	if err != nil {
		result.PolicyOK = false
		result.TamperedItems = append(result.TamperedItems, "policy (error: "+err.Error()+")")
	} else {
		result.PolicyHash = policyHash
		result.PolicyOK = subtle.ConstantTimeCompare([]byte(policyHash), []byte(c.ExpectedPolicyHash)) == 1
		if !result.PolicyOK {
			result.TamperedItems = append(result.TamperedItems, "policy (hash mismatch)")
		}
	}

	return result
}

// hashFile reads a file and returns its SHA-256 hash as a hex string.
func hashFile(path string) (string, error) {
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
