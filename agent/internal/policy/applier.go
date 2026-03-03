package policy

import (
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"

	sharedpolicy "github.com/SleuthCo/clawshield/shared/policy"
)

// Applier handles downloading and applying policy updates from the Hub.
type Applier struct {
	PolicyFilePath string         // local policy.yaml path
	PublicKey      *rsa.PublicKey // Hub's signing public key (optional)
}

func NewApplier(policyFilePath string, publicKey *rsa.PublicKey) *Applier {
	return &Applier{
		PolicyFilePath: policyFilePath,
		PublicKey:      publicKey,
	}
}

// Apply verifies the signature if PublicKey is set and writes the policy to disk atomically.
// If PublicKey is set but signature is empty, returns an error.
// If verification fails, returns an error.
func (a *Applier) Apply(policyYAML, signature string) error {
	// If public key is set, signature is required
	if a.PublicKey != nil {
		if signature == "" {
			return fmt.Errorf("policy signature required but not provided")
		}
		if err := sharedpolicy.VerifyPolicy(policyYAML, signature, a.PublicKey); err != nil {
			return fmt.Errorf("signature verification failed: %w", err)
		}
	}

	// Write to a temporary file first
	dir := filepath.Dir(a.PolicyFilePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	tmpFile, err := os.CreateTemp(dir, ".policy-tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer tmpFile.Close()

	tmpPath := tmpFile.Name()

	// Write the policy YAML to the temp file
	if _, err := tmpFile.WriteString(policyYAML); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("write to temp file: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("sync temp file: %w", err)
	}

	// Atomically rename temp file to final location
	if err := os.Rename(tmpPath, a.PolicyFilePath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename temp file: %w", err)
	}

	return nil
}

// CurrentHash reads the current policy file and returns its SHA-256 hash.
// Returns empty string if the file doesn't exist.
func (a *Applier) CurrentHash() (string, error) {
	data, err := os.ReadFile(a.PolicyFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read policy file: %w", err)
	}

	hash := sharedpolicy.ComputePolicyHash(string(data))
	return hash, nil
}
