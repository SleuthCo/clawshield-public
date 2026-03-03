// Package crypto provides field-level AES-256-GCM encryption for ClawShield
// audit logs. It encrypts sensitive fields (tool call request/response JSON,
// decision details, arguments hashes) before they are written to SQLite,
// and decrypts them on read.
//
// SECURITY DESIGN:
//   - Algorithm: AES-256-GCM (authenticated encryption with associated data)
//   - Nonce: 12-byte random nonce per encryption operation (crypto/rand)
//   - Key: 32-byte (256-bit) key, provided directly or via hex-encoded env var
//   - Format: version_prefix(1) || nonce(12) || ciphertext(variable) || GCM_tag(16)
//   - The version prefix enables future algorithm rotation without re-encryption
//
// This package uses only Go standard library crypto primitives — no external
// dependencies — to minimise supply chain risk.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	// KeySize is the required key length in bytes (AES-256).
	KeySize = 32

	// NonceSize is the GCM nonce length in bytes.
	NonceSize = 12

	// versionV1 is the ciphertext format version byte.
	// Future algorithm changes increment this to enable transparent migration.
	versionV1 byte = 0x01

	// versionPrefixLen is the length of the version prefix.
	versionPrefixLen = 1

	// EnvKeyName is the environment variable for the hex-encoded encryption key.
	EnvKeyName = "CLAWSHIELD_AUDIT_ENCRYPTION_KEY"
)

var (
	// ErrInvalidKeySize is returned when the key is not exactly 32 bytes.
	ErrInvalidKeySize = errors.New("encryption key must be exactly 32 bytes (256 bits)")

	// ErrCiphertextTooShort is returned when ciphertext is shorter than
	// the minimum size (version + nonce + at least 1 byte + GCM tag).
	ErrCiphertextTooShort = errors.New("ciphertext too short to be valid")

	// ErrUnsupportedVersion is returned when the ciphertext version prefix
	// is not recognised, indicating either corruption or a newer format.
	ErrUnsupportedVersion = errors.New("unsupported ciphertext version")

	// ErrEmptyKey is returned when an empty key is provided.
	ErrEmptyKey = errors.New("encryption key must not be empty")
)

// FieldEncryptor provides AES-256-GCM encryption and decryption for
// individual audit log fields. It is safe for concurrent use.
type FieldEncryptor struct {
	gcm cipher.AEAD
}

// NewFieldEncryptor creates a new encryptor with the given 32-byte key.
// Returns ErrInvalidKeySize if the key length is not exactly 32 bytes.
func NewFieldEncryptor(key []byte) (*FieldEncryptor, error) {
	if len(key) == 0 {
		return nil, ErrEmptyKey
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidKeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	return &FieldEncryptor{gcm: gcm}, nil
}

// NewFieldEncryptorFromEnv creates a new encryptor using a hex-encoded key
// from the CLAWSHIELD_AUDIT_ENCRYPTION_KEY environment variable.
// Returns an error if the variable is not set or contains an invalid key.
func NewFieldEncryptorFromEnv() (*FieldEncryptor, error) {
	hexKey := os.Getenv(EnvKeyName)
	if hexKey == "" {
		return nil, fmt.Errorf("%s environment variable not set", EnvKeyName)
	}

	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("decode hex key from %s: %w", EnvKeyName, err)
	}

	return NewFieldEncryptor(key)
}

// Encrypt encrypts plaintext using AES-256-GCM with a random nonce.
// Returns version-prefixed ciphertext: v1 || nonce || encrypted || tag.
// Returns nil without error if plaintext is nil.
// Returns empty versioned ciphertext for empty (non-nil) plaintext.
func (e *FieldEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	if plaintext == nil {
		return nil, nil
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// GCM Seal appends ciphertext + tag to the dst slice.
	// Pre-allocate: version(1) + nonce(12) + plaintext_len + GCM_overhead(16)
	ciphertext := make([]byte, versionPrefixLen+NonceSize, versionPrefixLen+NonceSize+len(plaintext)+e.gcm.Overhead())
	ciphertext[0] = versionV1
	copy(ciphertext[versionPrefixLen:], nonce)

	ciphertext = e.gcm.Seal(ciphertext, nonce, plaintext, nil)

	return ciphertext, nil
}

// Decrypt decrypts version-prefixed ciphertext produced by Encrypt.
// Returns nil without error if ciphertext is nil.
// Returns ErrCiphertextTooShort if the data is too small to be valid.
// Returns ErrUnsupportedVersion if the version prefix is unrecognised.
// Returns an authentication error if the ciphertext has been tampered with.
func (e *FieldEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	if ciphertext == nil {
		return nil, nil
	}

	minSize := versionPrefixLen + NonceSize + e.gcm.Overhead()
	if len(ciphertext) < minSize {
		return nil, fmt.Errorf("%w: got %d bytes, need at least %d", ErrCiphertextTooShort, len(ciphertext), minSize)
	}

	version := ciphertext[0]
	if version != versionV1 {
		return nil, fmt.Errorf("%w: got 0x%02x", ErrUnsupportedVersion, version)
	}

	nonce := ciphertext[versionPrefixLen : versionPrefixLen+NonceSize]
	encrypted := ciphertext[versionPrefixLen+NonceSize:]

	plaintext, err := e.gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

// EncryptString is a convenience wrapper that encrypts a string value.
// Returns nil without error if the input is empty.
func (e *FieldEncryptor) EncryptString(plaintext string) ([]byte, error) {
	if plaintext == "" {
		return nil, nil
	}
	return e.Encrypt([]byte(plaintext))
}

// DecryptToString is a convenience wrapper that decrypts to a string.
// Returns empty string without error if ciphertext is nil.
func (e *FieldEncryptor) DecryptToString(ciphertext []byte) (string, error) {
	if ciphertext == nil {
		return "", nil
	}
	plaintext, err := e.Decrypt(ciphertext)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// IsEncrypted checks whether the given data appears to be encrypted by
// this package (i.e., starts with a known version prefix byte).
// This is used for graceful handling of mixed encrypted/plaintext data
// during migration from unencrypted to encrypted audit storage.
//
// SECURITY NOTE: This is a heuristic check based on the version prefix byte.
// It cannot guarantee the data is truly encrypted — only that it starts with
// a recognised version byte. False positives are possible but unlikely for
// text/JSON data since 0x01 is not a valid leading byte for UTF-8 text or JSON.
func IsEncrypted(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	return data[0] == versionV1
}

// GenerateKey generates a cryptographically secure random 32-byte key.
// This is a helper for key generation tooling — production deployments
// should use a proper key management system (KMS).
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate random key: %w", err)
	}
	return key, nil
}
