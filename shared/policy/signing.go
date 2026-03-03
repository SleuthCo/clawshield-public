package policy

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// SignPolicy signs the policy YAML with the private key and returns the base64-encoded signature.
func SignPolicy(policyYAML string, privateKey *rsa.PrivateKey) (string, error) {
	hash := sha256.Sum256([]byte(policyYAML))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", fmt.Errorf("sign policy: %w", err)
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// VerifyPolicy verifies that the signature matches the policy YAML using the public key.
func VerifyPolicy(policyYAML, signature string, publicKey *rsa.PublicKey) error {
	hash := sha256.Sum256([]byte(policyYAML))
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], sig)
	if err != nil {
		return fmt.Errorf("verify signature: %w", err)
	}
	return nil
}

// ComputePolicyHash computes the SHA-256 hash of the policy YAML and returns it as a hex string.
func ComputePolicyHash(policyYAML string) string {
	hash := sha256.Sum256([]byte(policyYAML))
	return hex.EncodeToString(hash[:])
}

// GenerateSigningKeyPair generates a new RSA key pair for signing policies.
func GenerateSigningKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	if bits < 2048 {
		return nil, nil, fmt.Errorf("key size %d is too small: minimum 2048 bits required", bits)
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	return privateKey, &privateKey.PublicKey, nil
}

// PrivateKeyToPEM converts a private key to PEM format (PKCS#1).
func PrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	return x509.MarshalPKCS1PrivateKey(privateKey)
}

// PublicKeyToPEM converts a public key to PEM format (PKIX).
func PublicKeyToPEM(publicKey *rsa.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(publicKey)
}

// PrivateKeyFromPEM parses a PEM-encoded private key (PKCS#1).
func PrivateKeyFromPEM(data []byte) (*rsa.PrivateKey, error) {
	return x509.ParsePKCS1PrivateKey(data)
}

// PublicKeyFromPEM parses a PEM-encoded public key (PKIX).
func PublicKeyFromPEM(data []byte) (*rsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, err
	}
	publicKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}
	return publicKey, nil
}
