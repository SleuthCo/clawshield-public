package policy

import (
	"crypto/rsa"

	sharedpolicy "github.com/SleuthCo/clawshield/shared/policy"
)

// SignPolicy signs the policy YAML with the private key and returns the base64-encoded signature.
func SignPolicy(policyYAML string, privateKey *rsa.PrivateKey) (string, error) {
	return sharedpolicy.SignPolicy(policyYAML, privateKey)
}

// VerifyPolicy verifies that the signature matches the policy YAML using the public key.
func VerifyPolicy(policyYAML, signature string, publicKey *rsa.PublicKey) error {
	return sharedpolicy.VerifyPolicy(policyYAML, signature, publicKey)
}

// ComputePolicyHash computes the SHA-256 hash of the policy YAML and returns it as a hex string.
func ComputePolicyHash(policyYAML string) string {
	return sharedpolicy.ComputePolicyHash(policyYAML)
}

// GenerateSigningKeyPair generates a new RSA key pair for signing policies.
func GenerateSigningKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	return sharedpolicy.GenerateSigningKeyPair(bits)
}

// PrivateKeyToPEM converts a private key to PEM format (PKCS#1).
func PrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	return sharedpolicy.PrivateKeyToPEM(privateKey)
}

// PublicKeyToPEM converts a public key to PEM format (PKIX).
func PublicKeyToPEM(publicKey *rsa.PublicKey) ([]byte, error) {
	return sharedpolicy.PublicKeyToPEM(publicKey)
}

// PrivateKeyFromPEM parses a PEM-encoded private key (PKCS#1).
func PrivateKeyFromPEM(data []byte) (*rsa.PrivateKey, error) {
	return sharedpolicy.PrivateKeyFromPEM(data)
}

// PublicKeyFromPEM parses a PEM-encoded public key (PKIX).
func PublicKeyFromPEM(data []byte) (*rsa.PublicKey, error) {
	return sharedpolicy.PublicKeyFromPEM(data)
}
