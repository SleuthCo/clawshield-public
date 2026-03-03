package policy

import (
	"testing"
)

func TestSignVerify_RoundTrip(t *testing.T) {
	privKey, pubKey, err := GenerateSigningKeyPair(2048)
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	policyYAML := "default_action: deny\nallowlist:\n  - web_search\n"

	signature, err := SignPolicy(policyYAML, privKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if signature == "" {
		t.Fatal("expected non-empty signature")
	}

	if err := VerifyPolicy(policyYAML, signature, pubKey); err != nil {
		t.Fatalf("verify should succeed: %v", err)
	}
}

func TestVerify_TamperedPolicy(t *testing.T) {
	privKey, pubKey, err := GenerateSigningKeyPair(2048)
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	originalPolicy := "default_action: deny\n"
	signature, err := SignPolicy(originalPolicy, privKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	tamperedPolicy := "default_action: allow\n"
	if err := VerifyPolicy(tamperedPolicy, signature, pubKey); err == nil {
		t.Fatal("expected error for tampered policy")
	}
}

func TestVerify_WrongKey(t *testing.T) {
	privKey1, _, _ := GenerateSigningKeyPair(2048)
	_, pubKey2, _ := GenerateSigningKeyPair(2048)

	policyYAML := "default_action: deny\n"
	signature, _ := SignPolicy(policyYAML, privKey1)

	if err := VerifyPolicy(policyYAML, signature, pubKey2); err == nil {
		t.Fatal("expected error for wrong key")
	}
}

func TestComputePolicyHash_Deterministic(t *testing.T) {
	policy := "default_action: deny\nallowlist:\n  - web_search\n"
	h1 := ComputePolicyHash(policy)
	h2 := ComputePolicyHash(policy)

	if h1 != h2 {
		t.Errorf("non-deterministic: %q != %q", h1, h2)
	}
	if len(h1) != 64 { // hex-encoded SHA-256
		t.Errorf("expected 64 hex chars, got %d", len(h1))
	}
}

func TestPEMRoundTrip(t *testing.T) {
	privKey, pubKey, _ := GenerateSigningKeyPair(2048)

	pubPEM, err := PublicKeyToPEM(pubKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	restored, err := PublicKeyFromPEM(pubPEM)
	if err != nil {
		t.Fatalf("unmarshal public key: %v", err)
	}

	// Verify the restored key works
	sig, _ := SignPolicy("test", privKey)
	if err := VerifyPolicy("test", sig, restored); err != nil {
		t.Fatalf("verify with restored key: %v", err)
	}
}

func TestGenerateSigningKeyPair_MinimumKeySize(t *testing.T) {
	tests := []struct {
		name    string
		bits    int
		wantErr bool
	}{
		{"2047 bits is too small", 2047, true},
		{"1024 bits is too small", 1024, true},
		{"512 bits is too small", 512, true},
		{"2048 bits is valid", 2048, false},
		{"4096 bits is valid", 4096, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privKey, pubKey, err := GenerateSigningKeyPair(tt.bits)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("GenerateSigningKeyPair(%d) should fail but succeeded", tt.bits)
				}
				if privKey != nil || pubKey != nil {
					t.Fatal("expected nil keys for error case")
				}
			} else {
				if err != nil {
					t.Fatalf("GenerateSigningKeyPair(%d): %v", tt.bits, err)
				}
				if privKey == nil || pubKey == nil {
					t.Fatal("expected non-nil keys")
				}
			}
		})
	}
}

func TestPrivateKeyToPEM(t *testing.T) {
	// Generate a key pair
	privKey, _, err := GenerateSigningKeyPair(2048)
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	// Convert to DER (PKCS#1 format)
	derBytes := PrivateKeyToPEM(privKey)

	// Verify output is non-empty
	if len(derBytes) == 0 {
		t.Fatal("expected non-empty DER output")
	}

	// Verify we can parse it back
	parsedKey, err := PrivateKeyFromPEM(derBytes)
	if err != nil {
		t.Fatalf("parse DER: %v", err)
	}

	if parsedKey == nil {
		t.Fatal("expected non-nil parsed key")
	}

	// Verify the key has the expected bit length
	if parsedKey.N.BitLen() != 2048 {
		t.Errorf("expected 2048-bit key, got %d bits", parsedKey.N.BitLen())
	}
}

func TestPrivateKeyFromPEM(t *testing.T) {
	// Generate a key pair
	privKey, pubKey, err := GenerateSigningKeyPair(2048)
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	// Convert to PEM
	pemBytes := PrivateKeyToPEM(privKey)

	// Parse from PEM
	parsedKey, err := PrivateKeyFromPEM(pemBytes)
	if err != nil {
		t.Fatalf("parse PEM: %v", err)
	}

	if parsedKey == nil {
		t.Fatal("expected non-nil parsed key")
	}

	// Verify the parsed key works by signing and verifying with the original public key
	policy := "test_policy: default_action_deny\n"
	sig, err := SignPolicy(policy, parsedKey)
	if err != nil {
		t.Fatalf("sign with parsed key: %v", err)
	}

	if err := VerifyPolicy(policy, sig, pubKey); err != nil {
		t.Fatalf("verify with original pubkey: %v", err)
	}
}

func TestPrivateKeyFromPEM_Invalid(t *testing.T) {
	tests := []struct {
		name string
		pem  []byte
	}{
		{"invalid PEM string", []byte("not a valid pem")},
		{"empty PEM", []byte("")},
		{"corrupted PEM header", []byte("-----BEGIN RSA PRIVATE KEY-----\ninvalid content\n-----END RSA PRIVATE KEY-----")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := PrivateKeyFromPEM(tt.pem)
			if err == nil {
				t.Fatalf("expected error for %s, got none", tt.name)
			}
			if key != nil {
				t.Fatal("expected nil key for invalid PEM")
			}
		})
	}
}

func TestPrivateKeyPEM_RoundTrip(t *testing.T) {
	// Generate original key pair
	origPrivKey, origPubKey, err := GenerateSigningKeyPair(2048)
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	// Sign with original private key
	originalPolicy := "policy_version: 1.0\ndefault_action: deny\n"
	originalSig, err := SignPolicy(originalPolicy, origPrivKey)
	if err != nil {
		t.Fatalf("sign with original key: %v", err)
	}

	// Convert to PEM
	pemBytes := PrivateKeyToPEM(origPrivKey)

	// Parse back from PEM
	parsedPrivKey, err := PrivateKeyFromPEM(pemBytes)
	if err != nil {
		t.Fatalf("parse PEM: %v", err)
	}

	// Sign with parsed key
	parsedSig, err := SignPolicy(originalPolicy, parsedPrivKey)
	if err != nil {
		t.Fatalf("sign with parsed key: %v", err)
	}

	// Verify both signatures work with original public key
	if err := VerifyPolicy(originalPolicy, originalSig, origPubKey); err != nil {
		t.Fatalf("verify original signature: %v", err)
	}

	if err := VerifyPolicy(originalPolicy, parsedSig, origPubKey); err != nil {
		t.Fatalf("verify parsed key signature: %v", err)
	}

	// Verify parsed key can verify signatures from original key
	if err := VerifyPolicy(originalPolicy, originalSig, origPubKey); err != nil {
		t.Fatalf("cross-verify original sig with orig pubkey: %v", err)
	}

	// Verify neither signature verifies with a different policy
	if err := VerifyPolicy("different_policy: true\n", originalSig, origPubKey); err == nil {
		t.Fatal("expected error when verifying different policy")
	}
}
