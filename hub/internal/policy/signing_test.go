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
