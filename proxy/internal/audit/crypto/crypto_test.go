package crypto

import (
	"bytes"
	"crypto/rand"
	"sync"
	"testing"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	return key
}

func TestNewFieldEncryptor_ValidKey(t *testing.T) {
	enc, err := NewFieldEncryptor(testKey(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if enc == nil {
		t.Fatal("expected non-nil encryptor")
	}
}

func TestNewFieldEncryptor_EmptyKey(t *testing.T) {
	_, err := NewFieldEncryptor([]byte{})
	if err == nil {
		t.Fatal("expected error for empty key")
	}
}

func TestNewFieldEncryptor_ShortKey(t *testing.T) {
	_, err := NewFieldEncryptor(make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for 16-byte key")
	}
}

func TestNewFieldEncryptor_LongKey(t *testing.T) {
	_, err := NewFieldEncryptor(make([]byte, 64))
	if err == nil {
		t.Fatal("expected error for 64-byte key")
	}
}

func TestNewFieldEncryptor_NilKey(t *testing.T) {
	_, err := NewFieldEncryptor(nil)
	if err == nil {
		t.Fatal("expected error for nil key")
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	enc, err := NewFieldEncryptor(testKey(t))
	if err != nil {
		t.Fatalf("create encryptor: %v", err)
	}

	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"simple text", []byte("hello world")},
		{"json", []byte(`{"tool":"web_search","args":{"query":"secrets"}}`)},
		{"unicode", []byte("日本語テスト 🔒🛡️")},
		{"binary-like", []byte{0x00, 0x01, 0x02, 0xFF, 0xFE}},
		{"empty bytes", []byte{}},
		{"large payload", bytes.Repeat([]byte("A"), 1024*1024)}, // 1MB
		{"single byte", []byte{0x42}},
		{"pii data", []byte(`SSN: 123-45-6789, CC: 4111-1111-1111-1111`)},
		{"api key", []byte(`Authorization: Bearer sk-proj-abc123def456`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := enc.Encrypt(tt.plaintext)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}

			// Ciphertext should differ from plaintext
			if bytes.Equal(ciphertext, tt.plaintext) && len(tt.plaintext) > 0 {
				t.Error("ciphertext equals plaintext")
			}

			// Ciphertext should start with version prefix
			if len(ciphertext) > 0 && ciphertext[0] != versionV1 {
				t.Errorf("expected version prefix 0x%02x, got 0x%02x", versionV1, ciphertext[0])
			}

			decrypted, err := enc.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}

			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("round-trip failed: got %q, want %q", decrypted, tt.plaintext)
			}
		})
	}
}

func TestEncrypt_NilPlaintext(t *testing.T) {
	enc, _ := NewFieldEncryptor(testKey(t))
	ct, err := enc.Encrypt(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ct != nil {
		t.Errorf("expected nil ciphertext for nil plaintext, got %v", ct)
	}
}

func TestDecrypt_NilCiphertext(t *testing.T) {
	enc, _ := NewFieldEncryptor(testKey(t))
	pt, err := enc.Decrypt(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pt != nil {
		t.Errorf("expected nil plaintext for nil ciphertext, got %v", pt)
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	enc1, _ := NewFieldEncryptor(testKey(t))
	enc2, _ := NewFieldEncryptor(testKey(t))

	plaintext := []byte("sensitive audit data")
	ciphertext, err := enc1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	_, err = enc2.Decrypt(ciphertext)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key")
	}
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	enc, _ := NewFieldEncryptor(testKey(t))

	plaintext := []byte("tamper test data")
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Tamper with a byte in the middle of the ciphertext (past the nonce)
	tamperIdx := versionPrefixLen + NonceSize + 1
	if tamperIdx < len(ciphertext) {
		ciphertext[tamperIdx] ^= 0xFF
	}

	_, err = enc.Decrypt(ciphertext)
	if err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
}

func TestDecrypt_TamperedNonce(t *testing.T) {
	enc, _ := NewFieldEncryptor(testKey(t))

	ciphertext, _ := enc.Encrypt([]byte("nonce tamper test"))

	// Tamper with the nonce
	ciphertext[versionPrefixLen] ^= 0xFF

	_, err := enc.Decrypt(ciphertext)
	if err == nil {
		t.Fatal("expected error for tampered nonce")
	}
}

func TestDecrypt_TooShort(t *testing.T) {
	enc, _ := NewFieldEncryptor(testKey(t))

	_, err := enc.Decrypt([]byte{versionV1, 0x00, 0x01})
	if err == nil {
		t.Fatal("expected ErrCiphertextTooShort")
	}
}

func TestDecrypt_UnsupportedVersion(t *testing.T) {
	enc, _ := NewFieldEncryptor(testKey(t))

	// Create fake ciphertext with wrong version
	fake := make([]byte, 100)
	fake[0] = 0xFF // unsupported version

	_, err := enc.Decrypt(fake)
	if err == nil {
		t.Fatal("expected ErrUnsupportedVersion")
	}
}

func TestEncrypt_UniqueNonces(t *testing.T) {
	enc, _ := NewFieldEncryptor(testKey(t))
	plaintext := []byte("same plaintext")

	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		ct, err := enc.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("encrypt iteration %d: %v", i, err)
		}

		// Extract nonce
		nonce := string(ct[versionPrefixLen : versionPrefixLen+NonceSize])
		if seen[nonce] {
			t.Fatalf("nonce collision at iteration %d", i)
		}
		seen[nonce] = true
	}
}

func TestEncrypt_SamePlaintextDifferentCiphertext(t *testing.T) {
	enc, _ := NewFieldEncryptor(testKey(t))
	plaintext := []byte("determinism check")

	ct1, _ := enc.Encrypt(plaintext)
	ct2, _ := enc.Encrypt(plaintext)

	if bytes.Equal(ct1, ct2) {
		t.Error("encrypting same plaintext twice produced identical ciphertext (nonce reuse)")
	}
}

func TestEncryptString_DecryptToString(t *testing.T) {
	enc, _ := NewFieldEncryptor(testKey(t))

	original := `{"request": "sensitive tool call data"}`
	ct, err := enc.EncryptString(original)
	if err != nil {
		t.Fatalf("encrypt string: %v", err)
	}

	decrypted, err := enc.DecryptToString(ct)
	if err != nil {
		t.Fatalf("decrypt to string: %v", err)
	}

	if decrypted != original {
		t.Errorf("got %q, want %q", decrypted, original)
	}
}

func TestEncryptString_Empty(t *testing.T) {
	enc, _ := NewFieldEncryptor(testKey(t))

	ct, err := enc.EncryptString("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ct != nil {
		t.Errorf("expected nil for empty string, got %v", ct)
	}
}

func TestDecryptToString_Nil(t *testing.T) {
	enc, _ := NewFieldEncryptor(testKey(t))

	s, err := enc.DecryptToString(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s != "" {
		t.Errorf("expected empty string for nil, got %q", s)
	}
}

func TestIsEncrypted(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{"nil", nil, false},
		{"empty", []byte{}, false},
		{"version v1", []byte{versionV1, 0x00}, true},
		{"json data", []byte(`{"key": "value"}`), false},
		{"plain text", []byte("hello world"), false},
		{"version 0xFF", []byte{0xFF, 0x00}, false},
		{"version 0x00", []byte{0x00, 0x00}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsEncrypted(tt.data)
			if got != tt.expected {
				t.Errorf("IsEncrypted(%v) = %v, want %v", tt.data, got, tt.expected)
			}
		})
	}
}

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if len(key) != KeySize {
		t.Errorf("key length = %d, want %d", len(key), KeySize)
	}

	// Ensure two generated keys are different
	key2, _ := GenerateKey()
	if bytes.Equal(key, key2) {
		t.Error("two generated keys are identical")
	}
}

func TestConcurrentEncryptDecrypt(t *testing.T) {
	enc, _ := NewFieldEncryptor(testKey(t))

	var wg sync.WaitGroup
	errs := make(chan error, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			plaintext := []byte("concurrent test data")
			ct, err := enc.Encrypt(plaintext)
			if err != nil {
				errs <- err
				return
			}
			pt, err := enc.Decrypt(ct)
			if err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(pt, plaintext) {
				errs <- bytes.ErrTooLarge // use as sentinel
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent error: %v", err)
	}
}

func TestNewFieldEncryptorFromEnv(t *testing.T) {
	key := testKey(t)

	// Set the env variable
	t.Setenv(EnvKeyName, "invalid-hex")
	_, err := NewFieldEncryptorFromEnv()
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}

	// Valid hex key
	t.Setenv(EnvKeyName, "")
	_, err = NewFieldEncryptorFromEnv()
	if err == nil {
		t.Fatal("expected error for empty env var")
	}

	// Correct key
	t.Setenv(EnvKeyName, bytesToHex(key))
	enc, err := NewFieldEncryptorFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify it works
	ct, _ := enc.Encrypt([]byte("env test"))
	pt, _ := enc.Decrypt(ct)
	if string(pt) != "env test" {
		t.Errorf("env encryptor round-trip failed")
	}
}

func bytesToHex(b []byte) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, len(b)*2)
	for i, v := range b {
		result[i*2] = hexChars[v>>4]
		result[i*2+1] = hexChars[v&0x0f]
	}
	return string(result)
}
