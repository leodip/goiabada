package encryption

import (
	"bytes"
	"testing"
)

func TestInitDataCipher_Validation(t *testing.T) {
	// Save and restore the package-wide cipher so this test is isolated.
	saved := dataCipher
	defer func() { dataCipher = saved }()

	dataCipher = nil
	if err := InitDataCipher([]byte("too-short")); err == nil {
		t.Error("expected error for a non-32-byte key, got nil")
	}
	if IsDataCipherInitialized() {
		t.Error("cipher should not be initialized after a failed InitDataCipher")
	}

	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	if err := InitDataCipher(key); err != nil {
		t.Fatalf("InitDataCipher: %v", err)
	}
	if !IsDataCipherInitialized() {
		t.Error("cipher should be initialized")
	}
}

func TestEncryptData_RoundTrip(t *testing.T) {
	saved := dataCipher
	defer func() { dataCipher = saved }()

	if err := InitDataCipher([]byte("0123456789abcdef0123456789abcdef")); err != nil {
		t.Fatalf("InitDataCipher: %v", err)
	}

	const secret = "a-secret-value"
	ct, err := EncryptData(secret)
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}
	if bytes.Contains(ct, []byte(secret)) {
		t.Error("ciphertext contains the plaintext")
	}
	pt, err := DecryptData(ct)
	if err != nil {
		t.Fatalf("DecryptData: %v", err)
	}
	if pt != secret {
		t.Errorf("round-trip = %q, want %q", pt, secret)
	}
}

func TestEncryptDecryptData_NotInitialized(t *testing.T) {
	saved := dataCipher
	defer func() { dataCipher = saved }()

	dataCipher = nil
	if _, err := EncryptData("x"); err == nil {
		t.Error("EncryptData without init: expected error, got nil")
	}
	if _, err := DecryptData([]byte("x")); err == nil {
		t.Error("DecryptData without init: expected error, got nil")
	}
}

func TestDecryptData_WrongKey(t *testing.T) {
	saved := dataCipher
	defer func() { dataCipher = saved }()

	_ = InitDataCipher([]byte("0123456789abcdef0123456789abcdef"))
	ct, err := EncryptData("secret")
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}

	_ = InitDataCipher([]byte("fedcba9876543210fedcba9876543210"))
	if _, err := DecryptData(ct); err == nil {
		t.Error("DecryptData with a different key: expected error, got nil")
	}
}
