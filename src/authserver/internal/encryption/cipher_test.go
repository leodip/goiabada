package encryption

import (
	"bytes"
	"strconv"
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

const (
	testDataKey  = "0123456789abcdef0123456789abcdef"
	otherDataKey = "fedcba9876543210fedcba9876543210"
)

func newTestDataCipher(t *testing.T, key string) *DataCipher {
	t.Helper()
	c, err := NewDataCipher([]byte(key))
	if err != nil {
		t.Fatalf("NewDataCipher: %v", err)
	}
	return c
}

func TestNewDataCipher_KeyLength(t *testing.T) {
	for _, n := range []int{0, 31, 33} {
		c, err := NewDataCipher(bytes.Repeat([]byte{'k'}, n))
		if err == nil {
			t.Errorf("a %d-byte key: expected an error, got nil", n)
			continue
		}
		if c != nil {
			t.Errorf("a %d-byte key: expected no cipher beside the error", n)
		}
		want := "data encryption key must be 32 bytes, but it has " + strconv.Itoa(n) + " bytes"
		if err.Error() != want {
			t.Errorf("a %d-byte key: error = %q, want %q", n, err.Error(), want)
		}
	}

	c, err := NewDataCipher(bytes.Repeat([]byte{'k'}, 32))
	if err != nil || c == nil {
		t.Fatalf("a 32-byte key: got %v, %v; want a cipher and no error", c, err)
	}
}

func TestDataCipher_RoundTrip(t *testing.T) {
	c := newTestDataCipher(t, testDataKey)

	const secret = "a-secret-value"
	ct, err := c.Encrypt(secret)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Contains(ct, []byte(secret)) {
		t.Error("ciphertext contains the plaintext")
	}
	pt, err := c.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if pt != secret {
		t.Errorf("round-trip = %q, want %q", pt, secret)
	}

	again, err := c.Encrypt(secret)
	if err != nil {
		t.Fatalf("Encrypt (second): %v", err)
	}
	if bytes.Equal(ct, again) {
		t.Error("two encryptions of one secret produced the same ciphertext, so the nonce was reused")
	}
}

// TestDataCipher_RefusesAnotherKeysCiphertext is the case otpcredential's key swap exercised
// through the global: two ciphers, and neither opens what the other sealed.
func TestDataCipher_RefusesAnotherKeysCiphertext(t *testing.T) {
	ct, err := newTestDataCipher(t, testDataKey).Encrypt("secret")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := newTestDataCipher(t, otherDataKey).Decrypt(ct); err == nil {
		t.Error("a cipher under another key opened the ciphertext")
	}
}

// TestDataCipher_RefusesATamperedCiphertext flips one byte in each region of the sealed
// value: the nonce, the encrypted body and the GCM tag.
func TestDataCipher_RefusesATamperedCiphertext(t *testing.T) {
	c := newTestDataCipher(t, testDataKey)
	ct, err := c.Encrypt("a-secret-value")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	for name, i := range map[string]int{"nonce": 0, "body": 12, "tag": len(ct) - 1} {
		tampered := append([]byte(nil), ct...)
		tampered[i] ^= 0x01
		if _, err := c.Decrypt(tampered); err == nil {
			t.Errorf("a ciphertext with its %s altered was opened", name)
		}
	}
	if _, err := c.Decrypt(ct[:len(ct)-1]); err == nil {
		t.Error("a truncated ciphertext was opened")
	}
	if _, err := c.Decrypt(nil); err == nil {
		t.Error("an empty ciphertext was opened")
	}
}

// TestDataCipher_RefusesEmptyPlaintext holds the cipher to EncryptText's refusal: an empty
// ciphertext is a storable value, and so an empty secret is not sealed into one.
func TestDataCipher_RefusesEmptyPlaintext(t *testing.T) {
	ct, err := newTestDataCipher(t, testDataKey).Encrypt("")
	if err == nil {
		t.Fatal("an empty plaintext was encrypted")
	}
	if ct != nil {
		t.Errorf("a ciphertext came back beside the error: %x", ct)
	}
}

func TestDataCipher_NilErrors(t *testing.T) {
	var c *DataCipher
	const want = "data cipher is nil: build one with encryption.NewDataCipher"

	ct, err := c.Encrypt("secret")
	if err == nil || err.Error() != want || ct != nil {
		t.Errorf("Encrypt on a nil cipher = %x, %v; want nil, %q", ct, err, want)
	}
	pt, err := c.Decrypt([]byte("ciphertext"))
	if err == nil || err.Error() != want || pt != "" {
		t.Errorf("Decrypt on a nil cipher = %q, %v; want \"\", %q", pt, err, want)
	}
}

// TestNewDataCipher_CopiesTheKey overwrites the caller's slice after construction: the
// cipher still opens what it sealed, and what it seals still opens under the original key.
func TestNewDataCipher_CopiesTheKey(t *testing.T) {
	key := []byte(testDataKey)
	c, err := NewDataCipher(key)
	if err != nil {
		t.Fatalf("NewDataCipher: %v", err)
	}
	before, err := c.Encrypt("secret")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	for i := range key {
		key[i] = 0
	}

	pt, err := c.Decrypt(before)
	if err != nil || pt != "secret" {
		t.Errorf("after the caller zeroed its key, Decrypt = %q, %v; want \"secret\", nil", pt, err)
	}
	after, err := c.Encrypt("secret")
	if err != nil {
		t.Fatalf("Encrypt after the caller zeroed its key: %v", err)
	}
	if pt, err := DecryptText(after, []byte(testDataKey)); err != nil || pt != "secret" {
		t.Errorf("a value sealed after the caller zeroed its key opens as %q, %v under the original key", pt, err)
	}
}

// TestDataCipher_OpensWhatEncryptTextSealed is the property that makes moving every consumer
// onto the cipher safe: every value stored before #434 was sealed by EncryptText under the
// data key, and the re-encryption sweep still reads and writes with the keyed pair. Both
// directions have to open, or an upgrade strands every stored client secret, OTP seed, SMTP
// password and private key.
func TestDataCipher_OpensWhatEncryptTextSealed(t *testing.T) {
	c := newTestDataCipher(t, testDataKey)

	stored, err := EncryptText("sealed-before-434", []byte(testDataKey))
	if err != nil {
		t.Fatalf("EncryptText: %v", err)
	}
	pt, err := c.Decrypt(stored)
	if err != nil || pt != "sealed-before-434" {
		t.Errorf("Decrypt of an EncryptText value = %q, %v", pt, err)
	}

	sealed, err := c.Encrypt("sealed-by-the-cipher")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if pt, err := DecryptText(sealed, []byte(testDataKey)); err != nil || pt != "sealed-by-the-cipher" {
		t.Errorf("DecryptText of a cipher value = %q, %v", pt, err)
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
