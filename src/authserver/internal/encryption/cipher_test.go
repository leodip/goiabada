package encryption

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
)

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

// thirdDataKey is a key neither of a rotation's two keys is.
const thirdDataKey = "0011223344556677001122334455667f"

func newRotatingTestCipher(t *testing.T, current, previous string) *DataCipher {
	t.Helper()
	c, err := NewDataCipherWithPrevious([]byte(current), []byte(previous))
	if err != nil {
		t.Fatalf("NewDataCipherWithPrevious: %v", err)
	}
	return c
}

// TestDataCipherWithPrevious_OpensUnderEitherKey is the rotation's reading half (#492 decision 2):
// a value sealed under the current key and one sealed under the previous key both open, each to its
// own plaintext. The values are sealed by ciphers holding one key each, independently of the
// cipher under test.
func TestDataCipherWithPrevious_OpensUnderEitherKey(t *testing.T) {
	c := newRotatingTestCipher(t, otherDataKey, testDataKey)

	underPrevious, err := EncryptText("sealed-under-the-previous-key", []byte(testDataKey))
	if err != nil {
		t.Fatalf("EncryptText: %v", err)
	}
	underCurrent, err := EncryptText("sealed-under-the-current-key", []byte(otherDataKey))
	if err != nil {
		t.Fatalf("EncryptText: %v", err)
	}

	if pt, err := c.Decrypt(underPrevious); err != nil || pt != "sealed-under-the-previous-key" {
		t.Errorf("a value under the previous key opens as %q, %v", pt, err)
	}
	if pt, err := c.Decrypt(underCurrent); err != nil || pt != "sealed-under-the-current-key" {
		t.Errorf("a value under the current key opens as %q, %v", pt, err)
	}
}

// TestDataCipherWithPrevious_SealsUnderTheCurrentKey is the rotation's writing half: what the
// cipher seals opens under the current key alone and not under the previous key alone, so nothing
// it writes stays on the key the database is leaving.
func TestDataCipherWithPrevious_SealsUnderTheCurrentKey(t *testing.T) {
	c := newRotatingTestCipher(t, otherDataKey, testDataKey)

	sealed, err := c.Encrypt("a-secret-value")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if pt, err := DecryptText(sealed, []byte(otherDataKey)); err != nil || pt != "a-secret-value" {
		t.Errorf("under the current key alone the sealed value opens as %q, %v", pt, err)
	}
	if _, err := DecryptText(sealed, []byte(testDataKey)); err == nil {
		t.Error("the previous key alone opened what the cipher sealed")
	}
}

// TestDataCipherWithPrevious_NamesNeitherKey: a value under a third key opens under neither, and
// the error says so, since that is what a caller logs and an operator reads.
func TestDataCipherWithPrevious_NamesNeitherKey(t *testing.T) {
	c := newRotatingTestCipher(t, otherDataKey, testDataKey)

	elsewhere, err := EncryptText("sealed-under-a-third-key", []byte(thirdDataKey))
	if err != nil {
		t.Fatalf("EncryptText: %v", err)
	}
	pt, err := c.Decrypt(elsewhere)
	if err == nil {
		t.Fatalf("a value under a third key opened as %q", pt)
	}
	const want = "the value decrypts under neither the current data encryption key nor the previous one"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error = %q, want it to contain %q", err.Error(), want)
	}
	if pt != "" {
		t.Errorf("a plaintext came back beside the error: %q", pt)
	}
}

// TestDataCipherWithPrevious_RefusesATamperedCiphertext holds the two-key cipher to the one-key
// cipher's refusal: a value under the previous key with one byte altered opens under neither.
func TestDataCipherWithPrevious_RefusesATamperedCiphertext(t *testing.T) {
	c := newRotatingTestCipher(t, otherDataKey, testDataKey)
	ct, err := EncryptText("a-secret-value", []byte(testDataKey))
	if err != nil {
		t.Fatalf("EncryptText: %v", err)
	}
	tampered := append([]byte(nil), ct...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := c.Decrypt(tampered); err == nil {
		t.Error("a tampered value under the previous key was opened")
	}
}

// TestDataCipherWithPrevious_APreviousKeyThatTakesNoPart: a previous key that is absent, or equal
// to the current one, takes no part. The cipher is then the one-key cipher: it opens the current
// key's values, refuses another key's, and answers that key's own error rather than one naming a
// previous key.
func TestDataCipherWithPrevious_APreviousKeyThatTakesNoPart(t *testing.T) {
	for name, previous := range map[string][]byte{"absent": nil, "empty": {}, "equal": []byte(testDataKey)} {
		c, err := NewDataCipherWithPrevious([]byte(testDataKey), previous)
		if err != nil {
			t.Fatalf("%s: NewDataCipherWithPrevious: %v", name, err)
		}
		mine, err := EncryptText("mine", []byte(testDataKey))
		if err != nil {
			t.Fatalf("EncryptText: %v", err)
		}
		if pt, err := c.Decrypt(mine); err != nil || pt != "mine" {
			t.Errorf("%s: the current key's value opens as %q, %v", name, pt, err)
		}
		other, err := EncryptText("other", []byte(otherDataKey))
		if err != nil {
			t.Fatalf("EncryptText: %v", err)
		}
		_, err = c.Decrypt(other)
		if err == nil {
			t.Errorf("%s: another key's value was opened", name)
			continue
		}
		if strings.Contains(err.Error(), "previous") {
			t.Errorf("%s: with no previous key the error names one: %q", name, err.Error())
		}
	}
}

// TestNewDataCipherWithPrevious_KeyLengths: either key at the wrong length is refused, with no
// cipher beside the error, so no caller goes on with half a validated pair.
func TestNewDataCipherWithPrevious_KeyLengths(t *testing.T) {
	good := []byte(testDataKey)
	for _, n := range []int{1, 31, 33} {
		short := bytes.Repeat([]byte{'k'}, n)

		c, err := NewDataCipherWithPrevious(good, short)
		want := "previous data encryption key must be 32 bytes, but it has " + strconv.Itoa(n) + " bytes"
		if err == nil || err.Error() != want || c != nil {
			t.Errorf("a %d-byte previous key: got %v, %v; want nil, %q", n, c, err, want)
		}

		c, err = NewDataCipherWithPrevious(short, good)
		want = "data encryption key must be 32 bytes, but it has " + strconv.Itoa(n) + " bytes"
		if err == nil || err.Error() != want || c != nil {
			t.Errorf("a %d-byte current key: got %v, %v; want nil, %q", n, c, err, want)
		}
	}
}

// TestNewDataCipherWithPrevious_CopiesThePreviousKey: the caller zeroing its previous key after
// construction leaves the cipher opening what that key sealed.
func TestNewDataCipherWithPrevious_CopiesThePreviousKey(t *testing.T) {
	previous := []byte(testDataKey)
	c, err := NewDataCipherWithPrevious([]byte(otherDataKey), previous)
	if err != nil {
		t.Fatalf("NewDataCipherWithPrevious: %v", err)
	}
	for i := range previous {
		previous[i] = 0
	}
	stored, err := EncryptText("sealed-under-the-previous-key", []byte(testDataKey))
	if err != nil {
		t.Fatalf("EncryptText: %v", err)
	}
	if pt, err := c.Decrypt(stored); err != nil || pt != "sealed-under-the-previous-key" {
		t.Errorf("after the caller zeroed its previous key, Decrypt = %q, %v", pt, err)
	}
}
