package encryption

import (
	"bytes"

	"github.com/leodip/goiabada/core/errs"
)

// DataCipher encrypts and decrypts secrets stored at rest under the data key. main builds
// one from the configured keys and hands it to every consumer, so no service reaches for a
// process-wide key and a test holds a cipher of its own rather than swapping a shared one
// (#434). The keys still come from the environment and never from the row they protect
// (#83).
//
// While the data key is being rotated the cipher also holds the previous key: it opens a
// stored secret with the current key and then the previous one, and seals with the current
// key alone, as the session keys do (#492 decision 2). Two auth servers on neighboring
// configurations of a rotation then each open what the other seals.
type DataCipher struct {
	key      []byte
	previous []byte // nil unless a rotation is under way
}

// NewDataCipher builds the cipher over a 32-byte AES-256 key. The key is copied, so a
// caller reusing or zeroing its slice afterwards cannot change what the cipher seals with.
func NewDataCipher(key []byte) (*DataCipher, error) {
	if len(key) != 32 {
		return nil, errs.Errorf("data encryption key must be 32 bytes, but it has %d bytes", len(key))
	}
	return &DataCipher{key: append([]byte(nil), key...)}, nil
}

// NewDataCipherWithPrevious builds the cipher over the current key and the previous one,
// both 32-byte AES-256 keys, for a data key under rotation. A previous key that is absent, or
// equal to the current one, takes no part, and the cipher is NewDataCipher's. Both keys are
// copied.
func NewDataCipherWithPrevious(current, previous []byte) (*DataCipher, error) {
	c, err := NewDataCipher(current)
	if err != nil {
		return nil, err
	}
	if len(previous) == 0 || bytes.Equal(previous, current) {
		return c, nil
	}
	if len(previous) != 32 {
		return nil, errs.Errorf("previous data encryption key must be 32 bytes, but it has %d bytes", len(previous))
	}
	c.previous = append([]byte(nil), previous...)
	return c, nil
}

// errNilDataCipher is what both methods answer on a nil receiver: a consumer handed no
// cipher fails its first encryption rather than panicking the request serving it.
func errNilDataCipher() error {
	return errs.New("data cipher is nil: build one with encryption.NewDataCipher")
}

// Encrypt seals a secret for storage at rest, under the current key. The format is
// EncryptText's, so what it writes the re-encryption sweep's DecryptText reads.
func (c *DataCipher) Encrypt(plaintext string) ([]byte, error) {
	if c == nil {
		return nil, errNilDataCipher()
	}
	return EncryptText(plaintext, c.key)
}

// Decrypt opens a secret stored at rest, including one EncryptText sealed under the same
// key: with the current key, and then, when the cipher holds one, with the previous key.
// A value neither opens answers an error saying so, which is what reaches the record an
// operator reads; with no previous key the error is the current key's own.
func (c *DataCipher) Decrypt(ciphertext []byte) (string, error) {
	if c == nil {
		return "", errNilDataCipher()
	}
	plaintext, err := DecryptText(ciphertext, c.key)
	if err == nil || c.previous == nil {
		return plaintext, err
	}
	plaintext, previousErr := DecryptText(ciphertext, c.previous)
	if previousErr == nil {
		return plaintext, nil
	}
	return "", errs.Errorf("the value decrypts under neither the current data encryption key nor the previous one: %w", err)
}
