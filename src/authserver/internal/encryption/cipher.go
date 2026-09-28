package encryption

import "github.com/leodip/goiabada/core/errs"

// dataCipher holds the process-wide data-at-rest encryption key, set once at
// startup via InitDataCipher. EncryptData/DecryptData use it so callers do not
// have to thread the key through every layer, and so the key is sourced from the
// environment rather than co-located with the ciphertext (issue #83).
//
// The startup re-encryption migration, which needs the old and new keys at the
// same time, uses the key-parameterized EncryptText/DecryptText directly instead
// of this package-wide cipher.
var dataCipher []byte

// InitDataCipher sets the process-wide data-encryption key. It must be called
// once at startup, after config is loaded and before the database is opened,
// with a 32-byte key (config.GetAESEncryptionKey()). Tests may call it to set up
// the cipher.
func InitDataCipher(key []byte) error {
	if len(key) != 32 {
		return errs.New("data encryption key must be 32 bytes")
	}
	dataCipher = key
	return nil
}

// IsDataCipherInitialized reports whether the data cipher has been initialized.
func IsDataCipherInitialized() bool {
	return len(dataCipher) == 32
}

// DataCipher encrypts and decrypts secrets stored at rest under the data key. main builds
// one from the configured key and hands it to every consumer, so no service reaches for a
// process-wide key and a test holds a cipher of its own rather than swapping a shared one
// (#434). The key still comes from the environment and never from the row it protects
// (#83).
type DataCipher struct {
	key []byte
}

// NewDataCipher builds the cipher over a 32-byte AES-256 key. The key is copied, so a
// caller reusing or zeroing its slice afterwards cannot change what the cipher seals with.
func NewDataCipher(key []byte) (*DataCipher, error) {
	if len(key) != 32 {
		return nil, errs.Errorf("data encryption key must be 32 bytes, but it has %d bytes", len(key))
	}
	return &DataCipher{key: append([]byte(nil), key...)}, nil
}

// errNilDataCipher is what both methods answer on a nil receiver: a consumer handed no
// cipher fails its first encryption rather than panicking the request serving it.
func errNilDataCipher() error {
	return errs.New("data cipher is nil: build one with encryption.NewDataCipher")
}

// Encrypt seals a secret for storage at rest. The format is EncryptText's, so what it
// writes the re-encryption sweep's DecryptText reads.
func (c *DataCipher) Encrypt(plaintext string) ([]byte, error) {
	if c == nil {
		return nil, errNilDataCipher()
	}
	return EncryptText(plaintext, c.key)
}

// Decrypt opens a secret stored at rest, including one EncryptText sealed under the same
// key.
func (c *DataCipher) Decrypt(ciphertext []byte) (string, error) {
	if c == nil {
		return "", errNilDataCipher()
	}
	return DecryptText(ciphertext, c.key)
}

// EncryptData encrypts a secret for storage at rest using the process-wide data
// key set by InitDataCipher.
func EncryptData(plaintext string) ([]byte, error) {
	if len(dataCipher) != 32 {
		return nil, errs.New("data cipher not initialized: call encryption.InitDataCipher at startup")
	}
	return EncryptText(plaintext, dataCipher)
}

// DecryptData decrypts a secret stored at rest using the process-wide data key
// set by InitDataCipher.
func DecryptData(ciphertext []byte) (string, error) {
	if len(dataCipher) != 32 {
		return "", errs.New("data cipher not initialized: call encryption.InitDataCipher at startup")
	}
	return DecryptText(ciphertext, dataCipher)
}
