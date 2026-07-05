package encryption

import "github.com/pkg/errors"

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
		return errors.WithStack(errors.New("data encryption key must be 32 bytes"))
	}
	dataCipher = key
	return nil
}

// IsDataCipherInitialized reports whether the data cipher has been initialized.
func IsDataCipherInitialized() bool {
	return len(dataCipher) == 32
}

// EncryptData encrypts a secret for storage at rest using the process-wide data
// key set by InitDataCipher.
func EncryptData(plaintext string) ([]byte, error) {
	if len(dataCipher) != 32 {
		return nil, errors.WithStack(errors.New("data cipher not initialized: call encryption.InitDataCipher at startup"))
	}
	return EncryptText(plaintext, dataCipher)
}

// DecryptData decrypts a secret stored at rest using the process-wide data key
// set by InitDataCipher.
func DecryptData(ciphertext []byte) (string, error) {
	if len(dataCipher) != 32 {
		return "", errors.WithStack(errors.New("data cipher not initialized: call encryption.InitDataCipher at startup"))
	}
	return DecryptText(ciphertext, dataCipher)
}
