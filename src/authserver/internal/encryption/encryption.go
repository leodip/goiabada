// Package encryption holds the symmetric encryption the auth server applies to data
// at rest and to the one value a client hands it encrypted: the AES-GCM data cipher
// over client secrets and OTP secrets, the standalone EncryptText/DecryptText pair
// the re-encryption sweep uses when the data key changes, the JWE encoding of an
// encrypted id_token_hint, and the random key generation the rest of it stands on.
//
// It belongs to the auth server because nothing else holds the data encryption key
// or writes a row that needs one; the admin console reaches every encrypted value
// through the admin API instead (#360).
package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/leodip/goiabada/core/errs"
)

func EncryptText(text string, encryptionKey []byte) ([]byte, error) {

	if len(text) == 0 {
		return nil, errs.New("text to encrypt is empty")
	}

	if len(encryptionKey) != 32 {
		return nil, errs.Errorf("encryption key must have 32 bytes, but it has %v bytes", len(encryptionKey))
	}

	// create a new AES cipher block
	c, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}

	// create a new GCM (Galois/Counter Mode) cipher
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	// generate a random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// encrypt the text using GCM
	result := gcm.Seal(nonce, nonce, []byte(text), nil)
	return result, nil
}

func DecryptText(encryptedText []byte, encryptionKey []byte) (string, error) {
	if len(encryptedText) == 0 {
		return "", errs.New("encrypted text is empty")
	}

	if len(encryptionKey) != 32 {
		return "", errs.Errorf("encryption key must have 32 bytes, but it has %v bytes", len(encryptionKey))
	}

	// create a new AES cipher block
	c, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	// create a new GCM (Galois/Counter Mode) cipher
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", err
	}

	// nonce size
	nonceSize := gcm.NonceSize()
	if len(encryptedText) < nonceSize {
		return "", errs.New("encrypted text is too short")
	}

	// split the nonce and ciphertext
	nonce, ciphertext := encryptedText[:nonceSize], encryptedText[nonceSize:]

	// decrypt the text
	decryptedText, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(decryptedText), nil
}
