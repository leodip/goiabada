package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"math"

	"github.com/pkg/errors"
)

func EncryptText(text string, encryptionKey []byte) ([]byte, error) {

	if len(text) == 0 {
		return nil, errors.WithStack(errors.New("text to encrypt is empty"))
	}

	if len(encryptionKey) != 32 {
		return nil, errors.WithStack(fmt.Errorf("encryption key must have 32 bytes, but it has %v bytes", len(encryptionKey)))
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
		return "", errors.WithStack(errors.New("encrypted text is empty"))
	}

	if len(encryptionKey) != 32 {
		return "", errors.WithStack(fmt.Errorf("encryption key must have 32 bytes, but it has %v bytes", len(encryptionKey)))
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
		return "", errors.WithStack(errors.New("encrypted text is too short"))
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

func AesGcmEncryption(idTokenUnencrypted string, clientSecret string) (string, error) {
	key := make([]byte, 32)

	// Use the first 32 bytes of the client secret as key
	keyBytes := []byte(clientSecret)
	copy(key, keyBytes[:int(math.Min(float64(len(keyBytes)), float64(len(key))))])

	// Random nonce
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	cipherText := aesGcm.Seal(nil, nonce, []byte(idTokenUnencrypted), nil)

	// Concatenate nonce (12 bytes) + ciphertext (? bytes) + tag (16 bytes)
	encrypted := make([]byte, len(nonce)+len(cipherText))
	copy(encrypted, nonce)
	copy(encrypted[len(nonce):], cipherText)

	return base64.StdEncoding.EncodeToString(encrypted), nil
}
