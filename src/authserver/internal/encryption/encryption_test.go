package encryption

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	tests := []struct {
		name string
		text string
	}{
		{"Empty", ""},
		{"Short", "Hello"},
		{"Long", "This is a longer text to encrypt and decrypt"},
	}

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := EncryptText(tt.text, key)
			if tt.text == "" {
				if err == nil {
					t.Error("Expected error for empty text, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("EncryptText() error = %v", err)
			}

			decrypted, err := DecryptText(encrypted, key)
			if err != nil {
				t.Fatalf("DecryptText() error = %v", err)
			}

			if decrypted != tt.text {
				t.Errorf("DecryptText() = %v, want %v", decrypted, tt.text)
			}
		})
	}
}

func TestInvalidKey(t *testing.T) {
	text := "Test text"
	invalidKey := make([]byte, 16)

	_, err := EncryptText(text, invalidKey)
	if err == nil {
		t.Error("Expected error for invalid key length, got nil")
	}

	_, err = DecryptText([]byte("invalid"), invalidKey)
	if err == nil {
		t.Error("Expected error for invalid key length, got nil")
	}
}

func TestDecryptInvalidText(t *testing.T) {
	key := make([]byte, 32)
	_, err := DecryptText([]byte("invalid"), key)
	if err == nil {
		t.Error("Expected error for invalid encrypted text, got nil")
	}
}

func TestEncryptDifferentResults(t *testing.T) {
	text := "Test text"
	key := make([]byte, 32)

	encrypted1, _ := EncryptText(text, key)
	encrypted2, _ := EncryptText(text, key)

	if bytes.Equal(encrypted1, encrypted2) {
		t.Error("Encrypted results should be different due to random nonce")
	}
}
