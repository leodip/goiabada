package hashutil

import (
	"testing"

	"github.com/brianvoe/gofakeit/v6"
)

func TestHashString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantErr  bool
		wantHash string
	}{
		{"Empty string", "", false, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"Normal string", "hello world", false, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"},
		{"Long string", "Lorem ipsum dolor sit amet, consectetur adipiscing elit.", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HashString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("HashString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.wantHash && tt.wantHash != "" {
				t.Errorf("HashString() = %v, want %v", got, tt.wantHash)
			}
		})
	}
}

func TestVerifyStringHash(t *testing.T) {
	tests := []struct {
		name         string
		hashedString string
		input        string
		wantVerified bool
	}{
		{"Correct hash", "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", "hello world", true},
		{"Incorrect hash", "incorrecthash", "hello world", false},
		{"Empty string", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VerifyStringHash(tt.hashedString, tt.input); got != tt.wantVerified {
				t.Errorf("VerifyStringHash() = %v, want %v", got, tt.wantVerified)
			}
		})
	}
}

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"Normal password", "password123", false},
		{"Empty password", "", false},
		{"Max length password", gofakeit.LetterN(72), false},
		{"Exceeds max length", gofakeit.LetterN(73), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HashPassword(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("HashPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got == "" {
				t.Errorf("HashPassword() returned empty string")
			}
		})
	}
}

func TestVerifyPasswordHash(t *testing.T) {
	password := "password123"
	hashedPassword, _ := HashPassword(password)

	tests := []struct {
		name           string
		hashedPassword string
		password       string
		wantVerified   bool
	}{
		{"Correct password", hashedPassword, password, true},
		{"Incorrect password", hashedPassword, "wrongpassword", false},
		{"Empty password", hashedPassword, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VerifyPasswordHash(tt.hashedPassword, tt.password); got != tt.wantVerified {
				t.Errorf("VerifyPasswordHash() = %v, want %v", got, tt.wantVerified)
			}
		})
	}
}
