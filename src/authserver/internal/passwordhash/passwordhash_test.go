package passwordhash

import (
	"testing"

	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
)

func TestHash(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"Normal password", "password123", false},
		{"Empty password", "", false},
		{"Max length password", fake.LetterN(72), false},
		{"Exceeds max length", fake.LetterN(73), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Hash(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("Hash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got == "" {
				t.Errorf("Hash() returned empty string")
			}
		})
	}
}

func TestVerify(t *testing.T) {
	password := "password123"
	hashedPassword, _ := Hash(password)

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
			if got := Verify(tt.hashedPassword, tt.password); got != tt.wantVerified {
				t.Errorf("Verify() = %v, want %v", got, tt.wantVerified)
			}
		})
	}
}

func TestDummyHash(t *testing.T) {
	// Verify that DummyHash is a valid bcrypt hash that can be used
	// for timing-safe user enumeration protection. The hash should be parseable
	// by bcrypt and work with Verify without errors or panics.

	t.Run("DummyHash is a valid bcrypt hash", func(t *testing.T) {
		// This should not panic and should return false (since we're not using the original password)
		result := Verify(DummyHash, "any_password_here")
		if result {
			t.Error("DummyHash should not verify against arbitrary passwords")
		}
	})

	t.Run("DummyHash works with empty password", func(t *testing.T) {
		// Ensure it handles empty passwords gracefully (important for timing protection)
		result := Verify(DummyHash, "")
		if result {
			t.Error("DummyHash should not verify against empty password")
		}
	})

	t.Run("DummyHash has correct bcrypt format", func(t *testing.T) {
		// Bcrypt hashes start with $2a$, $2b$, or $2y$ followed by cost factor
		if len(DummyHash) < 60 {
			t.Errorf("DummyHash length %d is too short for bcrypt (expected >= 60)", len(DummyHash))
		}
		if DummyHash[0:4] != "$2a$" && DummyHash[0:4] != "$2b$" && DummyHash[0:4] != "$2y$" {
			t.Errorf("DummyHash does not have valid bcrypt prefix: %s", DummyHash[0:4])
		}
	})
}
