package passwordhash

import (
	"errors"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"golang.org/x/crypto/bcrypt"
)

func TestHash(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"Normal password", "password123", false},
		{"Empty password", "", false},
		{"Max length password", fake.LetterN(MaxPasswordBytes), false},
		{"Exceeds max length", fake.LetterN(MaxPasswordBytes + 1), true},
		// 36 two-byte characters are 72 bytes and pass; 37 are 74 and do not, although both
		// are far fewer than 72 characters. The bound is bcrypt's, and bcrypt counts bytes.
		{"Max length in two-byte characters", strings.Repeat("é", MaxPasswordBytes/2), false},
		{"Exceeds max length in two-byte characters", strings.Repeat("é", MaxPasswordBytes/2+1), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Hash(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("Hash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && !errors.Is(err, bcrypt.ErrPasswordTooLong) {
				t.Errorf("Hash() error = %v, want it to wrap bcrypt.ErrPasswordTooLong", err)
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

// TestVerify_RefusesAnythingPastTheStoredPassword pins that Verify compares the whole submitted
// password. bcrypt keys on at most MaxPasswordBytes bytes plus a trailing NUL: below the bound the
// NUL is part of the key, so a suffix never matched, but at exactly the bound it falls off, and
// bcrypt alone would accept the stored password with anything appended. Verify refuses a password
// past the bound before comparing, which NIST SP 800-63B-4 3.1.1.2 asks ("SHALL verify the entire
// submitted password") and which no stored hash can lose by, since Hash refuses those (#550).
func TestVerify_RefusesAnythingPastTheStoredPassword(t *testing.T) {
	tests := []struct {
		name   string
		length uint
	}{
		{"At the bound", MaxPasswordBytes},
		{"One byte below the bound", MaxPasswordBytes - 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			password := fake.LetterN(tt.length)
			hashed, err := Hash(password)
			if err != nil {
				t.Fatalf("Hash() error = %v", err)
			}

			if !Verify(hashed, password) {
				t.Error("Verify() = false for the stored password")
			}
			if Verify(hashed, password+"x") {
				t.Error("Verify() = true for the stored password plus one byte")
			}
			if Verify(hashed, password+strings.Repeat("x", MaxPasswordBytes)) {
				t.Error("Verify() = true for the stored password plus a long suffix")
			}
			if Verify(hashed, password[:tt.length-1]) {
				t.Error("Verify() = true for the stored password less its last byte")
			}
		})
	}

	// A two-byte character appended to a password at the bound is refused like any other
	// suffix: the bound is in bytes, as Hash's is.
	t.Run("Past the bound by a multi-byte character", func(t *testing.T) {
		password := fake.LetterN(MaxPasswordBytes)
		hashed, err := Hash(password)
		if err != nil {
			t.Fatalf("Hash() error = %v", err)
		}
		if Verify(hashed, password+"é") {
			t.Error("Verify() = true for the stored password plus a two-byte character")
		}
	})
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

	t.Run("DummyHash refuses a password past the bound", func(t *testing.T) {
		// The missing-account path compares against DummyHash through Verify too, so it takes the
		// same refusal a real account does for a password past the bound.
		if Verify(DummyHash, fake.LetterN(MaxPasswordBytes+1)) {
			t.Error("DummyHash should not verify against a password past the bound")
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
