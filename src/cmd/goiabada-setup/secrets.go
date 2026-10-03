package main

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/leodip/goiabada/core/securerandom"
)

func generateHexKey(bytes int) string {
	key := make([]byte, bytes)
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(key)
}

// generatedAlphabet is the letters and digits every generated password and secret is drawn over.
const generatedAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// generatedPasswordLength is the length of every password the wizard generates.
const generatedPasswordLength = 16

// generatePassword is a generated admin or database password. It is redrawn whole until it holds
// an uppercase letter, a lowercase letter and a digit, which keeps it uniform over the passwords
// that do: SQL Server refuses an SA password with fewer than three character classes and its
// container exits, and one uniform 16-character draw in 17 had no digit (#430).
func generatePassword() string {
	for {
		password := securerandom.StringFromAlphabet(generatedPasswordLength, generatedAlphabet)
		if hasThreeClasses(password) {
			return password
		}
	}
}

// hasThreeClasses reports whether s holds an ASCII uppercase letter, lowercase letter and digit.
func hasThreeClasses(s string) bool {
	var upper, lower, digit bool
	for _, c := range s {
		switch {
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= '0' && c <= '9':
			digit = true
		}
	}
	return upper && lower && digit
}

// generateSecret is a secret no one types, the OAuth client secret: a plain uniform draw, with no
// character classes to hold.
func generateSecret(length int) string {
	return securerandom.StringFromAlphabet(length, generatedAlphabet)
}
