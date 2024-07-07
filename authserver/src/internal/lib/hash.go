package lib

import (
	"crypto/sha256"
	"fmt"

	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

// HashString can hash strings of any length
func HashString(s string) (string, error) {
	h := sha256.New()
	_, err := h.Write([]byte(s))
	if err != nil {
		return "", errors.Wrap(err, "unable to hash")
	}
	bs := h.Sum(nil)
	hex := fmt.Sprintf("%x", bs)
	return hex, nil
}

func VerifyStringHash(hashedString string, s string) bool {
	hash, err := HashString(s)
	if err != nil {
		return false
	}
	return hash == hashedString
}

// The maximum length for password is 72 bytes
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", errors.Wrap(err, "unable to hash")
	}
	return string(hash), nil
}

func VerifyPasswordHash(hashedPassword string, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}
