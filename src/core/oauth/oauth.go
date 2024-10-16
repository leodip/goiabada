package oauth

import (
	"crypto/sha256"
	"encoding/base64"
)

func GeneratePKCECodeChallenge(codeVerifier string) string {
	bytes := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(bytes[:])
}
