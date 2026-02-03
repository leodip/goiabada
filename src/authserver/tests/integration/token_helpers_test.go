package integrationtests

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// decodeJWTPayload extracts and decodes the payload from a JWT
func decodeJWTPayload(t *testing.T, token string) map[string]interface{} {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("Invalid JWT format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("Failed to decode JWT payload: %v", err)
	}

	var claims map[string]interface{}
	err = json.Unmarshal(payload, &claims)
	if err != nil {
		t.Fatalf("Failed to unmarshal JWT claims: %v", err)
	}

	return claims
}
