package oauth

import (
	"testing"
	"time"

	"github.com/leodip/goiabada/core/hashutil"
	"github.com/stretchr/testify/assert"
)

func TestGetAudience(t *testing.T) {
	tests := []struct {
		name     string
		claims   map[string]interface{}
		expected []string
	}{
		{
			name:     "No audience",
			claims:   map[string]interface{}{},
			expected: []string{},
		},
		{
			name:     "Single audience string",
			claims:   map[string]interface{}{"aud": "aud1"},
			expected: []string{"aud1"},
		},
		{
			name:     "Multiple audience array",
			claims:   map[string]interface{}{"aud": []interface{}{"aud1", "aud2"}},
			expected: []string{"aud1", "aud2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jwt := JwtToken{Claims: tt.claims}
			assert.Equal(t, tt.expected, jwt.GetAudience())
		})
	}
}

func TestGetStringClaim(t *testing.T) {
	jwt := JwtToken{Claims: map[string]interface{}{"test": "value"}}
	assert.Equal(t, "value", jwt.GetStringClaim("test"))
	assert.Equal(t, "", jwt.GetStringClaim("nonexistent"))
}

func TestGetTimeClaim(t *testing.T) {
	now := time.Now().Unix()
	jwt := JwtToken{Claims: map[string]interface{}{"time": now}}
	assert.Equal(t, time.Unix(now, 0), jwt.GetTimeClaim("time"))
	assert.Equal(t, time.Time{}, jwt.GetTimeClaim("nonexistent"))
}

func TestGetBoolClaim(t *testing.T) {
	jwt := JwtToken{Claims: map[string]interface{}{"bool": true}}
	assert.Equal(t, true, *jwt.GetBoolClaim("bool"))
	assert.Nil(t, jwt.GetBoolClaim("nonexistent"))
}

func TestGetAddressClaim(t *testing.T) {
	address := map[string]interface{}{"street": "123 Main St", "city": "Anytown"}
	jwt := JwtToken{Claims: map[string]interface{}{"address": address}}
	expected := map[string]string{"street": "123 Main St", "city": "Anytown"}
	assert.Equal(t, expected, jwt.GetAddressClaim())
	assert.Empty(t, JwtToken{Claims: map[string]interface{}{}}.GetAddressClaim())
}

func TestHasScope(t *testing.T) {
	jwt := JwtToken{Claims: map[string]interface{}{"scope": "read write"}}
	assert.True(t, jwt.HasScope("read"))
	assert.True(t, jwt.HasScope("write"))
	assert.False(t, jwt.HasScope("delete"))
	assert.False(t, JwtToken{Claims: map[string]interface{}{}}.HasScope("read"))
}

func TestIsNonceValid(t *testing.T) {
	tests := []struct {
		name          string
		storedNonce   string
		providedNonce string
		expected      bool
	}{
		{
			name:          "Valid nonce",
			storedNonce:   "validHashedNonce",
			providedNonce: "validNonce",
			expected:      true,
		},
		{
			name:          "Invalid nonce",
			storedNonce:   "validHashedNonce",
			providedNonce: "invalidNonce",
			expected:      false,
		},
		{
			name:          "Empty provided nonce",
			storedNonce:   "validHashedNonce",
			providedNonce: "",
			expected:      false,
		},
		{
			name:          "Empty stored nonce",
			storedNonce:   "",
			providedNonce: "someNonce",
			expected:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// If we expect the nonce to be valid, we need to hash the provided nonce
			// to match the behavior of the actual implementation
			if tt.expected {
				hashedNonce, err := hashutil.HashString(tt.providedNonce)
				assert.NoError(t, err)
				tt.storedNonce = hashedNonce
			}

			jwt := JwtToken{Claims: map[string]interface{}{"nonce": tt.storedNonce}}
			assert.Equal(t, tt.expected, jwt.IsNonceValid(tt.providedNonce))
		})
	}
}

func TestIsIssuerValid(t *testing.T) {
	jwt := JwtToken{Claims: map[string]interface{}{"iss": "validIssuer"}}
	assert.True(t, jwt.IsIssuerValid("validIssuer"))
	assert.False(t, jwt.IsIssuerValid("invalidIssuer"))
}
