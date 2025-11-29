package oauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseResponseType(t *testing.T) {
	tests := []struct {
		name         string
		responseType string
		wantCode     bool
		wantToken    bool
		wantIdToken  bool
	}{
		// Single valid response types
		{
			name:         "code only",
			responseType: "code",
			wantCode:     true,
			wantToken:    false,
			wantIdToken:  false,
		},
		{
			name:         "token only",
			responseType: "token",
			wantCode:     false,
			wantToken:    true,
			wantIdToken:  false,
		},
		{
			name:         "id_token only",
			responseType: "id_token",
			wantCode:     false,
			wantToken:    false,
			wantIdToken:  true,
		},

		// Multiple response types (OIDC combinations)
		{
			name:         "id_token token",
			responseType: "id_token token",
			wantCode:     false,
			wantToken:    true,
			wantIdToken:  true,
		},
		{
			name:         "token id_token (reversed order)",
			responseType: "token id_token",
			wantCode:     false,
			wantToken:    true,
			wantIdToken:  true,
		},
		{
			name:         "code token (hybrid)",
			responseType: "code token",
			wantCode:     true,
			wantToken:    true,
			wantIdToken:  false,
		},
		{
			name:         "code id_token (hybrid)",
			responseType: "code id_token",
			wantCode:     true,
			wantToken:    false,
			wantIdToken:  true,
		},
		{
			name:         "code id_token token (hybrid)",
			responseType: "code id_token token",
			wantCode:     true,
			wantToken:    true,
			wantIdToken:  true,
		},

		// Empty and whitespace
		{
			name:         "empty string",
			responseType: "",
			wantCode:     false,
			wantToken:    false,
			wantIdToken:  false,
		},
		{
			name:         "whitespace only",
			responseType: "   ",
			wantCode:     false,
			wantToken:    false,
			wantIdToken:  false,
		},
		{
			name:         "tabs only",
			responseType: "\t\t",
			wantCode:     false,
			wantToken:    false,
			wantIdToken:  false,
		},

		// Whitespace handling
		{
			name:         "leading space",
			responseType: " token",
			wantCode:     false,
			wantToken:    true,
			wantIdToken:  false,
		},
		{
			name:         "trailing space",
			responseType: "token ",
			wantCode:     false,
			wantToken:    true,
			wantIdToken:  false,
		},
		{
			name:         "multiple spaces between tokens",
			responseType: "id_token  token",
			wantCode:     false,
			wantToken:    true,
			wantIdToken:  true,
		},
		{
			name:         "tab between tokens",
			responseType: "id_token\ttoken",
			wantCode:     false,
			wantToken:    true,
			wantIdToken:  true,
		},
		{
			name:         "newline between tokens",
			responseType: "id_token\ntoken",
			wantCode:     false,
			wantToken:    true,
			wantIdToken:  true,
		},

		// Invalid/unrecognized response types
		{
			name:         "unrecognized type",
			responseType: "invalid",
			wantCode:     false,
			wantToken:    false,
			wantIdToken:  false,
		},
		{
			name:         "partial match - tokens (plural)",
			responseType: "tokens",
			wantCode:     false,
			wantToken:    false,
			wantIdToken:  false,
		},
		{
			name:         "partial match - id_tokens (plural)",
			responseType: "id_tokens",
			wantCode:     false,
			wantToken:    false,
			wantIdToken:  false,
		},
		{
			name:         "partial match - codes (plural)",
			responseType: "codes",
			wantCode:     false,
			wantToken:    false,
			wantIdToken:  false,
		},

		// Case sensitivity (OAuth is case-sensitive)
		{
			name:         "uppercase CODE",
			responseType: "CODE",
			wantCode:     false,
			wantToken:    false,
			wantIdToken:  false,
		},
		{
			name:         "uppercase TOKEN",
			responseType: "TOKEN",
			wantCode:     false,
			wantToken:    false,
			wantIdToken:  false,
		},
		{
			name:         "uppercase ID_TOKEN",
			responseType: "ID_TOKEN",
			wantCode:     false,
			wantToken:    false,
			wantIdToken:  false,
		},
		{
			name:         "mixed case Code",
			responseType: "Code",
			wantCode:     false,
			wantToken:    false,
			wantIdToken:  false,
		},

		// Mixed valid and invalid
		{
			name:         "valid with unknown type",
			responseType: "token unknown",
			wantCode:     false,
			wantToken:    true,
			wantIdToken:  false,
		},
		{
			name:         "unknown with valid type",
			responseType: "unknown code",
			wantCode:     true,
			wantToken:    false,
			wantIdToken:  false,
		},

		// Duplicates (edge case - should still work)
		{
			name:         "duplicate token",
			responseType: "token token",
			wantCode:     false,
			wantToken:    true,
			wantIdToken:  false,
		},
		{
			name:         "duplicate code",
			responseType: "code code",
			wantCode:     true,
			wantToken:    false,
			wantIdToken:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseResponseType(tt.responseType)
			assert.Equal(t, tt.wantCode, result.HasCode, "HasCode mismatch for %q", tt.responseType)
			assert.Equal(t, tt.wantToken, result.HasToken, "HasToken mismatch for %q", tt.responseType)
			assert.Equal(t, tt.wantIdToken, result.HasIdToken, "HasIdToken mismatch for %q", tt.responseType)
		})
	}
}

func TestResponseTypeInfo_IsImplicitFlow(t *testing.T) {
	tests := []struct {
		name     string
		info     ResponseTypeInfo
		expected bool
	}{
		// Implicit flow cases (token or id_token without code)
		{
			name:     "token only is implicit",
			info:     ResponseTypeInfo{HasCode: false, HasToken: true, HasIdToken: false},
			expected: true,
		},
		{
			name:     "id_token only is implicit",
			info:     ResponseTypeInfo{HasCode: false, HasToken: false, HasIdToken: true},
			expected: true,
		},
		{
			name:     "token and id_token is implicit",
			info:     ResponseTypeInfo{HasCode: false, HasToken: true, HasIdToken: true},
			expected: true,
		},

		// Authorization code flow (code without token/id_token)
		{
			name:     "code only is not implicit",
			info:     ResponseTypeInfo{HasCode: true, HasToken: false, HasIdToken: false},
			expected: false,
		},

		// Hybrid flows (code with token and/or id_token)
		{
			name:     "code with token is hybrid, not implicit",
			info:     ResponseTypeInfo{HasCode: true, HasToken: true, HasIdToken: false},
			expected: false,
		},
		{
			name:     "code with id_token is hybrid, not implicit",
			info:     ResponseTypeInfo{HasCode: true, HasToken: false, HasIdToken: true},
			expected: false,
		},
		{
			name:     "code with token and id_token is hybrid, not implicit",
			info:     ResponseTypeInfo{HasCode: true, HasToken: true, HasIdToken: true},
			expected: false,
		},

		// Empty/none
		{
			name:     "no response types is not implicit",
			info:     ResponseTypeInfo{HasCode: false, HasToken: false, HasIdToken: false},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.info.IsImplicitFlow()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsImplicitFlow_Integration(t *testing.T) {
	// Integration tests using ParseResponseType().IsImplicitFlow() together
	tests := []struct {
		name         string
		responseType string
		expected     bool
	}{
		// Implicit flow response types
		{"token", "token", true},
		{"id_token", "id_token", true},
		{"id_token token", "id_token token", true},
		{"token id_token", "token id_token", true},

		// Authorization code flow
		{"code", "code", false},

		// Hybrid flows (not implicit)
		{"code token", "code token", false},
		{"code id_token", "code id_token", false},
		{"code id_token token", "code id_token token", false},
		{"code token id_token", "code token id_token", false},

		// Empty/invalid
		{"empty", "", false},
		{"whitespace", "   ", false},
		{"invalid", "invalid", false},

		// Case sensitivity
		{"TOKEN uppercase", "TOKEN", false},
		{"ID_TOKEN uppercase", "ID_TOKEN", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseResponseType(tt.responseType).IsImplicitFlow()
			assert.Equal(t, tt.expected, result, "IsImplicitFlow(%q) = %v, want %v", tt.responseType, result, tt.expected)
		})
	}
}
