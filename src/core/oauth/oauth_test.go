package oauth

import (
	"testing"
)

func TestGeneratePKCECodeChallenge(t *testing.T) {
	tests := []struct {
		name         string
		codeVerifier string
		expected     string
	}{
		{
			name:         "Basic test case",
			codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			expected:     "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		},
		{
			name:         "Empty string",
			codeVerifier: "",
			expected:     "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
		},
		{
			name:         "Alphanumeric string",
			codeVerifier: "abc123XYZ",
			expected:     "L90zCnMV3MoSgPw4PzCSDD1uR62jV3ZdeBahXNlh4mc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GeneratePKCECodeChallenge(tt.codeVerifier)
			if result != tt.expected {
				t.Errorf("GeneratePKCECodeChallenge(%q) = %v, want %v", tt.codeVerifier, result, tt.expected)
			}
		})
	}
}
