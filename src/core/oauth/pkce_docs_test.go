package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

// TestDocumentationGoSnippet tests the Go code snippet from the PKCE documentation
// to ensure it produces the same result as the actual implementation.
//
// Documentation snippet:
//
//	func generateCodeChallenge(verifier string) string {
//	    h := sha256.Sum256([]byte(verifier))
//	    return base64.RawURLEncoding.EncodeToString(h[:])
//	}
func TestDocumentationGoSnippet(t *testing.T) {
	// This is the exact code from the documentation
	generateCodeChallenge := func(verifier string) string {
		h := sha256.Sum256([]byte(verifier))
		return base64.RawURLEncoding.EncodeToString(h[:])
	}

	// RFC 7636 Appendix B test vector
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	expectedChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	// Test documentation snippet
	docResult := generateCodeChallenge(codeVerifier)
	if docResult != expectedChallenge {
		t.Errorf("Documentation Go snippet: got %q, want %q", docResult, expectedChallenge)
	}

	// Verify it matches the actual implementation
	actualResult := GeneratePKCECodeChallenge(codeVerifier)
	if docResult != actualResult {
		t.Errorf("Documentation snippet doesn't match actual implementation: doc=%q, actual=%q", docResult, actualResult)
	}
}
