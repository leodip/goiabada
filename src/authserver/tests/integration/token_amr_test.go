package integrationtests

import (
	"net/url"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/config"
	"github.com/stretchr/testify/assert"
)

// ============================================================================
// AMR (Authentication Methods Reference) format tests
// OIDC Core 1.0 Section 2 requires amr to be a JSON array of strings
// ============================================================================

// TestToken_AuthCode_AMR_IsArray verifies that AMR in tokens is a JSON array per OIDC spec
func TestToken_AuthCode_AMR_IsArray(t *testing.T) {
	clientSecret := gofakeit.LetterN(32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
		"client_secret": {clientSecret},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	// Verify we got tokens
	assert.NotNil(t, data["access_token"])
	assert.NotNil(t, data["id_token"])

	// Decode and verify access_token AMR is an array
	accessToken := data["access_token"].(string)
	accessClaims := decodeJWTPayload(t, accessToken)

	amrAccess := accessClaims["amr"]
	assert.NotNil(t, amrAccess, "access_token must contain amr claim")
	amrArrayAccess, ok := amrAccess.([]interface{})
	assert.True(t, ok, "amr in access_token must be a JSON array, got %T", amrAccess)
	assert.GreaterOrEqual(t, len(amrArrayAccess), 1, "amr array must contain at least one method")

	// Decode and verify id_token AMR is an array
	idToken := data["id_token"].(string)
	idClaims := decodeJWTPayload(t, idToken)

	amrId := idClaims["amr"]
	assert.NotNil(t, amrId, "id_token must contain amr claim")
	amrArrayId, ok := amrId.([]interface{})
	assert.True(t, ok, "amr in id_token must be a JSON array, got %T", amrId)
	assert.GreaterOrEqual(t, len(amrArrayId), 1, "amr array must contain at least one method")

	// Verify the array contains "pwd" (password authentication)
	// Since this is a normal auth code flow, at minimum pwd should be present
	assert.Contains(t, amrArrayAccess, "pwd", "amr should contain 'pwd' for password authentication")
	assert.Contains(t, amrArrayId, "pwd", "amr should contain 'pwd' for password authentication")
}

// TestToken_Refresh_AMR_IsArray verifies AMR is preserved as array through refresh
func TestToken_Refresh_AMR_IsArray(t *testing.T) {
	clientSecret := gofakeit.LetterN(32)
	// Use "openid profile email" instead of "offline_access" to avoid consent flow
	// The auth code flow still returns a refresh token with these scopes
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	// First, get initial tokens
	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
		"client_secret": {clientSecret},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)
	assert.NotNil(t, data["refresh_token"])

	// Refresh the token
	refreshToken := data["refresh_token"].(string)
	refreshFormData := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {code.Client.ClientIdentifier},
		"refresh_token": {refreshToken},
		"client_secret": {clientSecret},
	}

	refreshData := postToTokenEndpoint(t, httpClient, destUrl, refreshFormData)
	assert.NotNil(t, refreshData["access_token"])

	// Verify AMR is still an array after refresh
	accessToken := refreshData["access_token"].(string)
	accessClaims := decodeJWTPayload(t, accessToken)

	amrAccess := accessClaims["amr"]
	assert.NotNil(t, amrAccess, "access_token after refresh must contain amr claim")
	amrArrayAccess, ok := amrAccess.([]interface{})
	assert.True(t, ok, "amr in refreshed access_token must be a JSON array, got %T", amrAccess)
	assert.Contains(t, amrArrayAccess, "pwd", "amr should contain 'pwd' after refresh")
}
