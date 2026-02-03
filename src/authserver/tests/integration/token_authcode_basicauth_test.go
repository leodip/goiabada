package integrationtests

import (
	"net/url"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/config"
	"github.com/stretchr/testify/assert"
)

// ============================================================================
// client_secret_basic tests (HTTP Basic Authentication)
// ============================================================================

func TestToken_AuthCode_ClientSecretBasic_Success(t *testing.T) {
	clientSecret := gofakeit.LetterN(32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	// Use Basic auth instead of client_secret in form body
	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
	}

	data := postToTokenEndpointWithBasicAuth(t, httpClient, destUrl, formData, code.Client.ClientIdentifier, clientSecret)

	assert.NotNil(t, data["access_token"])
	assert.NotNil(t, data["token_type"])
	assert.Equal(t, "Bearer", data["token_type"])
	assert.NotNil(t, data["expires_in"])
	assert.NotNil(t, data["id_token"])

	// Verify that the code has been marked as used
	usedCode, err := database.GetCodeById(nil, code.Id)
	assert.NoError(t, err)
	assert.True(t, usedCode.Used)
}

func TestToken_AuthCode_ClientSecretBasic_WrongSecret(t *testing.T) {
	clientSecret := gofakeit.LetterN(32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
	}

	// Use wrong secret in Basic auth
	data := postToTokenEndpointWithBasicAuth(t, httpClient, destUrl, formData, code.Client.ClientIdentifier, "wrong_secret")

	// RFC 6749 Section 5.2: invalid_client for failed client authentication
	assert.Equal(t, "invalid_client", data["error"])
	assert.Equal(t, "Client authentication failed. Please review your client_secret.", data["error_description"])
}

func TestToken_AuthCode_ClientSecretBasic_BothMethodsProvided(t *testing.T) {
	clientSecret := gofakeit.LetterN(32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	// Provide client_secret in BOTH Basic auth header AND form body
	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
		"client_secret": {clientSecret}, // Also in form body
	}

	data := postToTokenEndpointWithBasicAuth(t, httpClient, destUrl, formData, code.Client.ClientIdentifier, clientSecret)

	// Should be rejected per RFC 6749
	assert.Equal(t, "invalid_request", data["error"])
	assert.Contains(t, data["error_description"].(string), "multiple authentication methods")
}
