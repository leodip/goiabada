package integrationtests

import (
	"net/url"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

func TestToken_AuthCode_MissingCode(t *testing.T) {
	httpClient, code := createAuthCode(t, gofakeit.LetterN(32), "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {gofakeit.LetterN(43)},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_request", data["error"])
	assert.Equal(t, "Missing required code parameter.", data["error_description"])
}

func TestToken_AuthCode_MissingRedirectURI(t *testing.T) {
	httpClient, code := createAuthCode(t, gofakeit.LetterN(32), "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"code_verifier": {gofakeit.LetterN(43)},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_request", data["error"])
	assert.Equal(t, "Missing required redirect_uri parameter.", data["error_description"])
}

func TestToken_AuthCode_MissingCodeVerifier(t *testing.T) {
	clientSecret := gofakeit.LetterN(32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"client_secret": {clientSecret},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_request", data["error"])
	assert.Equal(t, "Missing required code_verifier parameter.", data["error_description"])
}

func TestToken_AuthCode_ClientDoesNotExist(t *testing.T) {
	httpClient, code := createAuthCode(t, gofakeit.LetterN(32), "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"non-existent-client"},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {gofakeit.LetterN(43)},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_request", data["error"])
	assert.Equal(t, "Client does not exist.", data["error_description"])
}

func TestToken_AuthCode_CodeIsInvalid(t *testing.T) {
	httpClient, code := createAuthCode(t, gofakeit.LetterN(32), "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {"invalid_code"},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {gofakeit.LetterN(43)},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_grant", data["error"])
	assert.Equal(t, "Code is invalid.", data["error_description"])
}

func TestToken_AuthCode_RedirectURIIsInvalid(t *testing.T) {
	httpClient, code := createAuthCode(t, gofakeit.LetterN(32), "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {"https://invalid-redirect-uri.com"},
		"code_verifier": {gofakeit.LetterN(43)},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_grant", data["error"])
	assert.Equal(t, "Invalid redirect_uri.", data["error_description"])
}

func TestToken_AuthCode_WrongClient(t *testing.T) {
	httpClient, code := createAuthCode(t, gofakeit.LetterN(32), "openid profile email")

	// Create a new client to use as the wrong client
	wrongClient := &models.Client{
		ClientIdentifier:         "wrong-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
	}
	err := database.CreateClient(nil, wrongClient)
	assert.NoError(t, err)

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {wrongClient.ClientIdentifier}, // Use the wrong client ID
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {gofakeit.LetterN(43)},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_grant", data["error"])
	assert.Equal(t, "The client_id provided does not match the client_id from code.", data["error_description"])
}

func TestToken_AuthCode_ConfidentialClient_NoClientSecret(t *testing.T) {
	httpClient, code := createAuthCode(t, gofakeit.LetterN(32), "openid profile email")

	// Ensure the client is not public (confidential)
	code.Client.IsPublic = false
	err := database.UpdateClient(nil, &code.Client)
	assert.NoError(t, err)

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {gofakeit.LetterN(43)},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	// RFC 6749 Section 5.2: invalid_client for missing client credentials
	assert.Equal(t, "invalid_client", data["error"])
	assert.Equal(t, "This client is configured as confidential (not public), which means a client_secret is required for authentication. Please provide a valid client_secret to proceed.", data["error_description"])
}

func TestToken_AuthCode_ConfidentialClient_ClientAuthFailed(t *testing.T) {
	clientSecret := gofakeit.LetterN(32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	// Ensure the client is confidential (not public)
	code.Client.IsPublic = false
	err := database.UpdateClient(nil, &code.Client)
	assert.NoError(t, err)

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {gofakeit.LetterN(43)},
		"client_secret": {"incorrect_secret"}, // Provide an incorrect client secret
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	// RFC 6749 Section 5.2: invalid_client for failed client authentication
	assert.Equal(t, "invalid_client", data["error"])
	assert.Equal(t, "Client authentication failed. Please review your client_secret.", data["error_description"])
}

func TestToken_AuthCode_InvalidCodeVerifier(t *testing.T) {
	clientSecret := gofakeit.LetterN(32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	code.Client.IsPublic = false
	err := database.UpdateClient(nil, &code.Client)
	assert.NoError(t, err)

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"invalid_code_verifier"}, // Using an invalid code verifier
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_grant", data["error"])
	assert.Equal(t, "Invalid code_verifier (PKCE).", data["error_description"])
}

func TestToken_AuthCode_SuccessPath(t *testing.T) {
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
