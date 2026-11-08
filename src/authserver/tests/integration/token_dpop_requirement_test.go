package integration

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/dpop/dpoptest"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
)

// A client set to "Require DPoP for token requests" is refused every token request without a DPoP
// header, 400 invalid_dpop_proof (RFC 9449 section 5.2 MUST, #42 decision 12), on all four grants,
// and answered a bound token with one. The refusal is decided once the client has authenticated, so
// a wrong secret is still invalid_client and a stranger learns nothing of the setting, and before the
// grant, so no password is compared and no code is spent.

// requiresDPoPRefusal is the refusal of a token request without a proof from a client that requires
// DPoP.
var requiresDPoPRefusal = map[string]any{
	"error":             "invalid_dpop_proof",
	"error_description": "This client requires a DPoP proof with every token request.",
}

// requireDPoPFor switches the client's requirement on.
func requireDPoPFor(t *testing.T, clientId int64) {
	t.Helper()
	require.NoError(t, database.SetClientDPoPBoundAccessTokens(context.Background(), nil, clientId, true))
}

// assertRefusedForNoProof holds an answer to the requirement's refusal: a request without a DPoP
// header is no DPoP request, so it carries no nonce.
func assertRefusedForNoProof(t *testing.T, resp *http.Response, body map[string]any) {
	t.Helper()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, requiresDPoPRefusal, body)
	assert.Empty(t, resp.Header.Values("DPoP-Nonce"))
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
}

func TestDPoPRequirement_TheClientCredentialsGrant(t *testing.T) {
	clientSecret := fake.Password(32)
	secretEncrypted, err := dataCipher.Encrypt(clientSecret)
	require.NoError(t, err)
	resource := createResourceWithId(t, "dpop-required-api-"+fake.LetterN(8))
	permission := createPermissionWithId(t, resource.Id, "read-"+fake.LetterN(8))
	client := &record.Client{
		ClientIdentifier:         "dpop-required-service-" + fake.LetterN(8),
		Enabled:                  true,
		ClientCredentialsEnabled: true,
		DefaultAcrLevel:          record.AcrLevel2Optional,
		ClientSecretEncrypted:    secretEncrypted,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	require.NoError(t, database.CreateClientPermission(context.Background(), nil,
		&record.ClientPermission{ClientId: client.Id, PermissionId: permission.Id}))
	form := url.Values{"grant_type": {"client_credentials"}}

	// Before the requirement, the same request is answered a Bearer token.
	resp, body := postWithProof(t, form, client.ClientIdentifier, clientSecret, "")
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", body)
	assert.Equal(t, "Bearer", body["token_type"])

	requireDPoPFor(t, client.Id)

	resp, body = postWithProof(t, form, client.ClientIdentifier, clientSecret, "")
	assertRefusedForNoProof(t, resp, body)

	resp, body = postWithProof(t, form, client.ClientIdentifier, "not-the-secret", "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "client authentication is decided first")
	assert.Equal(t, "invalid_client", body["error"])

	redeemWithDPoP(t, form, client.ClientIdentifier, clientSecret, dpoptest.RFC7517Key(t))
}

// The code is not spent by the refusal: the same code is then redeemed with a proof, and the
// refresh after it is refused without a proof and answered with one.
func TestDPoPRequirement_TheAuthorizationCodeAndRefreshTokenGrants(t *testing.T) {
	clientSecret := fake.Password(32)
	_, code := createAuthCode(t, clientSecret, "openid profile")
	requireDPoPFor(t, code.ClientId)
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {testCodeVerifier},
	}

	resp, body := postWithProof(t, form, code.Client.ClientIdentifier, clientSecret, "")
	assertRefusedForNoProof(t, resp, body)

	body = redeemWithDPoP(t, form, code.Client.ClientIdentifier, clientSecret, dpoptest.RFC7517Key(t))
	refreshToken, ok := body["refresh_token"].(string)
	require.True(t, ok, "a refresh token: %v", body)
	refreshForm := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}

	resp, body = postWithProof(t, refreshForm, code.Client.ClientIdentifier, clientSecret, "")
	assertRefusedForNoProof(t, resp, body)

	redeemWithDPoP(t, refreshForm, code.Client.ClientIdentifier, clientSecret, dpoptest.RFC7515Key(t))
}

// Refused before the password is looked at: a wrong password without a proof is answered the
// requirement's refusal, not invalid_grant.
func TestDPoPRequirement_ThePasswordGrant(t *testing.T) {
	changeSettings(t, func(settings *record.Settings) { settings.ResourceOwnerPasswordCredentialsEnabled = true })
	clientSecret := fake.Password(32)
	client := createROPCClient(t, clientSecret, false)
	password := fake.Password(12)
	user := createROPCUser(t, password)
	requireDPoPFor(t, client.Id)
	form := func(password string) url.Values {
		return url.Values{"grant_type": {"password"}, "username": {user.Email}, "password": {password}, "scope": {"openid"}}
	}

	resp, body := postWithProof(t, form("not-the-password"), client.ClientIdentifier, clientSecret, "")
	assertRefusedForNoProof(t, resp, body)
	resp, body = postWithProof(t, form(password), client.ClientIdentifier, clientSecret, "")
	assertRefusedForNoProof(t, resp, body)

	redeemWithDPoP(t, form(password), client.ClientIdentifier, clientSecret, dpoptest.RFC7517Key(t))
}
