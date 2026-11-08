package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/dpop/dpoptest"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
)

// DPoP at the token endpoint, through the running server (RFC 9449, #42 decisions 2, 3 and 7):
// every grant answers a proof without a nonce use_dpop_nonce with a DPoP-Nonce header, and the
// retry carrying that nonce gets an access token bound to the proof's key, token_type DPoP and
// cnf.jkt the key's thumbprint, with a fresh nonce on the answer.

// dpopTokenURL is the token endpoint's URL as a proof names it: the public base URL and the path.
func dpopTokenURL() string { return appConfig.AuthServer.BaseURL + "/auth/token" }

// postWithProof posts form to the token endpoint with proof in a DPoP header, and basic
// credentials when clientSecret is not empty, and returns the answer and its JSON body.
func postWithProof(t *testing.T, form url.Values, clientId, clientSecret, proof string) (*http.Response, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, dpopTokenURL(), strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if clientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(clientId), url.QueryEscape(clientSecret))
	}
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	resp, err := createHttpClient(t).Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var body map[string]any
	require.NoError(t, json.Unmarshal(raw, &body), "status %d, body %s", resp.StatusCode, string(raw))
	return resp, body
}

// redeemWithDPoP sends form with a proof by key and no nonce, which is answered use_dpop_nonce,
// then again with the nonce that answer gave, and returns the second answer's body, a bound token
// response. nonce, when not empty, is a nonce from an earlier answer, used from the start.
func redeemWithDPoP(t *testing.T, form url.Values, clientId, clientSecret string, key dpoptest.Key) map[string]any {
	t.Helper()
	resp, body := postWithProof(t, form, clientId, clientSecret, key.Proof(t, "POST", dpopTokenURL(), time.Now(), ""))
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "%v", body)
	assert.Equal(t, map[string]any{"error": "use_dpop_nonce", "error_description": "Authorization server requires nonce in DPoP proof."}, body)
	require.Len(t, resp.Header.Values("DPoP-Nonce"), 1, "the refusal carries one nonce")
	nonce := resp.Header.Get("DPoP-Nonce")

	resp, body = postWithProof(t, form, clientId, clientSecret, key.Proof(t, "POST", dpopTokenURL(), time.Now(), nonce))
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", body)
	require.Len(t, resp.Header.Values("DPoP-Nonce"), 1, "the answer carries one fresh nonce")
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	assertBoundTo(t, body, key)
	return body
}

// assertBoundTo checks a token response answers an access token bound to key.
func assertBoundTo(t *testing.T, body map[string]any, key dpoptest.Key) {
	t.Helper()
	assert.Equal(t, "DPoP", body["token_type"])
	accessToken, ok := body["access_token"].(string)
	require.True(t, ok, "an access token: %v", body)
	claims := decodeJWTPayload(t, accessToken)
	assert.Equal(t, map[string]any{"jkt": key.Thumbprint}, claims["cnf"], "cnf.jkt is the proof key's thumbprint")
	assert.Equal(t, "Bearer", claims["typ"], "the body's typ is the access-token label")
	if refreshToken, ok := body["refresh_token"].(string); ok {
		assert.NotContains(t, decodeJWTPayload(t, refreshToken), "cnf", "the refresh token carries no cnf")
	}
}

func TestDPoP_ClientCredentialsGrant(t *testing.T) {
	clientSecret := fake.Password(32)
	secretEncrypted, err := dataCipher.Encrypt(clientSecret)
	require.NoError(t, err)
	resource := createResourceWithId(t, "dpop-api-"+fake.LetterN(8))
	permission := createPermissionWithId(t, resource.Id, "read-"+fake.LetterN(8))
	client := &record.Client{
		ClientIdentifier:         "dpop-service-" + fake.LetterN(8),
		Enabled:                  true,
		ClientCredentialsEnabled: true,
		DefaultAcrLevel:          record.AcrLevel2Optional,
		ClientSecretEncrypted:    secretEncrypted,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	require.NoError(t, database.CreateClientPermission(context.Background(), nil,
		&record.ClientPermission{ClientId: client.Id, PermissionId: permission.Id}))

	redeemWithDPoP(t, url.Values{"grant_type": {"client_credentials"}}, client.ClientIdentifier, clientSecret,
		dpoptest.RFC7517Key(t))
}

// The code exchange binds its access token to the exchange's proof key; the refresh after it binds
// the new access token to the refresh's own proof key.
func TestDPoP_AuthorizationCodeGrantAndItsRefresh(t *testing.T) {
	clientSecret := fake.Password(32)
	_, code := createAuthCode(t, clientSecret, "openid profile")

	body := redeemWithDPoP(t, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {testCodeVerifier},
	}, code.Client.ClientIdentifier, clientSecret, dpoptest.RFC7517Key(t))
	require.NotEmpty(t, body["id_token"])
	assert.NotContains(t, decodeJWTPayload(t, body["id_token"].(string)), "cnf", "the ID token carries no cnf")

	refreshToken, ok := body["refresh_token"].(string)
	require.True(t, ok, "a refresh token: %v", body)
	redeemWithDPoP(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}},
		code.Client.ClientIdentifier, clientSecret, dpoptest.RFC7515Key(t))
}

func TestDPoP_PasswordGrant(t *testing.T) {
	changeSettings(t, func(settings *record.Settings) { settings.ResourceOwnerPasswordCredentialsEnabled = true })
	clientSecret := fake.Password(32)
	client := createROPCClient(t, clientSecret, false)
	password := fake.Password(12)
	user := createROPCUser(t, password)

	redeemWithDPoP(t, url.Values{
		"grant_type": {"password"},
		"username":   {user.Email},
		"password":   {password},
		"scope":      {"openid"},
	}, client.ClientIdentifier, clientSecret, dpoptest.RFC7517Key(t))
}

// A proof for another URL is refused invalid_dpop_proof with a fresh nonce, even carrying a good
// nonce; a request without a DPoP header is answered a Bearer token and no nonce.
func TestDPoP_ARefusedProofAndARequestWithoutOne(t *testing.T) {
	clientSecret := fake.Password(32)
	secretEncrypted, err := dataCipher.Encrypt(clientSecret)
	require.NoError(t, err)
	resource := createResourceWithId(t, "dpop-api-"+fake.LetterN(8))
	permission := createPermissionWithId(t, resource.Id, "read-"+fake.LetterN(8))
	client := &record.Client{
		ClientIdentifier:         "dpop-service-" + fake.LetterN(8),
		Enabled:                  true,
		ClientCredentialsEnabled: true,
		DefaultAcrLevel:          record.AcrLevel2Optional,
		ClientSecretEncrypted:    secretEncrypted,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	require.NoError(t, database.CreateClientPermission(context.Background(), nil,
		&record.ClientPermission{ClientId: client.Id, PermissionId: permission.Id}))
	key := dpoptest.RFC7517Key(t)
	form := url.Values{"grant_type": {"client_credentials"}}

	resp, _ := postWithProof(t, form, client.ClientIdentifier, clientSecret, key.Proof(t, "POST", dpopTokenURL(), time.Now(), ""))
	nonce := resp.Header.Get("DPoP-Nonce")
	require.NotEmpty(t, nonce)

	resp, body := postWithProof(t, form, client.ClientIdentifier, clientSecret,
		key.Proof(t, "POST", "https://another-server.example.com/auth/token", time.Now(), nonce))
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, map[string]any{"error": "invalid_dpop_proof", "error_description": "The DPoP proof is invalid."}, body)
	assert.Len(t, resp.Header.Values("DPoP-Nonce"), 1)

	resp, body = postWithProof(t, form, client.ClientIdentifier, clientSecret, "")
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", body)
	assert.Equal(t, "Bearer", body["token_type"])
	assert.NotContains(t, decodeJWTPayload(t, body["access_token"].(string)), "cnf")
	assert.Empty(t, resp.Header.Values("DPoP-Nonce"))
}
