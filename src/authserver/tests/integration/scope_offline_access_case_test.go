package integrationtests

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file is the end-to-end account of offline_access being matched exactly, per RFC 6749
// section 3.3, which makes scope values case-sensitive strings (#425). Until then the validators
// case-folded offline_access, so OFFLINE_ACCESS passed validation and was stored with the grant,
// while consent and issuance matched it exactly and never treated it as offline access.
//
// Two halves. A request carrying the uppercase spelling is refused where it arrives: the
// authorization endpoint, the password grant and the client credentials grant. And a grant stored
// before the change, still carrying it, is refused on refresh with invalid_grant rather than the
// 500 it answered while the value fell through to the permission check as if it were a resource
// scope.

// notIssuedDescription is the refresh arm's answer to a stored value that is none of the scopes
// this server issues.
const notIssuedDescription = "Scope 'OFFLINE_ACCESS' is not recognized. It is not a scope this server issues."

// refreshWithScope presents a refresh token, with `scope` when scope is not empty, and returns the
// status and body. It goes through concurrentTokenPost because postToTokenEndpoint hides the
// status, and 400 against 500 is what the stored-grant cases are about.
func refreshWithScope(t *testing.T, httpClient *http.Client, clientIdentifier, clientSecret,
	refreshToken, scope string) (int, map[string]interface{}) {
	t.Helper()

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientIdentifier},
		"client_secret": {clientSecret},
		"refresh_token": {refreshToken},
	}
	if scope != "" {
		form.Set("scope", scope)
	}
	status, body, err := concurrentTokenPost(httpClient, config.GetAuthServer().BaseURL+"/auth/token/", form)
	require.NoError(t, err, "refresh request failed at the transport level")
	return status, body
}

// enableROPCGlobally turns the resource owner password credentials grant on and returns the restore.
func enableROPCGlobally(t *testing.T) func() {
	t.Helper()

	settings, err := database.GetSettingsById(context.Background(), nil, 1)
	require.NoError(t, err)
	original := settings.ResourceOwnerPasswordCredentialsEnabled
	settings.ResourceOwnerPasswordCredentialsEnabled = true
	require.NoError(t, database.UpdateSettings(context.Background(), nil, settings))
	return func() {
		settings.ResourceOwnerPasswordCredentialsEnabled = original
		_ = database.UpdateSettings(context.Background(), nil, settings)
	}
}

// TestAuthorize_OfflineAccessIsCaseSensitive sends each spelling to the authorization endpoint
// with prompt=none, so a validation failure is answered at once rather than parked until after a
// login (#213). The lowercase row is the control: it passes validation, and the silent request
// then finds no session.
func TestAuthorize_OfflineAccessIsCaseSensitive(t *testing.T) {
	const malformed = "Invalid scope format: '%s'. Scopes must adhere to the resource-identifier:permission-identifier format. For instance: backend-service:create-product."

	for _, tc := range []struct {
		name      string
		value     string
		wantError string
	}{
		{name: "uppercase is refused", value: "OFFLINE_ACCESS", wantError: "invalid_scope"},
		{name: "mixed case is refused", value: "Offline_Access", wantError: "invalid_scope"},
		{name: "offline_access passes validation", value: "offline_access", wantError: "login_required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, redirectUri := createTestClientAndRedirectURI(t)
			httpClient := createHttpClient(t)
			requestState := fake.LetterN(8)

			destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
				"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
				"&response_type=code" +
				"&code_challenge_method=S256" +
				"&code_challenge=" + fake.LetterN(43) +
				"&scope=" + url.QueryEscape("openid "+tc.value) +
				"&state=" + requestState +
				"&prompt=none"

			resp, err := httpClient.Get(destUrl)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			errorCode, errorDescription, state := getErrorFromUrl(t, resp)
			assert.Equal(t, tc.wantError, errorCode)
			assert.Equal(t, requestState, state)
			if tc.wantError == "invalid_scope" {
				assert.Equal(t, fmt.Sprintf(malformed, tc.value), errorDescription)
			}
		})
	}
}

// TestROPC_OfflineAccessIsCaseSensitive sends each spelling through the password grant. The
// uppercase one used to be accepted and stored with the grant, which is how the refresh tokens the
// stored-grant cases below rebuild came to exist.
func TestROPC_OfflineAccessIsCaseSensitive(t *testing.T) {
	defer enableROPCGlobally(t)()

	password := fake.Password(12)
	client := createROPCClient(t, "", true)
	user := createROPCUser(t, password)
	httpClient := createHttpClient(t)

	request := func(scope string) (int, map[string]interface{}) {
		status, body, err := concurrentTokenPost(httpClient, config.GetAuthServer().BaseURL+"/auth/token/", url.Values{
			"grant_type": {"password"},
			"client_id":  {client.ClientIdentifier},
			"username":   {user.Email},
			"password":   {password},
			"scope":      {scope},
		})
		require.NoError(t, err)
		return status, body
	}

	t.Run("uppercase is refused", func(t *testing.T) {
		status, body := request("openid OFFLINE_ACCESS")

		assert.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "invalid_scope", body["error"])
		assert.Equal(t, "Invalid scope format: 'OFFLINE_ACCESS'. Scopes must be either OIDC scopes (openid, profile, email, address, phone, groups, attributes) or resource-identifier:permission-identifier format.",
			body["error_description"])
		assert.Nil(t, body["refresh_token"])
	})

	t.Run("offline_access is granted", func(t *testing.T) {
		status, body := request("openid offline_access")

		require.Equal(t, http.StatusOK, status, "body: %v", body)
		scope, ok := body["scope"].(string)
		require.True(t, ok)
		assert.Contains(t, strings.Split(scope, " "), "offline_access")
		assert.NotEmpty(t, body["refresh_token"])
	})
}

// TestClientCredentials_OfflineAccessIsCaseSensitive sends each spelling through the client
// credentials grant, where both are refused but not alike: offline_access is a scope this server
// knows and refuses for this grant, while OFFLINE_ACCESS is no scope at all, so it is refused as
// malformed. Before #425 both got the first answer.
func TestClientCredentials_OfflineAccessIsCaseSensitive(t *testing.T) {
	clientSecret := fake.Password(32)
	encryptedSecret, err := encryption.EncryptData(clientSecret)
	require.NoError(t, err)
	client := &models.Client{
		ClientIdentifier:         "cc-offline-case-" + fake.LetterN(8),
		Enabled:                  true,
		ClientCredentialsEnabled: true,
		ClientSecretEncrypted:    encryptedSecret,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))

	httpClient := createHttpClient(t)

	for _, tc := range []struct {
		name      string
		scope     string
		wantError string
		wantDesc  string
	}{
		{
			name:      "uppercase is refused as malformed",
			scope:     "OFFLINE_ACCESS",
			wantError: "invalid_scope",
			wantDesc:  "Invalid scope format: 'OFFLINE_ACCESS'. Scopes must adhere to the resource-identifier:permission-identifier format. For instance: backend-service:create-product.",
		},
		{
			name:      "offline_access is refused for this grant",
			scope:     "offline_access",
			wantError: "invalid_request",
			wantDesc:  "Id token scopes (such as 'offline_access') are not supported in the client credentials flow. Please use scopes in the format 'resource:permission' (e.g., 'backendA:read'). Multiple scopes can be specified, separated by spaces.",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body, postErr := concurrentTokenPost(httpClient, config.GetAuthServer().BaseURL+"/auth/token/", url.Values{
				"grant_type":    {"client_credentials"},
				"client_id":     {client.ClientIdentifier},
				"client_secret": {clientSecret},
				"scope":         {tc.scope},
			})
			require.NoError(t, postErr)

			assert.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, tc.wantError, body["error"])
			assert.Equal(t, tc.wantDesc, body["error_description"])
			assert.Nil(t, body["access_token"])
		})
	}
}

// TestToken_Refresh_StoredUppercaseOfflineAccess_AuthCode rebuilds an authorization code grant as a
// release before #425 stored it for a client that sent OFFLINE_ACCESS, and refreshes it. The rows
// are rewritten directly because no current path can store the value: the code, whose scope is
// what the refresh arm checks, and the refresh token, whose scope a rotation copies to its
// successor. The grant is session-bound, as those were, since issuance never read the uppercase
// spelling as offline access.
func TestToken_Refresh_StoredUppercaseOfflineAccess_AuthCode(t *testing.T) {
	const legacyScope = "openid profile email OFFLINE_ACCESS"
	ctx := context.Background()

	clientSecret := fake.Password(32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")
	clientIdentifier := code.Client.ClientIdentifier
	refreshToken := exchangeAuthCode(t, httpClient, clientIdentifier, clientSecret,
		code.Code, code.RedirectURI, "code-verifier")

	storedCode, err := database.GetCodeById(ctx, nil, code.Id)
	require.NoError(t, err)
	require.NotNil(t, storedCode)
	storedCode.Scope = legacyScope
	require.NoError(t, database.UpdateCode(ctx, nil, storedCode))

	row := refreshTokenRowByJti(t, refreshToken)
	require.Equal(t, "Refresh", row.RefreshTokenType, "the fixture must be a session-bound grant")
	row.Scope = legacyScope
	require.NoError(t, database.UpdateRefreshToken(ctx, nil, row))

	t.Run("scope omitted is refused as invalid_grant", func(t *testing.T) {
		status, body := refreshWithScope(t, httpClient, clientIdentifier, clientSecret, refreshToken, "")

		assertRefusedAsInvalidGrant(t, status, body, "a grant carrying OFFLINE_ACCESS")
		assert.Equal(t, notIssuedDescription, body["error_description"])
	})

	t.Run("the value requested explicitly is refused the same way", func(t *testing.T) {
		status, body := refreshWithScope(t, httpClient, clientIdentifier, clientSecret, refreshToken, "openid OFFLINE_ACCESS")

		assertRefusedAsInvalidGrant(t, status, body, "an explicit request for OFFLINE_ACCESS")
		assert.Equal(t, notIssuedDescription, body["error_description"])
	})

	t.Run("offline_access is beyond this grant", func(t *testing.T) {
		status, body := refreshWithScope(t, httpClient, clientIdentifier, clientSecret, refreshToken, "openid offline_access")

		assert.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "invalid_scope", body["error"])
		assert.Equal(t, "Scope 'offline_access' is not recognized. The original access token does not grant the 'offline_access' permission.",
			body["error_description"])
	})

	t.Run("the refusals did not spend the token", func(t *testing.T) {
		assert.False(t, refreshTokenRowByJti(t, refreshToken).Revoked)
	})

	var successor string
	t.Run("a request that leaves the value out refreshes", func(t *testing.T) {
		status, body := refreshWithScope(t, httpClient, clientIdentifier, clientSecret, refreshToken, "openid profile email")

		require.Equal(t, http.StatusOK, status, "body: %v", body)
		scope, ok := body["scope"].(string)
		require.True(t, ok)
		assert.NotContains(t, strings.Split(scope, " "), "OFFLINE_ACCESS")
		successor, ok = body["refresh_token"].(string)
		require.True(t, ok)

		// RFC 6749 section 6: the successor's scope is identical to the presented token's, so the
		// grant still carries the value.
		assert.Equal(t, legacyScope, refreshTokenRowByJti(t, successor).Scope)
		assert.True(t, refreshTokenRowByJti(t, refreshToken).Revoked, "rotation retires the presented token")
	})

	t.Run("the successor inheriting the grant is refused again", func(t *testing.T) {
		require.NotEmpty(t, successor)
		status, body := refreshWithScope(t, httpClient, clientIdentifier, clientSecret, successor, "")

		assertRefusedAsInvalidGrant(t, status, body, "the successor of a grant carrying OFFLINE_ACCESS")
		assert.Equal(t, notIssuedDescription, body["error_description"])
	})
}

// TestROPC_RefreshToken_StoredUppercaseOfflineAccess is the same rebuild for the password grant,
// the population that lasts: an ROPC refresh token is always offline, so it lives up to the offline
// maximum lifetime. Its scope is on the token row, which is what the refresh arm reads for it.
func TestROPC_RefreshToken_StoredUppercaseOfflineAccess(t *testing.T) {
	defer enableROPCGlobally(t)()

	const legacyScope = "openid OFFLINE_ACCESS"

	clientSecret := fake.Password(32)
	password := fake.Password(12)
	client := createROPCClient(t, clientSecret, false)
	user := createROPCUser(t, password)
	httpClient := createHttpClient(t)

	data := postToTokenEndpoint(t, httpClient, config.GetAuthServer().BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"password"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"username":      {user.Email},
		"password":      {password},
		"scope":         {"openid"},
	})
	refreshToken, ok := data["refresh_token"].(string)
	require.True(t, ok, "the password grant must return a refresh token: %v", data)

	row := refreshTokenRowByJti(t, refreshToken)
	require.Equal(t, "Offline", row.RefreshTokenType, "an ROPC refresh token is always offline")
	row.Scope = legacyScope
	require.NoError(t, database.UpdateRefreshToken(context.Background(), nil, row))

	t.Run("scope omitted is refused as invalid_grant", func(t *testing.T) {
		status, body := refreshWithScope(t, httpClient, client.ClientIdentifier, clientSecret, refreshToken, "")

		assertRefusedAsInvalidGrant(t, status, body, "an ROPC grant carrying OFFLINE_ACCESS")
		assert.Equal(t, notIssuedDescription, body["error_description"])
	})

	t.Run("the refusal did not spend the token", func(t *testing.T) {
		assert.False(t, refreshTokenRowByJti(t, refreshToken).Revoked)
	})

	t.Run("a request that leaves the value out refreshes", func(t *testing.T) {
		status, body := refreshWithScope(t, httpClient, client.ClientIdentifier, clientSecret, refreshToken, "openid")

		require.Equal(t, http.StatusOK, status, "body: %v", body)
		scope, hasScope := body["scope"].(string)
		require.True(t, hasScope)
		assert.NotContains(t, strings.Split(scope, " "), "OFFLINE_ACCESS")
		successor, hasSuccessor := body["refresh_token"].(string)
		require.True(t, hasSuccessor)
		assert.Equal(t, legacyScope, refreshTokenRowByJti(t, successor).Scope,
			"RFC 6749 section 6: the successor's scope is identical to the presented token's")
	})
}
