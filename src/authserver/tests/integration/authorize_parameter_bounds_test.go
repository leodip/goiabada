package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/core/oauth"
)

// state, nonce and scope are stored in codes, and the scope in the consent and the refresh token as
// well, in columns that were 512 wide on MySQL, PostgreSQL and SQL Server; migration 000052 widened
// them to models.StateMaxBytes, NonceMaxBytes and ScopeMaxBytes, and the authorization endpoint and
// the password grant refuse a longer value. A value between 512 and the bound used to be accepted
// and then refused by the column, as a 500, after the user had signed in (#437). What counts as too
// long is protocolvalidation's table; these show each answer on the wire, and the first, run by CI
// on the three widened engines, shows the widths.

// createScopeAtTheBound creates a resource whose permissions are all granted to user, and returns
// a scope of exactly models.ScopeMaxBytes bytes that begins with prefix and continues with one of
// them per value. Every value is a real permission the user holds, so the scope survives the
// endpoint's resolution and the permission filter and reaches storage whole.
func createScopeAtTheBound(t *testing.T, user *models.User, prefix string) string {
	t.Helper()
	resource := createResourceWithId(t, "bnd"+fake.LetterN(8))
	overhead := len(" " + resource.ResourceIdentifier + ":")

	scope := prefix
	for i := 0; ; i++ {
		// The identifier bytes still to place. A permission identifier is at most 38 bytes; a scope
		// is filled with 38-byte ones, and when what is left could not hold another value the
		// last but one is shortened to leave room for a final identifier of one byte.
		room := models.ScopeMaxBytes - len(scope) - overhead
		require.Positive(t, room, "the prefix leaves no room for a value, so the bound cannot be hit exactly")
		width := room
		if room > 38 {
			width = 38
			if room-38 <= overhead {
				width = room - overhead - 1
			}
		}
		identifier := fmt.Sprintf("p%04d", i)
		if len(identifier) > width {
			identifier = identifier[:width]
		}
		identifier += strings.Repeat("x", width-len(identifier))

		permission := createPermissionWithId(t, resource.Id, identifier)
		assignPermissionToUser(t, user.Id, permission.Id)
		scope += " " + resource.ResourceIdentifier + ":" + identifier
		if width == room {
			break
		}
	}
	require.Len(t, scope, models.ScopeMaxBytes, "the fixture is off the bound, so the case no longer observes the edge")
	return scope
}

// TestAuthorize_ValuesAtTheBoundAreStoredAndRedeemed runs one sign-in end to end with state, nonce
// and scope each at exactly its bound. The consent is saved, the code is issued, the code is
// redeemed and its refresh token rotated: every write that carries one of the five widened columns
// happens, and each would answer 500 on a column still 512 wide.
func TestAuthorize_ValuesAtTheBoundAreStoredAndRedeemed(t *testing.T) {
	clientSecret := fake.LetterN(32)
	clientSecretEncrypted, err := dataCipher.Encrypt(clientSecret)
	require.NoError(t, err)
	client := &models.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          true,
		DefaultAcrLevel:          models.AcrLevel1,
		ClientSecretEncrypted:    clientSecretEncrypted,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	redirectUri := &models.RedirectURI{ClientId: client.Id, URI: fake.URL()}
	require.NoError(t, database.CreateRedirectURI(context.Background(), nil, redirectUri))

	password := fake.Password(8)
	passwordHashed, err := passwordhash.Hash(password)
	require.NoError(t, err)
	user := &models.User{Subject: fake.UUID(), Enabled: true, Email: fake.Email(), PasswordHash: passwordHashed}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))

	requestScope := createScopeAtTheBound(t, user, "openid offline_access")
	requestState := strings.Repeat("s", models.StateMaxBytes)
	requestNonce := strings.Repeat("n", models.NonceMaxBytes)
	codeVerifier := fake.LetterN(64)

	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + oauth.GeneratePKCECodeChallenge(codeVerifier) +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	resp = authenticateWithPassword(t, httpClient, redirectLocation, resp, user.Email, password)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/consent")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	ticked := make([]int, 0, 64)
	for i := range strings.Fields(requestScope) {
		ticked = append(ticked, i)
	}
	resp = postConsent(t, httpClient, redirectLocation, resp, ticked)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal, "the state comes back exactly as sent")

	// The code is redeemed and the refresh token rotated through the token endpoint, which is how
	// the stored values are read back: the scope and nonce reach the response only if the code row
	// held them whole, and the refreshed token only if the refresh token row did.
	tokenUrl := appConfig.AuthServer.BaseURL + "/auth/token/"
	tokens := postToTokenEndpoint(t, httpClient, tokenUrl, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {codeVal},
		"redirect_uri":  {redirectUri.URI},
		"code_verifier": {codeVerifier},
	})
	require.NotEmpty(t, tokens["access_token"], "the code was refused: %v", tokens)
	assert.Equal(t, requestScope, tokens["scope"], "the scope the code held")
	idToken, ok := tokens["id_token"].(string)
	require.True(t, ok, "openid was granted, so an ID token is issued: %v", tokens)
	assert.Equal(t, requestNonce, decodeJWTPayload(t, idToken)["nonce"], "the nonce the code held")

	refreshToken, ok := tokens["refresh_token"].(string)
	require.True(t, ok, "offline_access was granted, so a refresh token is issued: %v", tokens)
	refreshed := postToTokenEndpoint(t, httpClient, tokenUrl, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"refresh_token": {refreshToken},
	})
	require.NotEmpty(t, refreshed["access_token"], "the refresh token was refused: %v", refreshed)
	assert.Equal(t, requestScope, refreshed["scope"], "the scope the refresh token held")
}

func TestAuthorize_OverlongValueIsRefusedAtOnce(t *testing.T) {
	client, redirectUri := createTestClientWithRedirect(t)

	// A session holder is answered at once (#213), so the refusal is on the redirect itself.
	answer := func(t *testing.T, query url.Values) *url.URL {
		t.Helper()
		resp, err := createAuthenticatedHttpClient(t).Get(appConfig.AuthServer.BaseURL + "/auth/authorize/?" + query.Encode())
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusFound, resp.StatusCode)
		location, err := url.Parse(resp.Header.Get("Location"))
		require.NoError(t, err)
		return location
	}
	request := func(overrides map[string]string) url.Values {
		query := repeatedParametersQuery(client, redirectUri)
		for name, value := range overrides {
			query.Set(name, value)
		}
		return query
	}

	// One byte over each bound, differing from a request that is served in that parameter alone.
	t.Run("a state one byte over, echoed exactly", func(t *testing.T) {
		state := strings.Repeat("s", models.StateMaxBytes+1)

		location := answer(t, request(map[string]string{"state": state}))

		assert.Equal(t, "invalid_request", location.Query().Get("error"))
		assert.Equal(t, fmt.Sprintf("The 'state' parameter is too long (%d bytes, the maximum is %d).",
			models.StateMaxBytes+1, models.StateMaxBytes), location.Query().Get("error_description"))
		assert.Equal(t, state, location.Query().Get("state"), "RFC 6749 4.1.2.1: the exact value received")
	})

	t.Run("a nonce one byte over", func(t *testing.T) {
		location := answer(t, request(map[string]string{"nonce": strings.Repeat("n", models.NonceMaxBytes+1)}))

		assert.Equal(t, "invalid_request", location.Query().Get("error"))
		assert.Equal(t, fmt.Sprintf("The 'nonce' parameter is too long (%d bytes, the maximum is %d).",
			models.NonceMaxBytes+1, models.NonceMaxBytes), location.Query().Get("error_description"))
	})

	t.Run("a scope over the bound", func(t *testing.T) {
		values := make([]string, 0, 300)
		for i := 0; i < 300; i++ {
			values = append(values, fmt.Sprintf("r:p%04d", i))
		}
		scope := strings.Join(values, " ")

		location := answer(t, request(map[string]string{"scope": scope}))

		assert.Equal(t, "invalid_scope", location.Query().Get("error"))
		assert.Equal(t, fmt.Sprintf("The 'scope' parameter is too long (%d bytes, the maximum is %d).",
			len(scope), models.ScopeMaxBytes), location.Query().Get("error_description"))
	})

	// A leniency chosen on purpose: the bound counts the normalized scope, which is what is stored,
	// so a request whose raw scope is far over it in repeated values, each separated from the next
	// by one space, is the one-value scope it collapses to, and the sign-in goes on.
	t.Run("a raw scope over the bound that normalizes under it proceeds", func(t *testing.T) {
		scope := repeatedOpenidScope()
		require.Greater(t, len(scope), models.ScopeMaxBytes)

		location := answer(t, request(map[string]string{"scope": scope}))

		assert.Equal(t, "/auth/level1completed", location.Path, "the session holder's sign-in goes on: %v", location)
	})

	// The same values joined by a tab used to collapse the same way. A tab separates nothing since
	// #244, so they are one value far over the bound.
	t.Run("the same values joined by a tab are one value over the bound", func(t *testing.T) {
		scope := strings.ReplaceAll(repeatedOpenidScope(), " ", "\t")

		location := answer(t, request(map[string]string{"scope": scope}))

		assert.Equal(t, "invalid_scope", location.Query().Get("error"))
		assert.Equal(t, fmt.Sprintf("The 'scope' parameter is too long (%d bytes, the maximum is %d).",
			len(scope), models.ScopeMaxBytes), location.Query().Get("error_description"))
	})
}

// repeatedOpenidScope is openid repeated, one space between each copy, to three times the scope
// bound: a well-formed scope far over the bound whose normalized value is "openid".
func repeatedOpenidScope() string {
	copies := make([]string, 3*models.ScopeMaxBytes/len("openid "))
	for i := range copies {
		copies[i] = "openid"
	}
	return strings.Join(copies, " ")
}

func TestROPC_ScopeBound(t *testing.T) {
	changeSettings(t, func(settings *models.Settings) { settings.ResourceOwnerPasswordCredentialsEnabled = true })
	tokenUrl := appConfig.AuthServer.BaseURL + "/auth/token/"

	setup := func(t *testing.T) (client *models.Client, user *models.User, password string) {
		t.Helper()
		password = fake.Password(12)
		return createROPCClient(t, "", true), createROPCUser(t, password), password
	}
	request := func(client *models.Client, user *models.User, password, scope string) url.Values {
		return url.Values{
			"grant_type": {"password"},
			"client_id":  {client.ClientIdentifier},
			"username":   {user.Email},
			"password":   {password},
			"scope":      {scope},
		}
	}

	t.Run("a scope filling the bound is granted whole, and its refresh token holds it", func(t *testing.T) {
		client, user, password := setup(t)
		scope := createScopeAtTheBound(t, user, "openid")

		data := postToTokenEndpoint(t, createHttpClient(t), tokenUrl, request(client, user, password, scope))

		require.NotEmpty(t, data["access_token"], "the grant was refused: %v", data)
		assert.Equal(t, scope, data["scope"])
		refreshToken, ok := data["refresh_token"].(string)
		require.True(t, ok, "the password grant issues a refresh token: %v", data)

		refreshed := postToTokenEndpoint(t, createHttpClient(t), tokenUrl, url.Values{
			"grant_type":    {"refresh_token"},
			"client_id":     {client.ClientIdentifier},
			"refresh_token": {refreshToken},
		})
		require.NotEmpty(t, refreshed["access_token"], "the refresh was refused: %v", refreshed)
		assert.Equal(t, scope, refreshed["scope"], "the scope the refresh token held")
	})

	t.Run("a scope one byte over the bound is invalid_scope", func(t *testing.T) {
		client, user, password := setup(t)
		values := make([]string, 0, 300)
		for i := 0; i < 300; i++ {
			values = append(values, fmt.Sprintf("r:p%04d", i))
		}
		scope := strings.Join(values, " ")

		data := postToTokenEndpoint(t, createHttpClient(t), tokenUrl, request(client, user, password, scope))

		assert.Equal(t, "invalid_scope", data["error"])
		assert.Equal(t, fmt.Sprintf("The 'scope' parameter is too long (%d bytes, the maximum is %d).",
			len(scope), models.ScopeMaxBytes), data["error_description"])
	})

	// The bound sits behind the proof of the password, so a caller that has not proved it learns
	// nothing about its scope: the same request with a wrong password is the answer any wrong
	// password gets, and is charged as one (#137, #219).
	t.Run("the same scope with a wrong password is invalid_grant", func(t *testing.T) {
		client, user, _ := setup(t)
		values := make([]string, 0, 300)
		for i := 0; i < 300; i++ {
			values = append(values, fmt.Sprintf("r:p%04d", i))
		}

		data := postToTokenEndpoint(t, createHttpClient(t), tokenUrl,
			request(client, user, "wrongpassword", strings.Join(values, " ")))

		assert.Equal(t, "invalid_grant", data["error"])
		assert.Contains(t, data["error_description"], "credentials")
	})

	// The same leniency at the token endpoint: it normalizes the scope before the validator counts
	// it.
	t.Run("a raw scope over the bound that normalizes under it is granted", func(t *testing.T) {
		client, user, password := setup(t)
		scope := repeatedOpenidScope()
		require.Greater(t, len(scope), models.ScopeMaxBytes)

		data := postToTokenEndpoint(t, createHttpClient(t), tokenUrl, request(client, user, password, scope))

		require.NotEmpty(t, data["access_token"], "the grant was refused: %v", data)
		assert.Equal(t, "openid", data["scope"])
	})
}
