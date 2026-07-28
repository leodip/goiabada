package integrationtests

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests cover the second vulnerability in #104, which is independent of the
// cross-resource scope escalation: /userinfo and the Account API resolved the acting user
// from the token's `sub` claim without checking that the token was issued for a user at
// all. On a client_credentials token `sub` is the CLIENT identifier, so a client whose
// identifier equalled a user's subject acted as that user.
//
// The guard is RequireUserBoundToken, which keys on the presence of `auth_time`. What
// these tests establish, and what the middleware unit tests cannot, is the asymmetry the
// guard rests on: real client credentials tokens lack `auth_time` and real user tokens
// carry it, across every issuance path.

// newUserSubjectValidAsClientIdentifier returns a UUID that also satisfies
// ValidateIdentifier, so a client can genuinely be created with this string as its
// identifier through the admin API rather than only by direct database insert.
//
// The identifier regex is ^[a-zA-Z]([a-zA-Z0-9_-]*[a-zA-Z0-9])?$ with a 38 character
// maximum. A 36 character UUID satisfies all of it whenever its first hex digit is a-f,
// which is 6 of 16 values, so 3 in 8 UUIDs qualify and a handful of draws suffices.
// Generated rather than hardcoded so the test does not silently depend on one literal.
func newUserSubjectValidAsClientIdentifier(t *testing.T) uuid.UUID {
	t.Helper()

	for i := 0; i < 200; i++ {
		candidate := uuid.New()
		first := candidate.String()[0]
		if first >= 'a' && first <= 'f' {
			return candidate
		}
	}
	t.Fatal("could not generate a UUID whose first character is a-f")
	return uuid.UUID{}
}

// createUserWithSubject creates an enabled user with a caller-chosen subject.
func createUserWithSubject(t *testing.T, subject uuid.UUID) (*models.User, string) {
	t.Helper()

	password := gofakeit.Password(true, true, true, true, false, 12)
	passwordHashed, err := hashutil.HashPassword(password)
	require.NoError(t, err)

	user := &models.User{
		Subject:      subject,
		Enabled:      true,
		Email:        strings.ToLower(gofakeit.LetterN(10)) + "@example.com",
		PasswordHash: passwordHashed,
		GivenName:    gofakeit.FirstName(),
		FamilyName:   gofakeit.LastName(),
	}
	err = database.CreateUser(nil, user)
	require.NoError(t, err)

	return user, password
}

// createImpersonatingClientCredentialsToken mints a real client credentials token for a
// client whose identifier EQUALS the given user's subject, carrying the given built-in
// authserver permission. This is the attacker's token in the original vulnerability.
func createImpersonatingClientCredentialsToken(t *testing.T, subject uuid.UUID, permissionIdentifier string) string {
	t.Helper()

	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	clientSecretEncrypted, err := encryption.EncryptData(clientSecret)
	require.NoError(t, err)

	client := &models.Client{
		// The whole point: the client identifier is the user's subject.
		ClientIdentifier:         subject.String(),
		Enabled:                  true,
		ClientCredentialsEnabled: true,
		IsPublic:                 false,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
		ClientSecretEncrypted:    clientSecretEncrypted,
	}
	err = database.CreateClient(nil, client)
	require.NoError(t, err)

	authserverResource, err := database.GetResourceByResourceIdentifier(nil, constants.AuthServerResourceIdentifier)
	require.NoError(t, err)
	require.NotNil(t, authserverResource)

	permissions, err := database.GetPermissionsByResourceId(nil, authserverResource.Id)
	require.NoError(t, err)

	var granted *models.Permission
	for i := range permissions {
		if permissions[i].PermissionIdentifier == permissionIdentifier {
			granted = &permissions[i]
			break
		}
	}
	require.NotNil(t, granted, "built-in permission %q must exist on the authserver resource", permissionIdentifier)

	err = database.CreateClientPermission(nil, &models.ClientPermission{
		ClientId:     client.Id,
		PermissionId: granted.Id,
	})
	require.NoError(t, err)

	requestedScope := constants.AuthServerResourceIdentifier + ":" + permissionIdentifier
	data := postToTokenEndpoint(t, createHttpClient(t), config.GetAuthServer().BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"scope":         {requestedScope},
	})

	accessToken, ok := data["access_token"].(string)
	require.True(t, ok, "client credentials token should be issued: %v", data)
	require.Equal(t, requestedScope, data["scope"])

	return accessToken
}

// TestUserBoundToken_ClientCredentialsCannotActAsUser is the regression guard for the
// impersonation path. Against pre-fix main the first subtest returns 200 and changes the
// user's email.
func TestUserBoundToken_ClientCredentialsCannotActAsUser(t *testing.T) {
	// Account API fixture: a real user whose subject doubles as a valid client identifier.
	accountSubject := newUserSubjectValidAsClientIdentifier(t)
	accountUser, _ := createUserWithSubject(t, accountSubject)
	originalEmail := accountUser.Email

	// /userinfo fixture: a SECOND colliding pair, and one token shared by both subtests.
	//
	// A second pair rather than reusing the one above, because the impersonating client takes
	// the user's subject as its own client_identifier and one identifier cannot back two
	// clients. One token rather than two, because GET and POST /userinfo are separate route
	// registrations that must both reject the same token, and minting a second token would
	// need a third user for no added coverage.
	//
	// The matching user genuinely exists, which is what makes this the fixture the spec
	// describes: with the guard removed, the handler resolves THIS user from the token's sub.
	userinfoSubject := newUserSubjectValidAsClientIdentifier(t)
	_, _ = createUserWithSubject(t, userinfoSubject)
	userinfoToken := createImpersonatingClientCredentialsToken(t, userinfoSubject,
		constants.UserinfoPermissionIdentifier)

	t.Run("PUT account email is refused and the email is unchanged", func(t *testing.T) {
		accessToken := createImpersonatingClientCredentialsToken(t, accountSubject,
			constants.ManageAccountPermissionIdentifier)

		attemptedEmail := strings.ToLower(gofakeit.LetterN(9)) + "@attacker.example.com"
		resp := makeAPIRequest(t, "PUT", config.GetAuthServer().BaseURL+"/api/v1/account/email",
			accessToken, api.UpdateAccountEmailRequest{Email: attemptedEmail})
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)

		var errResp api.ErrorResponse
		body, _ := io.ReadAll(resp.Body)
		_ = json.Unmarshal(body, &errResp)
		assert.Equal(t, "USER_CONTEXT_REQUIRED", errResp.ErrorCode,
			"unexpected body: %s", string(body))

		// Asserting the status alone would still pass against a guard placed after the
		// mutation, so check the data.
		persisted, err := database.GetUserById(nil, accountUser.Id)
		require.NoError(t, err)
		assert.Equal(t, originalEmail, persisted.Email,
			"the user's email must not have been modified")
		assert.NotEqual(t, attemptedEmail, persisted.Email)
	})

	t.Run("GET userinfo is refused", func(t *testing.T) {
		resp := makeAPIRequest(t, "GET", config.GetAuthServer().BaseURL+"/userinfo", userinfoToken, nil)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		var errResp api.ErrorResponse
		body, _ := io.ReadAll(resp.Body)
		_ = json.Unmarshal(body, &errResp)
		assert.Equal(t, "USER_CONTEXT_REQUIRED", errResp.ErrorCode, "unexpected body: %s", string(body))
	})

	// GET and POST /userinfo are separate route registrations, so a guard added to only
	// one leaves the other reachable. The POST form carries the token in the body, which
	// also exercises the distinct extraction path in JwtAuthorizationHeaderToContext.
	t.Run("POST userinfo with a form-body access_token is refused", func(t *testing.T) {
		form := url.Values{"access_token": {userinfoToken}}
		req, err := http.NewRequest("POST", config.GetAuthServer().BaseURL+"/userinfo",
			strings.NewReader(form.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := createHttpClient(t).Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		var errResp api.ErrorResponse
		body, _ := io.ReadAll(resp.Body)
		_ = json.Unmarshal(body, &errResp)
		assert.Equal(t, "USER_CONTEXT_REQUIRED", errResp.ErrorCode, "unexpected body: %s", string(body))
	})
}

// TestUserBoundToken_EveryUserTokenPathStillWorks is the other half, and the half that
// would turn this guard into a serious regression if it were wrong. Every path that
// produces a user access token must still reach these endpoints. All five route through
// generateAccessTokenCore, which sets auth_time unconditionally, so these confirm rather
// than discover; but the guard's whole premise is that claim's universality and nothing
// else asserts it end to end.
func TestUserBoundToken_EveryUserTokenPathStillWorks(t *testing.T) {
	accountEmailUrl := config.GetAuthServer().BaseURL + "/api/v1/account/email"

	assertEmailChangeSucceeds := func(t *testing.T, accessToken string, user *models.User) {
		t.Helper()

		newEmail := strings.ToLower(gofakeit.LetterN(9)) + "@example.com"
		resp := makeAPIRequest(t, "PUT", accountEmailUrl, accessToken,
			api.UpdateAccountEmailRequest{Email: newEmail})
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d. body: %s", resp.StatusCode, string(body))
		}

		persisted, err := database.GetUserById(nil, user.Id)
		require.NoError(t, err)
		assert.Equal(t, newEmail, persisted.Email)
	}

	t.Run("authorization code token", func(t *testing.T) {
		accessToken, user := createUserAccessTokenWithScope(t,
			"openid profile email "+constants.AuthServerResourceIdentifier+":"+constants.ManageAccountPermissionIdentifier)
		assertEmailChangeSucceeds(t, accessToken, user)
	})

	t.Run("authorization code refresh token", func(t *testing.T) {
		accessToken, user := userAccessTokenViaAuthCodeRefresh(t)
		assertEmailChangeSucceeds(t, accessToken, user)
	})

	// Pins the auth_time-over-sid choice. `sid` is set only when a session exists, so a
	// sessionless ROPC token has none: an implementation checking `sid` instead passes
	// every other case here and fails these two.
	t.Run("sessionless ROPC token", func(t *testing.T) {
		accessToken, user, _ := userAccessTokenViaROPC(t)
		assertEmailChangeSucceeds(t, accessToken, user)
	})

	t.Run("sessionless ROPC refresh token", func(t *testing.T) {
		_, user, refreshToken := userAccessTokenViaROPC(t)
		accessToken := refreshROPCToken(t, refreshToken)
		assertEmailChangeSucceeds(t, accessToken, user)
	})

	t.Run("implicit flow token reaches userinfo", func(t *testing.T) {
		accessToken := userAccessTokenViaImplicit(t)

		resp := makeAPIRequest(t, "GET", config.GetAuthServer().BaseURL+"/userinfo", accessToken, nil)
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d. body: %s", resp.StatusCode, string(body))
		}
	})
}

// userAccessTokenViaAuthCodeRefresh exchanges an authorization code for tokens, then
// exchanges the refresh token, returning the REFRESHED access token.
func userAccessTokenViaAuthCodeRefresh(t *testing.T) (string, *models.User) {
	t.Helper()

	// Deliberately NOT offline_access. Requesting it routes the flow through /auth/consent,
	// which createAuthCodeEnsuringUserScope does not walk, and the auth code grant returns a
	// refresh token with these scopes anyway. Same reasoning as the comment in
	// token_amr_test.go:TestToken_Refresh_AMR_IsArray.
	clientSecret := gofakeit.LetterN(32)
	scope := "openid profile email " +
		constants.AuthServerResourceIdentifier + ":" + constants.ManageAccountPermissionIdentifier
	httpClient, code := createAuthCodeEnsuringUserScope(t, clientSecret, scope)

	tokenEndpoint := config.GetAuthServer().BaseURL + "/auth/token/"
	data := postToTokenEndpoint(t, httpClient, tokenEndpoint, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
	})

	refreshToken, ok := data["refresh_token"].(string)
	require.True(t, ok, "the authorization code grant should yield a refresh token: %v", data)

	refreshed := postToTokenEndpoint(t, httpClient, tokenEndpoint, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {code.Client.ClientIdentifier},
		"client_secret": {clientSecret},
		"refresh_token": {refreshToken},
	})

	accessToken, ok := refreshed["access_token"].(string)
	require.True(t, ok, "refresh should yield an access token: %v", refreshed)

	return accessToken, &code.User
}

// userAccessTokenViaROPC issues a sessionless ROPC token for a user granted
// authserver:manage-account, returning the access token, the user, and the refresh token.
func userAccessTokenViaROPC(t *testing.T) (string, *models.User, string) {
	t.Helper()

	settings, err := database.GetSettingsById(nil, 1)
	require.NoError(t, err)
	original := settings.ResourceOwnerPasswordCredentialsEnabled
	settings.ResourceOwnerPasswordCredentialsEnabled = true
	err = database.UpdateSettings(nil, settings)
	require.NoError(t, err)
	t.Cleanup(func() {
		settings.ResourceOwnerPasswordCredentialsEnabled = original
		_ = database.UpdateSettings(nil, settings)
	})

	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	client := createROPCClient(t, clientSecret, false)

	password := gofakeit.Password(true, true, true, true, false, 12)
	user, _ := createUserWithSubject(t, uuid.New())
	passwordHashed, err := hashutil.HashPassword(password)
	require.NoError(t, err)
	user.PasswordHash = passwordHashed
	err = database.UpdateUser(nil, user)
	require.NoError(t, err)

	// ROPC checks the USER holds each requested resource permission, so manage-account has to be
	// granted. Nothing else: the user must NOT hold authserver:userinfo.
	//
	// That absence is load-bearing rather than incidental. This helper used to grant it too, to
	// work around the refresh defect where the server re-validated the authserver:userinfo scope
	// it injects itself against the user's permissions. With the defect fixed, the grant is gone,
	// and its absence is what makes the "sessionless ROPC refresh token" case exercise the fix.
	// Do not add it back to make a failure go away: a failure here means the injected-scope
	// exception has regressed.
	authserverResource, err := database.GetResourceByResourceIdentifier(nil, constants.AuthServerResourceIdentifier)
	require.NoError(t, err)
	permissions, err := database.GetPermissionsByResourceId(nil, authserverResource.Id)
	require.NoError(t, err)
	for i := range permissions {
		if permissions[i].PermissionIdentifier == constants.ManageAccountPermissionIdentifier {
			assignPermissionToUser(t, user.Id, permissions[i].Id)
			break
		}
	}

	// ROPC bypasses consent entirely, but offline_access is still unnecessary: the grant
	// returns a refresh token with plain openid (see TestROPC_Success).
	scope := "openid " +
		constants.AuthServerResourceIdentifier + ":" + constants.ManageAccountPermissionIdentifier
	data := postToTokenEndpoint(t, createHttpClient(t), config.GetAuthServer().BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"password"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"username":      {user.Email},
		"password":      {password},
		"scope":         {scope},
	})

	accessToken, ok := data["access_token"].(string)
	require.True(t, ok, "ROPC should yield an access token: %v", data)
	refreshToken, _ := data["refresh_token"].(string)

	// Store the client secret so the refresh helper can reuse it.
	ropcRefreshCredentials[refreshToken] = ropcClientCredentials{
		clientIdentifier: client.ClientIdentifier,
		clientSecret:     clientSecret,
	}

	return accessToken, user, refreshToken
}

type ropcClientCredentials struct {
	clientIdentifier string
	clientSecret     string
}

// ropcRefreshCredentials lets refreshROPCToken find the client that issued a given
// refresh token without threading the secret through every call site.
var ropcRefreshCredentials = map[string]ropcClientCredentials{}

func refreshROPCToken(t *testing.T, refreshToken string) string {
	t.Helper()

	creds, ok := ropcRefreshCredentials[refreshToken]
	require.True(t, ok, "refresh token should have recorded credentials")

	data := postToTokenEndpoint(t, createHttpClient(t), config.GetAuthServer().BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {creds.clientIdentifier},
		"client_secret": {creds.clientSecret},
		"refresh_token": {refreshToken},
	})

	accessToken, ok := data["access_token"].(string)
	require.True(t, ok, "ROPC refresh should yield an access token: %v", data)
	return accessToken
}

// userAccessTokenViaImplicit drives the implicit flow to an access token carrying
// authserver:userinfo.
func userAccessTokenViaImplicit(t *testing.T) string {
	t.Helper()

	settings, err := database.GetSettingsById(nil, 1)
	require.NoError(t, err)
	original := settings.ImplicitFlowEnabled
	settings.ImplicitFlowEnabled = true
	err = database.UpdateSettings(nil, settings)
	require.NoError(t, err)
	t.Cleanup(func() {
		settings.ImplicitFlowEnabled = original
		_ = database.UpdateSettings(nil, settings)
	})

	client, redirectUri := createImplicitFlowClient(t, nil)
	user, password := createTestUserForImplicit(t)

	// Just "openid". authserver:userinfo must NOT be requested explicitly: the authorize
	// validator rejects it outright (authorize_validator.go ValidateScopes) because
	// generateAccessTokenCore appends it to the issued token whenever an OIDC scope is
	// present. That injection is what lets this token reach /userinfo, and it is also why
	// the user needs no userinfo permission grant here.
	requestScope := "openid"
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=token" +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + gofakeit.LetterN(16)

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

	csrf := getCsrfValue(t, resp)
	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	tokens := getTokensFromFragment(t, resp)
	accessToken := tokens["access_token"]
	require.NotEmpty(t, accessToken, "implicit flow should yield an access token")

	return accessToken
}
