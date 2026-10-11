package integration

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The token endpoint's half of #509: a refresh token descended from a code, from a client other than
// the admin console's, renews authserver:manage-account only while the user's stored consent to the
// client covers it, whatever the client's Consent required says and whether the token is offline or
// session-bound (decision 3). The refusal is invalid_grant with the sentences a client requiring
// consent already gets, and comes before the token is spent, so the same token refreshes once the
// request leaves manage-account out (RFC 6749 section 6). A password grant's refresh token is not
// asked.
//
// The grants here are issued while the user's consent covers manage-account, through the fixture
// every Account API test uses, and the consent is then withdrawn or rewritten: the grant a user's
// withdrawal under Account, Manage consents leaves in a client's hands, and the same state a token
// issued with no consent before the upgrade is in.

// refreshNoConsent is the refresh grant's answer when the user has no stored consent to the client.
const refreshNoConsent = "The user has either not given consent to this client or the previously granted consent has been revoked."

// refreshManageAccountNotConsented is its answer when the stored consent leaves manage-account out.
const refreshManageAccountNotConsented = "Scope 'authserver:manage-account' is not recognized. " +
	"The user has not consented to the 'authserver:manage-account' permission."

// manageAccountGrant is a refresh token carrying authserver:manage-account from a consent-off client.
type manageAccountGrant struct {
	httpClient   *http.Client
	code         *record.Code
	clientSecret string
	refreshToken string
}

// newManageAccountGrant redeems a code for scope, which names authserver:manage-account, through a
// new consent-off client, and answers its refresh token.
func newManageAccountGrant(t *testing.T, scope string) *manageAccountGrant {
	t.Helper()

	clientSecret := fake.LetterN(32)
	httpClient, code := createAuthCodeEnsuringUserScope(t, clientSecret, scope)
	require.False(t, code.Client.ConsentRequired, "the fixture's client has Consent required off")
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, code.Client.Id) })

	tokens := postToTokenEndpoint(t, httpClient, appConfig.AuthServer.BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {testCodeVerifier},
	})
	refreshToken, ok := tokens["refresh_token"].(string)
	require.True(t, ok, "the code grant yields a refresh token: %v", tokens)
	return &manageAccountGrant{httpClient: httpClient, code: code, clientSecret: clientSecret, refreshToken: refreshToken}
}

// refresh presents the grant's current refresh token with scope, empty to omit it, and on success
// keeps the rotated token.
func (g *manageAccountGrant) refresh(t *testing.T, scope string) (int, map[string]interface{}) {
	t.Helper()
	status, body := refreshWithScope(t, g.httpClient, g.code.Client.ClientIdentifier, g.clientSecret, g.refreshToken, scope)
	if rotated, ok := body["refresh_token"].(string); ok && status == http.StatusOK {
		g.refreshToken = rotated
	}
	return status, body
}

// storedConsent is the user's stored consent to the grant's client, which the fixture created.
func (g *manageAccountGrant) storedConsent(t *testing.T) *record.UserConsent {
	t.Helper()
	consent, err := database.GetConsentByUserIdAndClientId(context.Background(), nil, g.code.UserId, g.code.Client.Id)
	require.NoError(t, err)
	require.NotNil(t, consent, "the fixture stores a consent covering the scope")
	return consent
}

// withdrawConsent deletes the user's consent to the grant's client, as Account, Manage consents does.
func (g *manageAccountGrant) withdrawConsent(t *testing.T) {
	t.Helper()
	require.NoError(t, database.DeleteUserConsent(context.Background(), nil, g.storedConsent(t).Id))
}

// assertManageAccountRefreshRefused holds a refresh's answer to invalid_grant with description, and
// no token in it.
func assertManageAccountRefreshRefused(t *testing.T, status int, body map[string]interface{}, description string) {
	t.Helper()
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"])
	assert.Equal(t, description, body["error_description"])
	assert.NotContains(t, body, "access_token")
	assert.NotContains(t, body, "refresh_token")
}

// The user withdraws the consent. The next refresh is refused, and the same token, not spent by the
// refusal, refreshes once the request leaves manage-account out.
func TestToken_ManageAccount_RefreshAfterTheConsentWasWithdrawn(t *testing.T) {
	g := newManageAccountGrant(t, "openid profile authserver:manage-account")

	// The control: while the consent covers it, the grant refreshes whole.
	status, body := g.refresh(t, "")
	require.Equal(t, http.StatusOK, status, "a consented grant refreshes: %v", body)
	assert.Equal(t, "openid profile authserver:manage-account", body["scope"])

	g.withdrawConsent(t)

	status, body = g.refresh(t, "")
	assertManageAccountRefreshRefused(t, status, body, refreshNoConsent)

	status, body = g.refresh(t, "openid profile authserver:manage-account")
	assertManageAccountRefreshRefused(t, status, body, refreshNoConsent)

	status, body = g.refresh(t, "openid profile")
	require.Equal(t, http.StatusOK, status, "a refresh leaving manage-account out succeeds: %v", body)
	assert.Equal(t, "openid profile", body["scope"])
	assert.NotEmpty(t, body["access_token"])
}

// The stored consent is rewritten to leave manage-account out, as unticking it on the screen leaves
// it. The refresh is refused naming the scope, and narrowing still refreshes.
func TestToken_ManageAccount_RefreshWithAConsentLeavingItOut(t *testing.T) {
	g := newManageAccountGrant(t, "openid profile authserver:manage-account")

	consent := g.storedConsent(t)
	consent.Scope = "openid profile"
	require.NoError(t, database.UpdateUserConsent(context.Background(), nil, consent))

	status, body := g.refresh(t, "")
	assertManageAccountRefreshRefused(t, status, body, refreshManageAccountNotConsented)

	status, body = g.refresh(t, "openid profile")
	require.Equal(t, http.StatusOK, status, "a refresh leaving manage-account out succeeds: %v", body)
	assert.Equal(t, "openid profile", body["scope"])
}

// An offline grant, which a client gets only through the consent screen, is held to the same
// consent: the user approves the screen, and later withdraws the consent.
func TestToken_ManageAccount_AnOfflineRefreshAfterTheConsentWasWithdrawn(t *testing.T) {
	const scope = "openid offline_access authserver:manage-account"
	f := newManageAccountConsentFixture(t, false)
	f.signIn(t)

	consentURL, page := f.toConsentScreen(t, f.link("code", scope, ""))
	defer func() { _ = page.Body.Close() }()
	require.Equal(t, []string{"openid", "offline_access", "authserver:manage-account"}, scopesOnScreen(t, page))
	resp := postConsent(t, f.browser, consentURL, page, []int{0, 1, 2})
	defer func() { _ = resp.Body.Close() }()
	location := assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, f.browser, location)
	defer func() { _ = resp.Body.Close() }()
	codeVal, _ := getCodeAndStateFromUrl(t, resp)

	tokens := postToTokenEndpoint(t, f.browser, appConfig.AuthServer.BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {f.client.ClientIdentifier},
		"client_secret": {f.clientSecret},
		"code":          {codeVal},
		"redirect_uri":  {manageAccountRedirectURI},
		"code_verifier": {testCodeVerifier},
	})
	refreshToken, ok := tokens["refresh_token"].(string)
	require.True(t, ok, "the code grant yields a refresh token: %v", tokens)
	assert.Equal(t, scope, tokens["scope"])

	// The control: while the consent covers it, the grant refreshes whole.
	status, body := refreshWithScope(t, f.browser, f.client.ClientIdentifier, f.clientSecret, refreshToken, "")
	require.Equal(t, http.StatusOK, status, "a consented offline grant refreshes: %v", body)
	refreshToken = body["refresh_token"].(string)

	consent, err := database.GetConsentByUserIdAndClientId(context.Background(), nil, f.user.Id, f.client.Id)
	require.NoError(t, err)
	require.NotNil(t, consent)
	require.NoError(t, database.DeleteUserConsent(context.Background(), nil, consent.Id))

	status, body = refreshWithScope(t, f.browser, f.client.ClientIdentifier, f.clientSecret, refreshToken, "")
	assertManageAccountRefreshRefused(t, status, body, refreshNoConsent)
}

// A password grant's refresh token carrying manage-account refreshes with no consent stored: the
// user typed the password into the client, which skips consent (decision 3).
func TestToken_ManageAccount_APasswordGrantRefreshTokenIsNotAsked(t *testing.T) {
	enableROPCGlobally(t)

	clientSecret := fake.Password(32)
	client := createROPCClient(t, clientSecret, false)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })

	password := fake.Password(12)
	passwordHashed, err := passwordhash.Hash(password)
	require.NoError(t, err)
	user := &record.User{Subject: fake.UUID(), Enabled: true, Email: fake.Email(), PasswordHash: passwordHashed}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, user.Id) })
	assignPermissionToUser(t, user.Id, authServerPermissionId(t, builtin.ManageAccountPermissionIdentifier))

	status, tokens := passwordGrant(t, client, clientSecret, user, password, "openid authserver:manage-account")
	require.Equal(t, http.StatusOK, status, "the password grant issues manage-account: %v", tokens)
	refreshToken, ok := tokens["refresh_token"].(string)
	require.True(t, ok, "the password grant yields a refresh token: %v", tokens)

	consent, err := database.GetConsentByUserIdAndClientId(context.Background(), nil, user.Id, client.Id)
	require.NoError(t, err)
	require.Nil(t, consent, "no consent is stored")

	status, body := refreshWithScope(t, createHttpClient(t), client.ClientIdentifier, clientSecret, refreshToken, "")
	require.Equal(t, http.StatusOK, status, "the password grant's token refreshes: %v", body)
	assert.Equal(t, "openid authserver:manage-account", body["scope"])
}

// A replay of a rotated manage-account token is contained whatever the consent now says: the
// family is recorded as revoked and the live successor with it, so the successor refreshes no
// further even narrowed to leave manage-account out. The consent re-check must not answer the
// replay first, which left the successor live (#509 review R1-1). The client is public, the shape
// rotation exists to protect (RFC 9700 sections 2.2.2 and 4.14.2), and the covering consent is the
// control.
func TestToken_ManageAccount_AReplayIsContainedWhateverTheConsent(t *testing.T) {
	for _, change := range []string{"consent still covers it", "consent withdrawn", "consent leaves manage-account out"} {
		t.Run(change, func(t *testing.T) {
			f := newManageAccountConsentFixture(t, false)
			f.client.IsPublic = true
			f.client.ClientSecretEncrypted = nil
			require.NoError(t, database.UpdateClient(context.Background(), nil, f.client))
			f.signIn(t)

			const scope = "openid profile authserver:manage-account"
			consentURL, page := f.toConsentScreen(t, f.link("code", scope, ""))
			defer func() { _ = page.Body.Close() }()
			require.Equal(t, []string{"openid", "profile", "authserver:manage-account"}, scopesOnScreen(t, page))
			resp := postConsent(t, f.browser, consentURL, page, []int{0, 1, 2})
			defer func() { _ = resp.Body.Close() }()
			location := assertRedirect(t, resp, "/auth/issue")
			resp = loadPage(t, f.browser, location)
			defer func() { _ = resp.Body.Close() }()
			code, _ := getCodeAndStateFromUrl(t, resp)
			tokens := postToTokenEndpoint(t, f.browser, appConfig.AuthServer.BaseURL+"/auth/token/", url.Values{
				"grant_type":    {"authorization_code"},
				"client_id":     {f.client.ClientIdentifier},
				"code":          {code},
				"redirect_uri":  {manageAccountRedirectURI},
				"code_verifier": {testCodeVerifier},
			})
			parent, ok := tokens["refresh_token"].(string)
			require.True(t, ok, "the public client's code grants a refresh token")
			child := rotateRefreshToken(t, f.browser, f.client.ClientIdentifier, "", parent)
			first := refreshTokenRowByJti(t, parent).FirstRefreshTokenJti
			require.False(t, refreshTokenRowByJti(t, child).Revoked)

			consent, err := database.GetConsentByUserIdAndClientId(context.Background(), nil, f.user.Id, f.client.Id)
			require.NoError(t, err)
			require.NotNil(t, consent)
			switch change {
			case "consent withdrawn":
				require.NoError(t, database.DeleteUserConsent(context.Background(), nil, consent.Id))
			case "consent leaves manage-account out":
				consent.Scope = "openid profile"
				require.NoError(t, database.UpdateUserConsent(context.Background(), nil, consent))
			}

			status, body := replayRefreshToken(t, f.browser, f.client.ClientIdentifier, "", parent)
			assertRefusedAsInvalidGrant(t, status, body, "the retired parent")
			recorded, err := database.IsRefreshTokenFamilyRevoked(context.Background(), nil, first)
			require.NoError(t, err)
			assert.True(t, recorded, "the replay records the family as revoked")
			assert.True(t, refreshTokenRowByJti(t, child).Revoked, "the replay revokes the live successor")

			status, body = refreshWithScope(t, f.browser, f.client.ClientIdentifier, "", child, "openid profile")
			// The messages name the error alone: on failure the body holds live tokens.
			assert.Equal(t, http.StatusBadRequest, status, "the contained successor refreshes no further: %v", body["error"])
			assert.Equal(t, "invalid_grant", body["error"])
			_, hasAccessToken := body["access_token"]
			_, hasRefreshToken := body["refresh_token"]
			assert.False(t, hasAccessToken, "the contained successor gets no access token")
			assert.False(t, hasRefreshToken, "the contained successor gets no refresh token")
		})
	}
}
