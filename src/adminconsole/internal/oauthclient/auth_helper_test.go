package oauthclient_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
)

const (
	helperSessionName   = "the-session"
	helperConsoleBase   = "https://console.example"
	helperAuthBase      = "https://auth.example"
	helperClientID      = "the-client"
	helperScope         = "openid profile authserver:manage"
	helperRedirectBack  = "https://console.example/admin/clients"
	rfc7636VerifierMin  = 43
	rfc7636VerifierMax  = 128
	rfc7636Unreserved   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	helperAuthorizePath = helperAuthBase + "/auth/authorize?"
)

// redirToAuthorize runs one RedirToAuthorize over a store mock whose Get hands back a fresh
// session and whose Save succeeds, and returns that session and what was written.
func redirToAuthorize(t *testing.T) (*sessionstore.Session, *httptest.ResponseRecorder) {
	t.Helper()
	sess := &sessionstore.Session{Values: map[string]any{}}
	store := mocks_sessionstore.NewStore(t)
	store.On("Get", mock.Anything, helperSessionName).Return(sess, nil).Once()
	store.On("Save", mock.Anything, mock.Anything, sess).Return(nil).Once()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin/clients", nil)
	err := oauthclient.NewAuthHelper(store, helperSessionName, helperConsoleBase, helperAuthBase).
		RedirToAuthorize(w, r, helperClientID, helperScope, helperRedirectBack)
	require.NoError(t, err)
	return sess, w
}

func storedString(t *testing.T, sess *sessionstore.Session, key string) string {
	t.Helper()
	value, ok := sess.Values[key].(string)
	require.Truef(t, ok, "the session holds %s as a string", key)
	require.NotEmptyf(t, value, "the session's %s is not empty", key)
	return value
}

// The authorize redirect and the handshake it parks in the session are one contract with the
// callback: every value the Location sends is derived from what the session keeps, and the
// callback can only check what was kept. Each parameter is recomputed here from the stored value
// rather than compared with a second call's output (#427 seam 3).
func TestRedirToAuthorize_SendsWhatItStores(t *testing.T) {
	sess, w := redirToAuthorize(t)

	require.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	require.True(t, strings.HasPrefix(location, helperAuthorizePath), "redirects to the authorize endpoint: %s", location)
	query, err := url.ParseQuery(strings.TrimPrefix(location, helperAuthorizePath))
	require.NoError(t, err)

	state := storedString(t, sess, constants.SessionKeyState)
	nonce := storedString(t, sess, constants.SessionKeyNonce)
	verifier := storedString(t, sess, constants.SessionKeyCodeVerifier)
	redirectURI := storedString(t, sess, constants.SessionKeyRedirectURI)

	assert.Equal(t, helperClientID, query.Get("client_id"))
	assert.Equal(t, helperConsoleBase+"/auth/callback", redirectURI)
	assert.Equal(t, redirectURI, query.Get("redirect_uri"), "the redirect URI sent is the one the callback will send again")
	assert.Equal(t, "form_post", query.Get("response_mode"))
	assert.Equal(t, "code", query.Get("response_type"))
	assert.Equal(t, "S256", query.Get("code_challenge_method"), "RFC 7636 section 4.2: S256 when the client is capable of it")
	assert.Equal(t, state, query.Get("state"))
	assert.Equal(t, helperScope, query.Get("scope"))
	assert.Equal(t, helperScope, storedString(t, sess, constants.SessionKeyRequestedScope),
		"the requested scope is kept for the callback, which takes the grant to equal it when the response names none")
	assert.Equal(t, helperRedirectBack, storedString(t, sess, constants.SessionKeyRedirectBack))

	challenge := sha256.Sum256([]byte(verifier))
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(challenge[:]), query.Get("code_challenge"),
		"BASE64URL-ENCODE(SHA256(ASCII(code_verifier))), RFC 7636 section 4.2")

	assert.GreaterOrEqual(t, len(verifier), rfc7636VerifierMin, "RFC 7636 section 4.1's minimum length")
	assert.LessOrEqual(t, len(verifier), rfc7636VerifierMax, "RFC 7636 section 4.1's maximum length")
	for _, c := range verifier {
		assert.Truef(t, strings.ContainsRune(rfc7636Unreserved, c), "%q is not an unreserved character", c)
	}

	sentNonce := sha256.Sum256([]byte(nonce))
	assert.Equal(t, hex.EncodeToString(sentNonce[:]), query.Get("nonce"),
		"the hash of the stored nonce is sent and the raw value kept, OIDC Core 15.5.2")
	assert.NotEqual(t, nonce, query.Get("nonce"), "the raw nonce never leaves the session")
}

// State, nonce and verifier are minted per sign-in: a value repeated across two redirects would be
// one an attacker who saw the first could replay into the second.
func TestRedirToAuthorize_MintsFreshValuesEachTime(t *testing.T) {
	first, _ := redirToAuthorize(t)
	second, _ := redirToAuthorize(t)

	for _, key := range []string{constants.SessionKeyState, constants.SessionKeyNonce, constants.SessionKeyCodeVerifier} {
		assert.NotEqualf(t, storedString(t, first, key), storedString(t, second, key), "%s is minted afresh", key)
	}
}

// A session that cannot be read or saved sends nobody to the auth server: a redirect whose
// handshake was never stored could only come back to a callback that refuses it.
func TestRedirToAuthorize_SessionFailures(t *testing.T) {
	testCases := []struct {
		name  string
		setup func(store *mocks_sessionstore.Store)
	}{
		{
			name: "get fails",
			setup: func(store *mocks_sessionstore.Store) {
				store.On("Get", mock.Anything, helperSessionName).
					Return(&sessionstore.Session{Values: map[string]any{}}, errs.New("the store is down")).Once()
			},
		},
		{
			name: "save fails",
			setup: func(store *mocks_sessionstore.Store) {
				store.On("Get", mock.Anything, helperSessionName).
					Return(&sessionstore.Session{Values: map[string]any{}}, nil).Once()
				store.On("Save", mock.Anything, mock.Anything, mock.Anything).
					Return(errs.New("the store is down")).Once()
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := mocks_sessionstore.NewStore(t)
			tc.setup(store)

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/admin/clients", nil)
			err := oauthclient.NewAuthHelper(store, helperSessionName, helperConsoleBase, helperAuthBase).
				RedirToAuthorize(w, r, helperClientID, helperScope, helperRedirectBack)

			require.Error(t, err)
			assert.Empty(t, w.Header().Get("Location"), "no redirect")
		})
	}
}

// Authenticated means an ID token verified onto the request; a token response whose strings are
// set but whose ID token was never verified is not a signed-in administrator.
func TestIsAuthenticated(t *testing.T) {
	testCases := []struct {
		name    string
		jwtInfo oauthclient.JwtInfo
		want    bool
	}{
		{"nothing", oauthclient.JwtInfo{}, false},
		{"token strings but no verified id token",
			oauthclient.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: "a", IdToken: "i"}}, false},
		{"a verified id token", oauthclient.JwtInfo{IdToken: &oauth.JwtToken{TokenBase64: "i"}}, true},
	}

	helper := oauthclient.NewAuthHelper(nil, helperSessionName, helperConsoleBase, helperAuthBase)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, helper.IsAuthenticated(tc.jwtInfo))
		})
	}
}
