package oauthclient_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
)

const (
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

// createCountingBackend counts the rows the store inserts.
type createCountingBackend struct {
	*sessiontest.MemoryBackend
	creates atomic.Int64
}

func (b *createCountingBackend) Create(ctx context.Context, id string, data []byte, authenticated bool) (time.Time, error) {
	b.creates.Add(1)
	return b.MemoryBackend.Create(ctx, id, data, authenticated)
}

// newHandshakeStore is the production session store over an in-memory backend, which is what
// seals the handshake cookie. The backend is returned so a test can see that nothing reached it.
func newHandshakeStore(t *testing.T, secure bool) (*sessionstore.ServerSideStore, *createCountingBackend) {
	t.Helper()
	backend := &createCountingBackend{MemoryBackend: sessiontest.NewMemoryBackend()}
	store, err := sessionstore.NewServerSideStore(backend, sessionkeys.JWT, secure, sessionstore.BrowserSessionCookie,
		sessionstore.KeyPair{
			AuthenticationKey: []byte("12345678901234567890123456789012"),
			EncryptionKey:     []byte("abcdefghijklmnopqrstuvwxyz123456"),
		}, nil)
	require.NoError(t, err)
	return store, backend
}

// redirToAuthorize runs one RedirToAuthorize over the real store, and returns the handshake the
// cookie it set carries, opened as the callback opens it, and what was written.
func redirToAuthorize(t *testing.T) (map[string]string, *httptest.ResponseRecorder) {
	t.Helper()
	store, _ := newHandshakeStore(t, false)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin/clients", nil)
	err := oauthclient.NewAuthHelper(store, helperConsoleBase, helperAuthBase).
		RedirToAuthorize(w, r, helperClientID, helperScope, helperRedirectBack)
	require.NoError(t, err)

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1, "one cookie, the handshake's")
	require.Equal(t, store.CookieName(oauthclient.SignInHandshakeCookie), cookies[0].Name)
	handshake, err := store.OpenCookieValues(oauthclient.SignInHandshakeCookie, cookies[0].Value)
	require.NoError(t, err)
	return handshake, w
}

func storedString(t *testing.T, handshake map[string]string, key string) string {
	t.Helper()
	value, ok := handshake[key]
	require.Truef(t, ok, "the handshake holds %s", key)
	require.NotEmptyf(t, value, "the handshake's %s is not empty", key)
	return value
}

// The authorize redirect and the handshake it parks in its cookie are one contract with the
// callback: every value the Location sends is derived from what the handshake keeps, and the
// callback can only check what was kept. Each parameter is recomputed here from the stored value
// rather than compared with a second call's output (#427 seam 3).
func TestRedirToAuthorize_SendsWhatItStores(t *testing.T) {
	sess, w := redirToAuthorize(t)
	assert.Len(t, sess, 6, "the six values the callback reads, and nothing else")

	require.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	require.True(t, strings.HasPrefix(location, helperAuthorizePath), "redirects to the authorize endpoint: %s", location)
	query, err := url.ParseQuery(strings.TrimPrefix(location, helperAuthorizePath))
	require.NoError(t, err)

	state := storedString(t, sess, sessionkeys.State)
	nonce := storedString(t, sess, sessionkeys.Nonce)
	verifier := storedString(t, sess, sessionkeys.CodeVerifier)
	redirectURI := storedString(t, sess, sessionkeys.RedirectURI)

	assert.Equal(t, helperClientID, query.Get("client_id"))
	assert.Equal(t, helperConsoleBase+"/auth/callback", redirectURI)
	assert.Equal(t, redirectURI, query.Get("redirect_uri"), "the redirect URI sent is the one the callback will send again")
	assert.Equal(t, "form_post", query.Get("response_mode"))
	assert.Equal(t, "code", query.Get("response_type"))
	assert.Equal(t, "S256", query.Get("code_challenge_method"), "RFC 7636 section 4.2: S256 when the client is capable of it")
	assert.Equal(t, state, query.Get("state"))
	assert.Equal(t, helperScope, query.Get("scope"))
	assert.Equal(t, helperScope, storedString(t, sess, sessionkeys.RequestedScope),
		"the requested scope is kept for the callback, which takes the grant to equal it when the response names none")
	assert.Equal(t, helperRedirectBack, storedString(t, sess, sessionkeys.RedirectBack))

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
	assert.NotEqual(t, nonce, query.Get("nonce"), "the raw nonce never leaves the handshake")
}

// State, nonce and verifier are minted per sign-in: a value repeated across two redirects would be
// one an attacker who saw the first could replay into the second.
func TestRedirToAuthorize_MintsFreshValuesEachTime(t *testing.T) {
	first, _ := redirToAuthorize(t)
	second, _ := redirToAuthorize(t)

	for _, key := range []string{sessionkeys.State, sessionkeys.Nonce, sessionkeys.CodeVerifier} {
		assert.NotEqualf(t, storedString(t, first, key), storedString(t, second, key), "%s is minted afresh", key)
	}
}

// The handshake rides in a cookie, so starting a sign-in writes no row: an anonymous request to
// any /admin or /account path used to cost the auth server an insert, at no limit (#620). The
// cookie is the store's own, HttpOnly, Secure and __Host- prefixed on https, for the
// pre-authentication lifetime.
func TestRedirToAuthorize_WritesNoRowAndSetsTheHandshakeCookie(t *testing.T) {
	for _, secure := range []bool{true, false} {
		t.Run(fmt.Sprintf("secure=%v", secure), func(t *testing.T) {
			store, backend := newHandshakeStore(t, secure)

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/admin/clients", nil)
			require.NoError(t, oauthclient.NewAuthHelper(store, helperConsoleBase, helperAuthBase).
				RedirToAuthorize(w, r, helperClientID, helperScope, helperRedirectBack))

			assert.Zero(t, backend.creates.Load(), "no browser-session row")
			cookies := w.Result().Cookies()
			require.Len(t, cookies, 1)
			cookie := cookies[0]
			if secure {
				assert.Equal(t, "__Host-"+oauthclient.SignInHandshakeCookie, cookie.Name)
			} else {
				assert.Equal(t, oauthclient.SignInHandshakeCookie, cookie.Name)
			}
			assert.Equal(t, secure, cookie.Secure)
			assert.True(t, cookie.HttpOnly)
			assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
			assert.Equal(t, "/", cookie.Path)
			assert.Equal(t, int(sessionstore.PreAuthLifetime.Seconds()), cookie.MaxAge)
		})
	}
}

// failingSealer is a store whose seal fails, the one way the handshake cannot be carried.
type failingSealer struct{}

func (failingSealer) SealCookieValues(string, map[string]string) (string, error) {
	return "", errs.New("the handshake is too long")
}

func (failingSealer) ValuesCookie(name, value string) *http.Cookie {
	return &http.Cookie{Name: name, Value: value}
}

// A handshake that cannot be sealed sends nobody to the auth server: a redirect whose handshake
// was never carried could only come back to a callback that refuses it.
func TestRedirToAuthorize_ASealThatFails(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin/clients", nil)
	err := oauthclient.NewAuthHelper(failingSealer{}, helperConsoleBase, helperAuthBase).
		RedirToAuthorize(w, r, helperClientID, helperScope, helperRedirectBack)

	require.Error(t, err)
	assert.Empty(t, w.Header().Get("Location"), "no redirect")
	assert.Empty(t, w.Result().Cookies(), "no cookie")
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

	helper := oauthclient.NewAuthHelper(nil, helperConsoleBase, helperAuthBase)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, helper.IsAuthenticated(tc.jwtInfo))
		})
	}
}

// Authorized means the grant the token response records names one of the scopes asked for, matched
// exactly. It is read from the response's scope, which the console sets to the effective grant on
// arrival, never from inside the access token: the rows whose access token string would decode to
// a matching scope, were anything to decode it, must still be refused (#427).
func TestIsAuthorizedToAccessResource(t *testing.T) {
	const manage = "authserver:manage"
	const manageAccount = "authserver:manage-account"
	withGrant := func(scope string) oauthclient.JwtInfo {
		return oauthclient.JwtInfo{
			TokenResponse: oauth.TokenResponse{AccessToken: "opaque", Scope: scope},
			IdToken:       &oauth.JwtToken{TokenBase64: "i"},
		}
	}

	testCases := []struct {
		name        string
		jwtInfo     oauthclient.JwtInfo
		scopesAnyOf []string
		want        bool
	}{
		{"nothing", oauthclient.JwtInfo{}, []string{manage}, false},
		{"the one scope asked for", withGrant("openid " + manage), []string{manage}, true},
		{"the second of two asked for", withGrant("openid " + manageAccount), []string{manage, manageAccount}, true},
		{"none of those asked for", withGrant("openid profile"), []string{manage, manageAccount}, false},
		{"nothing asked for", withGrant("openid " + manage), nil, false},
		{"a prefix of the scope", withGrant("openid authserver:manag"), []string{manage}, false},
		{"the scope as a prefix of a granted one", withGrant("openid " + manageAccount), []string{manage}, false},
		{"a case variant", withGrant("openid AUTHSERVER:MANAGE"), []string{manage}, false},
		{"an empty grant", withGrant(""), []string{manage}, false},
		{"an empty scope asked for against a doubled space", withGrant("openid  " + manage), []string{""}, false},
		{"the scope only inside the access token string",
			oauthclient.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: manage, Scope: "openid"}},
			[]string{manage}, false},
	}

	helper := oauthclient.NewAuthHelper(nil, helperConsoleBase, helperAuthBase)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, helper.IsAuthorizedToAccessResource(tc.jwtInfo, tc.scopesAnyOf))
		})
	}
}
