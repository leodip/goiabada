package oauthclient_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
)

// safeModeAuthorize runs one redirect over the real store for a request whose page is, or is not, in
// safe mode, and returns the authorize request's query and the handshake its cookie carries.
func safeModeAuthorize(t *testing.T, safe bool,
	redirect func(*oauthclient.AuthHelper, http.ResponseWriter, *http.Request) error) (url.Values, map[string]string) {
	t.Helper()
	store, _ := newHandshakeStore(t, false)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin/clients", nil)
	r = r.WithContext(reqctx.WithSafeMode(context.Background(), safe))
	require.NoError(t, redirect(oauthclient.NewAuthHelper(store, helperConsoleBase, helperAuthBase, reqctx.SafeModeFrom), w, r))

	require.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	require.True(t, strings.HasPrefix(location, helperAuthorizePath), "redirects to the authorize endpoint: %s", location)
	query, err := url.ParseQuery(strings.TrimPrefix(location, helperAuthorizePath))
	require.NoError(t, err)

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	handshake, err := store.OpenCookieValues(oauthclient.SignInHandshakeCookie, cookies[0].Value)
	require.NoError(t, err)
	return query, handshake
}

// While the console's request is in safe mode, every authorization request it sends carries
// goiabada_safe_mode=true, the ordinary sign-in and the stronger one a page asks for alike, and the
// handshake keeps it for the callback, which keeps the console session in safe mode (#816
// decision 2). Out of safe mode, neither carries anything.
func TestRedirToAuthorize_SendsSafeModeWhileTheRequestIsInIt(t *testing.T) {
	signIns := []struct {
		name     string
		redirect func(*oauthclient.AuthHelper, http.ResponseWriter, *http.Request) error
	}{
		{"the ordinary sign-in", func(h *oauthclient.AuthHelper, w http.ResponseWriter, r *http.Request) error {
			return h.RedirToAuthorize(w, r, helperClientID, helperScope, helperRedirectBack)
		}},
		{"a stronger sign-in", func(h *oauthclient.AuthHelper, w http.ResponseWriter, r *http.Request) error {
			return h.RedirToAuthorizeWith(w, r, helperClientID, helperScope, helperRedirectBack,
				oauthclient.SignInOptions{Prompt: "login", AcrValues: "urn:goiabada:level2_mandatory"})
		}},
	}
	for _, signIn := range signIns {
		t.Run(signIn.name+" in safe mode", func(t *testing.T) {
			query, handshake := safeModeAuthorize(t, true, signIn.redirect)

			assert.Equal(t, []string{"true"}, query["goiabada_safe_mode"])
			assert.Equal(t, "true", handshake[sessionkeys.SafeMode])
			assert.Len(t, handshake, 7, "the six values the callback reads, and safe mode")
		})
		t.Run(signIn.name+" out of it", func(t *testing.T) {
			query, handshake := safeModeAuthorize(t, false, signIn.redirect)

			assert.NotContains(t, query, "goiabada_safe_mode")
			assert.NotContains(t, handshake, sessionkeys.SafeMode)
			assert.Len(t, handshake, 6)
		})
	}
}
