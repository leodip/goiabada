package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/config"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	mocks_handlerhelpers "github.com/leodip/goiabada/adminconsole/internal/handlerhelpers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	coreconstants "github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
	"github.com/leodip/goiabada/core/testutil"
)

// failingExchanger is the shortest path from a callback request to the record under test: the
// handler writes it, then exchanges, then answers 500 on the failure. Nothing here asserts on the
// 500; it exists so the handler stops before it needs a token response to parse.
type failingExchanger struct{}

func (failingExchanger) ExchangeCodeForTokens(_ context.Context, code, redirectURI, clientId,
	clientSecret, codeVerifier, tokenEndpoint string) (*oauth.TokenResponse, error) {
	return nil, errs.New("the auth server refused the code")
}

// unusedTokenParser satisfies the handler's dependency. The exchange fails above it, so a call to
// it is a test that stopped measuring what it says it measures.
type unusedTokenParser struct{ t *testing.T }

func (p unusedTokenParser) DecodeAndValidateSignInResponse(_ context.Context, _ *oauth.TokenResponse,
	_ string) (*oauthclient.JwtInfo, error) {
	p.t.Fatal("the token parser must not be reached: the exchange fails before it")
	return nil, nil
}

// handshakeSession is a session holding all six values RedirToAuthorize parks, with the state
// "the-state", so a callback posting that state reaches the exchange. The handler reads all six
// before it exchanges, so a case missing one stops short of what it is about.
func handshakeSession() *sessionstore.Session {
	return &sessionstore.Session{Values: map[string]any{
		constants.SessionKeyState:          "the-state",
		constants.SessionKeyCodeVerifier:   "the-code-verifier",
		constants.SessionKeyRedirectURI:    "https://adminconsole.example/auth/callback",
		constants.SessionKeyNonce:          "the-nonce",
		constants.SessionKeyRedirectBack:   "https://adminconsole.example/admin/clients",
		constants.SessionKeyRequestedScope: "openid authserver:manage",
	}}
}

// The code exchange record, moved from Info to Debug and from a concatenated message to an
// attribute (#320 decisions 4 and 5).
//
// It fired at Info on every administrator sign-in, which is per-request tracing in the level
// reserved for lifecycle and configuration, and it carried the auth server's address by string
// concatenation, so nothing could query it. Level is not decidable from the text, so the lint
// stage 7 adds cannot hold this: this case is what holds it.
//
// It is also this module's end-to-end check of decision 2. The handler names neither the
// request_id key nor its value; the id reaches the record because chi's RequestID middleware put
// it on the context and the installed handler read it off there. Remove that wrapper and the
// correlation disappears from every record the console writes, with nothing else here failing.
func TestSlogConvention_TheCodeExchangeIsDebugAndCarriesTheBaseUrlAndTheRequestId(t *testing.T) {
	// The internal base URL is what the handler must exchange against when one is configured,
	// which is the whole reason this value is worth a record. Restored, because config is
	// process-global and this package's TestMain loads it once.
	authServer := config.GetAuthServer()
	previous := authServer.InternalBaseURL
	authServer.InternalBaseURL = "https://authserver.internal.example"
	t.Cleanup(func() { authServer.InternalBaseURL = previous })

	logs := testutil.CaptureSlog(t)

	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/no_menu_layout.html", "/sign_in_error.html").Once()

	httpSession := mocks_sessionstore.NewStore(t)
	httpSession.On("Get", mock.Anything, coreconstants.AdminConsoleSessionName).Return(handshakeSession(), nil)

	form := url.Values{"state": {"the-state"}, "code": {"the-code"}}
	req := httptest.NewRequest(http.MethodPost, "/auth/callback", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// chi's RequestID takes X-Request-Id from the caller verbatim, so this is the id the
	// record must carry without the handler ever naming it.
	req.Header.Set("X-Request-Id", "req-admin-callback")

	handler := HandleAuthCallbackPost(httpHelper, httpSession, unusedTokenParser{t: t}, failingExchanger{})
	chimiddleware.RequestID(handler).ServeHTTP(httptest.NewRecorder(), req)

	records := logs.Records()
	// The second is the failed exchange's own refusal, at Error; the first is the one under test.
	require.Len(t, records, 2, "the exchange record, then the refusal of the exchange that failed")
	assert.Equal(t, slog.LevelError, records[1].Level)
	assert.Equal(t, slog.LevelDebug, records[0].Level,
		"per-request tracing is Debug: an operator reading the log does not need a line per sign-in")
	assert.Equal(t, "exchanging the code for tokens", records[0].Message,
		"a literal message, with the address it used as an attribute rather than concatenated into it")
	assert.Equal(t, "https://authserver.internal.example", records[0].Attrs["base_url"],
		"the effective base URL, which is the internal one when a deployment configures it")
	assert.Equal(t, "req-admin-callback", records[0].Attrs["request_id"],
		"injected from chi's request id, with nothing in this file or in the handler naming it")
}
