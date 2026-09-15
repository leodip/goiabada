package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
)

// contextRecordingExchanger records what the context the handler hands it looked
// like at the moment of the call, then fails so the case stops before token
// parsing. It is the shape failingExchanger in slog_convention_test.go already
// uses; only the recording is new.
//
// It records the two facts rather than the context itself because the handler
// holds a deferred cancel, which is correct -- a timeout context that is never
// cancelled leaks its timer until it fires -- and means the context is already
// done by the time the handler has returned and the assertions run.
type contextRecordingExchanger struct {
	called   bool
	ctxErr   error
	deadline time.Time
	hasLimit bool
}

func (e *contextRecordingExchanger) ExchangeCodeForTokens(ctx context.Context, code, redirectURI,
	clientId, clientSecret, codeVerifier, tokenEndpoint string) (*oauth.TokenResponse, error) {
	e.called = true
	e.ctxErr = ctx.Err()
	e.deadline, e.hasLimit = ctx.Deadline()
	return nil, errs.New("the auth server refused the code")
}

// Decision 12, the authorization_code half. The code the auth server just
// redirected back with is single use and already burned by the time it answers,
// so a browser that goes away between the redirect and the exchange must not
// take the exchange with it -- the tokens it issued would be the only copy and
// the administrator would be signed out of a session the auth server thinks
// exists.
//
// The inbound request here is already cancelled, which is exactly that. What the
// handler hands the exchanger has to be live anyway, and bounded by the ten
// seconds that replaces the cancellation. Passing r.Context() straight through
// is the one-token change this case exists to catch, and every other case in
// this package stays green under it.
func TestHandleAuthCallbackPost_DetachesTheExchangeFromTheBrowsersContext(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Return()

	session := &sessionstore.Session{Values: map[string]any{
		constants.SessionKeyState:        "the-state",
		constants.SessionKeyCodeVerifier: "the-code-verifier",
		constants.SessionKeyRedirectURI:  "https://adminconsole.example/auth/callback",
	}}
	httpSession := mocks_sessionstore.NewStore(t)
	httpSession.On("Get", mock.Anything, constants.AdminConsoleSessionName).Return(session, nil)

	form := url.Values{"state": {"the-state"}, "code": {"the-code"}}
	req := httptest.NewRequest(http.MethodPost, "/auth/callback", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	ctx, cancel := context.WithCancel(req.Context())
	cancel()
	req = req.WithContext(ctx)

	exchanger := &contextRecordingExchanger{}
	HandleAuthCallbackPost(httpHelper, httpSession, unusedTokenParser{t: t}, exchanger).
		ServeHTTP(httptest.NewRecorder(), req)

	require.True(t, exchanger.called, "the exchange was reached")
	assert.NoError(t, exchanger.ctxErr,
		"the exchange runs on a context detached from the browser's, which is already cancelled")

	require.True(t, exchanger.hasLimit, "detached, but not unbounded")
	assert.LessOrEqual(t, time.Until(exchanger.deadline), oauth.TokenExchangeTimeout,
		"bounded by TokenExchangeTimeout, which is what replaces the cancellation")
	// The tolerance is what the handler spends between taking the deadline and calling the
	// exchanger, which is a few microseconds; a second is generous for a loaded machine and
	// still refuses any value that is not the ten seconds decision 11 chose. Subtracting a
	// minute from a ten second constant was the earlier form, and a negative lower bound
	// asserts nothing (#338).
	assert.Greater(t, time.Until(exchanger.deadline), oauth.TokenExchangeTimeout-time.Second,
		"and by that value rather than by something shorter")
}
