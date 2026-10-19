package middleware

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient/oauthclienttest"
	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

// #621, the two rows its done-when asks for. The console refreshes an administrator's access
// token from its JWT middleware, on whichever request finds the token due, and the auth server
// rotates refresh tokens strictly (#128, RFC 9700 section 4.14.2), so two requests from one
// session that both find the token due race each other: the loser's grant is refused, and its
// sign-out clears the token set from the copy the request read at its start and saves over the
// winner's, because the console's session store is last-writer-wins (#579). Two tabs in the last
// thirty seconds of the access token were enough. The refresh is serialized per session now: the
// request that waited for the session's lock re-reads the session and carries the answer the
// winner stored, and a grant that is refused anyway never clears a token set newer than the one
// it presented.

// A refused grant never clears a token set newer than the one it presented. The other winner is
// another replica of the console here — beyond this process's lock, which is why the grant is
// refused at all — and it stores its answer while this request's grant is in flight. Before #621
// the sign-out that answered the refused grant saved this request's copy over the newer set,
// signing the administrator out over live tokens.
func TestSessionHandler_ARefusedGrantDoesNotClearATokenSetNewerThanTheOnePresented(t *testing.T) {
	h := newSessionHarness(t)
	cookies := h.seed(signedIn(due()))
	h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, storedIDTokenRaw).Return(verifiedStored, nil)
	h.refresher.err = errs.WithStack(&oauthclient.TokenEndpointError{
		StatusCode: http.StatusBadRequest, ErrorCode: "invalid_grant"})

	// The other replica's answer, stored while this request's grant is in flight.
	winner := oauth.TokenResponse{
		AccessToken:  "the-winners-access-token",
		IdToken:      refreshedIDTokenRaw,
		RefreshToken: "the-winners-refresh-token",
		ExpiresIn:    600,
		Scope:        storedGrant,
	}
	h.refresher.during = func() {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		sess, err := h.store.Get(req, sessionTestName)
		require.NoError(h.t, err)
		sess.Values[sessionkeys.JWT] = winner
		sess.Values[sessionkeys.JWTExpiresAt] = notDue()
		rec := httptest.NewRecorder()
		require.NoError(h.t, h.store.Save(req, rec, sess))
	}
	h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, refreshedIDTokenRaw).
		Return(&oauth.JwtToken{TokenBase64: refreshedIDTokenRaw, Claims: map[string]any{"sub": "the-admin"}}, nil)

	out := h.serve(h.parser, cookies)

	assert.True(h.t, out.reached, "the chain continues")
	require.NotNil(h.t, out.jwtInfo, "the administrator is still signed in")
	assert.Equal(h.t, winner, out.jwtInfo.TokenResponse, "carrying the token set the other replica stored")

	sess := h.readBack(cookies)
	assert.Equal(h.t, winner, sess.Values[sessionkeys.JWT], "the newer token set is kept")
	assert.Equal(h.t, "kept", sess.Values["unrelated"], "the session itself survives")
	calls, _ := h.refresher.sent()
	assert.Equal(h.t, 1, calls, "this request presented its refresh token once")
	h.assertOneRecord(slog.LevelWarn,
		"the refresh grant was refused, but a token set newer than the one it presented had been stored meanwhile, so the session keeps it",
		"invalid_grant")
}

// Two concurrent requests from one session, both finding the token due, share one grant: the
// request that waited for the session's lock carries the answer the winner stored, the
// administrator stays signed in, and only one refresh token is ever presented. The parser is the
// real one because two requests must verify real tokens concurrently, and the refresher is the
// fake, holding the first grant until both requests have loaded the session — the copy each
// makes its due check on, so both find the token due whatever the winner does next.
func TestSessionHandler_ConcurrentRequestsShareOneRefreshGrant(t *testing.T) {
	h := newSessionHarness(t)

	signing, _ := oauthclienttest.Keys(t)
	claims := oauthclienttest.ValidClaims()
	stored := oauthclienttest.SignRS256(t, signing, "current", claims)
	refreshed := oauthclienttest.SignRS256(t, signing, "current", claims)
	jwks, _ := oauthclienttest.NewJwksServer(t, oauthclienttest.JwkFromPublicKey("current", &signing.PublicKey))
	parser := oauthclient.NewJWKSTokenParser(jwks.URL, jwks.Client(), nil,
		oauthclienttest.ClientID, oauthclienttest.StaticIssuer(oauthclienttest.Issuer))

	response := storedResponse()
	response.IdToken = stored
	cookies := h.seed(map[string]any{
		sessionkeys.JWT:          response,
		sessionkeys.JWTExpiresAt: due(),
		"unrelated":              "kept",
	})

	// The answer the winner stores: its ID token signed by the same key, an expiry an hour out.
	winner := oauth.TokenResponse{
		AccessToken:  "the-new-access-token",
		IdToken:      refreshed,
		RefreshToken: "the-new-refresh-token",
		ExpiresIn:    600,
		Scope:        storedGrant,
	}
	// The auth server's strict rotation as the fake answers it: the first presentation claims
	// the refresh token, the second is refused.
	h.refresher.inOrder = []scriptedGrant{
		{answer: &winner},
		{err: errs.WithStack(&oauthclient.TokenEndpointError{
			StatusCode: http.StatusBadRequest, ErrorCode: "invalid_grant"})},
	}
	h.refresher.during = func() {
		// Hold the grant until both requests have loaded the session: the third load is the
		// second request's own, the first two being the first request's step-1 load and its
		// re-read under the lock. The deadline is safety for a machine that cannot schedule
		// two goroutines in time, not a timing the test depends on.
		deadline := time.Now().Add(5 * time.Second)
		for h.backend.loadsCount() < 3 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
	}

	m := h.middleware(parser)
	var wg sync.WaitGroup
	outs := make([]served, 2)
	for i := range outs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			outs[i] = h.serveThrough(t.Context(), m, cookies)
		}(i)
	}
	wg.Wait()

	calls, _ := h.refresher.sent()
	assert.Equal(t, 1, calls, "one refresh grant for the whole session")
	for i, out := range outs {
		assert.True(t, out.reached, "the chain continues")
		require.NotNil(t, out.jwtInfo, "request %d is still signed in", i)
		assert.Equal(t, winner, out.jwtInfo.TokenResponse, "request %d carries the winner's answer", i)
	}

	sess := h.readBack(cookies)
	storedWinner, ok := sess.Values[sessionkeys.JWT].(oauth.TokenResponse)
	require.True(t, ok, "the session holds the winner's token set")
	assert.Equal(t, winner, storedWinner)
	assert.Equal(t, "kept", sess.Values["unrelated"], "the session itself survives")
	assert.Empty(t, h.logs.Records(), h.logs.Text())
}
