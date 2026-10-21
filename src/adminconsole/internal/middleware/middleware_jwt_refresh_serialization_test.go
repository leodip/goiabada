package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient/oauthclienttest"
	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

// #621, the two rows its done-when asks for and what they rest on. The console refreshes an
// administrator's access token from its JWT middleware, on whichever request finds the token due,
// and the auth server rotates refresh tokens strictly (#128, RFC 9700 section 4.14.2), so two
// requests from one session that both find the token due race each other: the loser's grant is
// refused, and its sign-out clears the token set from the copy the request read at its start and
// saves over the winner's, because the console's session store is last-writer-wins (#579). Two
// tabs in the last thirty seconds of the access token were enough. The refresh is serialized per
// session now: the request that waited for the session's lock re-reads the session and carries
// the answer the winner stored, into its own session too, so a page that saves the session after
// it writes that answer; a grant that is refused anyway never clears a token set newer than the
// one it presented; and a failed refresh's clear is saved before the lock is released.
//
// Every request here goes through CookieReset as the console mounts it, so the session the
// middleware reads is the one the whole request shares (#269).

const flashKey = "the-flash"

// savingAFlash is a page further down the chain that sets a flash and saves the session, as some
// thirty of the console's handlers do: whatever token set the request's session holds then is
// what it writes back.
func (h *sessionHarness) savingAFlash() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := h.store.Get(r, sessionTestName)
		if err != nil {
			h.t.Errorf("unable to get the session: %v", err)
			return
		}
		sess.SetFlash(flashKey, "saved")
		if err := h.store.Save(r, w, sess); err != nil {
			h.t.Errorf("unable to save the session: %v", err)
		}
	}
}

// writeAsAnotherRequest changes the session the cookies name the way another request would,
// through a request, and a load, of its own.
func (h *sessionHarness) writeAsAnotherRequest(cookies []*http.Cookie, change func(values map[string]any)) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	sess, err := h.store.Get(req, sessionTestName)
	if err != nil {
		h.t.Errorf("unable to get the session: %v", err)
		return
	}
	change(sess.Values)
	if err := h.store.Save(req, httptest.NewRecorder(), sess); err != nil {
		h.t.Errorf("unable to save the session: %v", err)
	}
}

// forgetWrites drops the writes the backend has recorded so far, the seed's among them, so a case
// reads only what the request it serves wrote.
func (h *sessionHarness) forgetWrites() {
	h.backend.mu.Lock()
	defer h.backend.mu.Unlock()
	h.backend.writes = nil
}

// sessionIDOf is the identifier the session's refresh lock is keyed by.
func (h *sessionHarness) sessionIDOf(cookies []*http.Cookie) string {
	h.t.Helper()
	for _, c := range cookies {
		if c.Name == h.store.CookieName(sessionTestName) {
			id, err := h.store.OpenCookie(sessionTestName, c.Value)
			require.NoError(h.t, err)
			return id
		}
	}
	h.t.Fatal("no session cookie")
	return ""
}

// inBackground serves one request through m on its own goroutine, reporting what it came to on
// the channel it returns.
func (h *sessionHarness) inBackground(ctx context.Context, m *JWT, cookies []*http.Cookie,
	then func(w http.ResponseWriter, r *http.Request)) <-chan served {
	done := make(chan served, 1)
	go func() { done <- h.serveChain(ctx, m, cookies, then) }()
	return done
}

func awaitServed(t *testing.T, done <-chan served) served {
	t.Helper()
	select {
	case out := <-done:
		return out
	case <-time.After(10 * time.Second):
		t.Fatal("the request never finished")
		return served{}
	}
}

// waitForQueued is awaitQueued for a goroutine other than the test's, where a failure may not
// stop the test.
func waitForQueued(t *testing.T, queued <-chan string) {
	select {
	case <-queued:
	case <-time.After(5 * time.Second):
		t.Error("no second request queued on the session's refresh lock")
	}
}

// winnerSet is the token set another request stored: its ID token the refreshed one, an expiry
// an hour out.
func winnerSet() oauth.TokenResponse {
	return oauth.TokenResponse{
		AccessToken:  "the-winners-access-token",
		IdToken:      refreshedIDTokenRaw,
		RefreshToken: "the-winners-refresh-token",
		ExpiresIn:    600,
		Scope:        storedGrant,
	}
}

var verifiedRefreshed = &oauth.JwtToken{TokenBase64: refreshedIDTokenRaw, Claims: map[string]any{"sub": "the-admin"}}

func invalidGrant() error {
	return errs.WithStack(&oauthclient.TokenEndpointError{StatusCode: http.StatusBadRequest, ErrorCode: "invalid_grant"})
}

// assertHolds asserts the session the cookies name holds set, expiring at expiresAt, and that an
// unrelated value survived.
func (h *sessionHarness) assertHolds(cookies []*http.Cookie, set oauth.TokenResponse, expiresAt int64) {
	h.t.Helper()
	sess := h.readBack(cookies)
	assert.Equal(h.t, set, sess.Values[sessionkeys.JWT], "the session holds the token set")
	assert.Equal(h.t, expiresAt, sess.Values[sessionkeys.JWTExpiresAt], "with its expiry")
	assert.Equal(h.t, "kept", sess.Values["unrelated"], "the session itself survives")
}

// assertTheNextRequestSendsNoGrant serves one more request on the session and asserts it carries
// set without sending a grant: the stored set is not due, so its refresh token, the live one, has
// not been put back over by an older one.
func (h *sessionHarness) assertTheNextRequestSendsNoGrant(cookies []*http.Cookie, set oauth.TokenResponse) {
	h.t.Helper()
	before, _ := h.refresher.sent()
	out := h.serve(h.parser, cookies)
	require.NotNil(h.t, out.jwtInfo, "the next request is signed in")
	assert.Equal(h.t, set, out.jwtInfo.TokenResponse, "carrying the stored set")
	after, _ := h.refresher.sent()
	assert.Equal(h.t, before, after, "and sends no grant")
}

// A refused grant never clears a token set newer than the one it presented. The other winner is
// another replica of the console here — beyond this process's lock, which is why the grant is
// refused at all — and it stores its answer while this request's grant is in flight. Before #621
// the sign-out that answered the refused grant saved this request's copy over the newer set,
// signing the administrator out over live tokens. The page this request goes on to saves the
// session, so the newer set must be in the request's own session too, or the save puts the
// presented set, and its rotated-away refresh token, back.
func TestSessionHandler_ARefusedGrantDoesNotClearATokenSetNewerThanTheOnePresented(t *testing.T) {
	h := newSessionHarness(t)
	cookies := h.seed(signedIn(due()))
	h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, storedIDTokenRaw).Return(verifiedStored, nil)
	h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, refreshedIDTokenRaw).Return(verifiedRefreshed, nil)
	h.refresher.err = invalidGrant()

	// The other replica's answer, stored while this request's grant is in flight.
	winner, winnerExpiresAt := winnerSet(), notDue()
	h.refresher.during = func() {
		h.writeAsAnotherRequest(cookies, func(values map[string]any) {
			values[sessionkeys.JWT] = winner
			values[sessionkeys.JWTExpiresAt] = winnerExpiresAt
		})
	}

	out := h.serveChain(context.Background(), h.middleware(h.parser), cookies, h.savingAFlash())

	assert.True(t, out.reached, "the chain continues")
	require.NotNil(t, out.jwtInfo, "the administrator is still signed in")
	assert.Equal(t, winner, out.jwtInfo.TokenResponse, "carrying the token set the other replica stored")
	assert.Same(t, verifiedRefreshed, out.jwtInfo.IdToken, "whose ID token verified")

	h.assertHolds(cookies, winner, winnerExpiresAt)
	_, flashed := h.readBack(cookies).TakeFlash(flashKey)
	assert.True(t, flashed, "the page's save landed")
	calls, _ := h.refresher.sent()
	assert.Equal(t, 1, calls, "this request presented its refresh token once")
	h.assertOneRecord(slog.LevelWarn,
		"the refresh grant was refused, but a token set newer than the one it presented had been stored meanwhile, so the session keeps it",
		"invalid_grant")

	h.assertTheNextRequestSendsNoGrant(cookies, winner)
}

// A newer set whose ID token the parser refuses is not carried: the refused grant's sign-out
// stands, and clears it, as it would any set no verified token vouches for.
func TestSessionHandler_ARefusedGrantCarriesNoNewerSetWhoseIDTokenDoesNotVerify(t *testing.T) {
	h := newSessionHarness(t)
	cookies := h.seed(signedIn(due()))
	h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, storedIDTokenRaw).Return(verifiedStored, nil)
	h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, refreshedIDTokenRaw).
		Return(nil, errs.New("unable to verify the id token's signature"))
	h.refresher.err = invalidGrant()
	h.refresher.during = func() {
		h.writeAsAnotherRequest(cookies, func(values map[string]any) {
			values[sessionkeys.JWT] = winnerSet()
			values[sessionkeys.JWTExpiresAt] = notDue()
		})
	}

	out := h.serve(h.parser, cookies)

	h.assertContinuedUnauthenticated(out)
	h.assertSignedOut(cookies)
	h.assertOneRecord(slog.LevelWarn, "unable to refresh the access token, signing the session out", "invalid_grant")
}

// Two concurrent requests from one session, both finding the token due, share one grant: the
// request that waited for the session's lock carries the answer the winner stored, the
// administrator stays signed in, and only one refresh token is ever presented. The parser is the
// real one because two requests must verify real tokens concurrently. The first grant is held
// until the second request is queued on the session's lock, which the lock reports, and the fake
// refresher serializes nothing itself, so without the lock both grants are sent.
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
		{err: invalidGrant()},
	}

	m := h.middleware(parser)
	queued := queuedSignal(m.refreshLocks)
	var first sync.Once
	h.refresher.during = func() {
		first.Do(func() { waitForQueued(t, queued) })
	}

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

// The request that waited carries the set the winner stored into its own session as well as onto
// its context. That session is the one CookieReset loaded at the start of the request and every
// later Get on it answers with, so a page that saves it, for a flash, writes the winner's set and
// not the due one the request began with, whose refresh token the auth server rotated away: put
// back, it is presented on the next request and read as a replay, which contains the whole family.
// The holder is the test, so which request waits is not left to the scheduler.
func TestSessionHandler_AWaiterCarriesTheStoredSetIntoItsOwnSession(t *testing.T) {
	h := newSessionHarness(t)
	cookies := h.seed(signedIn(due()))
	h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, storedIDTokenRaw).Return(verifiedStored, nil)
	h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, refreshedIDTokenRaw).Return(verifiedRefreshed, nil)

	m := h.middleware(h.parser)
	queued := queuedSignal(m.refreshLocks)
	holder, err := m.refreshLocks.Lock(context.Background(), h.sessionIDOf(cookies))
	require.NoError(t, err)

	done := h.inBackground(context.Background(), m, cookies, h.savingAFlash())
	awaitQueued(t, queued)
	winner, winnerExpiresAt := winnerSet(), notDue()
	h.writeAsAnotherRequest(cookies, func(values map[string]any) {
		values[sessionkeys.JWT] = winner
		values[sessionkeys.JWTExpiresAt] = winnerExpiresAt
	})
	holder()
	out := awaitServed(t, done)

	assert.True(t, out.reached, "the chain continues")
	require.NotNil(t, out.jwtInfo, "the administrator is still signed in")
	assert.Equal(t, winner, out.jwtInfo.TokenResponse, "carrying the winner's set")
	assert.Same(t, verifiedRefreshed, out.jwtInfo.IdToken)
	h.assertNoRefreshSent()

	h.assertHolds(cookies, winner, winnerExpiresAt)
	_, flashed := h.readBack(cookies).TakeFlash(flashKey)
	assert.True(t, flashed, "the page's save landed")
	assert.Empty(t, h.logs.Records(), h.logs.Text())

	h.assertTheNextRequestSendsNoGrant(cookies, winner)
}

// A request that waited while another signed the session out finds the token set gone when it
// re-reads, and signs out the same way, presenting nothing.
func TestSessionHandler_AWaiterWhoseSessionWasSignedOutMeanwhileSendsNoGrant(t *testing.T) {
	h := newSessionHarness(t)
	cookies := h.seed(signedIn(due()))
	h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, storedIDTokenRaw).Return(verifiedStored, nil).Once()

	m := h.middleware(h.parser)
	queued := queuedSignal(m.refreshLocks)
	holder, err := m.refreshLocks.Lock(context.Background(), h.sessionIDOf(cookies))
	require.NoError(t, err)

	done := h.inBackground(context.Background(), m, cookies, nil)
	awaitQueued(t, queued)
	h.writeAsAnotherRequest(cookies, func(values map[string]any) {
		delete(values, sessionkeys.JWT)
		delete(values, sessionkeys.JWTExpiresAt)
	})
	holder()
	out := awaitServed(t, done)

	h.assertContinuedUnauthenticated(out)
	h.assertNoRefreshSent()
	h.assertSignedOut(cookies)
	assert.Empty(t, h.logs.Records(), h.logs.Text())
}

// A failed refresh's clear is saved before the session's lock is released. The waiter then
// re-reads a session already signed out and presents nothing; with the lock released first, its
// re-read could land before the clear, find the set the holder had just failed with, and present
// its refresh token again, a replay when the auth server had rotated it. The holder's clear is
// held for a moment to give a waiter that was let in early the time to re-read and send.
func TestSessionHandler_AFailedRefreshIsClearedBeforeAWaiterReReads(t *testing.T) {
	h := newSessionHarness(t)
	cookies := h.seed(signedIn(due()))
	h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, storedIDTokenRaw).Return(verifiedStored, nil)
	h.refresher.err = invalidGrant()

	m := h.middleware(h.parser)
	queued := queuedSignal(m.refreshLocks)
	inGrant := make(chan struct{})
	var first sync.Once
	h.refresher.during = func() {
		first.Do(func() {
			close(inGrant)
			waitForQueued(t, queued)
		})
	}

	// The first update is the holder's clear. Loads so far: each request's own, and the holder's
	// two re-reads; a fifth is the waiter's re-read.
	var clearing sync.Once
	h.backend.beforeUpdate = func() {
		clearing.Do(func() {
			deadline := time.Now().Add(300 * time.Millisecond)
			for len(h.backend.recordedLoads()) < 5 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
		})
	}

	holderDone := h.inBackground(context.Background(), m, cookies, nil)
	<-inGrant
	waiterDone := h.inBackground(context.Background(), m, cookies, nil)
	holderOut := awaitServed(t, holderDone)
	waiterOut := awaitServed(t, waiterDone)

	calls, sent := h.refresher.sent()
	assert.Equal(t, 1, calls, "the failed refresh token is presented once")
	assert.Equal(t, storedRefreshToken, sent)
	h.assertContinuedUnauthenticated(holderOut)
	h.assertContinuedUnauthenticated(waiterOut)
	h.assertSignedOut(cookies)
	h.assertOneRecord(slog.LevelWarn, "unable to refresh the access token, signing the session out", "invalid_grant")
}

// A re-read that could not be performed signs nobody out: nothing was presented on its strength,
// and nothing is known of what the session holds, so the request is refused with the error page,
// as a load that fails at the start of a request is (#266), and the session is neither cleared
// nor saved. The first row fails the re-read before the grant; the second the re-read after a
// refused grant, with a newer set stored meanwhile, which a clear would have destroyed.
func TestSessionHandler_AReReadThatFailsRefusesTheRequestAndClearsNothing(t *testing.T) {
	lookupFault := errs.New("the session endpoint is unreachable")

	t.Run("the re-read before the grant", func(t *testing.T) {
		h := newSessionHarness(t)
		expiresAt := due()
		cookies := h.seed(signedIn(expiresAt))
		h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, storedIDTokenRaw).Return(verifiedStored, nil)
		h.backend.loadFault = func(n int) error {
			if n == 2 {
				return lookupFault
			}
			return nil
		}
		h.forgetWrites()

		out := h.serve(h.parser, cookies)

		assert.False(t, out.reached, "the page asked for is not served")
		assert.Equal(t, http.StatusInternalServerError, out.recorder.Code)
		require.Error(t, h.errorPage.err)
		require.ErrorIs(t, h.errorPage.err, lookupFault)
		assert.Contains(t, h.errorPage.err.Error(), "unable to re-read the session under the refresh lock")
		h.assertNoRefreshSent()
		assert.Empty(t, h.backend.recordedWrites(), "nothing is saved")
		h.assertHolds(cookies, storedResponse(), expiresAt)
		assert.Empty(t, h.logs.Records(), h.logs.Text())
	})

	t.Run("the re-read after a refused grant, a newer set stored meanwhile", func(t *testing.T) {
		h := newSessionHarness(t)
		cookies := h.seed(signedIn(due()))
		h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, storedIDTokenRaw).Return(verifiedStored, nil)
		h.refresher.err = invalidGrant()
		winner, winnerExpiresAt := winnerSet(), notDue()
		h.refresher.during = func() {
			h.writeAsAnotherRequest(cookies, func(values map[string]any) {
				values[sessionkeys.JWT] = winner
				values[sessionkeys.JWTExpiresAt] = winnerExpiresAt
			})
			h.forgetWrites()
			h.backend.mu.Lock()
			h.backend.loadFault = func(int) error { return lookupFault }
			h.backend.mu.Unlock()
		}

		out := h.serve(h.parser, cookies)
		h.backend.mu.Lock()
		h.backend.loadFault = nil
		h.backend.mu.Unlock()

		assert.False(t, out.reached, "the page asked for is not served")
		assert.Equal(t, http.StatusInternalServerError, out.recorder.Code)
		require.ErrorIs(t, h.errorPage.err, lookupFault)
		assert.Empty(t, h.backend.recordedWrites(), "nothing is saved after the grant")
		h.assertHolds(cookies, winner, winnerExpiresAt)
		calls, _ := h.refresher.sent()
		assert.Equal(t, 1, calls)
		assert.Empty(t, h.logs.Records(), h.logs.Text())
	})
}

// The set the re-read finds is verified before it is carried or refreshed, and an ID token that
// no longer verifies under the lock ends the session as a refused refresh does, its class the
// parser's: foreign at Warn, anything else at Error, the browser sent to the root either way and
// nothing presented.
func TestSessionHandler_AnIDTokenThatNoLongerVerifiesUnderTheLockEndsTheSession(t *testing.T) {
	testCases := []struct {
		name    string
		refused error
		level   slog.Level
		message string
	}{
		{
			name:    "foreign",
			refused: errs.Wrap(oauthclient.ErrForeignToken, "the id token's iss is another"),
			level:   slog.LevelWarn,
			message: "the id token names another issuer or audience, clearing the session and redirecting to root",
		},
		{
			name:    "any other failure",
			refused: errs.New("unable to verify the id token's signature"),
			level:   slog.LevelError,
			message: "the refresh response was refused, clearing the session and redirecting to root",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := newSessionHarness(t)
			cookies := h.seed(signedIn(due()))
			h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, storedIDTokenRaw).Return(verifiedStored, nil).Once()
			h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, storedIDTokenRaw).Return(nil, tc.refused).Once()

			out := h.serve(h.parser, cookies)

			h.assertRedirectedToRoot(out)
			h.assertSignedOut(cookies)
			h.assertNoRefreshSent()
			h.assertOneRecord(tc.level, tc.message, tc.refused.Error())
		})
	}
}

// A wait for the lock ends at its bound, so a refresh that hangs holds no other request of the
// session past the listener's write timeout. The request that gave up sends nothing and writes
// nothing: it carries the access token it holds while that has not expired, and answers the
// error page once it has.
func TestSessionHandler_AWaitForTheRefreshLockEndsAtItsBound(t *testing.T) {
	t.Run("the access token held has not expired", func(t *testing.T) {
		h := newSessionHarness(t)
		expiresAt := due()
		cookies := h.seed(signedIn(expiresAt))
		h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, storedIDTokenRaw).Return(verifiedStored, nil).Once()
		m := h.middleware(h.parser)
		m.refreshWait = 20 * time.Millisecond
		holder, err := m.refreshLocks.Lock(context.Background(), h.sessionIDOf(cookies))
		require.NoError(t, err)
		defer holder()

		h.forgetWrites()
		started := time.Now()
		out := h.serveThrough(context.Background(), m, cookies)

		assert.Less(t, time.Since(started), 5*time.Second, "the request returned at the bound")
		assert.True(t, out.reached, "the chain continues")
		require.NotNil(t, out.jwtInfo, "signed in")
		assert.Equal(t, storedResponse(), out.jwtInfo.TokenResponse, "on the token set it holds")
		assert.Same(t, verifiedStored, out.jwtInfo.IdToken)
		h.assertNoRefreshSent()
		assert.Empty(t, h.backend.recordedWrites(), "nothing is saved")
		h.assertHolds(cookies, storedResponse(), expiresAt)
		h.assertOneRecord(slog.LevelWarn,
			"another request's refresh of the session outlasted the wait, carrying the access token the request holds",
			"context deadline exceeded")
	})

	t.Run("the access token held has expired", func(t *testing.T) {
		h := newSessionHarness(t)
		expiresAt := time.Now().Add(-time.Second).Unix()
		cookies := h.seed(signedIn(expiresAt))
		h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, storedIDTokenRaw).Return(verifiedStored, nil).Once()
		m := h.middleware(h.parser)
		m.refreshWait = 20 * time.Millisecond
		holder, err := m.refreshLocks.Lock(context.Background(), h.sessionIDOf(cookies))
		require.NoError(t, err)
		defer holder()

		h.forgetWrites()
		started := time.Now()
		out := h.serveThrough(context.Background(), m, cookies)

		assert.Less(t, time.Since(started), 5*time.Second, "the request returned at the bound")
		assert.False(t, out.reached, "the page asked for is not served")
		assert.Equal(t, http.StatusInternalServerError, out.recorder.Code)
		require.Error(t, h.errorPage.err)
		require.ErrorIs(t, h.errorPage.err, context.DeadlineExceeded)
		assert.Contains(t, h.errorPage.err.Error(), "unable to wait for another request's refresh of the session")
		h.assertNoRefreshSent()
		assert.Empty(t, h.backend.recordedWrites(), "nothing is saved")
		h.assertHolds(cookies, storedResponse(), expiresAt)
		assert.Empty(t, h.logs.Records(), h.logs.Text())
	})
}

// The re-read is a load of its own past the request's memo, and runs as the check and the write
// after the grant do: detached from the browser's cancellation, so a browser that left before it
// costs nothing the grant would then have to redo, bounded at TokenExchangeTimeout, and keeping
// the request's values, so its records name the request.
func TestSessionHandler_TheReReadKeepsTheRequestAndOutlivesTheBrowser(t *testing.T) {
	h := newSessionHarness(t)
	cookies := h.seed(signedIn(due()))

	const wantRequestID = "the-inbound-request-id"
	ctx, cancel := context.WithCancel(
		context.WithValue(context.Background(), chimiddleware.RequestIDKey, wantRequestID))
	defer cancel()

	// The browser leaves once the request has loaded its session and step 3 has begun.
	h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, storedIDTokenRaw).
		Run(func(mock.Arguments) { cancel() }).Return(verifiedStored, nil)
	h.refresher.answer = &oauth.TokenResponse{AccessToken: "the-new-access-token", IdToken: refreshedIDTokenRaw,
		RefreshToken: "the-new-refresh-token", ExpiresIn: 600}
	h.parser.On("DecodeAndValidateRefreshResponse", mock.Anything, mock.Anything, verifiedStored).
		Return(func(_ context.Context, tr *oauth.TokenResponse, _ *oauth.JwtToken) (*oauthclient.JwtInfo, error) {
			return &oauthclient.JwtInfo{TokenResponse: *tr, IdToken: verifiedRefreshed}, nil
		})
	loadsBefore := len(h.backend.recordedLoads())

	out := h.serveOn(ctx, h.parser, cookies)

	assert.True(t, out.reached, "the chain continues")
	require.NotNil(t, out.jwtInfo)
	assert.Equal(t, "the-new-access-token", out.jwtInfo.TokenResponse.AccessToken)

	loads := h.backend.recordedLoads()[loadsBefore:]
	require.Len(t, loads, 2, "the request's own load, then the re-read")
	reRead := loads[1]
	require.NoError(t, reRead.err, "the re-read is not cancelled with the browser")
	require.True(t, reRead.hasDeadline, "detached, but not unbounded")
	assert.LessOrEqual(t, time.Until(reRead.deadline), oauthclient.TokenExchangeTimeout, "bounded by TokenExchangeTimeout")
	assert.Equal(t, wantRequestID, reRead.requestID, "and keeping request_id")
}
