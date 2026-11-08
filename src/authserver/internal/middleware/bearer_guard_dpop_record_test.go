package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/dpop"
	"github.com/leodip/goiabada/authserver/internal/dpop/dpoptest"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/httpmw"
)

// Where and how long the resources record a DPoP proof (RFC 9449 section 11.1, #42 decisions 6, 8
// and 9): behind every other refusal on its route, rate limiters included; with its freshness
// judged again at the record point; for long enough that a sweep by one instance's clock never lets
// an instance whose clock runs behind accept the proof again; and against the path the client sent.

// sweep deletes the records that expired before now, as the cleanup worker's DeleteExpiredDPoPProofs
// does by the sweeping instance's clock.
func (s *replayStore) sweep(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, expiresAt := range s.records {
		if expiresAt.Before(now) {
			delete(s.records, hash)
		}
	}
}

// resourceInstance is one auth server instance's /userinfo chain over a shared replay store, at a
// clock the test sets.
type resourceInstance struct {
	now   time.Time
	chain http.Handler
}

func newResourceInstance(t *testing.T, store *replayStore, now time.Time, between func(http.Handler) http.Handler) *resourceInstance {
	t.Helper()
	checker, err := dpop.NewChecker(dpopResourceBaseURL)
	require.NoError(t, err)
	instance := &resourceInstance{now: now}
	guards := NewBearerTokenForAPI(dpopParser{jkt: dpoptest.RFC7517Key(t).Thumbprint},
		ResourceProofs{Checker: checker, Replays: store, Now: func() time.Time { return instance.now }})
	if between == nil {
		between = func(next http.Handler) http.Handler { return next }
	}
	instance.chain = guards.JwtAuthorizationHeaderToContext()(guards.RequireBearerTokenScope("openid")(between(
		guards.RecordDPoPProof()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("admitted")) })))))
	return instance
}

func (i *resourceInstance) serve(proof string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	i.chain.ServeHTTP(rr, dpopRequest("DPoP "+tokenBound, proof))
	return rr
}

// A proof accepted by one instance late in its iat window stays refused at an instance whose clock
// runs 30 seconds behind, after a third instance swept the table the moment the window ended by its
// own clock: the record is kept past the window by the grace.
func TestBearerGuardDPoP_ASweepByAnotherClockNeverLetsAProofBeAcceptedTwice(t *testing.T) {
	key := dpoptest.RFC7517Key(t)
	store := newReplayStore()
	proof := key.ResourceProof(t, "GET", dpopUserinfoURL, dpopNow, tokenBound)

	first := newResourceInstance(t, store, dpopNow.Add(55*time.Second), nil)
	require.Equal(t, http.StatusOK, first.serve(proof).Code)

	store.sweep(dpopNow.Add(61 * time.Second))
	behind := newResourceInstance(t, store, dpopNow.Add(31*time.Second), nil)
	rr := behind.serve(proof)

	assert.Equal(t, http.StatusUnauthorized, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Header().Get("WWW-Authenticate"), `error="invalid_dpop_proof"`)

	// Once every instance's clock is past the window and the grace, the record goes, and the proof
	// is refused for its iat.
	store.sweep(dpopNow.Add(60*time.Second + dpop.ReplayRecordGrace + time.Second))
	assert.Equal(t, 0, store.count())
	late := newResourceInstance(t, store, dpopNow.Add(60*time.Second+dpop.ReplayRecordGrace), nil)
	assert.Equal(t, http.StatusUnauthorized, late.serve(proof).Code)
}

// The iat is judged again where the proof is recorded: a request whose window ended while the
// guards ahead of the record ran is refused invalid_dpop_proof and records nothing, while one still
// inside the window at that moment, its last second included, is admitted.
func TestBearerGuardDPoP_FreshnessIsJudgedAgainAtTheRecordPoint(t *testing.T) {
	key := dpoptest.RFC7517Key(t)
	proof := key.ResourceProof(t, "GET", dpopUserinfoURL, dpopNow, tokenBound)

	for _, tc := range []struct {
		name     string
		recordAt time.Time
		status   int
		records  int
	}{
		{"still inside the window", dpopNow.Add(60 * time.Second), http.StatusOK, 1},
		{"past the window", dpopNow.Add(60*time.Second + time.Nanosecond), http.StatusUnauthorized, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newReplayStore()
			var instance *resourceInstance
			instance = newResourceInstance(t, store, dpopNow.Add(59*time.Second), func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					instance.now = tc.recordAt // the clock moves on while the request is in flight
					next.ServeHTTP(w, r)
				})
			})

			rr := instance.serve(proof)

			assert.Equal(t, tc.status, rr.Code, rr.Body.String())
			assert.Equal(t, tc.records, store.count())
			if tc.status != http.StatusOK {
				assert.Contains(t, rr.Header().Get("WWW-Authenticate"), `error="invalid_dpop_proof"`)
			}
		})
	}
}

// A request a route's rate limiter refuses leaves its proof unspent, the replay guard mounted
// behind the limiters as routes.go mounts it: the 429 calls no replay store, and the same proof is
// accepted once a limiter admits the request.
func TestBearerGuardDPoP_ARateLimitedRequestLeavesItsProofUnspent(t *testing.T) {
	const subject = "dpop-credential-change-user"
	store := newReplayStore()
	guards := NewBearerTokenForAPI(nil, ResourceProofs{Replays: store, Now: func() time.Time { return dpopNow }})
	route := func(limiter *RateLimiter, reached *bool) http.Handler {
		return limiter.LimitAccountCredentialChange(limiter.LimitAccountPassword(guards.RecordDPoPProof()(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				*reached = true
				w.WriteHeader(http.StatusTeapot)
			}))))
	}
	withProof := func() *http.Request {
		req := accountPasswordRequest(accountPasswordRoute, subject)
		return req.WithContext(reqctx.WithDPoPProof(req.Context(), &dpop.Proof{
			HTU: "https://auth.example.com/api/v1/account/password", JTI: "a-proof-refused-then-sent-again", IssuedAt: dpopNow,
		}))
	}

	limiter, _ := newAuditedTestMiddleware(nil, true)
	for i := 0; i < 10; i++ {
		status, reached, _ := runAccountCredentialChange(limiter, accountPasswordRoute, subject, false)
		require.Equal(t, http.StatusTeapot, status)
		require.True(t, reached)
	}
	reached := false
	rr := httptest.NewRecorder()
	route(limiter, &reached).ServeHTTP(rr, withProof())
	require.Equal(t, http.StatusTooManyRequests, rr.Code)
	assert.False(t, reached)
	assert.Equal(t, 0, store.count(), "a 429 leaves the proof unspent")

	// The limiter's window has passed: a limiter with a fresh budget admits the same proof, once.
	admitting, _ := newAuditedTestMiddleware(nil, true)
	rr = httptest.NewRecorder()
	route(admitting, &reached).ServeHTTP(rr, withProof())
	assert.Equal(t, http.StatusTeapot, rr.Code, rr.Body.String())
	assert.True(t, reached)
	assert.Equal(t, 1, store.count())
}

// A request its handler refuses keeps its proof spent. A proof names the method, the URL and the
// token, not the body (RFC 9449 section 11.7), so the same proof sent again could carry any other
// body: it is a replay, refused before the handler runs.
func TestBearerGuardDPoP_AHandlersRefusalKeepsTheProofSpent(t *testing.T) {
	key := dpoptest.RFC7517Key(t)
	store := newReplayStore()
	checker, err := dpop.NewChecker(dpopResourceBaseURL)
	require.NoError(t, err)
	guards := NewBearerTokenForAPI(dpopParser{jkt: key.Thumbprint},
		ResourceProofs{Checker: checker, Replays: store, Now: func() time.Time { return dpopNow }})
	handled := 0
	chain := guards.JwtAuthorizationHeaderToContext()(guards.RecordDPoPProof()(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			handled++
			w.WriteHeader(http.StatusBadRequest)
		})))
	proof := key.ResourceProof(t, "GET", dpopUserinfoURL, dpopNow, tokenBound)

	refused := httptest.NewRecorder()
	chain.ServeHTTP(refused, dpopRequest("DPoP "+tokenBound, proof))
	require.Equal(t, http.StatusBadRequest, refused.Code)
	assert.Equal(t, 1, store.count(), "the refused request spent its proof")

	replayed := httptest.NewRecorder()
	chain.ServeHTTP(replayed, dpopRequest("DPoP "+tokenBound, proof))
	assert.Equal(t, http.StatusUnauthorized, replayed.Code, replayed.Body.String())
	assert.Contains(t, replayed.Header().Get("WWW-Authenticate"), `error="invalid_dpop_proof"`)
	assert.Equal(t, 1, handled, "the replay never reached the handler")
}

// htu names the path the client sent, not the one routing rewrote: behind the trailing-slash strip
// that heads the router, a proof for /userinfo/ sent to /userinfo/ is accepted, and one for
// /userinfo sent to /userinfo/ is refused, while the path without the slash takes its own proof.
func TestBearerGuardDPoP_HTUNamesThePathTheClientSent(t *testing.T) {
	key := dpoptest.RFC7517Key(t)
	for _, tc := range []struct {
		name, path, htu string
		status          int
	}{
		{"a trailing slash, named", "/userinfo/", dpopUserinfoURL + "/", http.StatusOK},
		{"a trailing slash, not named", "/userinfo/", dpopUserinfoURL, http.StatusUnauthorized},
		{"no trailing slash", "/userinfo", dpopUserinfoURL, http.StatusOK},
		{"no trailing slash, one named", "/userinfo", dpopUserinfoURL + "/", http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			chain := httpmw.StripTrailingSlash(dpopChain(dpopGuards(t, "userinfo", dpopResourceBaseURL, newReplayStore())))
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.Header.Set("Authorization", "DPoP "+tokenBound)
			req.Header.Set("DPoP", key.ResourceProof(t, "GET", tc.htu, dpopNow, tokenBound))

			rr := httptest.NewRecorder()
			chain.ServeHTTP(rr, req)

			require.Equal(t, tc.status, rr.Code, rr.Body.String())
			if tc.status != http.StatusOK {
				assert.Contains(t, rr.Header().Get("WWW-Authenticate"), `error="invalid_dpop_proof"`)
			}
		})
	}
}
