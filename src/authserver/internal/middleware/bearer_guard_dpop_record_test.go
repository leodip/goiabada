package middleware

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/dpop"
	"github.com/leodip/goiabada/authserver/internal/dpop/dpoptest"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/httpmw"
	"github.com/leodip/goiabada/core/logging/logtest"
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
				w.WriteHeader(http.StatusNoContent)
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
	assert.Equal(t, http.StatusNoContent, rr.Code, rr.Body.String())
	assert.True(t, reached)
	assert.Equal(t, 1, store.count())
}

// handlerInstance is newResourceInstance's chain with handler in place of the one that admits
// every request: the route's own checks, behind every guard.
func handlerInstance(t *testing.T, store *replayStore, handler http.HandlerFunc) http.Handler {
	t.Helper()
	checker, err := dpop.NewChecker(dpopResourceBaseURL)
	require.NoError(t, err)
	guards := NewBearerTokenForAPI(dpopParser{jkt: dpoptest.RFC7517Key(t).Thumbprint},
		ResourceProofs{Checker: checker, Replays: store, Now: func() time.Time { return dpopNow }})
	return guards.JwtAuthorizationHeaderToContext()(guards.RequireBearerTokenScope("openid")(guards.RecordDPoPProof()(handler)))
}

// statusSeen is a recorder that notes how many proofs the store held when the handler's status
// reached it, which is when the client could first see it.
type statusSeen struct {
	*httptest.ResponseRecorder
	store   *replayStore
	records int
}

func (w *statusSeen) WriteHeader(code int) {
	w.records = w.store.count()
	w.ResponseRecorder.WriteHeader(code)
}

func serveSeen(chain http.Handler, store *replayStore, proof string) *statusSeen {
	w := &statusSeen{ResponseRecorder: httptest.NewRecorder(), store: store, records: -1}
	chain.ServeHTTP(w, dpopRequest("DPoP "+tokenBound, proof))
	return w
}

// A request its handler refuses, with any 4xx, leaves its proof unspent (#42 decision 9): the record
// is released before the status reaches the client, the refusal's own answer is untouched, and the
// same proof, sent again with the request corrected, is admitted once and then refused as a replay.
func TestBearerGuardDPoP_AHandlerRefusalLeavesItsProofUnspent(t *testing.T) {
	key := dpoptest.RFC7517Key(t)
	for _, tc := range []struct {
		name   string
		refuse func(w http.ResponseWriter)
		status int
	}{
		{"invalid request body", func(w http.ResponseWriter) { w.WriteHeader(http.StatusBadRequest) }, http.StatusBadRequest},
		{"invalid session", func(w http.ResponseWriter) { w.WriteHeader(http.StatusUnauthorized) }, http.StatusUnauthorized},
		{"forbidden", func(w http.ResponseWriter) { w.WriteHeader(http.StatusForbidden) }, http.StatusForbidden},
		{"not found", func(w http.ResponseWriter) { w.WriteHeader(http.StatusNotFound) }, http.StatusNotFound},
		{"conflict", func(w http.ResponseWriter) { w.WriteHeader(http.StatusConflict) }, http.StatusConflict},
		{"handler's own cooldown", func(w http.ResponseWriter) { w.WriteHeader(http.StatusTooManyRequests) }, http.StatusTooManyRequests},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newReplayStore()
			proof := key.ResourceProof(t, "GET", dpopUserinfoURL, dpopNow, tokenBound)
			corrected := false
			chain := handlerInstance(t, store, func(w http.ResponseWriter, _ *http.Request) {
				if !corrected {
					w.Header().Set("Content-Type", "application/json")
					tc.refuse(w)
					_, _ = w.Write([]byte(`{"error_code":"REFUSED"}`))
					return
				}
				_, _ = w.Write([]byte("admitted"))
			})

			refused := serveSeen(chain, store, proof)
			require.Equal(t, tc.status, refused.Code)
			assert.Equal(t, `{"error_code":"REFUSED"}`, refused.Body.String(), "the refusal's body is the handler's")
			assert.Equal(t, "application/json", refused.Header().Get("Content-Type"))
			assert.Equal(t, 0, refused.records, "the record was released before the status was written")
			assert.Equal(t, 0, store.count())

			corrected = true
			admitted := serveSeen(chain, store, proof)
			assert.Equal(t, http.StatusOK, admitted.Code, "the unspent proof is admitted with the request corrected")
			assert.Equal(t, "admitted", admitted.Body.String())
			assert.Equal(t, 1, store.count())

			replay := serveSeen(chain, store, proof)
			assert.Equal(t, http.StatusUnauthorized, replay.Code, "and is single-use from then on")
			assert.Contains(t, replay.Header().Get("WWW-Authenticate"), `error="invalid_dpop_proof"`)
			assert.Equal(t, 1, store.releaseCalls(), "only the handler's refusal released anything")
		})
	}
}

// A request its handler answers with a success or a 5xx keeps its proof spent: what the handler did
// before either may have taken effect. So does one it answers nothing at all, which is a 200.
func TestBearerGuardDPoP_ASuccessOrAServerErrorKeepsItsProofSpent(t *testing.T) {
	key := dpoptest.RFC7517Key(t)
	for _, tc := range []struct {
		name   string
		answer func(w http.ResponseWriter)
		status int
	}{
		{"a body with no status", func(w http.ResponseWriter) { _, _ = w.Write([]byte("{}")) }, http.StatusOK},
		{"nothing at all", func(http.ResponseWriter) {}, http.StatusOK},
		{"created", func(w http.ResponseWriter) { w.WriteHeader(http.StatusCreated) }, http.StatusCreated},
		{"no content", func(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) }, http.StatusNoContent},
		{"a body, then a superfluous refusal", func(w http.ResponseWriter) {
			_, _ = w.Write([]byte("{}"))
			w.WriteHeader(http.StatusBadRequest)
		}, http.StatusOK},
		{"internal server error", func(w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError) }, http.StatusInternalServerError},
		{"service unavailable", func(w http.ResponseWriter) { w.WriteHeader(http.StatusServiceUnavailable) }, http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newReplayStore()
			proof := key.ResourceProof(t, "GET", dpopUserinfoURL, dpopNow, tokenBound)
			chain := handlerInstance(t, store, func(w http.ResponseWriter, _ *http.Request) { tc.answer(w) })

			rr := serveSeen(chain, store, proof)
			require.Equal(t, tc.status, rr.Code)
			assert.Equal(t, 1, store.count(), "the proof stays spent")
			assert.Equal(t, 0, store.releaseCalls())

			replay := serveSeen(chain, store, proof)
			assert.Equal(t, http.StatusUnauthorized, replay.Code)
			assert.Contains(t, replay.Header().Get("WWW-Authenticate"), `error="invalid_dpop_proof"`)
		})
	}
}

// A release the store cannot make leaves the proof spent and the handler's refusal as it was, with
// an Error record: the fault refuses only the proof's reuse, which a fresh proof is admitted for.
func TestBearerGuardDPoP_AReleaseTheStoreCannotMakeKeepsTheRefusal(t *testing.T) {
	logs := logtest.CaptureSlog(t)
	key := dpoptest.RFC7517Key(t)
	store := newReplayStore()
	store.releaseFault = errors.New("connection reset")
	proof := key.ResourceProof(t, "GET", dpopUserinfoURL, dpopNow, tokenBound)
	chain := handlerInstance(t, store, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error_code":"REFUSED"}`))
	})

	rr := serveSeen(chain, store, proof)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, `{"error_code":"REFUSED"}`, rr.Body.String())
	assert.Equal(t, 1, store.count(), "the proof stays spent")
	var released []logtest.CapturedRecord
	for _, record := range logs.Records() {
		if record.Message == "unable to release the dpop proof of a refused request" {
			released = append(released, record)
		}
	}
	require.Len(t, released, 1)
	assert.Equal(t, slog.LevelError, released[0].Level)
	assert.Contains(t, fmt.Sprint(released[0].Attrs["error"]), "connection reset")
}

// Single-use holds while a refused request is in flight: a second use of its proof meanwhile is
// refused as a replay and never reaches the handler, and releases nothing; once the first request's
// refusal is written, the proof is unspent.
func TestBearerGuardDPoP_AProofIsSingleUseWhileItsRefusedRequestIsInFlight(t *testing.T) {
	key := dpoptest.RFC7517Key(t)
	store := newReplayStore()
	proof := key.ResourceProof(t, "GET", dpopUserinfoURL, dpopNow, tokenBound)
	inHandler, refuse := make(chan struct{}), make(chan struct{})
	var handled atomic.Int32
	chain := handlerInstance(t, store, func(w http.ResponseWriter, _ *http.Request) {
		if handled.Add(1) == 1 {
			close(inHandler)
			<-refuse
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte("admitted"))
	})

	first := make(chan *statusSeen)
	go func() { first <- serveSeen(chain, store, proof) }()
	<-inHandler
	concurrent := serveSeen(chain, store, proof)
	assert.Equal(t, http.StatusUnauthorized, concurrent.Code, "the second use is a replay")
	assert.Contains(t, concurrent.Header().Get("WWW-Authenticate"), `error="invalid_dpop_proof"`)
	assert.Equal(t, int32(1), handled.Load(), "and never reached the handler")
	assert.Equal(t, 1, store.count())

	close(refuse)
	assert.Equal(t, http.StatusBadRequest, (<-first).Code)
	assert.Equal(t, 0, store.count(), "the refusal unspent the proof")
	assert.Equal(t, 1, store.releaseCalls(), "the replay released nothing")
	assert.Equal(t, http.StatusOK, serveSeen(chain, store, proof).Code)
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
