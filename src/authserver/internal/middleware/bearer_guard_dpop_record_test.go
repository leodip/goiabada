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
	"github.com/leodip/goiabada/core/httpmw"
)

// Where and how long the resources record a DPoP proof (RFC 9449 section 11.1, #42 decisions 6, 8
// and 9): in the parse guard, as soon as it is accepted, so it stays spent whatever answers the
// request after; for long enough that a sweep by one instance's clock never lets an instance whose
// clock runs behind accept the proof again; and against the path the client sent.

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

func newResourceInstance(t *testing.T, store *replayStore, now time.Time) *resourceInstance {
	t.Helper()
	checker, err := dpop.NewChecker(dpopResourceBaseURL)
	require.NoError(t, err)
	instance := &resourceInstance{now: now}
	guards := NewBearerTokenForAPI(dpopParser{jkt: dpoptest.RFC7517Key(t).Thumbprint},
		ResourceProofs{Checker: checker, Replays: store, Now: func() time.Time { return instance.now }})
	instance.chain = guards.JwtAuthorizationHeaderToContext()(guards.RequireBearerTokenScope("openid")(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("admitted")) })))
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

	first := newResourceInstance(t, store, dpopNow.Add(55*time.Second))
	require.Equal(t, http.StatusOK, first.serve(proof).Code)

	store.sweep(dpopNow.Add(61 * time.Second))
	behind := newResourceInstance(t, store, dpopNow.Add(31*time.Second))
	rr := behind.serve(proof)

	assert.Equal(t, http.StatusUnauthorized, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Header().Get("WWW-Authenticate"), `error="invalid_dpop_proof"`)

	// Once every instance's clock is past the window and the grace, the record goes, and the proof
	// is refused for its iat.
	store.sweep(dpopNow.Add(60*time.Second + dpop.ReplayRecordGrace + time.Second))
	assert.Equal(t, 0, store.count())
	late := newResourceInstance(t, store, dpopNow.Add(60*time.Second+dpop.ReplayRecordGrace))
	assert.Equal(t, http.StatusUnauthorized, late.serve(proof).Code)
}

// Whatever answers a request after the parse guard accepted its proof, a guard, a route's rate
// limiter or the handler, success or refusal, the proof stays spent. A proof names the method, the
// URL and the token, not the body (RFC 9449 section 11.7), so the same proof sent again could carry
// any other body: it is a replay, refused by the parse guard before anything behind it runs.
func TestBearerGuardDPoP_WhateverTheRouteAnswersTheProofStaysSpent(t *testing.T) {
	key := dpoptest.RFC7517Key(t)
	checker, err := dpop.NewChecker(dpopResourceBaseURL)
	require.NoError(t, err)
	for _, status := range []int{http.StatusOK, http.StatusBadRequest, http.StatusForbidden,
		http.StatusTooManyRequests, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			store := newReplayStore()
			guards := NewBearerTokenForAPI(dpopParser{jkt: key.Thumbprint},
				ResourceProofs{Checker: checker, Replays: store, Now: func() time.Time { return dpopNow }})
			reached := 0
			chain := guards.JwtAuthorizationHeaderToContext()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached++
				w.WriteHeader(status)
			}))
			proof := key.ResourceProof(t, "GET", dpopUserinfoURL, dpopNow, tokenBound)

			first := httptest.NewRecorder()
			chain.ServeHTTP(first, dpopRequest("DPoP "+tokenBound, proof))
			require.Equal(t, status, first.Code)
			assert.Equal(t, 1, store.count(), "the proof is spent")

			replayed := httptest.NewRecorder()
			chain.ServeHTTP(replayed, dpopRequest("DPoP "+tokenBound, proof))
			assert.Equal(t, http.StatusUnauthorized, replayed.Code, replayed.Body.String())
			assert.Contains(t, replayed.Header().Get("WWW-Authenticate"), `error="invalid_dpop_proof"`)
			assert.Equal(t, 1, reached, "the replay never got past the parse guard")
		})
	}
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
