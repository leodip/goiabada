package middleware

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/dpop"
	"github.com/leodip/goiabada/authserver/internal/dpop/dpoptest"
	"github.com/leodip/goiabada/authserver/internal/render"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/signingkeys"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/oauth"
)

// This file is the DPoP half of the bearer guard set's seam (RFC 9449 section 7, #42 decision 10):
// the chain routes.go mounts on /userinfo, with the replay guard last, driven through httptest on
// both surfaces with a real proof checker, proofs signed by dpoptest's published keys, a replay
// store standing in for the database and a fixed clock. Every expected challenge and body is a
// literal: the algorithm list is decision 4's, in its order.

const (
	dpopResourceBaseURL = "https://auth.example.com"
	dpopUserinfoURL     = dpopResourceBaseURL + "/userinfo"

	// The tokens dpopParser knows. Each string is also the token whose hash a proof's ath carries.
	tokenBound         = "bound-access-token"
	tokenBoundNoOpenID = "bound-access-token-without-openid"
	tokenBoundClient   = "bound-client-credentials-token"
	tokenUnbound       = "unbound-access-token"

	dpopChallengeBare = `DPoP realm="goiabada", algs="ES256 ES384 ES512 PS256 PS384 PS512 RS256 RS384 RS512 Ed25519 EdDSA"`

	descriptionBoundAsBearer = "The access token is bound to a DPoP key and must be sent with the DPoP scheme."
	descriptionUnboundAsDPoP = "The access token is not bound to a DPoP key and must be sent with the Bearer scheme."
	descriptionKeyBinding    = "The DPoP proof is not signed with the key the access token is bound to."
	descriptionInvalidProof  = "The DPoP proof is invalid."
)

// dpopNow is the server's clock in every test here.
var dpopNow = time.Unix(1_800_000_000, 0)

// dpopParser stands in for the signed-token parser, as chainParser does, knowing four tokens: three
// bound to RFC 7517's key and one bearer token.
type dpopParser struct{ jkt string }

func (p dpopParser) DecodeAndValidateTokenString(_ context.Context, token string, _ bool) (*oauth.JwtToken, error) {
	claims := map[string]interface{}{"typ": "Bearer", "aud": "authserver", "sub": "u1", "auth_time": float64(1),
		"scope": "openid profile", "client_id": "spa-1", "cnf": map[string]interface{}{"jkt": p.jkt}}
	switch token {
	case tokenBound:
	case tokenBoundNoOpenID:
		claims["scope"] = "profile"
	case tokenBoundClient:
		delete(claims, "auth_time")
	case tokenUnbound:
		delete(claims, "cnf")
	default:
		return nil, fmt.Errorf("the token does not verify: %w", signingkeys.ErrTokenRefused)
	}
	return &oauth.JwtToken{TokenBase64: token, Claims: claims}, nil
}

// replayStore is the replay table: a proof hash is recorded once, with its expiry, and fault, when
// set, is every write's answer.
type replayStore struct {
	mu      sync.Mutex
	records map[string]time.Time
	fault   error
	// releaseFault is what ReleaseDPoPProof answers, when set, deleting nothing; releases counts its
	// calls.
	releaseFault error
	releases     int
}

func newReplayStore() *replayStore { return &replayStore{records: map[string]time.Time{}} }

func (s *replayStore) RecordDPoPProof(_ context.Context, _ *sql.Tx, proofHash string, expiresAt time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fault != nil {
		return false, s.fault
	}
	if _, seen := s.records[proofHash]; seen {
		return false, nil
	}
	s.records[proofHash] = expiresAt
	return true, nil
}

func (s *replayStore) ReleaseDPoPProof(_ context.Context, _ *sql.Tx, proofHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.releases++
	if s.releaseFault != nil {
		return s.releaseFault
	}
	delete(s.records, proofHash)
	return nil
}

func (s *replayStore) releaseCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.releases
}

func (s *replayStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

// dpopGuards builds one surface's guard set checking proofs for baseURL at dpopNow into store.
func dpopGuards(t *testing.T, surface, baseURL string, store *replayStore) *BearerToken {
	t.Helper()
	checker, err := dpop.NewChecker(baseURL)
	require.NoError(t, err)
	proofs := ResourceProofs{Checker: checker, Replays: store, Now: func() time.Time { return dpopNow }}
	parser := dpopParser{jkt: dpoptest.RFC7517Key(t).Thumbprint}
	if surface == "api" {
		return NewBearerTokenForAPI(parser, proofs)
	}
	return NewBearerTokenForUserInfo(parser, render.New(nil, nil), proofs)
}

// dpopChain is /userinfo's chain as routes.go mounts it, the session guard aside, with the replay
// guard last.
func dpopChain(guards *BearerToken) http.Handler {
	return guards.JwtAuthorizationHeaderToContext()(
		guards.RequireBearerTokenScope("openid")(guards.RequireUserBoundToken()(guards.RecordDPoPProof()(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("admitted")) })))))
}

// dpopRequest is a GET to /userinfo with authorization and every proof given as a DPoP header.
func dpopRequest(authorization string, proofs ...string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	for _, p := range proofs {
		req.Header.Add("DPoP", p)
	}
	return req
}

// dpopFormRequest is a POST to /userinfo whose form body is body, with authorization and proofs.
func dpopFormRequest(body, authorization string, proofs ...string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/userinfo", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	for _, p := range proofs {
		req.Header.Add("DPoP", p)
	}
	return req
}

// refusalAnswers is one refusal on each surface: the status, the challenge, and the error and
// description both bodies carry.
func refusalAnswers(status int, challenge, apiCode, code, description string) (chainAnswer, chainAnswer) {
	return chainAnswer{status, challenge, `{"error_code":"` + apiCode + `","error_description":"` + description + `"}`},
		chainAnswer{status, challenge, `{"error":"` + code + `","error_description":"` + description + `"}`}
}

// TestBearerGuardDPoP_RFC9449OnEachSurface is RFC 9449 section 7's table for this server: what a
// request presenting a bound or an unbound token with each scheme is answered, on each surface,
// and whether its proof was recorded.
func TestBearerGuardDPoP_RFC9449OnEachSurface(t *testing.T) {
	key := dpoptest.RFC7517Key(t)
	otherKey := dpoptest.RFC7515Key(t)
	proofFor := func(token string) string { return key.ResourceProof(t, "GET", dpopUserinfoURL, dpopNow, token) }

	invalidProofChallenge := `Bearer realm="goiabada", ` + dpopChallengeBare +
		`, error="invalid_dpop_proof", error_description="` + descriptionInvalidProof + `"`
	apiInvalidProof, userinfoInvalidProof := refusalAnswers(http.StatusUnauthorized, invalidProofChallenge,
		"INVALID_DPOP_PROOF", "invalid_dpop_proof", descriptionInvalidProof)
	apiBoundAsBearer, userinfoBoundAsBearer := refusalAnswers(http.StatusUnauthorized,
		`Bearer realm="goiabada", error="invalid_token", error_description="`+descriptionBoundAsBearer+`", `+dpopChallengeBare,
		"INVALID_TOKEN", "invalid_token", descriptionBoundAsBearer)
	apiUnboundAsDPoP, userinfoUnboundAsDPoP := refusalAnswers(http.StatusUnauthorized,
		`Bearer realm="goiabada", `+dpopChallengeBare+`, error="invalid_token", error_description="`+descriptionUnboundAsDPoP+`"`,
		"INVALID_TOKEN", "invalid_token", descriptionUnboundAsDPoP)
	apiKeyBinding, userinfoKeyBinding := refusalAnswers(http.StatusUnauthorized,
		`Bearer realm="goiabada", `+dpopChallengeBare+`, error="invalid_token", error_description="`+descriptionKeyBinding+`"`,
		"INVALID_TOKEN", "invalid_token", descriptionKeyBinding)
	apiInvalidDPoPToken, userinfoInvalidDPoPToken := refusalAnswers(http.StatusUnauthorized,
		`Bearer realm="goiabada", `+dpopChallengeBare+`, error="invalid_token", error_description="The access token is invalid."`,
		"INVALID_TOKEN", "invalid_token", "The access token is invalid.")
	// RFC 9449 section 7.2's figure 19: both schemes at once, the error in both challenges.
	bothDescription := "The access token must be sent by one method only."
	apiBothSchemes, userinfoBothSchemes := refusalAnswers(http.StatusBadRequest,
		`Bearer realm="goiabada", error="invalid_request", error_description="`+bothDescription+`", `+
			dpopChallengeBare+`, error="invalid_request", error_description="`+bothDescription+`"`,
		"INVALID_REQUEST", "invalid_request", bothDescription)
	// A 403 carries the challenge of the scheme used, alone.
	apiDPoPScope, userinfoDPoPScope := refusalAnswers(http.StatusForbidden,
		dpopChallengeBare+`, error="insufficient_scope", error_description="Insufficient scope."`,
		"INSUFFICIENT_SCOPE", "insufficient_scope", "Insufficient scope.")
	apiDPoPUserContext, userinfoDPoPUserContext := refusalAnswers(http.StatusForbidden,
		dpopChallengeBare+`, error="insufficient_scope", error_description="`+userContextDescription+`"`,
		"USER_CONTEXT_REQUIRED", "insufficient_scope", userContextDescription)

	tests := []struct {
		name     string
		request  func() *http.Request
		api      chainAnswer
		userinfo chainAnswer
		// recorded is how many proofs the request left in the replay store.
		recorded int
	}{
		{name: "a bound token with the DPoP scheme and its proof",
			request: func() *http.Request { return dpopRequest("DPoP "+tokenBound, proofFor(tokenBound)) },
			api:     answerAdmitted, userinfo: answerAdmitted, recorded: 1},
		{name: "the scheme in lower case",
			request: func() *http.Request { return dpopRequest("dpop "+tokenBound, proofFor(tokenBound)) },
			api:     answerAdmitted, userinfo: answerAdmitted, recorded: 1},
		{name: "an iat a minute old",
			request: func() *http.Request {
				return dpopRequest("DPoP "+tokenBound, key.ResourceProof(t, "GET", dpopUserinfoURL, dpopNow.Add(-60*time.Second), tokenBound))
			},
			api: answerAdmitted, userinfo: answerAdmitted, recorded: 1},
		{name: "an iat a minute ahead",
			request: func() *http.Request {
				return dpopRequest("DPoP "+tokenBound, key.ResourceProof(t, "GET", dpopUserinfoURL, dpopNow.Add(60*time.Second), tokenBound))
			},
			api: answerAdmitted, userinfo: answerAdmitted, recorded: 1},
		// A stray DPoP header beside an unbound Bearer token is ignored, and nothing is recorded.
		{name: "an unbound token with the Bearer scheme and a stray proof",
			request: func() *http.Request { return dpopRequest("Bearer "+tokenUnbound, proofFor(tokenUnbound)) },
			api:     answerAdmitted, userinfo: answerAdmitted},

		// RFC 9449 section 7.2 MUST: a bound token received as a bearer token is refused.
		{name: "a bound token with the Bearer scheme",
			request: func() *http.Request { return dpopRequest("Bearer " + tokenBound) },
			api:     apiBoundAsBearer, userinfo: userinfoBoundAsBearer},
		{name: "a bound token with the Bearer scheme, its proof beside it",
			request: func() *http.Request { return dpopRequest("Bearer "+tokenBound, proofFor(tokenBound)) },
			api:     apiBoundAsBearer, userinfo: userinfoBoundAsBearer},
		{name: "a bound token in a form body",
			request: func() *http.Request { return dpopFormRequest("access_token="+tokenBound, "", proofFor(tokenBound)) },
			api:     apiBoundAsBearer, userinfo: userinfoBoundAsBearer},
		{name: "an unbound token with the DPoP scheme",
			request: func() *http.Request { return dpopRequest("DPoP "+tokenUnbound, proofFor(tokenUnbound)) },
			api:     apiUnboundAsDPoP, userinfo: userinfoUnboundAsDPoP},
		{name: "a token that fails validation with the DPoP scheme",
			request: func() *http.Request { return dpopRequest("DPoP garbage", proofFor("garbage")) },
			api:     apiInvalidDPoPToken, userinfo: userinfoInvalidDPoPToken},
		{name: "the DPoP scheme with an empty token",
			request: func() *http.Request { return dpopRequest("DPoP ", proofFor("")) },
			api:     apiInvalidDPoPToken, userinfo: userinfoInvalidDPoPToken},

		// A proof problem is invalid_dpop_proof (RFC 9449 section 7.1).
		{name: "no DPoP header",
			request: func() *http.Request { return dpopRequest("DPoP " + tokenBound) },
			api:     apiInvalidProof, userinfo: userinfoInvalidProof},
		{name: "two DPoP headers",
			request: func() *http.Request {
				return dpopRequest("DPoP "+tokenBound, proofFor(tokenBound), proofFor(tokenBound))
			},
			api: apiInvalidProof, userinfo: userinfoInvalidProof},
		{name: "a proof whose ath is another token's",
			request: func() *http.Request { return dpopRequest("DPoP "+tokenBound, proofFor(tokenUnbound)) },
			api:     apiInvalidProof, userinfo: userinfoInvalidProof},
		{name: "a proof with no ath",
			request: func() *http.Request {
				return dpopRequest("DPoP "+tokenBound, key.Proof(t, "GET", dpopUserinfoURL, dpopNow, ""))
			},
			api: apiInvalidProof, userinfo: userinfoInvalidProof},
		{name: "a proof for another method",
			request: func() *http.Request {
				return dpopRequest("DPoP "+tokenBound, key.ResourceProof(t, "POST", dpopUserinfoURL, dpopNow, tokenBound))
			},
			api: apiInvalidProof, userinfo: userinfoInvalidProof},
		{name: "a proof for another URL",
			request: func() *http.Request {
				return dpopRequest("DPoP "+tokenBound, key.ResourceProof(t, "GET", dpopResourceBaseURL+"/api/v1/account/profile", dpopNow, tokenBound))
			},
			api: apiInvalidProof, userinfo: userinfoInvalidProof},
		{name: "an iat a second over a minute old",
			request: func() *http.Request {
				return dpopRequest("DPoP "+tokenBound, key.ResourceProof(t, "GET", dpopUserinfoURL, dpopNow.Add(-61*time.Second), tokenBound))
			},
			api: apiInvalidProof, userinfo: userinfoInvalidProof},
		{name: "an iat a second over a minute ahead",
			request: func() *http.Request {
				return dpopRequest("DPoP "+tokenBound, key.ResourceProof(t, "GET", dpopUserinfoURL, dpopNow.Add(61*time.Second), tokenBound))
			},
			api: apiInvalidProof, userinfo: userinfoInvalidProof},

		// RFC 9449 section 7.1 MUST: the proof's key is the one the token is bound to. A valid proof
		// by another key is the key binding failing, figure 16's invalid_token.
		{name: "a valid proof by another key",
			request: func() *http.Request {
				return dpopRequest("DPoP "+tokenBound, otherKey.ResourceProof(t, "GET", dpopUserinfoURL, dpopNow, tokenBound))
			},
			api: apiKeyBinding, userinfo: userinfoKeyBinding},

		{name: "the DPoP scheme and a token in the form body",
			request: func() *http.Request {
				return dpopFormRequest("access_token="+tokenBound, "DPoP "+tokenBound, proofFor(tokenBound))
			},
			api: apiBothSchemes, userinfo: userinfoBothSchemes},
		{name: "a Bearer line and a DPoP line",
			request: func() *http.Request {
				req := dpopRequest("Bearer "+tokenUnbound, proofFor(tokenBound))
				req.Header.Add("Authorization", "DPoP "+tokenBound)
				return req
			},
			api: chainAnswer{http.StatusBadRequest,
				`Bearer realm="goiabada", error="invalid_request", error_description="The Authorization header must be sent once.", ` +
					dpopChallengeBare + `, error="invalid_request", error_description="The Authorization header must be sent once."`,
				`{"error_code":"INVALID_REQUEST","error_description":"The Authorization header must be sent once."}`},
			userinfo: chainAnswer{http.StatusBadRequest,
				`Bearer realm="goiabada", error="invalid_request", error_description="The Authorization header must be sent once.", ` +
					dpopChallengeBare + `, error="invalid_request", error_description="The Authorization header must be sent once."`,
				`{"error":"invalid_request","error_description":"The Authorization header must be sent once."}`}},

		// A guard behind the parse guard refuses in the scheme used, and the proof is not spent.
		{name: "a bound token lacking the route's scope",
			request: func() *http.Request { return dpopRequest("DPoP "+tokenBoundNoOpenID, proofFor(tokenBoundNoOpenID)) },
			api:     apiDPoPScope, userinfo: userinfoDPoPScope},
		{name: "a bound client credentials token",
			request: func() *http.Request { return dpopRequest("DPoP "+tokenBoundClient, proofFor(tokenBoundClient)) },
			api:     apiDPoPUserContext, userinfo: userinfoDPoPUserContext},
	}

	for _, surface := range []string{"api", "userinfo"} {
		for _, tc := range tests {
			t.Run(surface+"/"+tc.name, func(t *testing.T) {
				store := newReplayStore()
				rr := httptest.NewRecorder()
				dpopChain(dpopGuards(t, surface, dpopResourceBaseURL, store)).ServeHTTP(rr, tc.request())

				want := tc.api
				if surface == "userinfo" {
					want = tc.userinfo
				}
				assertChainAnswer(t, want, rr)
				assert.Equal(t, tc.recorded, store.count(), "proofs recorded")
			})
		}
	}
}

// A request with no credentials is told both schemes, Bearer first, with no error (RFC 6750
// section 3.1, RFC 9449 section 7.2 figure 17), and with a stray DPoP header too.
func TestBearerGuardDPoP_NoCredentialsIsBothChallengesWithNoError(t *testing.T) {
	for _, surface := range []string{"api", "userinfo"} {
		t.Run(surface, func(t *testing.T) {
			for _, req := range []*http.Request{dpopRequest(""), dpopRequest("", "a.stray.proof")} {
				rr := httptest.NewRecorder()
				dpopChain(dpopGuards(t, surface, dpopResourceBaseURL, newReplayStore())).ServeHTTP(rr, req)

				assert.Equal(t, http.StatusUnauthorized, rr.Code)
				assert.Equal(t, `Bearer realm="goiabada", `+dpopChallengeBare, rr.Header().Get("WWW-Authenticate"))
				assert.Len(t, rr.Header().Values("WWW-Authenticate"), 1, "one field line, both challenges")
			}
		})
	}
}

// The proof is recorded under the hash of its normalized htu and its jti, the replay key, until
// its iat plus 60 seconds, the last moment the resources accept it (#42 decisions 8 and 9), and five
// minutes beyond, for instances whose clocks run behind the sweeper's. The hash is sha256sum's over
// "https://auth.example.com/userinfo resource-proof-1".
func TestBearerGuardDPoP_TheProofIsRecordedUntilItsIatPlusAMinuteAndTheGrace(t *testing.T) {
	key := dpoptest.RFC7517Key(t)
	store := newReplayStore()
	iat := dpopNow.Add(-20 * time.Second)
	proof := key.Sign(t, map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": key.JWK},
		map[string]any{"jti": "resource-proof-1", "htm": "GET", "htu": dpopUserinfoURL, "iat": iat.Unix(),
			"ath": dpoptest.ATH(tokenBound)})

	rr := httptest.NewRecorder()
	dpopChain(dpopGuards(t, "api", dpopResourceBaseURL, store)).ServeHTTP(rr, dpopRequest("DPoP "+tokenBound, proof))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, map[string]time.Time{
		"77ffe8c1cfe479f05df5c306f7fc455992001b22d080377cee01b12f23969717": time.Unix(1_800_000_040+300, 0),
	}, store.records)
}

// A proof is accepted once: the second request carrying it is refused invalid_dpop_proof, with a
// Warn record saying why (RFC 9449 section 11.1).
func TestBearerGuardDPoP_AReplayedProofIsRefused(t *testing.T) {
	for _, surface := range []string{"api", "userinfo"} {
		t.Run(surface, func(t *testing.T) {
			key := dpoptest.RFC7517Key(t)
			store := newReplayStore()
			chain := dpopChain(dpopGuards(t, surface, dpopResourceBaseURL, store))
			proof := key.ResourceProof(t, "GET", dpopUserinfoURL, dpopNow, tokenBound)

			first := httptest.NewRecorder()
			chain.ServeHTTP(first, dpopRequest("DPoP "+tokenBound, proof))
			require.Equal(t, http.StatusOK, first.Code, first.Body.String())

			logs := logtest.CaptureSlog(t)
			replay := httptest.NewRecorder()
			chain.ServeHTTP(replay, dpopRequest("DPoP "+tokenBound, proof))

			assert.Equal(t, http.StatusUnauthorized, replay.Code)
			assert.Equal(t, `Bearer realm="goiabada", `+dpopChallengeBare+`, error="invalid_dpop_proof", error_description="The DPoP proof is invalid."`,
				replay.Header().Get("WWW-Authenticate"))
			records := logs.Records()
			require.Len(t, records, 1)
			assert.Equal(t, slog.LevelWarn, records[0].Level)
			assert.Equal(t, "dpop proof refused at a resource", records[0].Message)
			assert.Contains(t, logs.Text(), "it has been used before")
			assert.Equal(t, 1, store.count())
		})
	}
}

// A replay store that cannot answer fails the request with the surface's 500 and no challenge: the
// request never goes ahead unchecked (#42 decision 9).
func TestBearerGuardDPoP_AStoreThatCannotAnswerIsAServerError(t *testing.T) {
	for _, surface := range []string{"api", "userinfo"} {
		t.Run(surface, func(t *testing.T) {
			logs := logtest.CaptureSlog(t)
			store := newReplayStore()
			store.fault = errors.New("the database is down")
			key := dpoptest.RFC7517Key(t)

			rr := httptest.NewRecorder()
			dpopChain(dpopGuards(t, surface, dpopResourceBaseURL, store)).ServeHTTP(rr,
				dpopRequest("DPoP "+tokenBound, key.ResourceProof(t, "GET", dpopUserinfoURL, dpopNow, tokenBound)))

			assert.Equal(t, http.StatusInternalServerError, rr.Code)
			assert.NotContains(t, rr.Body.String(), "admitted")
			assert.Empty(t, rr.Header().Get("WWW-Authenticate"), "a server fault is not a challenge")
			assert.Contains(t, logs.Text(), "the database is down")
		})
	}
}

// Each refusal of a DPoP request is a Warn record naming why, and a proof refused names the
// checker's reason (#42, "a refused proof is a Warn log record").
func TestBearerGuardDPoP_RefusalsAreWarnRecords(t *testing.T) {
	key := dpoptest.RFC7517Key(t)
	otherKey := dpoptest.RFC7515Key(t)
	tests := []struct {
		name    string
		request *http.Request
		message string
		detail  string
	}{
		{"a bound token sent as a bearer token", dpopRequest("Bearer " + tokenBound),
			"rejecting bearer token: a DPoP-bound token was sent with the Bearer scheme", ""},
		{"an unbound token sent with the DPoP scheme",
			dpopRequest("DPoP "+tokenUnbound, key.ResourceProof(t, "GET", dpopUserinfoURL, dpopNow, tokenUnbound)),
			"rejecting bearer token: a token bound to no DPoP key was sent with the DPoP scheme", ""},
		{"a proof whose ath is another token's",
			dpopRequest("DPoP "+tokenBound, key.ResourceProof(t, "GET", dpopUserinfoURL, dpopNow, tokenUnbound)),
			"dpop proof refused at a resource", "ath is not the hash of the access token presented"},
		{"a proof by another key",
			dpopRequest("DPoP "+tokenBound, otherKey.ResourceProof(t, "GET", dpopUserinfoURL, dpopNow, tokenBound)),
			"rejecting bearer token: the DPoP proof's key is not the one the token is bound to", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logs := logtest.CaptureSlog(t)
			rr := httptest.NewRecorder()
			dpopChain(dpopGuards(t, "api", dpopResourceBaseURL, newReplayStore())).ServeHTTP(rr, tc.request)

			require.Equal(t, http.StatusUnauthorized, rr.Code)
			records := logs.Records()
			require.Len(t, records, 1)
			assert.Equal(t, slog.LevelWarn, records[0].Level)
			assert.Equal(t, tc.message, records[0].Message)
			assert.Contains(t, logs.Text(), tc.detail)
		})
	}
}

// With a public base URL that carries a path, a proof must name it: the full public URL is
// accepted, and the bare path or the host without the prefix is refused, for a request that arrives
// without the prefix (#42 decisions 6 and 18). Nothing here says a prefixed deployment works.
func TestBearerGuardDPoP_ABaseURLCarryingAPath(t *testing.T) {
	key := dpoptest.RFC7517Key(t)
	const baseURL = "https://auth.example.com/goiabada"
	tests := []struct {
		htu    string
		status int
	}{
		{"https://auth.example.com/goiabada/userinfo", http.StatusOK},
		{"https://auth.example.com/userinfo", http.StatusUnauthorized},
		{"/goiabada/userinfo", http.StatusUnauthorized},
		{"/userinfo", http.StatusUnauthorized},
	}
	for _, surface := range []string{"api", "userinfo"} {
		for _, tc := range tests {
			t.Run(surface+"/"+tc.htu, func(t *testing.T) {
				rr := httptest.NewRecorder()
				dpopChain(dpopGuards(t, surface, baseURL, newReplayStore())).ServeHTTP(rr,
					dpopRequest("DPoP "+tokenBound, key.ResourceProof(t, "GET", tc.htu, dpopNow, tokenBound)))

				require.Equal(t, tc.status, rr.Code, rr.Body.String())
				if tc.status != http.StatusOK {
					assert.Contains(t, rr.Header().Get("WWW-Authenticate"), `error="invalid_dpop_proof"`)
				}
			})
		}
	}
}

// The challenges a handler behind the guards answers follow the scheme the token was presented
// with: a 401 names both, the error in the scheme used, and a 403 the scheme used alone.
func TestChallenges_FollowTheSchemeOnTheContext(t *testing.T) {
	bearer := context.Background()
	viaDPoP := reqctx.WithDPoPProof(context.Background(), &dpop.Proof{Thumbprint: "jkt"})

	assert.Equal(t, `Bearer realm="goiabada", error="invalid_token", error_description="Gone.", `+dpopChallengeBare,
		UnauthorizedChallenge(bearer, "invalid_token", "Gone."))
	assert.Equal(t, `Bearer realm="goiabada", `+dpopChallengeBare+`, error="invalid_token", error_description="Gone."`,
		UnauthorizedChallenge(viaDPoP, "invalid_token", "Gone."))
	assert.Equal(t, `Bearer realm="goiabada", error="insufficient_scope", error_description="Only manage.", scope="authserver:manage"`,
		InsufficientScopeChallenge(bearer, "Only manage.", "authserver:manage"))
	assert.Equal(t, dpopChallengeBare+`, error="insufficient_scope", error_description="Only manage.", scope="authserver:manage"`,
		InsufficientScopeChallenge(viaDPoP, "Only manage.", "authserver:manage"))
}
