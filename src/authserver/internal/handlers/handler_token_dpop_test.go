package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/dpop"
	"github.com/leodip/goiabada/authserver/internal/dpop/dpoptest"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/render"
	"github.com/leodip/goiabada/authserver/internal/tokenmetrics"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/metrics"
	"github.com/leodip/goiabada/core/oauth"
)

// DPoP at the token endpoint (RFC 9449, #42 decisions 2, 6, 7, 8 and 18). A request with a valid
// proof carrying a nonce the server minted has its access token bound to the proof's key, on every
// grant. The proof is checked before client authentication and the grant: one without such a nonce
// is answered use_dpop_nonce, and one failing any other check invalid_dpop_proof, both 400 in RFC
// 6749 section 5.2's error body. Every answer to a DPoP request carries exactly one DPoP-Nonce
// header with a fresh nonce. The handler is driven over the real JSON writer, so the answer is
// the one on the wire.

const (
	dpopPublicBaseURL = "https://auth.example.com"
	dpopTokenHTU      = dpopPublicBaseURL + "/auth/token"
)

var (
	dpopSessionKey      = []byte(strings.Repeat("s", 64))
	dpopOtherSessionKey = []byte(strings.Repeat("r", 64))
	dpopNow             = time.Unix(1_800_000_000, 0)
)

// testTokenProofs checks proofs for dpopPublicBaseURL under dpopSessionKey, for a test that sends
// none.
func testTokenProofs() TokenProofs {
	checker, err := dpop.NewChecker(dpopPublicBaseURL)
	if err != nil {
		panic(err)
	}
	return TokenProofs{Checker: checker, Nonces: dpop.NewNonces(dpopSessionKey)}
}

// dpopTokenEndpoint is one HandleTokenPost checking proofs for a public base URL under a session
// authentication key, at a clock the test sets, over strict doubles of the validator and issuer.
type dpopTokenEndpoint struct {
	issuer             *handlersmocks.TokenIssuer
	validator          *handlersmocks.TokenValidator
	auditLogger        *handlersmocks.AuditLogger
	credentialFailures *countingCredentialFailures
	registry           *metrics.Registry
	now                time.Time
	handler            http.HandlerFunc
}

type countingCredentialFailures struct{ count int }

func (c *countingCredentialFailures) RecordCredentialFailure(*http.Request) { c.count++ }

func newDPoPTokenEndpoint(t *testing.T, publicBaseURL string, sessionKey []byte) *dpopTokenEndpoint {
	t.Helper()
	checker, err := dpop.NewChecker(publicBaseURL)
	require.NoError(t, err)
	e := &dpopTokenEndpoint{
		issuer:             handlersmocks.NewTokenIssuer(t),
		validator:          handlersmocks.NewTokenValidator(t),
		auditLogger:        handlersmocks.NewAuditLogger(t),
		credentialFailures: &countingCredentialFailures{},
		registry:           metrics.NewRegistry(),
		now:                dpopNow,
	}
	e.handler = HandleTokenPost(render.New(nil, nil), datamocks.NewDatabase(t), e.issuer, e.validator, e.auditLogger,
		e.credentialFailures, tokenmetrics.Register(e.registry), &recordingLogoutTokens{},
		TokenProofs{Checker: checker, Nonces: dpop.NewNonces(sessionKey), Now: func() time.Time { return e.now }})
	return e
}

// post submits form to path with each of proofs as a DPoP header.
func (e *dpopTokenEndpoint) post(t *testing.T, path, form string, proofs ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form))
	req = withSettings(req, &record.Settings{})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, proof := range proofs {
		req.Header.Add("DPoP", proof)
	}
	rr := httptest.NewRecorder()
	e.handler.ServeHTTP(rr, req)
	return rr
}

// freshNonce is a nonce the endpoint's own key minted at its clock, as its last answer gave one.
func (e *dpopTokenEndpoint) freshNonce(t *testing.T) string {
	t.Helper()
	rr := e.post(t, "/auth/token", clientCredentialsForm, dpoptest.RFC7517Key(t).Proof(t, "POST", dpopTokenHTU, e.now, ""))
	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	return rr.Header().Get("DPoP-Nonce")
}

const clientCredentialsForm = "grant_type=client_credentials&client_id=test_client&client_secret=s&scope=r:p"

// assertTokenError checks rr is a 400 with RFC 6749 section 5.2's error body, not stored by a cache.
func assertTokenError(t *testing.T, rr *httptest.ResponseRecorder, code, description string) {
	t.Helper()
	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	var body map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, map[string]string{"error": code, "error_description": description}, body)
	assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
}

// assertFreshNonce checks rr carries exactly one DPoP-Nonce header, and that it holds a nonce an
// instance under sessionKey accepts at now.
func assertFreshNonce(t *testing.T, rr *httptest.ResponseRecorder, sessionKey []byte, now time.Time) {
	t.Helper()
	values := rr.Header().Values("DPoP-Nonce")
	require.Len(t, values, 1, "exactly one DPoP-Nonce header")
	assert.True(t, dpop.NewNonces(sessionKey).Accepts(values[0], now), "a nonce the server minted, not expired")
}

func refusalSample(grant, code string) string {
	return `goiabada_token_requests_refused_total{grant_type="` + grant + `",error="` + code + `"} 1`
}

// A proof without a nonce is answered use_dpop_nonce with a nonce to retry with, before the client
// is authenticated or the grant looked at: the validator, which authenticates the client, is never
// called, and nothing is logged as a refused client authentication or charged as a failed password.
func TestTokenDPoP_AProofWithoutANonceIsAnsweredUseDPoPNonce(t *testing.T) {
	for name, form := range map[string]string{
		"client_credentials": clientCredentialsForm,
		"password":           "grant_type=password&client_id=test_client&username=u&password=wrong&scope=openid",
	} {
		t.Run(name, func(t *testing.T) {
			e := newDPoPTokenEndpoint(t, dpopPublicBaseURL, dpopSessionKey)
			logged := logtest.CaptureSlog(t)

			rr := e.post(t, "/auth/token", form, dpoptest.RFC7517Key(t).Proof(t, "POST", dpopTokenHTU, dpopNow, ""))

			assertTokenError(t, rr, "use_dpop_nonce", "Authorization server requires nonce in DPoP proof.")
			assertFreshNonce(t, rr, dpopSessionKey, dpopNow)
			assert.Equal(t, 0, e.credentialFailures.count, "no failed sign-in is charged")
			for _, record := range logged.Records() {
				assert.Less(t, record.Level, slog.LevelWarn, "nothing is logged as a refusal: %s", record.Message)
			}
			assert.Equal(t, []string{refusalSample(name, "use_dpop_nonce")}, tokenSamples(t, e.registry))
		})
	}
}

// A request with a valid proof carrying the server's nonce goes on to the grant, which the issuer
// binds to the proof key's thumbprint, on all four grants. The answer carries a fresh nonce.
func TestTokenDPoP_AValidProofBindsTheAccessTokenOnEveryGrant(t *testing.T) {
	key := dpoptest.RFC7517Key(t)
	bound := &oauth.TokenResponse{AccessToken: "access_token", TokenType: "DPoP", ExpiresIn: 300}

	tests := []struct {
		grant string
		form  string
		arm   func(e *dpopTokenEndpoint)
	}{
		{"authorization_code", "grant_type=authorization_code&code=c&redirect_uri=https://app.example.com/cb&client_id=test_client&code_verifier=v",
			func(e *dpopTokenEndpoint) {
				code := &record.Code{Id: 1}
				e.validates(&protocolvalidation.AuthorizationCodeGrant{Code: code})
				e.issuer.On("IssueAuthorizationCodeGrant", mock.Anything, mock.Anything, code, key.Thumbprint).Return(bound, nil).Once()
			}},
		{"client_credentials", clientCredentialsForm,
			func(e *dpopTokenEndpoint) {
				client := &record.Client{Id: 1}
				e.validates(&protocolvalidation.ClientCredentialsGrant{Client: client, Scope: "r:p"})
				e.issuer.On("IssueClientCredentialsGrant", mock.Anything, mock.Anything, client, "r:p", key.Thumbprint).Return(bound, nil).Once()
			}},
		{"password", "grant_type=password&client_id=test_client&username=u&password=p&scope=openid",
			func(e *dpopTokenEndpoint) {
				e.validates(&protocolvalidation.PasswordGrant{Client: &record.Client{Id: 1}, User: &record.User{Id: 42}, Scope: "openid"})
				e.issuer.On("IssuePasswordGrant", mock.Anything, mock.Anything, mock.MatchedBy(func(in *issuance.ROPCGrantInput) bool {
					return in.DPoPThumbprint == key.Thumbprint
				})).Return(bound, nil).Once()
			}},
		{"refresh_token", "grant_type=refresh_token&refresh_token=r&client_id=test_client",
			func(e *dpopTokenEndpoint) {
				e.validates(codeRefreshGrant(false))
				e.issuer.On("IssueRefreshTokenGrant", mock.Anything, mock.Anything, mock.MatchedBy(func(in *issuance.RefreshTokenGrantInput) bool {
					return in.DPoPThumbprint == key.Thumbprint
				})).Return(bound, &issuance.RefreshOutcome{}, nil).Once()
			}},
	}
	for _, test := range tests {
		t.Run(test.grant, func(t *testing.T) {
			e := newDPoPTokenEndpoint(t, dpopPublicBaseURL, dpopSessionKey)
			nonce := e.freshNonce(t)
			test.arm(e)
			e.auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Return()

			e.now = dpopNow.Add(time.Minute)
			rr := e.post(t, "/auth/token", test.form, key.Proof(t, "POST", dpopTokenHTU, e.now, nonce))

			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			var body map[string]any
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
			assert.Equal(t, "DPoP", body["token_type"])
			assertFreshNonce(t, rr, dpopSessionKey, e.now)
			assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
		})
	}
}

func (e *dpopTokenEndpoint) validates(grant protocolvalidation.TokenGrant) {
	e.validator.On("ValidateTokenRequest", mock.Anything, mock.Anything,
		mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).Return(grant, nil).Once()
}

// A request without a DPoP header is answered as before: the token is not bound, and the answer
// carries no nonce.
func TestTokenDPoP_ARequestWithoutAProofIsAnsweredAsBefore(t *testing.T) {
	e := newDPoPTokenEndpoint(t, dpopPublicBaseURL, dpopSessionKey)
	client := &record.Client{Id: 1}
	e.validates(&protocolvalidation.ClientCredentialsGrant{Client: client, Scope: "r:p"})
	e.issuer.On("IssueClientCredentialsGrant", mock.Anything, mock.Anything, client, "r:p", "").
		Return(&oauth.TokenResponse{AccessToken: "access_token", TokenType: "Bearer", ExpiresIn: 300}, nil).Once()
	e.auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Return()

	rr := e.post(t, "/auth/token", clientCredentialsForm)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Empty(t, rr.Header().Values("DPoP-Nonce"), "no nonce for a request without a proof")

	t.Run("and a refusal too", func(t *testing.T) {
		e := newDPoPTokenEndpoint(t, dpopPublicBaseURL, dpopSessionKey)
		e.validator.On("ValidateTokenRequest", mock.Anything, mock.Anything, mock.Anything).
			Return(nil, oauth.NewErrorDetailWithHTTPStatus("invalid_client", "Client authentication failed.", http.StatusUnauthorized)).Once()

		rr := e.post(t, "/auth/token", clientCredentialsForm)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Empty(t, rr.Header().Values("DPoP-Nonce"))
	})
}

// A proof that fails any check is refused invalid_dpop_proof before the client is authenticated,
// with a fresh nonce and a Warn record saying why, even when it carries a good nonce.
func TestTokenDPoP_AnInvalidProofIsAnsweredInvalidDPoPProof(t *testing.T) {
	key := dpoptest.RFC7517Key(t)

	tests := []struct {
		name   string
		proofs func(t *testing.T, nonce string) []string
	}{
		{"two DPoP headers", func(t *testing.T, nonce string) []string {
			return []string{key.Proof(t, "POST", dpopTokenHTU, dpopNow, nonce), key.Proof(t, "POST", dpopTokenHTU, dpopNow, nonce)}
		}},
		{"an empty DPoP header", func(*testing.T, string) []string { return []string{""} }},
		{"a value that is no JWT", func(*testing.T, string) []string { return []string{"not-a-proof"} }},
		{"htm naming another method", func(t *testing.T, nonce string) []string {
			return []string{key.Proof(t, "GET", dpopTokenHTU, dpopNow, nonce)}
		}},
		{"htu naming another endpoint", func(t *testing.T, nonce string) []string {
			return []string{key.Proof(t, "POST", dpopPublicBaseURL+"/userinfo", dpopNow, nonce)}
		}},
		{"htu naming the internal base URL", func(t *testing.T, nonce string) []string {
			return []string{key.Proof(t, "POST", "http://goiabada-authserver:9090/auth/token", dpopNow, nonce)}
		}},
		{"a signature by another key", func(t *testing.T, nonce string) []string {
			proof := key.Proof(t, "POST", dpopTokenHTU, dpopNow, nonce)
			other := dpoptest.RFC7515Key(t).Sign(t, map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": key.JWK},
				map[string]any{"jti": "j", "htm": "POST", "htu": dpopTokenHTU, "iat": dpopNow.Unix(), "nonce": nonce})
			return []string{proof[:strings.LastIndex(proof, ".")] + other[strings.LastIndex(other, "."):]}
		}},
		{"a typ other than dpop+jwt", func(t *testing.T, nonce string) []string {
			return []string{key.Sign(t, map[string]any{"typ": "JWT", "alg": "ES256", "jwk": key.JWK},
				map[string]any{"jti": "j", "htm": "POST", "htu": dpopTokenHTU, "iat": dpopNow.Unix(), "nonce": nonce})}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := newDPoPTokenEndpoint(t, dpopPublicBaseURL, dpopSessionKey)
			nonce := e.freshNonce(t)
			logged := logtest.CaptureSlog(t)

			rr := e.post(t, "/auth/token", clientCredentialsForm, test.proofs(t, nonce)...)

			assertTokenError(t, rr, "invalid_dpop_proof", "The DPoP proof is invalid.")
			assertFreshNonce(t, rr, dpopSessionKey, dpopNow)
			records := logged.Records()
			require.Len(t, records, 1)
			assert.Equal(t, slog.LevelWarn, records[0].Level)
			assert.Equal(t, "dpop proof refused at the token endpoint", records[0].Message)
			assert.Contains(t, records[0].Attrs["reason"], "the DPoP proof is invalid: ")
			assert.NotContains(t, records[0].Attrs["reason"], "token_dpop.go", "no stack")
			assert.Equal(t, "client_credentials", records[0].Attrs["grant_type"])
			assert.Equal(t, "test_client", records[0].Attrs["client_identifier"])
			assert.Contains(t, tokenSamples(t, e.registry), refusalSample("client_credentials", "invalid_dpop_proof"))
		})
	}
}

// The nonce is stateless: one minted by any instance sharing the session authentication key is
// accepted, for ten minutes; one minted under another key, as before a rotation, or expired, is
// answered use_dpop_nonce with a fresh one (#42 decision 7).
func TestTokenDPoP_NoncesAcrossInstances(t *testing.T) {
	key := dpoptest.RFC7517Key(t)
	minting := newDPoPTokenEndpoint(t, dpopPublicBaseURL, dpopSessionKey)
	nonce := minting.freshNonce(t)

	accepted := func(t *testing.T, e *dpopTokenEndpoint) {
		t.Helper()
		client := &record.Client{Id: 1}
		e.validates(&protocolvalidation.ClientCredentialsGrant{Client: client, Scope: "r:p"})
		e.issuer.On("IssueClientCredentialsGrant", mock.Anything, mock.Anything, client, "r:p", key.Thumbprint).
			Return(&oauth.TokenResponse{AccessToken: "a", TokenType: "DPoP"}, nil).Once()
		e.auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Return()
		rr := e.post(t, "/auth/token", clientCredentialsForm, key.Proof(t, "POST", dpopTokenHTU, e.now, nonce))
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	}

	t.Run("another instance sharing the key accepts it", func(t *testing.T) {
		accepted(t, newDPoPTokenEndpoint(t, dpopPublicBaseURL, dpopSessionKey))
	})
	t.Run("ten minutes on, it is still accepted", func(t *testing.T) {
		e := newDPoPTokenEndpoint(t, dpopPublicBaseURL, dpopSessionKey)
		e.now = dpopNow.Add(10 * time.Minute)
		accepted(t, e)
	})
	t.Run("an instance under another key refuses it", func(t *testing.T) {
		e := newDPoPTokenEndpoint(t, dpopPublicBaseURL, dpopOtherSessionKey)
		rr := e.post(t, "/auth/token", clientCredentialsForm, key.Proof(t, "POST", dpopTokenHTU, e.now, nonce))
		assertTokenError(t, rr, "use_dpop_nonce", "Authorization server requires nonce in DPoP proof.")
		assertFreshNonce(t, rr, dpopOtherSessionKey, e.now)
	})
	t.Run("past ten minutes, it is refused", func(t *testing.T) {
		e := newDPoPTokenEndpoint(t, dpopPublicBaseURL, dpopSessionKey)
		e.now = dpopNow.Add(10*time.Minute + time.Second)
		rr := e.post(t, "/auth/token", clientCredentialsForm, key.Proof(t, "POST", dpopTokenHTU, e.now, nonce))
		assertTokenError(t, rr, "use_dpop_nonce", "Authorization server requires nonce in DPoP proof.")
		assertFreshNonce(t, rr, dpopSessionKey, e.now)
	})
}

// At the token endpoint a proof's freshness comes from its nonce alone: an iat an hour old or an
// hour ahead is not compared with the server's clock (#42 decision 8).
func TestTokenDPoP_FreshnessComesFromTheNonce(t *testing.T) {
	key := dpoptest.RFC7517Key(t)
	for name, iat := range map[string]time.Time{"an hour old": dpopNow.Add(-time.Hour), "an hour ahead": dpopNow.Add(time.Hour)} {
		t.Run(name, func(t *testing.T) {
			e := newDPoPTokenEndpoint(t, dpopPublicBaseURL, dpopSessionKey)
			nonce := e.freshNonce(t)
			client := &record.Client{Id: 1}
			e.validates(&protocolvalidation.ClientCredentialsGrant{Client: client, Scope: "r:p"})
			e.issuer.On("IssueClientCredentialsGrant", mock.Anything, mock.Anything, client, "r:p", key.Thumbprint).
				Return(&oauth.TokenResponse{AccessToken: "a", TokenType: "DPoP"}, nil).Once()
			e.auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Return()

			rr := e.post(t, "/auth/token", clientCredentialsForm, key.Proof(t, "POST", dpopTokenHTU, iat, nonce))

			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		})
	}
}

// A public base URL carrying a path is part of htu, as discovery's token endpoint carries it, for
// a request that arrives without it (#42 decision 18): the full public URL is accepted, and the
// host without the prefix, or the bare path, is refused.
func TestTokenDPoP_ABaseURLWithAPath(t *testing.T) {
	const baseURL = "https://example.com/goiabada"
	key := dpoptest.RFC7517Key(t)

	t.Run("the full public URL is accepted", func(t *testing.T) {
		e := newDPoPTokenEndpoint(t, baseURL, dpopSessionKey)
		rr := e.post(t, "/auth/token", clientCredentialsForm, key.Proof(t, "POST", baseURL+"/auth/token", e.now, ""))
		assertTokenError(t, rr, "use_dpop_nonce", "Authorization server requires nonce in DPoP proof.")
		nonce := rr.Header().Get("DPoP-Nonce")

		client := &record.Client{Id: 1}
		e.validates(&protocolvalidation.ClientCredentialsGrant{Client: client, Scope: "r:p"})
		e.issuer.On("IssueClientCredentialsGrant", mock.Anything, mock.Anything, client, "r:p", key.Thumbprint).
			Return(&oauth.TokenResponse{AccessToken: "a", TokenType: "DPoP"}, nil).Once()
		e.auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Return()
		rr = e.post(t, "/auth/token", clientCredentialsForm, key.Proof(t, "POST", baseURL+"/auth/token", e.now, nonce))
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	})
	for name, htu := range map[string]string{
		"the host without the prefix": "https://example.com/auth/token",
		"the bare path":               "/auth/token",
		"the prefix without the host": "/goiabada/auth/token",
	} {
		t.Run(name+" is refused", func(t *testing.T) {
			e := newDPoPTokenEndpoint(t, baseURL, dpopSessionKey)
			nonce := e.post(t, "/auth/token", clientCredentialsForm, key.Proof(t, "POST", baseURL+"/auth/token", e.now, "")).
				Header().Get("DPoP-Nonce")
			rr := e.post(t, "/auth/token", clientCredentialsForm, key.Proof(t, "POST", htu, e.now, nonce))
			assertTokenError(t, rr, "invalid_dpop_proof", "The DPoP proof is invalid.")
		})
	}
}
