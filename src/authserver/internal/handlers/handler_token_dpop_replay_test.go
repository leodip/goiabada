package handlers

import (
	"database/sql"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/dpop/dpoptest"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/oauth"
)

// The replay store at the token endpoint (RFC 9449 section 11.1, #42 decision 9). A request whose
// proof passed every check and whose grant validated records the proof just before its tokens are
// minted: a proof recorded before is a replay, refused invalid_dpop_proof, and a store that cannot
// answer fails the request with a 500, never letting it go on unchecked. The record is kept until
// the proof's nonce expires, the last moment it could still be accepted (decision 8). Over the real
// engine the same store holds across instances and simultaneous requests:
// handler_token_dpop_replay_sqlite_test.go.

// usedOnceProof is a proof with a fixed jti, so its replay key is a literal: sha256sum's digest of
// "https://auth.example.com/auth/token a-proof-used-once".
const usedOnceReplayKey = "ba9d10cb251134bb0c8d433dbafbe25d49a8cf4de38c4b20497d42c915065b00"

func usedOnceProof(t *testing.T, key dpoptest.Key, iat time.Time, nonce string) string {
	t.Helper()
	return key.Sign(t, map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": key.JWK},
		map[string]any{"jti": "a-proof-used-once", "htm": "POST", "htu": dpopTokenHTU, "iat": iat.Unix(), "nonce": nonce})
}

// The proof is recorded by its replay key, outside any transaction, until its nonce expires: ten
// minutes after the nonce was minted, whenever the proof is sent within them.
func TestTokenDPoP_TheProofIsRecordedUntilItsNonceExpires(t *testing.T) {
	key := dpoptest.RFC7517Key(t)
	e := newDPoPTokenEndpoint(t, dpopPublicBaseURL, dpopSessionKey)
	nonce := e.freshNonce(t) // minted at dpopNow
	client := &record.Client{Id: 1}
	e.validator.On("ValidateTokenRequest", mock.Anything, mock.Anything, mock.Anything).
		Return(&protocolvalidation.ClientCredentialsGrant{Client: client, Scope: "r:p"}, nil).Once()
	e.database.On("RecordDPoPProof", mock.Anything, (*sql.Tx)(nil), usedOnceReplayKey, dpopNow.Add(10*time.Minute)).
		Return(true, nil).Once()
	e.issuer.On("IssueClientCredentialsGrant", mock.Anything, mock.Anything, client, "r:p", key.Thumbprint).
		Return(&oauth.TokenResponse{AccessToken: "a", TokenType: "DPoP"}, nil).Once()
	e.auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Return()

	e.now = dpopNow.Add(7 * time.Minute)
	rr := e.post(t, "/auth/token", clientCredentialsForm, usedOnceProof(t, key, e.now, nonce))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
}

// A proof recorded before is a replay: refused invalid_dpop_proof with a fresh nonce, a Warn record
// saying so, and the refusal counted, before anything is minted. The issuer, a strict double, is
// never called.
func TestTokenDPoP_AReplayedProofIsRefusedInvalidDPoPProof(t *testing.T) {
	key := dpoptest.RFC7517Key(t)
	e := newDPoPTokenEndpoint(t, dpopPublicBaseURL, dpopSessionKey)
	nonce := e.freshNonce(t)
	e.validator.On("ValidateTokenRequest", mock.Anything, mock.Anything, mock.Anything).
		Return(&protocolvalidation.ClientCredentialsGrant{Client: &record.Client{Id: 1}, Scope: "r:p"}, nil).Once()
	e.database.On("RecordDPoPProof", mock.Anything, (*sql.Tx)(nil), usedOnceReplayKey, mock.Anything).
		Return(false, nil).Once()
	logged := logtest.CaptureSlog(t)

	rr := e.post(t, "/auth/token", clientCredentialsForm, usedOnceProof(t, key, e.now, nonce))

	assertTokenError(t, rr, "invalid_dpop_proof", "The DPoP proof is invalid.")
	assertFreshNonce(t, rr, dpopSessionKey, e.now)
	records := logged.Records()
	require.Len(t, records, 1)
	assert.Equal(t, slog.LevelWarn, records[0].Level)
	assert.Equal(t, "dpop proof refused at the token endpoint", records[0].Message)
	assert.Equal(t, "the DPoP proof is invalid: it has been used before", records[0].Attrs["reason"])
	assert.Equal(t, "client_credentials", records[0].Attrs["grant_type"])
	assert.Equal(t, "test_client", records[0].Attrs["client_identifier"])
	assert.Contains(t, tokenSamples(t, e.registry), refusalSample("client_credentials", "invalid_dpop_proof"))
}

// A store that cannot answer fails the request with a 500 in RFC 6749 section 5.2's shape, still
// carrying a fresh nonce, and nothing is minted: a request never goes ahead unchecked.
func TestTokenDPoP_AStoreThatCannotAnswerIsAServerError(t *testing.T) {
	key := dpoptest.RFC7517Key(t)
	e := newDPoPTokenEndpoint(t, dpopPublicBaseURL, dpopSessionKey)
	nonce := e.freshNonce(t)
	e.validator.On("ValidateTokenRequest", mock.Anything, mock.Anything, mock.Anything).
		Return(&protocolvalidation.ClientCredentialsGrant{Client: &record.Client{Id: 1}, Scope: "r:p"}, nil).Once()
	e.database.On("RecordDPoPProof", mock.Anything, (*sql.Tx)(nil), mock.Anything, mock.Anything).
		Return(false, errs.New("the database went away")).Once()

	rr := e.post(t, "/auth/token", clientCredentialsForm, key.Proof(t, "POST", dpopTokenHTU, e.now, nonce))

	assertServerErrorJSON(t, rr)
	assertFreshNonce(t, rr, dpopSessionKey, e.now)
	assert.Contains(t, tokenSamples(t, e.registry), refusalSample("client_credentials", "server_error"))
}

// Only a request that would otherwise succeed records its proof: one refused at its grant, at its
// nonce or at any other check of its proof adds no row, so the same proof can still be sent once
// the request is put right. The database double fails any call nobody expected.
func TestTokenDPoP_ARefusedRequestRecordsNoProof(t *testing.T) {
	key := dpoptest.RFC7517Key(t)

	t.Run("refused at its grant", func(t *testing.T) {
		e := newDPoPTokenEndpoint(t, dpopPublicBaseURL, dpopSessionKey)
		nonce := e.freshNonce(t)
		e.validator.On("ValidateTokenRequest", mock.Anything, mock.Anything, mock.Anything).
			Return(nil, oauth.NewErrorDetailWithHTTPStatus("invalid_client", "Client authentication failed.", http.StatusUnauthorized)).Once()

		rr := e.post(t, "/auth/token", clientCredentialsForm, usedOnceProof(t, key, e.now, nonce))

		assert.Equal(t, http.StatusUnauthorized, rr.Code, rr.Body.String())
	})
	t.Run("refused at its nonce", func(t *testing.T) {
		e := newDPoPTokenEndpoint(t, dpopPublicBaseURL, dpopSessionKey)

		rr := e.post(t, "/auth/token", clientCredentialsForm, key.Proof(t, "POST", dpopTokenHTU, e.now, ""))

		assertTokenError(t, rr, "use_dpop_nonce", "Authorization server requires nonce in DPoP proof.")
	})
	t.Run("refused at another check", func(t *testing.T) {
		e := newDPoPTokenEndpoint(t, dpopPublicBaseURL, dpopSessionKey)
		nonce := e.freshNonce(t)

		rr := e.post(t, "/auth/token", clientCredentialsForm, key.Proof(t, "GET", dpopTokenHTU, e.now, nonce))

		assertTokenError(t, rr, "invalid_dpop_proof", "The DPoP proof is invalid.")
	})
}
