package handlers

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/leodip/goiabada/authserver/internal/dpop/dpoptest"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/core/oauth"
)

// The token endpoint's half of a refresh token bound to a DPoP key (#42 decision 11): the validator,
// which refuses a bound token without a proof by its key, is handed the proof's key, or none for a
// request without a proof; and a rotation that refuses the same request on the row it holds is
// answered as the validator answers it.

const refreshForm = "grant_type=refresh_token&refresh_token=r&client_id=test_client"

func TestTokenDPoP_TheRefreshGrantIsHandedTheProofsKey(t *testing.T) {
	key := dpoptest.RFC7517Key(t)
	refusal := oauth.NewErrorDetailWithHTTPStatus("invalid_grant", protocolvalidation.BoundRefreshTokenMessage, http.StatusBadRequest)

	t.Run("a request with a proof", func(t *testing.T) {
		e := newDPoPTokenEndpoint(t, dpopPublicBaseURL, dpopSessionKey)
		nonce := e.freshNonce(t)
		e.validator.On("ValidateTokenRequest", mock.Anything, mock.Anything, mock.MatchedBy(func(in *protocolvalidation.ValidateTokenRequestInput) bool {
			return in.DPoPThumbprint == "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s" // RFC 7517 appendix A.1's key
		})).Return(nil, refusal).Once()

		rr := e.post(t, "/auth/token", refreshForm, key.Proof(t, "POST", dpopTokenHTU, e.now, nonce))

		assertTokenError(t, rr, "invalid_grant", "The refresh token is bound to a DPoP key, and the request carries no proof by that key.")
		assertFreshNonce(t, rr, dpopSessionKey, e.now)
	})

	t.Run("a request without one", func(t *testing.T) {
		e := newDPoPTokenEndpoint(t, dpopPublicBaseURL, dpopSessionKey)
		e.validator.On("ValidateTokenRequest", mock.Anything, mock.Anything, mock.MatchedBy(func(in *protocolvalidation.ValidateTokenRequestInput) bool {
			return in.DPoPThumbprint == ""
		})).Return(nil, refusal).Once()

		rr := e.post(t, "/auth/token", refreshForm)

		assertTokenError(t, rr, "invalid_grant", "The refresh token is bound to a DPoP key, and the request carries no proof by that key.")
		assert.Empty(t, rr.Header().Values("DPoP-Nonce"), "no nonce for a request without a proof")
	})
}

func TestTokenDPoP_ARotationRefusedForTheBindingIsAnsweredInvalidGrant(t *testing.T) {
	key := dpoptest.RFC7517Key(t)
	e := newDPoPTokenEndpoint(t, dpopPublicBaseURL, dpopSessionKey)
	nonce := e.freshNonce(t)
	e.validates(codeRefreshGrant(false))
	e.issuer.On("IssueRefreshTokenGrant", mock.Anything, mock.Anything, mock.Anything).
		Return(nil, nil, issuance.ErrRefreshTokenBindingMismatch).Once()

	e.now = dpopNow.Add(time.Minute)
	rr := e.post(t, "/auth/token", refreshForm, key.Proof(t, "POST", dpopTokenHTU, e.now, nonce))

	assertTokenError(t, rr, "invalid_grant", "The refresh token is bound to a DPoP key, and the request carries no proof by that key.")
	assertFreshNonce(t, rr, dpopSessionKey, e.now)
	assert.Contains(t, tokenSamples(t, e.registry), refusalSample("refresh_token", "invalid_grant"))
}
