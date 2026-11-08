package integration

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/dpop/dpoptest"
)

// Single-use proofs, through the running server and its database (RFC 9449 section 11.1, #42
// decision 9): a proof that got tokens is refused when it is sent again, as an invalid proof with a
// fresh nonce, while a request refused before anything was minted leaves its proof unspent.

// nonceFor asks the token endpoint for a nonce on behalf of service, by a request whose proof carries
// none.
func nonceFor(t *testing.T, service dpopService, key dpoptest.Key) string {
	t.Helper()
	resp, body := postWithProof(t, url.Values{"grant_type": {"client_credentials"}}, service.client.ClientIdentifier,
		service.secret, key.Proof(t, "POST", dpopTokenURL(), time.Now(), ""))
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "%v", body)
	nonce := resp.Header.Get("DPoP-Nonce")
	require.NotEmpty(t, nonce)
	return nonce
}

func TestDPoP_AReplayedProofIsRefused(t *testing.T) {
	service := createDPoPService(t)
	key := dpoptest.RFC7517Key(t)
	form := url.Values{"grant_type": {"client_credentials"}}
	proof := key.Proof(t, "POST", dpopTokenURL(), time.Now(), nonceFor(t, service, key))

	resp, body := postWithProof(t, form, service.client.ClientIdentifier, service.secret, proof)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", body)
	assertBoundTo(t, body, key)

	resp, body = postWithProof(t, form, service.client.ClientIdentifier, service.secret, proof)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, map[string]any{"error": "invalid_dpop_proof", "error_description": "The DPoP proof is invalid."}, body)
	assert.Len(t, resp.Header.Values("DPoP-Nonce"), 1, "the refusal carries a fresh nonce")
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
}

// A request refused at client authentication minted nothing, so its proof was not spent: the same
// proof, sent again with the right secret, gets tokens, once.
func TestDPoP_AProofRefusedAtItsGrantIsNotSpent(t *testing.T) {
	service := createDPoPService(t)
	key := dpoptest.RFC7517Key(t)
	form := url.Values{"grant_type": {"client_credentials"}}
	proof := key.Proof(t, "POST", dpopTokenURL(), time.Now(), nonceFor(t, service, key))

	resp, body := postWithProof(t, form, service.client.ClientIdentifier, "not-the-secret", proof)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "%v", body)
	assert.Equal(t, "invalid_client", body["error"])

	resp, body = postWithProof(t, form, service.client.ClientIdentifier, service.secret, proof)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", body)
	assertBoundTo(t, body, key)

	resp, body = postWithProof(t, form, service.client.ClientIdentifier, service.secret, proof)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_dpop_proof", body["error"])
}
