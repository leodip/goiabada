package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/dpop/dpoptest"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
)

// A public client's refresh tokens bound to its DPoP key, through the running server (RFC 9449
// section 5, #42 decision 11): bound on the family's first token issued with a proof, copied through
// every rotation, refused invalid_grant without a proof by that key while the token stays the key
// holder's to use, the upgrade of an unbound family, a confidential client's family left unbound, a
// binding enforced once its client is confidential, and concurrent refreshes of one bound token.

// boundRefreshTokenRefusal is the answer to a refresh of a bound token without a proof by its key.
var boundRefreshTokenRefusal = map[string]any{
	"error":             "invalid_grant",
	"error_description": "The refresh token is bound to a DPoP key, and the request carries no proof by that key.",
}

// refreshWith refreshes refreshToken for clientId, with basic credentials when clientSecret is not
// empty and the client_id in the form otherwise, and with a proof by key when key is not nil. A
// proof carries a nonce the endpoint has just handed out, asked for by a request whose proof has
// none, which is refused before the grant is looked at and so leaves the token unspent.
func refreshWith(t *testing.T, refreshToken, clientId, clientSecret string, key *dpoptest.Key) (*http.Response, map[string]any) {
	t.Helper()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}
	if clientSecret == "" {
		form.Set("client_id", clientId)
	}
	if key == nil {
		return postWithProof(t, form, clientId, clientSecret, "")
	}
	return postWithProof(t, form, clientId, clientSecret, key.Proof(t, "POST", dpopTokenURL(), time.Now(), nonceForRefresh(t, form, clientId, clientSecret, *key)))
}

func nonceForRefresh(t *testing.T, form url.Values, clientId, clientSecret string, key dpoptest.Key) string {
	t.Helper()
	resp, body := postWithProof(t, form, clientId, clientSecret, key.Proof(t, "POST", dpopTokenURL(), time.Now(), ""))
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "%v", body)
	require.Equal(t, "use_dpop_nonce", body["error"])
	nonce := resp.Header.Get("DPoP-Nonce")
	require.NotEmpty(t, nonce)
	return nonce
}

// boundCodeGrant signs a user in to a new client, public or confidential, and redeems the code, with
// a proof by key when key is not nil, and returns the code and the refresh token.
func boundCodeGrant(t *testing.T, public bool, clientSecret string, key *dpoptest.Key) (*record.Code, string) {
	t.Helper()
	_, code := createAuthCode(t, clientSecret, "openid profile", authCodeOptions{isPublic: public})
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {testCodeVerifier},
	}
	secret := clientSecret
	if public {
		form.Set("client_id", code.Client.ClientIdentifier)
		secret = ""
	}

	var body map[string]any
	if key != nil {
		body = redeemWithDPoP(t, form, code.Client.ClientIdentifier, secret, *key)
	} else {
		var resp *http.Response
		resp, body = postWithProof(t, form, code.Client.ClientIdentifier, secret, "")
		require.Equal(t, http.StatusOK, resp.StatusCode, "%v", body)
		assert.Equal(t, "Bearer", body["token_type"])
	}
	refreshToken, ok := body["refresh_token"].(string)
	require.True(t, ok, "a refresh token: %v", body)
	return code, refreshToken
}

// bindingOf is the thumbprint the refresh token is bound to on its row, empty for none.
func bindingOf(t *testing.T, refreshToken string) string {
	t.Helper()
	row, err := database.GetRefreshTokenByJti(context.Background(), nil, refreshTokenJti(t, refreshToken))
	require.NoError(t, err)
	require.NotNil(t, row)
	if row.DPoPJkt.Valid {
		require.NotEmpty(t, row.DPoPJkt.String, "a binding is NULL or a thumbprint, never empty")
	}
	return row.DPoPJkt.String
}

// requireRefused checks a refresh of a bound token without its key was refused, and spent nothing:
// the token is still live and its family not revoked.
func requireRefused(t *testing.T, resp *http.Response, body map[string]any, refreshToken string) {
	t.Helper()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "%v", body)
	assert.Equal(t, boundRefreshTokenRefusal, body)
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))

	row, err := database.GetRefreshTokenByJti(context.Background(), nil, refreshTokenJti(t, refreshToken))
	require.NoError(t, err)
	assert.False(t, row.Revoked, "the refused refresh spent nothing")
	revoked, err := database.IsRefreshTokenFamilyRevoked(context.Background(), nil, row.FirstRefreshTokenJti)
	require.NoError(t, err)
	assert.False(t, revoked, "and revoked no family")
}

func refreshTokenOf(t *testing.T, body map[string]any) string {
	t.Helper()
	refreshToken, ok := body["refresh_token"].(string)
	require.True(t, ok, "a refresh token: %v", body)
	return refreshToken
}

func TestDPoP_APublicClientsRefreshTokenIsBoundToItsKey(t *testing.T) {
	key, other := dpoptest.RFC7517Key(t), dpoptest.RFC7515Key(t)
	code, first := boundCodeGrant(t, true, fake.LetterN(32), &key)
	clientId := code.Client.ClientIdentifier
	assert.Equal(t, key.Thumbprint, bindingOf(t, first), "the family's first token is bound to the code exchange's proof key")

	resp, body := refreshWith(t, first, clientId, "", nil)
	requireRefused(t, resp, body, first)
	assert.Empty(t, resp.Header.Values("DPoP-Nonce"), "a request without a proof is not a DPoP request")

	resp, body = refreshWith(t, first, clientId, "", &other)
	requireRefused(t, resp, body, first)
	assert.Len(t, resp.Header.Values("DPoP-Nonce"), 1, "a DPoP request's refusal carries a fresh nonce")

	resp, body = refreshWith(t, first, clientId, "", &key)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", body)
	assertBoundTo(t, body, key)
	child := refreshTokenOf(t, body)
	assert.Equal(t, key.Thumbprint, bindingOf(t, child), "the rotation copies the binding")

	resp, body = refreshWith(t, child, clientId, "", nil)
	requireRefused(t, resp, body, child)
	resp, body = refreshWith(t, child, clientId, "", &key)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", body)
	assert.Equal(t, key.Thumbprint, bindingOf(t, refreshTokenOf(t, body)))
}

// A public client's family begun without a proof is bound by its first refresh with one, and stays
// bound.
func TestDPoP_AnUnboundFamilyOfAPublicClientIsBoundByItsFirstRefreshWithAProof(t *testing.T) {
	key := dpoptest.RFC7517Key(t)
	code, first := boundCodeGrant(t, true, fake.LetterN(32), nil)
	clientId := code.Client.ClientIdentifier
	assert.Empty(t, bindingOf(t, first), "a family begun without a proof is unbound")

	resp, body := refreshWith(t, first, clientId, "", &key)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", body)
	assertBoundTo(t, body, key)
	bound := refreshTokenOf(t, body)
	assert.Equal(t, key.Thumbprint, bindingOf(t, bound), "the first refresh with a proof binds the family")

	resp, body = refreshWith(t, bound, clientId, "", nil)
	requireRefused(t, resp, body, bound)
}

// A confidential client's family is never bound: a refresh by another key, or with no proof, is
// answered, each access token bound to its own request's key or to none.
func TestDPoP_AConfidentialClientsRefreshTokenStaysUnbound(t *testing.T) {
	key, other := dpoptest.RFC7517Key(t), dpoptest.RFC7515Key(t)
	clientSecret := fake.LetterN(32)
	code, first := boundCodeGrant(t, false, clientSecret, &key)
	clientId := code.Client.ClientIdentifier
	assert.Empty(t, bindingOf(t, first), "the confidential client's family is unbound")

	resp, body := refreshWith(t, first, clientId, clientSecret, &other)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", body)
	assertBoundTo(t, body, other)
	child := refreshTokenOf(t, body)
	assert.Empty(t, bindingOf(t, child))

	resp, body = refreshWith(t, child, clientId, clientSecret, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", body)
	assert.Equal(t, "Bearer", body["token_type"])
	assert.Empty(t, bindingOf(t, refreshTokenOf(t, body)))
}

// A public client switched to confidential keeps its grants, and a bound family's refreshes still
// take a proof by its key, now with the client's secret too.
func TestDPoP_ABoundFamilyStaysBoundOnceItsClientIsConfidential(t *testing.T) {
	key, other := dpoptest.RFC7517Key(t), dpoptest.RFC7515Key(t)
	code, first := boundCodeGrant(t, true, fake.LetterN(32), &key)

	clientSecret := fake.LetterN(32)
	client, err := database.GetClientById(context.Background(), nil, code.ClientId)
	require.NoError(t, err)
	client.IsPublic = false
	client.ClientSecretEncrypted, err = dataCipher.Encrypt(clientSecret)
	require.NoError(t, err)
	require.NoError(t, database.UpdateClient(context.Background(), nil, client))

	resp, body := refreshWith(t, first, client.ClientIdentifier, clientSecret, nil)
	requireRefused(t, resp, body, first)
	resp, body = refreshWith(t, first, client.ClientIdentifier, clientSecret, &other)
	requireRefused(t, resp, body, first)

	resp, body = refreshWith(t, first, client.ClientIdentifier, clientSecret, &key)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", body)
	assertBoundTo(t, body, key)
	assert.Equal(t, key.Thumbprint, bindingOf(t, refreshTokenOf(t, body)), "the binding is inherited")
}

// Concurrent refreshes of one bound token, by its key, by another key and with no proof: one is
// answered with tokens, and it is one by the family's key; every one without that key is refused
// for the binding, and every token the family holds afterwards is bound to the key, however the
// rotations were ordered.
func TestDPoP_ConcurrentRefreshesOfABoundTokenLeaveNoUnboundToken(t *testing.T) {
	const each = 3
	key, other := dpoptest.RFC7517Key(t), dpoptest.RFC7515Key(t)
	code, first := boundCodeGrant(t, true, fake.LetterN(32), &key)
	clientId := code.Client.ClientIdentifier
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {first}, "client_id": {clientId}}

	type request struct {
		key   *dpoptest.Key
		proof string
	}
	var requests []request
	for i := 0; i < each; i++ {
		for _, k := range []*dpoptest.Key{&key, &other, nil} {
			r := request{key: k}
			if k != nil {
				r.proof = k.Proof(t, "POST", dpopTokenURL(), time.Now(), nonceForRefresh(t, form, clientId, "", *k))
			}
			requests = append(requests, r)
		}
	}

	type answer struct {
		key    *dpoptest.Key
		status int
		body   map[string]any
		err    error
	}
	answers := make([]answer, len(requests))
	httpClient := createHttpClient(t)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, r := range requests {
		wg.Add(1)
		go func(i int, r request) {
			defer wg.Done()
			<-start
			status, body, err := postConcurrently(httpClient, form, r.proof)
			answers[i] = answer{key: r.key, status: status, body: body, err: err}
		}(i, r)
	}
	close(start)
	wg.Wait()

	succeeded := 0
	for _, a := range answers {
		require.NoError(t, a.err)
		if a.key != &key {
			assert.Equal(t, http.StatusBadRequest, a.status, "%v", a.body)
			assert.Equal(t, boundRefreshTokenRefusal, a.body, "a refresh without the family's key is refused for the binding")
			continue
		}
		if a.status == http.StatusOK {
			succeeded++
			assertBoundTo(t, a.body, key)
			continue
		}
		assert.Equal(t, "invalid_grant", a.body["error"], "a refresh by the key that lost the race is refused: %v", a.body)
	}
	assert.Equal(t, 1, succeeded, "exactly one refresh is answered with tokens")

	tokens, err := database.GetRefreshTokensByCodeId(context.Background(), nil, code.Id)
	require.NoError(t, err)
	require.Len(t, tokens, 2, "the family's first token and the one child its one rotation inserted")
	for _, token := range tokens {
		assert.Equalf(t, key.Thumbprint, token.DPoPJkt.String, "every token of the family is bound to its key, %s", token.RefreshTokenJti)
	}
}

// postConcurrently posts form to the token endpoint with proof in a DPoP header, when there is one,
// for a goroutine of its own: it reports a failure rather than asserting, which only the test's own
// goroutine may.
func postConcurrently(httpClient *http.Client, form url.Values, proof string) (int, map[string]any, error) {
	req, err := http.NewRequest(http.MethodPost, dpopTokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, body, nil
}
