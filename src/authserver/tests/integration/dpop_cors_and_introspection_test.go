package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/dpop/dpoptest"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
)

// DPoP across origins and at introspection, through the running server (RFC 9449 sections 6.2 and
// 8, #42 decisions 2 and 15). Script on a registered web origin can read the DPoP-Nonce of a
// use_dpop_nonce refusal and of the token response after it; an unregistered origin is given no
// CORS permission, while the server answers its request as it answers any. An API introspecting a
// bound access token is told token_type DPoP and the token's cnf.

// dpopService is a confidential client of the client credentials grant, with one permission on a
// resource of its own, so its token's aud is that resource alone.
type dpopService struct {
	client   *record.Client
	secret   string
	resource *record.Resource
}

func createDPoPService(t *testing.T) dpopService {
	t.Helper()
	secret := fake.Password(32)
	encrypted, err := dataCipher.Encrypt(secret)
	require.NoError(t, err)
	resource := createResourceWithId(t, "dpop-api-"+fake.LetterN(8))
	permission := createPermissionWithId(t, resource.Id, "read-"+fake.LetterN(8))
	client := &record.Client{
		ClientIdentifier:         "dpop-service-" + fake.LetterN(8),
		Enabled:                  true,
		ClientCredentialsEnabled: true,
		DefaultAcrLevel:          record.AcrLevel2Optional,
		ClientSecretEncrypted:    encrypted,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	require.NoError(t, database.CreateClientPermission(context.Background(), nil,
		&record.ClientPermission{ClientId: client.Id, PermissionId: permission.Id}))
	return dpopService{client: client, secret: secret, resource: resource}
}

// crossOriginTokenRequest posts a client credentials request of service to the token endpoint from
// origin, as script there does, with proof in a DPoP header.
func crossOriginTokenRequest(t *testing.T, service dpopService, origin, proof string) (*http.Response, map[string]any) {
	t.Helper()
	form := url.Values{"grant_type": {"client_credentials"}}
	req, err := http.NewRequest(http.MethodPost, dpopTokenURL(), strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(service.client.ClientIdentifier), url.QueryEscape(service.secret))
	req.Header.Set("Origin", origin)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("DPoP", proof)
	resp, err := createHttpClient(t).Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var body map[string]any
	require.NoError(t, json.Unmarshal(raw, &body), "status %d, body %s", resp.StatusCode, string(raw))
	return resp, body
}

// registerWebOrigin registers a fresh web origin on the client and returns it.
func registerWebOrigin(t *testing.T, client *record.Client) string {
	t.Helper()
	origin := "https://dpop-cors-" + strings.ToLower(fake.LetterN(8)) + ".example.com"
	require.NoError(t, database.CreateWebOrigin(context.Background(), nil, &record.WebOrigin{
		ClientId: client.Id, Origin: origin,
	}))
	return origin
}

// assertNonceReadableBy asserts the answer lets script on origin read its one DPoP-Nonce: it names
// the origin, and DPoP-Nonce is among the exposed headers (Fetch Standard section 3.2.4, RFC 9449
// section 8). It allows no credentials.
func assertNonceReadableBy(t *testing.T, resp *http.Response, origin string) {
	t.Helper()
	assert.Equal(t, []string{origin}, resp.Header.Values("Access-Control-Allow-Origin"))
	exposed := strings.Split(resp.Header.Get("Access-Control-Expose-Headers"), ",")
	for i := range exposed {
		exposed[i] = strings.TrimSpace(exposed[i])
	}
	assert.Contains(t, exposed, "DPoP-Nonce", "script may read the nonce")
	assert.Empty(t, resp.Header.Values("Access-Control-Allow-Credentials"))
	assert.Len(t, resp.Header.Values("DPoP-Nonce"), 1)
}

// Script on a registered web origin reads the nonce of the use_dpop_nonce refusal, retries with it,
// and reads the fresh nonce of the bound token response.
func TestDPoPCORS_ARegisteredOriginReadsTheNonce(t *testing.T) {
	service := createDPoPService(t)
	origin := registerWebOrigin(t, service.client)
	key := dpoptest.RFC7517Key(t)

	resp, body := crossOriginTokenRequest(t, service, origin, key.Proof(t, "POST", dpopTokenURL(), time.Now(), ""))
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "%v", body)
	assert.Equal(t, "use_dpop_nonce", body["error"])
	assertNonceReadableBy(t, resp, origin)
	nonce := resp.Header.Get("DPoP-Nonce")

	resp, body = crossOriginTokenRequest(t, service, origin, key.Proof(t, "POST", dpopTokenURL(), time.Now(), nonce))
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", body)
	assertBoundTo(t, body, key)
	assertNonceReadableBy(t, resp, origin)
}

// An origin no client registered is given no CORS permission at the token endpoint: its preflight
// asking for the DPoP header grants nothing, and its actual request carries no
// Access-Control-Allow-Origin and exposes nothing, so the browser withholds the answer and its
// nonce from script. The server still answers the request itself as it answers any, use_dpop_nonce
// with a nonce: CORS decides what script reads, not what the server answers.
func TestDPoPCORS_AnUnregisteredOriginIsGivenNoPermission(t *testing.T) {
	service := createDPoPService(t)
	registerWebOrigin(t, service.client)
	unregistered := "https://dpop-cors-" + strings.ToLower(fake.LetterN(8)) + ".example.com"
	key := dpoptest.RFC7517Key(t)
	corsFields := []string{
		"Access-Control-Allow-Origin", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers",
		"Access-Control-Max-Age", "Access-Control-Allow-Credentials", "Access-Control-Expose-Headers",
	}

	t.Run("the preflight", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodOptions, dpopTokenURL(), nil)
		require.NoError(t, err)
		req.Header.Set("Origin", unregistered)
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "content-type,dpop")
		resp, err := createHttpClient(t).Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		for _, field := range corsFields {
			assert.Empty(t, resp.Header.Values(field), field)
		}
	})

	t.Run("the actual request", func(t *testing.T) {
		resp, body := crossOriginTokenRequest(t, service, unregistered, key.Proof(t, "POST", dpopTokenURL(), time.Now(), ""))

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, "use_dpop_nonce", body["error"])
		assert.Len(t, resp.Header.Values("DPoP-Nonce"), 1, "the server answers as it answers any request")
		for _, field := range corsFields {
			assert.Empty(t, resp.Header.Values(field), field)
		}
	})
}

// An API introspecting a bound access token is answered token_type DPoP and the token's cnf, the
// proof key's thumbprint as jkt (RFC 9449 section 6.2), beside RFC 7662's members; the same
// client's Bearer token is answered token_type Bearer with no cnf.
func TestDPoPIntrospection_ABoundTokenIsAnsweredDPoPWithItsConfirmation(t *testing.T) {
	service := createDPoPService(t)
	api := createIntrospectingAPI(t, service.resource.ResourceIdentifier)
	key := dpoptest.RFC7517Key(t)

	bound := redeemWithDPoP(t, url.Values{"grant_type": {"client_credentials"}},
		service.client.ClientIdentifier, service.secret, key)["access_token"].(string)
	claims := decodeJWTPayload(t, bound)

	assert.Equal(t, map[string]any{
		"active":     true,
		"scope":      claims["scope"],
		"client_id":  service.client.ClientIdentifier,
		"sub":        service.client.ClientIdentifier,
		"aud":        service.resource.ResourceIdentifier,
		"iss":        claims["iss"],
		"exp":        claims["exp"],
		"iat":        claims["iat"],
		"nbf":        claims["nbf"],
		"jti":        claims["jti"],
		"token_type": "DPoP",
		"cnf":        map[string]any{"jkt": "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s"},
	}, api.introspect(t, bound))

	resp, body := postWithProof(t, url.Values{"grant_type": {"client_credentials"}},
		service.client.ClientIdentifier, service.secret, "")
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", body)
	members := api.introspect(t, body["access_token"].(string))
	assert.Equal(t, true, members["active"])
	assert.Equal(t, "Bearer", members["token_type"])
	assert.NotContains(t, members, "cnf")
}
