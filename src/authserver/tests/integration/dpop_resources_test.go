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
	"github.com/leodip/goiabada/core/builtin"
)

// DPoP at the auth server's own resources, through the running server (RFC 9449 section 7, #42
// decision 10): userinfo and the Account API take a bound token with the DPoP scheme and its proof,
// once; refuse a bound token sent as Bearer, a bearer token sent as DPoP and a proof for another
// token; and every 401 names both schemes, Bearer first, which script on a registered web origin
// reads.

// The DPoP challenge with no error, as every 401 carries it: decision 4's algorithms, in order.
const dpopChallengeBare = `DPoP realm="goiabada", algs="ES256 ES384 ES512 PS256 PS384 PS512 RS256 RS384 RS512 Ed25519 EdDSA"`

// dpopUser is a user of a confidential password grant client with manage-account granted, so its
// tokens reach userinfo and the Account API.
type dpopUser struct {
	client   *record.Client
	secret   string
	user     *record.User
	password string
}

func createDPoPUser(t *testing.T) dpopUser {
	t.Helper()
	changeSettings(t, func(settings *record.Settings) { settings.ResourceOwnerPasswordCredentialsEnabled = true })
	secret := fake.Password(32)
	password := fake.Password(12)
	u := dpopUser{client: createROPCClient(t, secret, false), secret: secret, password: password}
	u.user = createROPCUser(t, password)

	authserver, err := database.GetResourceByResourceIdentifier(context.Background(), nil, builtin.AuthServerResourceIdentifier)
	require.NoError(t, err)
	permissions, err := database.GetPermissionsByResourceId(context.Background(), nil, authserver.Id)
	require.NoError(t, err)
	for i := range permissions {
		if permissions[i].PermissionIdentifier == builtin.ManageAccountPermissionIdentifier {
			assignPermissionToUser(t, u.user.Id, permissions[i].Id)
		}
	}
	return u
}

func (u dpopUser) form() url.Values {
	return url.Values{
		"grant_type": {"password"},
		"username":   {u.user.Email},
		"password":   {u.password},
		"scope":      {"openid " + builtin.AuthServerResourceIdentifier + ":" + builtin.ManageAccountPermissionIdentifier},
	}
}

// boundToken is an access token of the user bound to key.
func (u dpopUser) boundToken(t *testing.T, key dpoptest.Key) string {
	t.Helper()
	return redeemWithDPoP(t, u.form(), u.client.ClientIdentifier, u.secret, key)["access_token"].(string)
}

// bearerToken is an access token of the user bound to no key.
func (u dpopUser) bearerToken(t *testing.T) string {
	t.Helper()
	resp, body := postWithProof(t, u.form(), u.client.ClientIdentifier, u.secret, "")
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", body)
	require.Equal(t, "Bearer", body["token_type"])
	return body["access_token"].(string)
}

// resourceAnswer is what a resource answered: the status, the challenges and the JSON body.
type resourceAnswer struct {
	status    int
	challenge []string
	header    http.Header
	body      map[string]any
}

// callResource sends method to the auth server's path with authorization and each proof given as a
// DPoP header, and headers beside them.
func callResource(t *testing.T, method, path, authorization string, proofs []string, headers map[string]string) resourceAnswer {
	t.Helper()
	req, err := http.NewRequest(method, appConfig.AuthServer.BaseURL+path, nil)
	require.NoError(t, err)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	for _, p := range proofs {
		req.Header.Add("DPoP", p)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	resp, err := createHttpClient(t).Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	answer := resourceAnswer{status: resp.StatusCode, challenge: resp.Header.Values("WWW-Authenticate"), header: resp.Header}
	if len(raw) > 0 {
		require.NoError(t, json.Unmarshal(raw, &answer.body), "status %d, body %s", resp.StatusCode, string(raw))
	}
	return answer
}

// The URL a proof for path names: the public base URL and the path.
func resourceURL(path string) string { return appConfig.AuthServer.BaseURL + path }

func TestDPoPResources_ABoundTokenWithItsProofIsAnswered(t *testing.T) {
	u := createDPoPUser(t)
	key := dpoptest.RFC7517Key(t)
	token := u.boundToken(t, key)

	userinfo := callResource(t, http.MethodGet, "/userinfo", "DPoP "+token,
		[]string{key.ResourceProof(t, "GET", resourceURL("/userinfo"), time.Now(), token)}, nil)
	require.Equal(t, http.StatusOK, userinfo.status, "%v", userinfo.body)
	assert.Equal(t, u.user.Subject, userinfo.body["sub"])
	assert.Equal(t, "no-store", userinfo.header.Get("Cache-Control"))

	profile := callResource(t, http.MethodGet, "/api/v1/account/profile", "DPoP "+token,
		[]string{key.ResourceProof(t, "GET", resourceURL("/api/v1/account/profile"), time.Now(), token)}, nil)
	require.Equal(t, http.StatusOK, profile.status, "%v", profile.body)
	assert.Equal(t, u.user.Email, profile.body["user"].(map[string]any)["email"])
}

// A proof is accepted once (RFC 9449 section 11.1): the same proof again is invalid_dpop_proof.
func TestDPoPResources_AReplayedProofIsRefused(t *testing.T) {
	u := createDPoPUser(t)
	key := dpoptest.RFC7517Key(t)
	token := u.boundToken(t, key)
	proof := key.ResourceProof(t, "GET", resourceURL("/userinfo"), time.Now(), token)

	first := callResource(t, http.MethodGet, "/userinfo", "DPoP "+token, []string{proof}, nil)
	require.Equal(t, http.StatusOK, first.status, "%v", first.body)

	replay := callResource(t, http.MethodGet, "/userinfo", "DPoP "+token, []string{proof}, nil)
	assert.Equal(t, http.StatusUnauthorized, replay.status)
	assert.Equal(t, []string{`Bearer realm="goiabada", ` + dpopChallengeBare +
		`, error="invalid_dpop_proof", error_description="The DPoP proof is invalid."`}, replay.challenge)
	assert.Equal(t, map[string]any{"error": "invalid_dpop_proof", "error_description": "The DPoP proof is invalid."}, replay.body)
}

// RFC 9449 section 7.2 MUST: a bound token sent as a bearer token is refused, at userinfo and at
// the Account API, with the error in the Bearer challenge.
func TestDPoPResources_ABoundTokenSentAsBearerIsRefused(t *testing.T) {
	u := createDPoPUser(t)
	token := u.boundToken(t, dpoptest.RFC7517Key(t))
	const description = "The access token is bound to a DPoP key and must be sent with the DPoP scheme."
	challenge := []string{`Bearer realm="goiabada", error="invalid_token", error_description="` + description + `", ` + dpopChallengeBare}

	userinfo := callResource(t, http.MethodGet, "/userinfo", "Bearer "+token, nil, nil)
	assert.Equal(t, http.StatusUnauthorized, userinfo.status)
	assert.Equal(t, challenge, userinfo.challenge)
	assert.Equal(t, map[string]any{"error": "invalid_token", "error_description": description}, userinfo.body)

	profile := callResource(t, http.MethodGet, "/api/v1/account/profile", "Bearer "+token, nil, nil)
	assert.Equal(t, http.StatusUnauthorized, profile.status)
	assert.Equal(t, challenge, profile.challenge)
	assert.Equal(t, map[string]any{"error_code": "INVALID_TOKEN", "error_description": description}, profile.body)
}

// A bearer token sent with the DPoP scheme is refused, with the error in the DPoP challenge, and
// the same token as Bearer, a stray proof beside it, is still answered.
func TestDPoPResources_ABearerTokenSentAsDPoPIsRefused(t *testing.T) {
	u := createDPoPUser(t)
	key := dpoptest.RFC7517Key(t)
	token := u.bearerToken(t)
	const description = "The access token is not bound to a DPoP key and must be sent with the Bearer scheme."

	refused := callResource(t, http.MethodGet, "/userinfo", "DPoP "+token,
		[]string{key.ResourceProof(t, "GET", resourceURL("/userinfo"), time.Now(), token)}, nil)
	assert.Equal(t, http.StatusUnauthorized, refused.status)
	assert.Equal(t, []string{`Bearer realm="goiabada", ` + dpopChallengeBare + `, error="invalid_token", error_description="` + description + `"`},
		refused.challenge)
	assert.Equal(t, map[string]any{"error": "invalid_token", "error_description": description}, refused.body)

	answered := callResource(t, http.MethodGet, "/userinfo", "Bearer "+token,
		[]string{key.ResourceProof(t, "GET", resourceURL("/userinfo"), time.Now(), token)}, nil)
	assert.Equal(t, http.StatusOK, answered.status, "%v", answered.body)
}

// A proof whose ath is another token's, or by another key than the token's, is refused, and the
// Account API answers INVALID_DPOP_PROOF in its envelope.
func TestDPoPResources_AProofForAnotherTokenOrByAnotherKeyIsRefused(t *testing.T) {
	u := createDPoPUser(t)
	key := dpoptest.RFC7517Key(t)
	token := u.boundToken(t, key)

	wrongATH := callResource(t, http.MethodGet, "/api/v1/account/profile", "DPoP "+token,
		[]string{key.ResourceProof(t, "GET", resourceURL("/api/v1/account/profile"), time.Now(), token+"x")}, nil)
	assert.Equal(t, http.StatusUnauthorized, wrongATH.status)
	assert.Equal(t, []string{`Bearer realm="goiabada", ` + dpopChallengeBare +
		`, error="invalid_dpop_proof", error_description="The DPoP proof is invalid."`}, wrongATH.challenge)
	assert.Equal(t, map[string]any{"error_code": "INVALID_DPOP_PROOF", "error_description": "The DPoP proof is invalid."}, wrongATH.body)

	const keyBinding = "The DPoP proof is not signed with the key the access token is bound to."
	otherKey := callResource(t, http.MethodGet, "/userinfo", "DPoP "+token,
		[]string{dpoptest.RFC7515Key(t).ResourceProof(t, "GET", resourceURL("/userinfo"), time.Now(), token)}, nil)
	assert.Equal(t, http.StatusUnauthorized, otherKey.status)
	assert.Equal(t, []string{`Bearer realm="goiabada", ` + dpopChallengeBare + `, error="invalid_token", error_description="` + keyBinding + `"`},
		otherKey.challenge)
	assert.Equal(t, map[string]any{"error": "invalid_token", "error_description": keyBinding}, otherKey.body)

	stale := callResource(t, http.MethodGet, "/userinfo", "DPoP "+token,
		[]string{key.ResourceProof(t, "GET", resourceURL("/userinfo"), time.Now().Add(-2*time.Minute), token)}, nil)
	assert.Equal(t, http.StatusUnauthorized, stale.status)
	assert.Equal(t, "invalid_dpop_proof", stale.body["error"], "a proof two minutes old")
}

// Script on a registered web origin reads both of userinfo's challenges: the answer names the
// origin and exposes WWW-Authenticate, whose one field line holds Bearer, then DPoP (#42 decision
// 10). The admin and account APIs give no cross-origin access, as before.
func TestDPoPResources_ARegisteredOriginReadsBothOfUserinfosChallenges(t *testing.T) {
	u := createDPoPUser(t)
	origin := registerWebOrigin(t, u.client)
	crossSite := map[string]string{"Origin": origin, "Sec-Fetch-Site": "cross-site"}

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		answer := callResource(t, method, "/userinfo", "", nil, crossSite)
		assert.Equal(t, http.StatusUnauthorized, answer.status, method)
		assert.Equal(t, []string{`Bearer realm="goiabada", ` + dpopChallengeBare}, answer.challenge, method)
		assert.Equal(t, []string{origin}, answer.header.Values("Access-Control-Allow-Origin"), method)
		exposed := strings.Split(answer.header.Get("Access-Control-Expose-Headers"), ",")
		for i := range exposed {
			exposed[i] = strings.TrimSpace(exposed[i])
		}
		assert.Contains(t, exposed, "WWW-Authenticate", "%s: script may read the challenges", method)
	}

	api := callResource(t, http.MethodGet, "/api/v1/account/profile", "", nil, crossSite)
	assert.Equal(t, http.StatusUnauthorized, api.status)
	assert.Equal(t, []string{`Bearer realm="goiabada", ` + dpopChallengeBare}, api.challenge)
	assert.Empty(t, api.header.Values("Access-Control-Allow-Origin"), "the Account API gives no cross-origin access")
}
