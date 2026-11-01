package integration

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/fake"
)

// The client authentication limit at the revocation and introspection endpoints, and its one
// budget across the three endpoints that authenticate a client with its secret (#707 decisions 2
// and 3): a guesser alternating between them gets 200 failures an hour, not 600. The budget,
// the 429 and the clients' isolation are written out as at the token endpoint.

// limitedClientAuthEndpoint is one of the three endpoints, with a request that reaches the client's secret
// check.
type limitedClientAuthEndpoint struct {
	name string
	path string
	form url.Values
}

func limitedClientAuthEndpoints() []limitedClientAuthEndpoint {
	return []limitedClientAuthEndpoint{
		{"token", "/auth/token/", clientCredentialsForm},
		{"revocation", "/auth/revoke", url.Values{"token": {"not-a-token"}}},
		{"introspection", "/auth/introspect", url.Values{"token": {"not-a-token"}}},
	}
}

func (e limitedClientAuthEndpoint) post(t *testing.T, basic bool, clientId, secret string) clientAuthAnswer {
	t.Helper()
	return postClientAuthenticationTo(t, e.path, e.form, basic, clientId, secret)
}

// assertAuthenticatedAt asserts the endpoint's answer to a client that authenticated, for a request
// that asks for nothing it may have: at the token endpoint the client credentials grant's
// invalid_scope for a client holding no permissions, which it answers only once the client
// authenticated; at revocation the 200 of an invalid token; at introspection {"active": false}.
func assertAuthenticatedAt(t *testing.T, endpoint limitedClientAuthEndpoint, answer clientAuthAnswer) {
	t.Helper()
	switch endpoint.name {
	case "token":
		require.Equal(t, http.StatusBadRequest, answer.status, "%s: %v", endpoint.name, answer)
		assert.Equal(t, "invalid_scope", answer.body["error"])
	case "revocation":
		require.Equal(t, http.StatusOK, answer.status, "%s: %v", endpoint.name, answer)
		assert.Nil(t, answer.body)
	case "introspection":
		require.Equal(t, http.StatusOK, answer.status, "%s: %v", endpoint.name, answer)
		assert.Equal(t, map[string]interface{}{"active": false}, answer.body)
	}
}

// TestClientAuthenticationLimit_OneBudgetAcrossTheThreeEndpoints spends one client's 200 failures
// spread across the three endpoints, under 70 at each, then finds the client refused 429 at every
// one of them, its right secret included, while another client still authenticates at each.
func TestClientAuthenticationLimit_OneBudgetAcrossTheThreeEndpoints(t *testing.T) {
	secret := fake.Password(32)
	client := newLimitedClient(t, secret)
	other := newLimitedClient(t, secret)
	endpoints := limitedClientAuthEndpoints()

	for i := 0; i < 200; i++ {
		wrong := "wrong-" + fake.LetterN(8)
		if i%10 == 0 {
			wrong = ""
		}
		endpoint := endpoints[i%3]
		answer := endpoint.post(t, i%2 == 0, client.ClientIdentifier, wrong)
		require.Equal(t, http.StatusUnauthorized, answer.status, "failure %d, at %s, is within the budget: %v",
			i+1, endpoint.name, answer)
		require.Equal(t, "invalid_client", answer.body["error"])
	}
	if counted, ok := clientAuthCounted(t, client.ClientIdentifier); ok {
		assert.Equal(t, 200, counted, "the three endpoints count in the one row")
	}

	for _, endpoint := range endpoints {
		for _, basic := range []bool{false, true} {
			assertOverTheLimit(t, endpoint.post(t, basic, client.ClientIdentifier, secret),
				"the right secret at %s, basic %v", endpoint.name, basic)
			assertOverTheLimit(t, endpoint.post(t, basic, client.ClientIdentifier, "wrong"),
				"a wrong secret at %s, basic %v", endpoint.name, basic)
		}
	}

	// Another client's budget is its own.
	for _, endpoint := range endpoints {
		assertInvalidClient(t, endpoint.post(t, false, other.ClientIdentifier, "wrong"), endpoint.name)
		assertAuthenticatedAt(t, endpoint, endpoint.post(t, true, other.ClientIdentifier, secret))
	}
}

// TestClientAuthenticationLimit_ARightSecretAtRevocationOrIntrospectionSpendsNothing: 199 failures
// at revocation and introspection, then right secrets at both, then the 200th failure is still
// answered invalid_client and only the next request is refused, wherever it arrives.
func TestClientAuthenticationLimit_ARightSecretAtRevocationOrIntrospectionSpendsNothing(t *testing.T) {
	secret := fake.Password(32)
	client := newLimitedClient(t, secret)
	endpoints := limitedClientAuthEndpoints()
	revocation, introspection := endpoints[1], endpoints[2]

	for i := 0; i < 199; i++ {
		endpoint := endpoints[1+i%2]
		require.Equal(t, http.StatusUnauthorized, endpoint.post(t, i%3 == 0, client.ClientIdentifier, "wrong").status,
			"failure %d at %s", i+1, endpoint.name)
	}
	for i := 0; i < 5; i++ {
		assertAuthenticatedAt(t, revocation, revocation.post(t, i%2 == 0, client.ClientIdentifier, secret))
		assertAuthenticatedAt(t, introspection, introspection.post(t, i%2 == 1, client.ClientIdentifier, secret))
	}
	if counted, ok := clientAuthCounted(t, client.ClientIdentifier); ok {
		assert.Equal(t, 199, counted, "a right secret's reservation is refunded")
	}
	assertInvalidClient(t, introspection.post(t, true, client.ClientIdentifier, "wrong"),
		"the 200th failure is within the budget")
	assertOverTheLimit(t, revocation.post(t, false, client.ClientIdentifier, secret))
	assertOverTheLimit(t, endpoints[0].post(t, true, client.ClientIdentifier, secret))
}

// TestClientAuthenticationLimit_APublicClientSpendsNothingAtRevocationOrIntrospection: a public
// client compares no secret, so 201 revocations by its identifier alone, and 201 introspections it
// is refused, with a secret or without, leave a whole budget for the confidential client it later
// becomes (decision 3).
func TestClientAuthenticationLimit_APublicClientSpendsNothingAtRevocationOrIntrospection(t *testing.T) {
	ctx := context.Background()
	secret := fake.Password(32)
	public := newLimitedClient(t, secret)
	public.IsPublic = true
	public.ClientCredentialsEnabled = false
	require.NoError(t, database.UpdateClient(ctx, nil, public))
	endpoints := limitedClientAuthEndpoints()
	revocation, introspection := endpoints[1], endpoints[2]

	for i := 0; i < 201; i++ {
		assertAuthenticatedAt(t, revocation, revocation.post(t, false, public.ClientIdentifier, ""))
		assertInvalidClient(t, introspection.post(t, false, public.ClientIdentifier, "wrong"), "introspection %d", i+1)
		assertInvalidClient(t, introspection.post(t, false, public.ClientIdentifier, ""), "introspection %d", i+1)
	}

	public.IsPublic = false
	public.ClientCredentialsEnabled = true
	require.NoError(t, database.UpdateClient(ctx, nil, public))
	if counted, ok := clientAuthCounted(t, public.ClientIdentifier); ok {
		assert.Zero(t, counted)
	}
	assertInvalidClient(t, revocation.post(t, false, public.ClientIdentifier, "wrong"), "its first failure")
	assertAuthenticatedAt(t, introspection, introspection.post(t, true, public.ClientIdentifier, secret))
}
