package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RequireAdminConsoleClient is the route guard that answers only tokens issued to the admin
// console's own client (#783 decision 3): account deletion mounts it so that an application holding
// authserver:manage-account cannot delete the account, and #782's data download mounts the same
// one. Its refusal is 403 CLIENT_NOT_ALLOWED with RFC 6750 section 3.1's insufficient_scope
// challenge, "the request requires higher privileges than provided by the access token", in
// English like every bearer refusal (TestBearerRefusals_EnglishOnly holds the sentence).

const (
	clientNotAllowedDescription = "This endpoint accepts only access tokens issued to the admin console's own client."
	challengeClientNotAllowed   = `Bearer realm="goiabada", error="insufficient_scope", error_description="` +
		clientNotAllowedDescription + `"`
)

var apiClientNotAllowed = chainAnswer{http.StatusForbidden, challengeClientNotAllowed,
	`{"error_code":"CLIENT_NOT_ALLOWED","error_description":"` + clientNotAllowedDescription + `"}`}

// accountTokenOf is a user's Account API token issued to clientId, or to no client when clientId
// is empty.
func accountTokenOf(clientId string) oauth.JwtToken {
	claims := map[string]interface{}{
		"sub": "u1", "auth_time": float64(1), "scope": "openid authserver:manage-account",
	}
	if clientId != "" {
		claims["client_id"] = clientId
	}
	return oauth.JwtToken{Claims: claims}
}

func serveAdminConsoleClientGuard(t *testing.T, token *oauth.JwtToken) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/account/deletion", nil)
	if token != nil {
		req = req.WithContext(reqctx.WithBearerToken(req.Context(), *token))
	}
	rr := httptest.NewRecorder()
	NewBearerTokenForAPI(nil).RequireAdminConsoleClient()(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("admitted")) })).ServeHTTP(rr, req)
	return rr
}

func TestRequireAdminConsoleClient_AdmitsTheConsolesToken(t *testing.T) {
	token := accountTokenOf(builtin.AdminConsoleClientIdentifier)
	assertChainAnswer(t, answerAdmitted, serveAdminConsoleClientGuard(t, &token))
}

func TestRequireAdminConsoleClient_RefusesAnyOtherClientsToken(t *testing.T) {
	for _, tc := range []struct{ name, clientId string }{
		{"another client holding authserver:manage-account", "my-app"},
		// Matched exactly, as the token endpoint matches client_id (#640): a client whose
		// identifier differs from the console's only in case is another client.
		{"a client named like the console in other letters", "Admin-Console-Client"},
		{"a client whose identifier starts with the console's", builtin.AdminConsoleClientIdentifier + "-2"},
		{"a token naming no client", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := logtest.CaptureSlog(t)
			token := accountTokenOf(tc.clientId)

			rr := serveAdminConsoleClientGuard(t, &token)

			assertChainAnswer(t, apiClientNotAllowed, rr)
			records := logs.Records()
			require.Len(t, records, 1, "one Warn record per refusal")
			assert.Equal(t, "rejecting bearer token: issued to a client other than the admin console's", records[0].Message)
		})
	}
}

// No token in the context is a request that presented no bearer credential, answered as the scope
// and user-bound guards answer it, so the guard adds no response shape of its own for that case.
func TestRequireAdminConsoleClient_NoTokenIsTheMissingCredential(t *testing.T) {
	assertChainAnswer(t, apiMissing, serveAdminConsoleClientGuard(t, nil))
}

// The guard in the chain the Account API mounts it in, after the scope and user-bound guards: a
// client credentials token is still USER_CONTEXT_REQUIRED, and a user's token from another client
// reaches this guard and is refused here.
func TestRequireAdminConsoleClient_InTheAccountAPIsChain(t *testing.T) {
	guards := NewBearerTokenForAPI(chainParser{})
	chain := guards.JwtAuthorizationHeaderToContext()(
		guards.RequireBearerTokenScope("openid")(guards.RequireUserBoundToken()(guards.RequireAdminConsoleClient()(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("admitted")) })))))

	for _, tc := range []struct {
		name  string
		token string
		want  chainAnswer
	}{
		{"a client credentials token", "client", apiUserContext},
		{"a user's token from another client", "good", apiClientNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/account/deletion", nil)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			rr := httptest.NewRecorder()
			chain.ServeHTTP(rr, req)
			assertChainAnswer(t, tc.want, rr)
		})
	}
}
