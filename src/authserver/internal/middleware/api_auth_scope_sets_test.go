package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RequireBearerTokenScopeSetAnyOf admits a token holding every scope of at least one of the sets.
// The user export is its route: it reads the user and the user's audit events, so its token must
// reach both the users and the settings domain, which admin-read and manage each do alone and
// manage-users does only beside manage-settings (#781 decision 1).
var userExportScopeSets = [][]string{
	{"authserver:admin-read"},
	{"authserver:manage"},
	{"authserver:manage-users", "authserver:manage-settings"},
}

func TestRequireBearerTokenScopeSetAnyOf_TheUserExportsSets(t *testing.T) {
	for _, c := range []struct {
		scope    string
		admitted bool
	}{
		{"authserver:admin-read", true},
		{"authserver:manage", true},
		{"authserver:manage-users authserver:manage-settings", true},
		{"openid authserver:manage-settings profile authserver:manage-users", true},
		{"authserver:manage-users", false},
		{"authserver:manage-settings", false},
		{"authserver:manage-users authserver:manage-clients", false},
		{"authserver:manage-clients", false},
		{"authserver:manage-account", false},
		{"openid profile", false},
		{"", false},
	} {
		t.Run(c.scope, func(t *testing.T) {
			token := oauth.JwtToken{Claims: map[string]interface{}{"scope": c.scope}}
			req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users/42/export", nil)
			req = req.WithContext(reqctx.WithBearerToken(req.Context(), token))
			rr := httptest.NewRecorder()
			var validated bool

			apiBearerForTest.RequireBearerTokenScopeSetAnyOf(userExportScopeSets)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, validated = reqctx.ValidatedTokenFrom(r.Context())
				w.WriteHeader(http.StatusOK)
			})).ServeHTTP(rr, req)

			if c.admitted {
				assert.Equal(t, http.StatusOK, rr.Code)
				assert.True(t, validated, "an admitted token reaches the handler as the validated token")
				return
			}
			assert.Equal(t, http.StatusForbidden, rr.Code)
			var body map[string]string
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
			assert.Equal(t, "INSUFFICIENT_SCOPE", body["error_code"],
				"refused as a token with none of a route's scopes is (decision 1)")
		})
	}
}

// A request that presented no token is the realm-only 401, as on every other scope guard.
func TestRequireBearerTokenScopeSetAnyOf_NoTokenIsTheBareChallenge(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users/42/export", nil)
	rr := httptest.NewRecorder()
	nextCalled := false

	apiBearerForTest.RequireBearerTokenScopeSetAnyOf(userExportScopeSets)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})).ServeHTTP(rr, req)

	assert.False(t, nextCalled)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Equal(t, BearerChallenge("", ""), rr.Header().Get("WWW-Authenticate"))
	var body map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, "ACCESS_TOKEN_REQUIRED", body["error_code"])
}

// An empty set would admit every token, so the guard refuses to be built with one.
func TestRequireBearerTokenScopeSetAnyOf_AnEmptySetIsAWiringFault(t *testing.T) {
	assert.Panics(t, func() { apiBearerForTest.RequireBearerTokenScopeSetAnyOf([][]string{{"authserver:manage"}, {}}) })
	assert.Panics(t, func() { apiBearerForTest.RequireBearerTokenScopeSetAnyOf(nil) })
}
