package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
)

func TestRequireBearerTokenScope(t *testing.T) {
	t.Run("passes when token has required scope", func(t *testing.T) {
		handler := RequireBearerTokenScope("authserver:manage")

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"scope": "authserver:manage authserver:userinfo",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, token)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		handler(next).ServeHTTP(rr, req)

		assert.True(t, nextCalled, "next handler should be called")
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("passes when token has only the required scope", func(t *testing.T) {
		handler := RequireBearerTokenScope("authserver:manage")

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"scope": "authserver:manage",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, token)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		handler(next).ServeHTTP(rr, req)

		assert.True(t, nextCalled, "next handler should be called")
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("returns 403 when token lacks required scope", func(t *testing.T) {
		handler := RequireBearerTokenScope("authserver:manage")

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"scope": "authserver:userinfo",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, token)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		handler(next).ServeHTTP(rr, req)

		assert.False(t, nextCalled, "next handler should not be called")
		assert.Equal(t, http.StatusForbidden, rr.Code)
	})

	t.Run("returns 403 when scope claim is empty string", func(t *testing.T) {
		handler := RequireBearerTokenScope("authserver:manage")

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"scope": "",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, token)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		handler(next).ServeHTTP(rr, req)

		assert.False(t, nextCalled, "next handler should not be called")
		assert.Equal(t, http.StatusForbidden, rr.Code)
	})

	t.Run("returns 403 when scope claim is missing", func(t *testing.T) {
		handler := RequireBearerTokenScope("authserver:manage")

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"sub": "user123",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, token)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		handler(next).ServeHTTP(rr, req)

		assert.False(t, nextCalled, "next handler should not be called")
		assert.Equal(t, http.StatusForbidden, rr.Code)
	})

	t.Run("returns 401 when token is missing", func(t *testing.T) {
		handler := RequireBearerTokenScope("authserver:manage")

		req := httptest.NewRequest(http.MethodGet, "/test", nil)

		rr := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		handler(next).ServeHTTP(rr, req)

		assert.False(t, nextCalled, "next handler should not be called")
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("returns 401 when token is invalid type", func(t *testing.T) {
		handler := RequireBearerTokenScope("authserver:manage")

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, "invalid-string-token")
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		handler(next).ServeHTTP(rr, req)

		assert.False(t, nextCalled, "next handler should not be called")
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("does not match partial scope names", func(t *testing.T) {
		handler := RequireBearerTokenScope("authserver:manage")

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"scope": "authserver:manage-users authserver:manage-clients",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, token)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		handler(next).ServeHTTP(rr, req)

		assert.False(t, nextCalled, "next handler should not be called - partial match should fail")
		assert.Equal(t, http.StatusForbidden, rr.Code)
	})

	t.Run("adds validated token to context", func(t *testing.T) {
		handler := RequireBearerTokenScope("authserver:manage")

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"scope": "authserver:manage",
				"sub":   "user123",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, token)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		var validatedToken *oauth.JwtToken
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			validatedToken, _ = GetValidatedToken(r)
		})

		handler(next).ServeHTTP(rr, req)

		assert.NotNil(t, validatedToken)
		assert.Equal(t, "user123", validatedToken.Claims["sub"])
	})
}

func TestRequireBearerTokenScopeAnyOf(t *testing.T) {
	t.Run("passes when token has first scope", func(t *testing.T) {
		handler := RequireBearerTokenScopeAnyOf([]string{"authserver:admin-read", "authserver:manage"})

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"scope": "authserver:admin-read",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, token)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		handler(next).ServeHTTP(rr, req)

		assert.True(t, nextCalled, "next handler should be called")
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("passes when token has second scope", func(t *testing.T) {
		handler := RequireBearerTokenScopeAnyOf([]string{"authserver:admin-read", "authserver:manage"})

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"scope": "authserver:manage",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, token)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		handler(next).ServeHTTP(rr, req)

		assert.True(t, nextCalled, "next handler should be called")
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("passes when token has any of three scopes", func(t *testing.T) {
		handler := RequireBearerTokenScopeAnyOf([]string{
			"authserver:admin-read",
			"authserver:manage-users",
			"authserver:manage",
		})

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"scope": "authserver:manage-users openid profile",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, token)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		handler(next).ServeHTTP(rr, req)

		assert.True(t, nextCalled, "next handler should be called")
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("returns 403 when token has none of the required scopes", func(t *testing.T) {
		handler := RequireBearerTokenScopeAnyOf([]string{"authserver:admin-read", "authserver:manage"})

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"scope": "authserver:userinfo openid",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, token)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		handler(next).ServeHTTP(rr, req)

		assert.False(t, nextCalled, "next handler should not be called")
		assert.Equal(t, http.StatusForbidden, rr.Code)
	})

	t.Run("returns 401 when token is missing", func(t *testing.T) {
		handler := RequireBearerTokenScopeAnyOf([]string{"authserver:admin-read", "authserver:manage"})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)

		rr := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		handler(next).ServeHTTP(rr, req)

		assert.False(t, nextCalled, "next handler should not be called")
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("returns 401 when token is invalid type", func(t *testing.T) {
		handler := RequireBearerTokenScopeAnyOf([]string{"authserver:admin-read", "authserver:manage"})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, "invalid-token")
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		handler(next).ServeHTTP(rr, req)

		assert.False(t, nextCalled, "next handler should not be called")
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("adds validated token to context", func(t *testing.T) {
		handler := RequireBearerTokenScopeAnyOf([]string{"authserver:manage"})

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"scope": "authserver:manage",
				"sub":   "user123",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, token)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		var validatedToken *oauth.JwtToken
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			validatedToken, _ = GetValidatedToken(r)
		})

		handler(next).ServeHTTP(rr, req)

		assert.NotNil(t, validatedToken)
		assert.Equal(t, "user123", validatedToken.Claims["sub"])
	})
}

func TestRequireBearerTokenScopeAnyOf_EdgeCases(t *testing.T) {
	t.Run("returns 403 when empty scope list is provided", func(t *testing.T) {
		handler := RequireBearerTokenScopeAnyOf([]string{})

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"scope": "authserver:manage",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, token)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		handler(next).ServeHTTP(rr, req)

		assert.False(t, nextCalled, "next handler should not be called with empty required scopes")
		assert.Equal(t, http.StatusForbidden, rr.Code)
	})

	t.Run("returns 403 when scope claim is empty string", func(t *testing.T) {
		handler := RequireBearerTokenScopeAnyOf([]string{"authserver:manage"})

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"scope": "",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, token)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		handler(next).ServeHTTP(rr, req)

		assert.False(t, nextCalled, "next handler should not be called")
		assert.Equal(t, http.StatusForbidden, rr.Code)
	})

	t.Run("returns 403 when scope claim is missing", func(t *testing.T) {
		handler := RequireBearerTokenScopeAnyOf([]string{"authserver:manage"})

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"sub": "user123",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, token)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		handler(next).ServeHTTP(rr, req)

		assert.False(t, nextCalled, "next handler should not be called")
		assert.Equal(t, http.StatusForbidden, rr.Code)
	})

	t.Run("does not match partial scope names", func(t *testing.T) {
		handler := RequireBearerTokenScopeAnyOf([]string{"authserver:manage"})

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"scope": "authserver:manage-users authserver:manage-clients",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, token)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		handler(next).ServeHTTP(rr, req)

		assert.False(t, nextCalled, "next handler should not be called - partial match should fail")
		assert.Equal(t, http.StatusForbidden, rr.Code)
	})

	t.Run("passes with single scope in list", func(t *testing.T) {
		handler := RequireBearerTokenScopeAnyOf([]string{"authserver:manage"})

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"scope": "authserver:manage",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, token)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		handler(next).ServeHTTP(rr, req)

		assert.True(t, nextCalled, "next handler should be called")
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("passes when token has last scope in list", func(t *testing.T) {
		handler := RequireBearerTokenScopeAnyOf([]string{
			"authserver:admin-read",
			"authserver:manage-users",
			"authserver:manage-clients",
			"authserver:manage",
		})

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"scope": "authserver:manage",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, token)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		handler(next).ServeHTTP(rr, req)

		assert.True(t, nextCalled, "next handler should be called")
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("passes when token has multiple matching scopes", func(t *testing.T) {
		handler := RequireBearerTokenScopeAnyOf([]string{
			"authserver:admin-read",
			"authserver:manage",
		})

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"scope": "authserver:admin-read authserver:manage openid",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, token)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		handler(next).ServeHTTP(rr, req)

		assert.True(t, nextCalled, "next handler should be called")
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

// Test scenarios matching the actual granular scope use cases
func TestGranularScopeScenarios(t *testing.T) {
	// Define scope sets matching routes.go
	scopesUsersRead := []string{
		"authserver:admin-read",
		"authserver:manage-users",
		"authserver:manage",
	}
	scopesUsers := []string{
		"authserver:manage-users",
		"authserver:manage",
	}
	scopesClientsRead := []string{
		"authserver:admin-read",
		"authserver:manage-clients",
		"authserver:manage",
	}
	scopesClients := []string{
		"authserver:manage-clients",
		"authserver:manage",
	}
	scopesSettingsRead := []string{
		"authserver:admin-read",
		"authserver:manage-settings",
		"authserver:manage",
	}
	scopesSettings := []string{
		"authserver:manage-settings",
		"authserver:manage",
	}

	t.Run("admin-read can read users but not write", func(t *testing.T) {
		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"scope": "authserver:admin-read",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, token)
		req = req.WithContext(ctx)

		// Should pass for read
		rr := httptest.NewRecorder()
		nextCalled := false
		RequireBearerTokenScopeAnyOf(scopesUsersRead)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})).ServeHTTP(rr, req)
		assert.True(t, nextCalled, "admin-read should access users read endpoints")

		// Should fail for write
		rr = httptest.NewRecorder()
		nextCalled = false
		RequireBearerTokenScopeAnyOf(scopesUsers)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})).ServeHTTP(rr, req)
		assert.False(t, nextCalled, "admin-read should NOT access users write endpoints")
		assert.Equal(t, http.StatusForbidden, rr.Code)
	})

	t.Run("manage-users can read and write users", func(t *testing.T) {
		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"scope": "authserver:manage-users",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, token)
		req = req.WithContext(ctx)

		// Should pass for read
		rr := httptest.NewRecorder()
		nextCalled := false
		RequireBearerTokenScopeAnyOf(scopesUsersRead)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})).ServeHTTP(rr, req)
		assert.True(t, nextCalled, "manage-users should access users read endpoints")

		// Should pass for write
		rr = httptest.NewRecorder()
		nextCalled = false
		RequireBearerTokenScopeAnyOf(scopesUsers)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})).ServeHTTP(rr, req)
		assert.True(t, nextCalled, "manage-users should access users write endpoints")
	})

	t.Run("manage-users cannot access clients", func(t *testing.T) {
		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"scope": "authserver:manage-users",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, token)
		req = req.WithContext(ctx)

		// Should fail for clients read
		rr := httptest.NewRecorder()
		nextCalled := false
		RequireBearerTokenScopeAnyOf(scopesClientsRead)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})).ServeHTTP(rr, req)
		assert.False(t, nextCalled, "manage-users should NOT access clients read endpoints")
		assert.Equal(t, http.StatusForbidden, rr.Code)

		// Should fail for clients write
		rr = httptest.NewRecorder()
		nextCalled = false
		RequireBearerTokenScopeAnyOf(scopesClients)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})).ServeHTTP(rr, req)
		assert.False(t, nextCalled, "manage-users should NOT access clients write endpoints")
		assert.Equal(t, http.StatusForbidden, rr.Code)
	})

	t.Run("manage scope has full access to everything", func(t *testing.T) {
		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"scope": "authserver:manage",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, token)
		req = req.WithContext(ctx)

		allScopeSets := [][]string{
			scopesUsersRead, scopesUsers,
			scopesClientsRead, scopesClients,
			scopesSettingsRead, scopesSettings,
		}

		for _, scopes := range allScopeSets {
			rr := httptest.NewRecorder()
			nextCalled := false
			RequireBearerTokenScopeAnyOf(scopes)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
			})).ServeHTTP(rr, req)
			assert.True(t, nextCalled, "manage should access all endpoints")
		}
	})

	t.Run("admin-read can read all domains", func(t *testing.T) {
		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"scope": "authserver:admin-read",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, token)
		req = req.WithContext(ctx)

		readScopeSets := [][]string{scopesUsersRead, scopesClientsRead, scopesSettingsRead}

		for _, scopes := range readScopeSets {
			rr := httptest.NewRecorder()
			nextCalled := false
			RequireBearerTokenScopeAnyOf(scopes)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
			})).ServeHTTP(rr, req)
			assert.True(t, nextCalled, "admin-read should access all read endpoints")
		}
	})

	t.Run("admin-read cannot write to any domain", func(t *testing.T) {
		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"scope": "authserver:admin-read",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, token)
		req = req.WithContext(ctx)

		writeScopeSets := [][]string{scopesUsers, scopesClients, scopesSettings}

		for _, scopes := range writeScopeSets {
			rr := httptest.NewRecorder()
			nextCalled := false
			RequireBearerTokenScopeAnyOf(scopes)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
			})).ServeHTTP(rr, req)
			assert.False(t, nextCalled, "admin-read should NOT access write endpoints")
			assert.Equal(t, http.StatusForbidden, rr.Code)
		}
	})

	t.Run("combined scopes work correctly", func(t *testing.T) {
		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"scope": "authserver:manage-users authserver:manage-clients",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, token)
		req = req.WithContext(ctx)

		// Should access users
		rr := httptest.NewRecorder()
		nextCalled := false
		RequireBearerTokenScopeAnyOf(scopesUsers)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})).ServeHTTP(rr, req)
		assert.True(t, nextCalled, "should access users")

		// Should access clients
		rr = httptest.NewRecorder()
		nextCalled = false
		RequireBearerTokenScopeAnyOf(scopesClients)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})).ServeHTTP(rr, req)
		assert.True(t, nextCalled, "should access clients")

		// Should NOT access settings
		rr = httptest.NewRecorder()
		nextCalled = false
		RequireBearerTokenScopeAnyOf(scopesSettings)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})).ServeHTTP(rr, req)
		assert.False(t, nextCalled, "should NOT access settings")
		assert.Equal(t, http.StatusForbidden, rr.Code)
	})
}

func TestGetValidatedToken(t *testing.T) {
	t.Run("returns token when present in context", func(t *testing.T) {
		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"sub": "user123",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyValidatedToken, token)
		req = req.WithContext(ctx)

		result, ok := GetValidatedToken(req)

		assert.True(t, ok)
		assert.NotNil(t, result)
		assert.Equal(t, "user123", result.Claims["sub"])
	})

	t.Run("returns false when token not in context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)

		result, ok := GetValidatedToken(req)

		assert.False(t, ok)
		assert.Nil(t, result)
	})

	t.Run("returns false when value is wrong type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyValidatedToken, "not-a-token")
		req = req.WithContext(ctx)

		result, ok := GetValidatedToken(req)

		assert.False(t, ok)
		assert.Nil(t, result)
	})
}
