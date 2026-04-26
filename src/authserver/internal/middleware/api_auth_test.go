package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/constants"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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

func TestRequireValidSession(t *testing.T) {
	settingsInCtx := func(req *http.Request) *http.Request {
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{
			UserSessionIdleTimeoutInSeconds: 3600,
			UserSessionMaxLifetimeInSeconds: 86400,
		})
		return req.WithContext(ctx)
	}

	t.Run("passes through when no bearer token in context", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rr := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		RequireValidSession(mockDB)(next).ServeHTTP(rr, req)

		assert.True(t, nextCalled, "next handler should be called")
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("passes through when bearer token has wrong type", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, "not-a-jwt")
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		RequireValidSession(mockDB)(next).ServeHTTP(rr, req)

		assert.True(t, nextCalled, "next handler should be called")
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("passes through when token has no sid claim (client_credentials/ROPC)", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"sub":   "client123",
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

		RequireValidSession(mockDB)(next).ServeHTTP(rr, req)

		assert.True(t, nextCalled, "next handler should be called")
		assert.Equal(t, http.StatusOK, rr.Code)
		// No DB calls expected; mock auto-asserts via NewDatabase(t)
	})

	t.Run("passes through when token sid resolves to a valid session", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)

		now := time.Now().UTC()
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, "sid-abc").
			Return(&models.UserSession{
				SessionIdentifier: "sid-abc",
				Started:           now.Add(-1 * time.Hour),
				LastAccessed:      now.Add(-5 * time.Minute),
			}, nil)

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"sid": "sid-abc",
				"sub": "user-1",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, token)
		req = req.WithContext(ctx)
		req = settingsInCtx(req)

		rr := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		RequireValidSession(mockDB)(next).ServeHTTP(rr, req)

		assert.True(t, nextCalled, "next handler should be called")
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("returns 401 invalid_token when session has been deleted", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)

		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, "sid-deleted").
			Return(nil, nil)

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"sid": "sid-deleted",
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

		RequireValidSession(mockDB)(next).ServeHTTP(rr, req)

		assert.False(t, nextCalled, "next handler should NOT be called")
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		wwwAuth := rr.Header().Get("WWW-Authenticate")
		assert.Contains(t, wwwAuth, `Bearer error="invalid_token"`)
		assert.Contains(t, wwwAuth, "Session has been terminated")
	})

	t.Run("returns 401 invalid_token when session has expired (idle timeout)", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)

		now := time.Now().UTC()
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, "sid-expired").
			Return(&models.UserSession{
				SessionIdentifier: "sid-expired",
				Started:           now.Add(-2 * time.Hour),
				LastAccessed:      now.Add(-2 * time.Hour), // older than 1h idle timeout
			}, nil)

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"sid": "sid-expired",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, token)
		req = req.WithContext(ctx)
		req = settingsInCtx(req)

		rr := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		RequireValidSession(mockDB)(next).ServeHTTP(rr, req)

		assert.False(t, nextCalled, "next handler should NOT be called")
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		wwwAuth := rr.Header().Get("WWW-Authenticate")
		assert.Contains(t, wwwAuth, `Bearer error="invalid_token"`)
		assert.Contains(t, wwwAuth, "Session has expired")
	})

	t.Run("returns 500 when settings not in context", func(t *testing.T) {
		// Without settings we cannot enforce idle/max-lifetime limits.
		// Silently skipping would let an expired session ride a still-valid
		// JWT past us, so we fail closed with a 500.
		mockDB := mocks_data.NewDatabase(t)

		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, "sid-no-settings").
			Return(&models.UserSession{
				SessionIdentifier: "sid-no-settings",
				Started:           time.Now().UTC().Add(-100 * time.Hour),
				LastAccessed:      time.Now().UTC().Add(-100 * time.Hour),
			}, nil)

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"sid": "sid-no-settings",
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

		RequireValidSession(mockDB)(next).ServeHTTP(rr, req)

		assert.False(t, nextCalled, "next handler should NOT be called when settings are missing")
		assert.Equal(t, http.StatusInternalServerError, rr.Code)
		// 500 path uses http.Error, not the bearer-auth helper, so no WWW-Authenticate.
		assert.Empty(t, rr.Header().Get("WWW-Authenticate"))
	})

	t.Run("returns 500 when settings is wrong type in context", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)

		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, "sid-bad-settings").
			Return(&models.UserSession{
				SessionIdentifier: "sid-bad-settings",
				Started:           time.Now().UTC(),
				LastAccessed:      time.Now().UTC(),
			}, nil)

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"sid": "sid-bad-settings",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, token)
		// Settings stored as a non-pointer struct, which fails the type assertion.
		ctx = context.WithValue(ctx, constants.ContextKeySettings, models.Settings{})
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		RequireValidSession(mockDB)(next).ServeHTTP(rr, req)

		assert.False(t, nextCalled, "next handler should NOT be called when settings type is wrong")
		assert.Equal(t, http.StatusInternalServerError, rr.Code)
	})

	t.Run("returns 500 when database lookup fails", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)

		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, "sid-boom").
			Return(nil, errors.New("connection refused"))

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"sid": "sid-boom",
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

		RequireValidSession(mockDB)(next).ServeHTTP(rr, req)

		assert.False(t, nextCalled, "next handler should NOT be called")
		assert.Equal(t, http.StatusInternalServerError, rr.Code)
		// 500 path uses http.Error, not the bearer-auth helper, so no WWW-Authenticate.
		assert.Empty(t, rr.Header().Get("WWW-Authenticate"))
	})

	t.Run("body matches WWW-Authenticate description on rejection", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)

		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, "sid-x").
			Return(nil, nil)

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"sid": "sid-x",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, token)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		RequireValidSession(mockDB)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).
			ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.True(t, strings.Contains(rr.Body.String(), "Session has been terminated"))
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
