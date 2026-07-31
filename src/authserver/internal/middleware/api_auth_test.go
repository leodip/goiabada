package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/api"
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
		mockDB.On("GetUserBySubject", mock.Anything, mock.Anything).
			Return(&models.User{Id: 1, Enabled: true}, nil).Maybe()
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, "sid-abc").
			Return(&models.UserSession{
				SessionIdentifier: "sid-abc",
				Started:           now.Add(-1 * time.Hour),
				LastAccessed:      now.Add(-5 * time.Minute),
			}, nil)

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"sid":       "sid-abc",
				"auth_time": float64(1),
				"sub":       "user-1",
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

		mockDB.On("GetUserBySubject", mock.Anything, mock.Anything).
			Return(&models.User{Id: 1, Enabled: true}, nil).Maybe()
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, "sid-deleted").
			Return(nil, nil)

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"sid":       "sid-deleted",
				"auth_time": float64(1),
				"sub":       "user-1",
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
		mockDB.On("GetUserBySubject", mock.Anything, mock.Anything).
			Return(&models.User{Id: 1, Enabled: true}, nil).Maybe()
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, "sid-expired").
			Return(&models.UserSession{
				SessionIdentifier: "sid-expired",
				Started:           now.Add(-2 * time.Hour),
				LastAccessed:      now.Add(-2 * time.Hour), // older than 1h idle timeout
			}, nil)

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"sid":       "sid-expired",
				"auth_time": float64(1),
				"sub":       "user-1",
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

		mockDB.On("GetUserBySubject", mock.Anything, mock.Anything).
			Return(&models.User{Id: 1, Enabled: true}, nil).Maybe()
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, "sid-no-settings").
			Return(&models.UserSession{
				SessionIdentifier: "sid-no-settings",
				Started:           time.Now().UTC().Add(-100 * time.Hour),
				LastAccessed:      time.Now().UTC().Add(-100 * time.Hour),
			}, nil)

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"sid":       "sid-no-settings",
				"auth_time": float64(1),
				"sub":       "user-1",
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

		mockDB.On("GetUserBySubject", mock.Anything, mock.Anything).
			Return(&models.User{Id: 1, Enabled: true}, nil).Maybe()
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, "sid-bad-settings").
			Return(&models.UserSession{
				SessionIdentifier: "sid-bad-settings",
				Started:           time.Now().UTC(),
				LastAccessed:      time.Now().UTC(),
			}, nil)

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"sid":       "sid-bad-settings",
				"auth_time": float64(1),
				"sub":       "user-1",
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

		mockDB.On("GetUserBySubject", mock.Anything, mock.Anything).
			Return(&models.User{Id: 1, Enabled: true}, nil).Maybe()
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, "sid-boom").
			Return(nil, errors.New("connection refused"))

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"sid":       "sid-boom",
				"auth_time": float64(1),
				"sub":       "user-1",
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

		mockDB.On("GetUserBySubject", mock.Anything, mock.Anything).
			Return(&models.User{Id: 1, Enabled: true}, nil).Maybe()
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, "sid-x").
			Return(nil, nil)

		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"sid":       "sid-x",
				"auth_time": float64(1),
				"sub":       "user-1",
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

// TestRequireUserBoundToken covers the second vulnerability in #104: /userinfo and the
// Account API resolve the acting user from `sub`, which is the CLIENT identifier on a
// client_credentials token, and neither existing guard rejects that token type.
//
// The asymmetry this guard rests on is that every user access token carries auth_time
// (set unconditionally by generateAccessTokenCore) and the client_credentials claim set
// never does. That asymmetry is asserted end to end by the integration tests; these cases
// assert the guard's own contract.
// TestRequireValidSession_Table is the exhaustive owner of the middleware decision table
// for #106. The hand-written subtests above cover the pre-existing session behaviour; this
// covers the full matrix once the Enabled and generation checks are in play.
//
// Every negative row varies exactly ONE field from a passing row, so none of them can pass
// with its gate removed. The gate each row is meant to hit is named in its label.
//
// Two rows will look wrong to a reader and must not be "cleaned up":
//
//   - "session-bound, stale token generation claim is IGNORED" pins the asymmetry of
//     decision 11(c). A sid-bearing token defers to its SESSION's generation, because a
//     self-service password change promotes the preserved session forward while the access
//     tokens already issued from it still carry the old value. Also checking the claim would
//     sign that caller out, which decision 4 exists to prevent.
//   - "sid-less, absent claim passes while the user is at 0" is what keeps access tokens
//     issued before this feature shipped working. Deleting it would let a change silently
//     invalidate every legacy token at deploy time.
func TestRequireValidSession_Table(t *testing.T) {
	const sid = "sid-table"

	type sessionSpec struct {
		missing    bool
		lookupErrs bool
		generation int64
		expired    bool
	}

	tests := []struct {
		label      string
		noBearer   bool
		wrongType  bool
		claims     map[string]interface{}
		noSettings bool
		userErrs   bool
		userNil    bool
		userState  *models.User
		session    *sessionSpec
		wantStatus int
		wantNext   bool
	}{
		// Pass-through gates: nothing to enforce, so no database call at all.
		{label: "no bearer token in context", noBearer: true, wantStatus: http.StatusOK, wantNext: true},
		{label: "bearer value is not a JwtToken", wrongType: true, wantStatus: http.StatusOK, wantNext: true},
		{
			label:      "no auth_time: the client_credentials gate",
			claims:     map[string]interface{}{"sub": "some-client"},
			wantStatus: http.StatusOK, wantNext: true,
		},

		// Subject gate.
		{
			label:      "empty sub",
			claims:     map[string]interface{}{"auth_time": float64(1), "sub": ""},
			wantStatus: http.StatusUnauthorized,
		},
		{
			label:      "whitespace-only sub",
			claims:     map[string]interface{}{"auth_time": float64(1), "sub": "   "},
			wantStatus: http.StatusUnauthorized,
		},

		// User gate, fail-closed.
		{
			label:      "user lookup errors",
			claims:     map[string]interface{}{"auth_time": float64(1), "sub": "u"},
			userErrs:   true,
			wantStatus: http.StatusInternalServerError,
		},
		{
			label:      "subject does not resolve to a user",
			claims:     map[string]interface{}{"auth_time": float64(1), "sub": "u"},
			userNil:    true,
			wantStatus: http.StatusUnauthorized,
		},
		// The sibling-branch audit: a disabled user must be rejected on BOTH branches, not
		// only the one that happened to be written first.
		{
			label:      "disabled user, sid-less branch",
			claims:     map[string]interface{}{"auth_time": float64(1), "sub": "u"},
			userState:  &models.User{Id: 1, Enabled: false},
			wantStatus: http.StatusUnauthorized,
		},
		{
			label:      "disabled user, session-bound branch",
			claims:     map[string]interface{}{"auth_time": float64(1), "sub": "u", "sid": sid},
			userState:  &models.User{Id: 1, Enabled: false},
			wantStatus: http.StatusUnauthorized,
		},

		// Session-bound branch.
		{
			label:      "session-bound, everything current",
			claims:     map[string]interface{}{"auth_time": float64(1), "sub": "u", "sid": sid},
			session:    &sessionSpec{},
			wantStatus: http.StatusOK, wantNext: true,
		},
		{
			label:      "session terminated",
			claims:     map[string]interface{}{"auth_time": float64(1), "sub": "u", "sid": sid},
			session:    &sessionSpec{missing: true},
			wantStatus: http.StatusUnauthorized,
		},
		{
			label:      "session lookup errors",
			claims:     map[string]interface{}{"auth_time": float64(1), "sub": "u", "sid": sid},
			session:    &sessionSpec{lookupErrs: true},
			wantStatus: http.StatusInternalServerError,
		},
		{
			label:      "settings missing from context",
			claims:     map[string]interface{}{"auth_time": float64(1), "sub": "u", "sid": sid},
			session:    &sessionSpec{},
			noSettings: true,
			wantStatus: http.StatusInternalServerError,
		},
		{
			label:      "session expired past its idle timeout",
			claims:     map[string]interface{}{"auth_time": float64(1), "sub": "u", "sid": sid},
			session:    &sessionSpec{expired: true},
			wantStatus: http.StatusUnauthorized,
		},
		{
			label:      "session generation behind the user's",
			claims:     map[string]interface{}{"auth_time": float64(1), "sub": "u", "sid": sid},
			userState:  &models.User{Id: 1, Enabled: true, AuthStateGeneration: 1},
			session:    &sessionSpec{generation: 0},
			wantStatus: http.StatusUnauthorized,
		},
		{
			label:      "session promoted to match the user",
			claims:     map[string]interface{}{"auth_time": float64(1), "sub": "u", "sid": sid},
			userState:  &models.User{Id: 1, Enabled: true, AuthStateGeneration: 1},
			session:    &sessionSpec{generation: 1},
			wantStatus: http.StatusOK, wantNext: true,
		},
		{
			// KEEP. Reverses the intuitive reading: see the note above the function.
			label: "session-bound, stale token generation claim is IGNORED",
			claims: map[string]interface{}{"auth_time": float64(1), "sub": "u", "sid": sid,
				"auth_state_generation": float64(0)},
			userState:  &models.User{Id: 1, Enabled: true, AuthStateGeneration: 1},
			session:    &sessionSpec{generation: 1},
			wantStatus: http.StatusOK, wantNext: true,
		},
		{
			label: "session-bound, malformed token generation claim is IGNORED",
			claims: map[string]interface{}{"auth_time": float64(1), "sub": "u", "sid": sid,
				"auth_state_generation": "not-a-number"},
			userState:  &models.User{Id: 1, Enabled: true, AuthStateGeneration: 1},
			session:    &sessionSpec{generation: 1},
			wantStatus: http.StatusOK, wantNext: true,
		},

		// Sid-less branch: offline grants and ROPC, where the token's own claim decides.
		{
			label: "sid-less, claim matches",
			claims: map[string]interface{}{"auth_time": float64(1), "sub": "u",
				"auth_state_generation": float64(3)},
			userState:  &models.User{Id: 1, Enabled: true, AuthStateGeneration: 3},
			wantStatus: http.StatusOK, wantNext: true,
		},
		{
			label: "sid-less, claim behind",
			claims: map[string]interface{}{"auth_time": float64(1), "sub": "u",
				"auth_state_generation": float64(2)},
			userState:  &models.User{Id: 1, Enabled: true, AuthStateGeneration: 3},
			wantStatus: http.StatusUnauthorized,
		},
		{
			label: "sid-less, claim ahead",
			claims: map[string]interface{}{"auth_time": float64(1), "sub": "u",
				"auth_state_generation": float64(4)},
			userState:  &models.User{Id: 1, Enabled: true, AuthStateGeneration: 3},
			wantStatus: http.StatusUnauthorized,
		},
		{
			// KEEP. The legacy-token row: see the note above the function.
			label:      "sid-less, absent claim passes while the user is at 0",
			claims:     map[string]interface{}{"auth_time": float64(1), "sub": "u"},
			userState:  &models.User{Id: 1, Enabled: true, AuthStateGeneration: 0},
			wantStatus: http.StatusOK, wantNext: true,
		},
		{
			label:      "sid-less, absent claim rejected once the user has advanced",
			claims:     map[string]interface{}{"auth_time": float64(1), "sub": "u"},
			userState:  &models.User{Id: 1, Enabled: true, AuthStateGeneration: 1},
			wantStatus: http.StatusUnauthorized,
		},
		{
			label: "sid-less, explicit float64 zero while the user is at 0",
			claims: map[string]interface{}{"auth_time": float64(1), "sub": "u",
				"auth_state_generation": float64(0)},
			userState:  &models.User{Id: 1, Enabled: true, AuthStateGeneration: 0},
			wantStatus: http.StatusOK, wantNext: true,
		},

		// Malformed claim shapes, each rejected. A malformed claim must never be read as 0,
		// or a forged-looking token would inherit the legacy-token exemption.
		{
			label: "sid-less, malformed claim: string",
			claims: map[string]interface{}{"auth_time": float64(1), "sub": "u",
				"auth_state_generation": "0"},
			userState:  &models.User{Id: 1, Enabled: true, AuthStateGeneration: 0},
			wantStatus: http.StatusUnauthorized,
		},
		{
			label: "sid-less, malformed claim: bool",
			claims: map[string]interface{}{"auth_time": float64(1), "sub": "u",
				"auth_state_generation": true},
			userState:  &models.User{Id: 1, Enabled: true, AuthStateGeneration: 0},
			wantStatus: http.StatusUnauthorized,
		},
		{
			label: "sid-less, malformed claim: nil",
			claims: map[string]interface{}{"auth_time": float64(1), "sub": "u",
				"auth_state_generation": nil},
			userState:  &models.User{Id: 1, Enabled: true, AuthStateGeneration: 0},
			wantStatus: http.StatusUnauthorized,
		},
		{
			label: "sid-less, malformed claim: non-integral",
			claims: map[string]interface{}{"auth_time": float64(1), "sub": "u",
				"auth_state_generation": float64(1.5)},
			userState:  &models.User{Id: 1, Enabled: true, AuthStateGeneration: 1},
			wantStatus: http.StatusUnauthorized,
		},
		{
			label: "sid-less, malformed claim: negative",
			claims: map[string]interface{}{"auth_time": float64(1), "sub": "u",
				"auth_state_generation": float64(-1)},
			userState:  &models.User{Id: 1, Enabled: true, AuthStateGeneration: 0},
			wantStatus: http.StatusUnauthorized,
		},
		{
			label: "sid-less, malformed claim: beyond exact float64 integer range",
			claims: map[string]interface{}{"auth_time": float64(1), "sub": "u",
				"auth_state_generation": float64(1<<53) + 2},
			userState:  &models.User{Id: 1, Enabled: true, AuthStateGeneration: 0},
			wantStatus: http.StatusUnauthorized,
		},
		{
			// KEEP, and do not "tidy" the -1 away as an impossible value. This row exists
			// because an earlier version of tokenGeneration returned -1 in band to mean
			// malformed, then compared it with the persisted generation like any other
			// value. auth_state_generation is a signed BIGINT/INTEGER on all four engines
			// with no nonnegative constraint, so a user row CAN hold -1, and such a user
			// accepted every malformed claim. The helper now reports validity separately
			// and callers reject on !ok before comparing, which is what this row pins.
			// It is the only row where malformed input meets a stored value that a
			// sentinel could collide with.
			label: "sid-less, malformed claim cannot collide with a persisted -1",
			claims: map[string]interface{}{"auth_time": float64(1), "sub": "u",
				"auth_state_generation": "-1"},
			userState:  &models.User{Id: 1, Enabled: true, AuthStateGeneration: -1},
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.label, func(t *testing.T) {
			mockDB := mocks_data.NewDatabase(t)
			now := time.Now().UTC()

			if !tc.noBearer && !tc.wrongType && tc.claims["auth_time"] != nil &&
				strings.TrimSpace(fmt.Sprint(tc.claims["sub"])) != "" {
				switch {
				case tc.userErrs:
					mockDB.On("GetUserBySubject", mock.Anything, mock.Anything).
						Return(nil, assert.AnError)
				case tc.userNil:
					mockDB.On("GetUserBySubject", mock.Anything, mock.Anything).Return(nil, nil)
				default:
					user := tc.userState
					if user == nil {
						user = &models.User{Id: 1, Enabled: true}
					}
					mockDB.On("GetUserBySubject", mock.Anything, mock.Anything).Return(user, nil)
				}
			}

			if tc.session != nil {
				switch {
				case tc.session.lookupErrs:
					mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, sid).
						Return(nil, assert.AnError)
				case tc.session.missing:
					mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, sid).
						Return(nil, nil)
				default:
					lastAccessed := now.Add(-5 * time.Minute)
					if tc.session.expired {
						// Past the 3600s idle timeout the harness puts in context.
						lastAccessed = now.Add(-2 * time.Hour)
					}
					mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, sid).
						Return(&models.UserSession{
							Id:                  9,
							SessionIdentifier:   sid,
							Started:             now.Add(-1 * time.Hour),
							LastAccessed:        lastAccessed,
							AuthStateGeneration: tc.session.generation,
						}, nil)
				}
			}

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			switch {
			case tc.noBearer:
				// nothing in context
			case tc.wrongType:
				req = req.WithContext(context.WithValue(req.Context(),
					constants.ContextKeyBearerToken, "not-a-jwt"))
			default:
				req = req.WithContext(context.WithValue(req.Context(),
					constants.ContextKeyBearerToken, oauth.JwtToken{Claims: tc.claims}))
			}
			if !tc.noSettings {
				req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings,
					&models.Settings{
						UserSessionIdleTimeoutInSeconds: 3600,
						UserSessionMaxLifetimeInSeconds: 86400,
					}))
			}

			rr := httptest.NewRecorder()
			nextCalled := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextCalled = true })

			RequireValidSession(mockDB)(next).ServeHTTP(rr, req)

			assert.Equal(t, tc.wantStatus, rr.Code, "status")
			assert.Equal(t, tc.wantNext, nextCalled, "next handler called")
		})
	}
}

func TestRequireUserBoundToken(t *testing.T) {
	// Assert the ErrorCode and not merely the status, since all three failure modes here
	// would otherwise be indistinguishable to a caller.
	decodeErrorCode := func(t *testing.T, rr *httptest.ResponseRecorder) string {
		t.Helper()
		var body api.ErrorResponse
		err := json.Unmarshal(rr.Body.Bytes(), &body)
		assert.NoError(t, err, "response body should be the standard error envelope")
		return body.ErrorCode
	}

	t.Run("passes a token carrying auth_time", func(t *testing.T) {
		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"sub":       "a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
				"scope":     "authserver:manage-account",
				"auth_time": float64(time.Now().Unix()),
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyBearerToken, token))

		rr := httptest.NewRecorder()
		nextCalled := false
		RequireUserBoundToken()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})).ServeHTTP(rr, req)

		assert.True(t, nextCalled, "a user-bound token must reach the handler")
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("rejects a client credentials token, which has no auth_time", func(t *testing.T) {
		// Exactly the claim set GenerateTokenResponseForClientCred produces: sub is the
		// client identifier, and the scope required by the route is present. Only the
		// absence of auth_time distinguishes it.
		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"sub":   "a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
				"scope": "authserver:manage-account",
				"typ":   "Bearer",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyBearerToken, token))

		rr := httptest.NewRecorder()
		nextCalled := false
		RequireUserBoundToken()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})).ServeHTTP(rr, req)

		assert.False(t, nextCalled, "the handler must not run: it would resolve a user from sub")
		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.Equal(t, "USER_CONTEXT_REQUIRED", decodeErrorCode(t, rr))
		// RFC 6750 §3.1 has no code for "wrong token type", so the 403 reuses
		// insufficient_scope in the header while ErrorCode carries the precise reason.
		assert.Contains(t, rr.Header().Get("WWW-Authenticate"), `error="insufficient_scope"`)
	})

	t.Run("rejects when no bearer token is in context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)

		rr := httptest.NewRecorder()
		nextCalled := false
		RequireUserBoundToken()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})).ServeHTTP(rr, req)

		assert.False(t, nextCalled)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Equal(t, "ACCESS_TOKEN_REQUIRED", decodeErrorCode(t, rr))
		assert.Contains(t, rr.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
	})

	t.Run("rejects when the context value is not a JwtToken", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyBearerToken, "not-a-token"))

		rr := httptest.NewRecorder()
		nextCalled := false
		RequireUserBoundToken()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})).ServeHTTP(rr, req)

		assert.False(t, nextCalled)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Equal(t, "INVALID_TOKEN_FORMAT", decodeErrorCode(t, rr))
	})

	t.Run("a zero auth_time is present and therefore accepted", func(t *testing.T) {
		// The guard reads presence, never the value, and this pins that deliberately. On the
		// ROPC refresh path the value is already wrong (it reports the refresh moment), so a
		// guard that validated the value would be asserting a property the issuer does not
		// currently hold.
		token := oauth.JwtToken{
			Claims: map[string]interface{}{
				"sub":       "some-user-subject",
				"auth_time": float64(0),
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyBearerToken, token))

		rr := httptest.NewRecorder()
		nextCalled := false
		RequireUserBoundToken()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})).ServeHTTP(rr, req)

		assert.True(t, nextCalled)
		assert.Equal(t, http.StatusOK, rr.Code)
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
