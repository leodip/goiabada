package server

import (
	"context"
	"crypto/rsa"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/oauth"
)

type tokenParser interface {
	DecodeAndValidateTokenString(ctx context.Context, token string, pubKey *rsa.PublicKey) (*oauth.JwtToken, error)
}

type MiddlewareJwt struct {
	tokenParser tokenParser
}

func NewMiddlewareJwt(
	tokenParser tokenParser,
) *MiddlewareJwt {
	return &MiddlewareJwt{
		tokenParser: tokenParser,
	}
}

// JwtAuthorizationHeaderToContext is a middleware that extracts the JWT token from the Authorization header and stores it in the context.
func (m *MiddlewareJwt) JwtAuthorizationHeaderToContext() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			const BEARER_SCHEMA = "Bearer "
			authHeader := r.Header.Get("Authorization")
			if len(authHeader) >= len(BEARER_SCHEMA) {
				tokenStr := authHeader[len(BEARER_SCHEMA):]
				token, err := m.tokenParser.DecodeAndValidateTokenString(ctx, tokenStr, nil)
				if err == nil {
					ctx = context.WithValue(ctx, constants.ContextKeyBearerToken, *token)
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
