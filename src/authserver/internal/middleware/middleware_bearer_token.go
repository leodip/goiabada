package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	coreconstants "github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/oauth"
)

// tokenParser is the one thing this middleware needs of the auth server's token parser:
// turning the presented string into a validated token. signingkeys.TokenParser satisfies
// it. Declared as the shape used rather than the whole parser, which is what the
// neighbouring ports in this package already do (#385).
type tokenParser interface {
	DecodeAndValidateTokenString(ctx context.Context, token string, withExpirationCheck bool) (*oauth.JwtToken, error)
}

type MiddlewareBearerToken struct {
	tokenParser tokenParser
}

// NewMiddlewareBearerToken constructs middleware that extracts bearer tokens from requests.
func NewMiddlewareBearerToken(tokenParser tokenParser) *MiddlewareBearerToken {
	return &MiddlewareBearerToken{tokenParser: tokenParser}
}

// JwtAuthorizationHeaderToContext is a middleware that extracts the JWT token from the Authorization header
// or from the POST body (access_token parameter) and stores it in the context.
// Per RFC 6750, the Authorization header takes precedence over the POST body.
// POST body token extraction is supported per OIDC Core 1.0 Section 5.3.1 for the UserInfo endpoint.
func (m *MiddlewareBearerToken) JwtAuthorizationHeaderToContext() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			var tokenStr string

			// First, try to extract token from Authorization header (takes precedence per RFC 6750)
			const BEARER_SCHEMA = "Bearer "
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, BEARER_SCHEMA) && len(authHeader) > len(BEARER_SCHEMA) {
				tokenStr = authHeader[len(BEARER_SCHEMA):]
			}

			// If no token in header and this is a POST request with form content type,
			// try to extract from POST body (OIDC Core 1.0 Section 5.3.1)
			if tokenStr == "" && r.Method == http.MethodPost {
				contentType := r.Header.Get("Content-Type")
				if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
					if err := r.ParseForm(); err == nil {
						tokenStr = r.PostFormValue("access_token")
					}
				}
			}

			// Validate and store the token if found
			if tokenStr != "" {
				token, err := m.tokenParser.DecodeAndValidateTokenString(r.Context(), tokenStr, true)
				if err == nil && isAccessTokenForAuthServer(r.Context(), token) {
					ctx = context.WithValue(ctx, constants.ContextKeyBearerToken, *token)
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// isAccessTokenForAuthServer admits a validly signed token as a bearer credential only when it
// is an access token issued for this server's own resource. The signature proves this server
// issued it, not which kind of token it is: refresh tokens and ID tokens are signed with the same
// key, and before this check a refresh token whose scope carried a route's permission passed
// that route's scope check (#401).
//
// typ must be "Bearer", which every access token carries, user or client; refresh tokens carry
// "Refresh" or "Offline" and ID tokens no typ at all. aud must contain authserver: RFC 7519
// section 4.1.3 requires a principal to reject a JWT whose aud does not identify it, and issuance
// names authserver in aud for every authserver:* scope and every claim scope, so every token a
// bearer-guarded route serves already does. GetAudience is the parser's own StringOrURI reading:
// a single string, or an array of strings, which arrives from a parsed token as []interface{}.
//
// A refused token is treated as absent, so the route answers exactly as it does for a token that
// does not parse, which is what #401 asks for.
func isAccessTokenForAuthServer(ctx context.Context, token *oauth.JwtToken) bool {
	if typ := token.GetStringClaim("typ"); typ != issuance.TokenTypeBearer.String() {
		slog.WarnContext(ctx, "rejecting bearer token: not an access token", "typ", typ)
		return false
	}
	audiences, err := token.Claims.GetAudience()
	if err != nil {
		slog.WarnContext(ctx, "rejecting bearer token: aud is malformed", "error", err)
		return false
	}
	if !slices.Contains(audiences, coreconstants.AuthServerResourceIdentifier) {
		slog.WarnContext(ctx, "rejecting bearer token: aud does not name this server's resource")
		return false
	}
	return true
}
