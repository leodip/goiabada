package constants

type ctxKey string

const (
	ContextKeyIdTokenClaims      ctxKey = "IdTokenClaims"
	ContextKeyAccessTokenClaims  ctxKey = "AccessTokenClaims"
	ContextKeyRefreshTokenClaims ctxKey = "RefreshTokenClaims"
)
