package handlers

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

type authHelper interface {
	GenerateVerifier() string
	GenerateAuthCodeURL(state string, nonce string, verifier string, scopes []string) string
	ExchangeAuthCodeWithToken(ctx context.Context, code string, verifier string) (*oauth2.Token, error)
	VerifyIdToken(ctx context.Context, rawIDToken string) (*oidc.IDToken, error)
	ParseAndValidateJWT(tokenString string) (*jwt.Token, error)
}
