package handlers

import (
	"context"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/core/oauth"
)

type HttpHelper interface {
	InternalServerError(w http.ResponseWriter, r *http.Request, err error)
	NotFound(w http.ResponseWriter, r *http.Request)
	RenderTemplate(w http.ResponseWriter, r *http.Request, layoutName string, templateName string,
		data map[string]interface{}) error
	JsonError(w http.ResponseWriter, r *http.Request, err error)
	EncodeJson(w http.ResponseWriter, r *http.Request, data interface{})
}

type AuthHelper interface {
	IsAuthenticated(jwtInfo oauthclient.JwtInfo) bool
}

// TokenParser is the sign-in's one question to the parser: is this token response, answering a
// sign-in that sent this nonce, one the console may accept.
type TokenParser interface {
	DecodeAndValidateSignInResponse(ctx context.Context, tokenResponse *oauth.TokenResponse, nonce string) (*oauthclient.JwtInfo, error)
}

type TokenExchanger interface {
	ExchangeCodeForTokens(ctx context.Context, code, redirectURI, clientId, clientSecret,
		codeVerifier, tokenEndpoint string) (*oauth.TokenResponse, error)
}
