package handlers

import (
	"bytes"
	"context"
	"crypto/rsa"
	"net/http"

	"github.com/leodip/goiabada/core/oauth"
)

type HttpHelper interface {
	InternalServerError(w http.ResponseWriter, r *http.Request, err error)
	NotFound(w http.ResponseWriter, r *http.Request)
	RenderTemplate(w http.ResponseWriter, r *http.Request, layoutName string, templateName string,
		data map[string]interface{}) error
	RenderTemplateToBuffer(r *http.Request, layoutName string, templateName string,
		data map[string]interface{}) (*bytes.Buffer, error)
	JsonError(w http.ResponseWriter, r *http.Request, err error)
	EncodeJson(w http.ResponseWriter, r *http.Request, data interface{})
	GetFromUrlQueryOrFormPost(r *http.Request, key string) string
}

type AuthHelper interface {
	GetAuthContext(r *http.Request) (*oauth.AuthContext, error)
	SaveAuthContext(w http.ResponseWriter, r *http.Request, authContext *oauth.AuthContext) error
	ClearAuthContext(w http.ResponseWriter, r *http.Request) error
	GetLoggedInSubject(r *http.Request) string
	IsAuthenticated(jwtInfo oauth.JwtInfo) bool
	IsAuthorizedToAccessResource(jwtInfo oauth.JwtInfo, scopesAnyOf []string) bool
	RedirToAuthorize(w http.ResponseWriter, r *http.Request, clientIdentifier string, scope string, redirectBack string) error
}

type IdentifierValidator interface {
	ValidateIdentifier(identifier string, enforceMinLength bool) error
}

type TokenParser interface {
	DecodeAndValidateTokenString(ctx context.Context, token string, pubKey *rsa.PublicKey, withExpirationCheck bool) (*oauth.JwtToken, error)
	DecodeAndValidateTokenResponse(ctx context.Context, tokenResponse *oauth.TokenResponse) (*oauth.JwtInfo, error)
}

type TokenExchanger interface {
	ExchangeCodeForTokens(code, redirectURI, clientId, clientSecret, codeVerifier, tokenEndpoint string) (*oauth.TokenResponse, error)
}
