package server

import (
	"context"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/models"
	"github.com/leodip/goiabada/internal/security"
	"github.com/leodip/goiabada/internal/validators"
)

type tokenIssuer interface {
	GenerateTokenResponseForRefresh(ctx context.Context, input *security.GenerateTokenForRefreshInput) (*security.TokenResponse, error)
}

type tokenValidator interface {
	ValidateTokenRequest(ctx context.Context, input *validators.ValidateTokenRequestInput) (*validators.ValidateTokenRequestResult, error)
}

type userSessionManager interface {
	BumpUserSession(r *http.Request, sessionIdentifier string, clientId int64) (*models.UserSession, error)
}

type MiddlewareTokenRefresh struct {
	sessionStore       sessions.Store
	tokenIssuer        tokenIssuer
	tokenValidator     tokenValidator
	tokenParser        tokenParser
	userSessionManager userSessionManager
	database           data.Database
}

func NewMiddlewareTokenRefresh(
	sessionStore sessions.Store,
	tokenIssuer tokenIssuer,
	tokenValidator tokenValidator,
	tokenParser tokenParser,
	userSessionManager userSessionManager,
	database data.Database,
) *MiddlewareTokenRefresh {
	return &MiddlewareTokenRefresh{
		sessionStore:       sessionStore,
		tokenIssuer:        tokenIssuer,
		tokenValidator:     tokenValidator,
		tokenParser:        tokenParser,
		userSessionManager: userSessionManager,
		database:           database,
	}
}

func (m *MiddlewareTokenRefresh) RefreshExpiredToken() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if m.shouldRefreshToken(r) {
				m.refreshToken(w, r)
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (m *MiddlewareTokenRefresh) shouldRefreshToken(r *http.Request) bool {
	sess, err := m.sessionStore.Get(r, constants.SessionName)
	if err != nil {
		return false
	}

	tokenResponse, ok := sess.Values[constants.SessionKeyJwt].(security.TokenResponse)
	if !ok || tokenResponse.AccessToken == "" || tokenResponse.RefreshToken == "" {
		return false
	}

	// Decode the access token to check its expiration
	accessToken, err := m.tokenParser.DecodeAndValidateTokenString(r.Context(), tokenResponse.AccessToken, nil)
	if err != nil {
		return true
	}

	exp := accessToken.GetTimeClaim("exp")
	now := time.Now()
	return exp.Before(now)
}

func (m *MiddlewareTokenRefresh) refreshToken(w http.ResponseWriter, r *http.Request) {
	sess, err := m.sessionStore.Get(r, constants.SessionName)
	if err != nil {
		return
	}

	tokenResponse, ok := sess.Values[constants.SessionKeyJwt].(security.TokenResponse)
	if !ok || tokenResponse.RefreshToken == "" {
		return
	}

	client, err := m.database.GetClientByClientIdentifier(nil, constants.SystemClientIdentifier)
	if err != nil {
		return
	}

	settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

	clientSecretDecrypted, err := lib.DecryptText(client.ClientSecretEncrypted, settings.AESEncryptionKey)
	if err != nil {
		return
	}

	input := &validators.ValidateTokenRequestInput{
		GrantType:    "refresh_token",
		RefreshToken: tokenResponse.RefreshToken,
		ClientId:     constants.SystemClientIdentifier,
		ClientSecret: clientSecretDecrypted,
	}

	validateResult, err := m.tokenValidator.ValidateTokenRequest(r.Context(), input)
	if err != nil {
		return
	}

	refreshToken := validateResult.RefreshToken
	refreshToken.Revoked = true
	err = m.database.UpdateRefreshToken(nil, refreshToken)
	if err != nil {
		return
	}

	refreshInput := &security.GenerateTokenForRefreshInput{
		Code:             validateResult.CodeEntity,
		RefreshToken:     validateResult.RefreshToken,
		RefreshTokenInfo: validateResult.RefreshTokenInfo,
	}

	newTokenResponse, err := m.tokenIssuer.GenerateTokenResponseForRefresh(r.Context(), refreshInput)
	if err != nil {
		return
	}

	sess.Values[constants.SessionKeyJwt] = *newTokenResponse
	err = sess.Save(r, w)
	if err != nil {
		return
	}

	if len(refreshToken.SessionIdentifier) > 0 {
		m.userSessionManager.BumpUserSession(r, refreshToken.SessionIdentifier, refreshToken.Code.ClientId)
	}
}
