package server

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"

	"github.com/gorilla/sessions"

	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/models"
	"github.com/leodip/goiabada/internal/security"
	"github.com/leodip/goiabada/internal/validators"
)

type tokenParser interface {
	DecodeAndValidateTokenResponse(ctx context.Context, tokenResponse *security.TokenResponse) (*security.JwtInfo, error)
	DecodeAndValidateTokenString(ctx context.Context, token string, pubKey *rsa.PublicKey) (*security.JwtToken, error)
}

type authHelper interface {
	RedirToAuthorize(w http.ResponseWriter, r *http.Request, clientIdentifier string, referrer string) error
	IsAuthorizedToAccessResource(jwtInfo security.JwtInfo, scopesAnyOf []string) bool
}

type MiddlewareJwt struct {
	sessionStore       sessions.Store
	tokenIssuer        tokenIssuer
	tokenValidator     tokenValidator
	tokenParser        tokenParser
	userSessionManager userSessionManager
	database           data.Database
	authHelper         authHelper
}

func NewMiddlewareJwt(
	sessionStore sessions.Store,
	tokenIssuer tokenIssuer,
	tokenValidator tokenValidator,
	tokenParser tokenParser,
	userSessionManager userSessionManager,
	database data.Database,
	authHelper authHelper,
) *MiddlewareJwt {
	return &MiddlewareJwt{
		sessionStore:       sessionStore,
		tokenIssuer:        tokenIssuer,
		tokenValidator:     tokenValidator,
		tokenParser:        tokenParser,
		userSessionManager: userSessionManager,
		database:           database,
		authHelper:         authHelper,
	}
}

// JwtSessionHandler is a middleware that checks if the user has a valid JWT session.
// It will also refresh the token if needed.
func (m *MiddlewareJwt) JwtSessionHandler() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			sess, err := m.sessionStore.Get(r, constants.SessionName)
			if err != nil {
				http.Error(w, fmt.Sprintf("unable to get the session: %v", err.Error()), http.StatusInternalServerError)
				return
			}

			if sess.Values[constants.SessionKeyJwt] != nil {
				tokenResponse, ok := sess.Values[constants.SessionKeyJwt].(security.TokenResponse)
				if !ok {
					http.Error(w, "unable to cast the session value to TokenResponse", http.StatusInternalServerError)
					return
				}

				// Check if token needs refresh
				accessToken, err := m.tokenParser.DecodeAndValidateTokenString(ctx, tokenResponse.AccessToken, nil)
				if err != nil || accessToken.IsExpired {
					refreshed, err := m.refreshToken(w, r, &tokenResponse)
					if err != nil || !refreshed {
						// If refresh failed, clear the session and continue
						delete(sess.Values, constants.SessionKeyJwt)
						sess.Save(r, w)
						next.ServeHTTP(w, r)
						return
					}
				}

				// Get the latest token response from the session
				tokenResponse = sess.Values[constants.SessionKeyJwt].(security.TokenResponse)
				jwtInfo, err := m.tokenParser.DecodeAndValidateTokenResponse(ctx, &tokenResponse)
				if err == nil {

					settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

					if jwtInfo.IdToken != nil && !jwtInfo.IdToken.IsIssuerValid(settings.Issuer) {
						http.Error(w, "Invalid issuer", http.StatusUnauthorized)
						return
					}

					if jwtInfo.AccessToken != nil && !jwtInfo.AccessToken.IsIssuerValid(settings.Issuer) {
						http.Error(w, "Invalid issuer", http.StatusUnauthorized)
						return
					}

					if jwtInfo.RefreshToken != nil && !jwtInfo.RefreshToken.IsIssuerValid(settings.Issuer) {
						http.Error(w, "Invalid issuer", http.StatusUnauthorized)
						return
					}

					ctx = context.WithValue(ctx, constants.ContextKeyJwtInfo, *jwtInfo)
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (m *MiddlewareJwt) refreshToken(
	w http.ResponseWriter,
	r *http.Request,
	tokenResponse *security.TokenResponse,
) (bool, error) {
	sess, err := m.sessionStore.Get(r, constants.SessionName)
	if err != nil {
		return false, err
	}

	if tokenResponse.RefreshToken == "" {
		return false, nil
	}

	client, err := m.database.GetClientByClientIdentifier(nil, constants.SystemClientIdentifier)
	if err != nil {
		return false, err
	}

	settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

	clientSecretDecrypted, err := lib.DecryptText(client.ClientSecretEncrypted, settings.AESEncryptionKey)
	if err != nil {
		return false, err
	}

	input := &validators.ValidateTokenRequestInput{
		GrantType:    "refresh_token",
		RefreshToken: tokenResponse.RefreshToken,
		ClientId:     constants.SystemClientIdentifier,
		ClientSecret: clientSecretDecrypted,
	}

	validateResult, err := m.tokenValidator.ValidateTokenRequest(r.Context(), input)
	if err != nil {
		return false, err
	}

	refreshInput := &security.GenerateTokenForRefreshInput{
		Code:             validateResult.CodeEntity,
		RefreshToken:     validateResult.RefreshToken,
		RefreshTokenInfo: validateResult.RefreshTokenInfo,
	}

	newTokenResponse, err := m.tokenIssuer.GenerateTokenResponseForRefresh(r.Context(), refreshInput)
	if err != nil {
		return false, err
	}

	refreshToken := validateResult.RefreshToken
	refreshToken.Revoked = true
	err = m.database.UpdateRefreshToken(nil, refreshToken)
	if err != nil {
		return false, err
	}

	sess.Values[constants.SessionKeyJwt] = *newTokenResponse
	err = sess.Save(r, w)
	if err != nil {
		return false, err
	}

	if len(refreshToken.SessionIdentifier) > 0 {
		_, err := m.userSessionManager.BumpUserSession(r, refreshToken.SessionIdentifier, refreshToken.Code.ClientId)
		if err != nil {
			return false, err
		}
	}

	return true, nil
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

// RequiresScope is a middleware that checks if the user has the required scope to access the resource.
func (m *MiddlewareJwt) RequiresScope(
	scopesAnyOf []string,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			var jwtInfo security.JwtInfo
			var ok bool
			if r.Context().Value(constants.ContextKeyJwtInfo) != nil {
				jwtInfo, ok = r.Context().Value(constants.ContextKeyJwtInfo).(security.JwtInfo)
				if !ok {
					http.Error(w, "unable to cast the context value to JwtInfo in WithAuthorization middleware", http.StatusInternalServerError)
					return
				}
			}

			isAuthorized := m.authHelper.IsAuthorizedToAccessResource(jwtInfo, scopesAnyOf)

			// Ajax request?
			if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
				if !isAuthorized {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					_, err := w.Write([]byte(`{"error":"unauthorized"}`))
					if err != nil {
						http.Error(w, fmt.Sprintf("unable to write the response in WithAuthorization middleware: %v", err.Error()), http.StatusInternalServerError)
					}
					return
				}
			} else {
				sess, err := m.sessionStore.Get(r, constants.SessionName)
				if err != nil {
					http.Error(w, fmt.Sprintf("unable to get the session in WithAuthorization middleware: %v", err.Error()), http.StatusInternalServerError)
					return
				}

				if !isAuthorized {
					var redirectCount int
					if sess.Values[constants.SessionKeyRedirToAuthorizeCount] != nil {
						redirectCount, ok = sess.Values[constants.SessionKeyRedirToAuthorizeCount].(int)
						if !ok {
							http.Error(w, "unable to cast the session value (SessionKeyRedirToAuthorizeCount) to int in WithAuthorization middleware", http.StatusInternalServerError)
							return
						}
						redirectCount++
					} else {
						redirectCount = 1
					}
					sess.Values[constants.SessionKeyRedirToAuthorizeCount] = redirectCount

					if redirectCount > 2 {
						// reset the counter
						delete(sess.Values, constants.SessionKeyRedirToAuthorizeCount)
						err = sess.Save(r, w)
						if err != nil {
							http.Error(w, fmt.Sprintf("unable to save the session in WithAuthorization middleware: %v", err.Error()), http.StatusInternalServerError)
							return
						}

						// prevent infinite loop
						// redirect to unauthorized page
						http.Redirect(w, r, "/unauthorized", http.StatusFound)
						return
					}

					err = m.authHelper.RedirToAuthorize(w, r, constants.SystemClientIdentifier, lib.GetBaseUrl()+r.RequestURI)
					if err != nil {
						http.Error(w, fmt.Sprintf("unable to redirect to authorize in WithAuthorization middleware: %v", err.Error()), http.StatusInternalServerError)
					}
					return
				} else {
					// reset the counter
					delete(sess.Values, constants.SessionKeyRedirToAuthorizeCount)
					err = sess.Save(r, w)
					if err != nil {
						http.Error(w, fmt.Sprintf("unable to save the session in WithAuthorization middleware: %v", err.Error()), http.StatusInternalServerError)
						return
					}
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
