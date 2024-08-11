package server

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/sessions"

	"github.com/leodip/goiabada/adminconsole/internal/config"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/data"
	"github.com/leodip/goiabada/adminconsole/internal/encryption"
	"github.com/leodip/goiabada/adminconsole/internal/models"
	"github.com/leodip/goiabada/adminconsole/internal/oauth"
)

type tokenParser interface {
	DecodeAndValidateTokenResponse(ctx context.Context, tokenResponse *oauth.TokenResponse) (*oauth.JwtInfo, error)
	DecodeAndValidateTokenString(ctx context.Context, token string, pubKey *rsa.PublicKey) (*oauth.JwtToken, error)
}

type authHelper interface {
	RedirToAuthorize(w http.ResponseWriter, r *http.Request, clientIdentifier string, scope string, redirectBack string) error
	IsAuthorizedToAccessResource(jwtInfo oauth.JwtInfo, scopesAnyOf []string) bool
}

type MiddlewareJwt struct {
	sessionStore sessions.Store
	tokenParser  tokenParser
	database     data.Database
	authHelper   authHelper
}

func NewMiddlewareJwt(
	sessionStore sessions.Store,
	tokenParser tokenParser,
	database data.Database,
	authHelper authHelper,
) *MiddlewareJwt {
	return &MiddlewareJwt{
		sessionStore: sessionStore,
		tokenParser:  tokenParser,
		database:     database,
		authHelper:   authHelper,
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
				tokenResponse, ok := sess.Values[constants.SessionKeyJwt].(oauth.TokenResponse)
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
						err := sess.Save(r, w)
						if err != nil {
							http.Error(w, fmt.Sprintf("unable to save the session: %v", err.Error()), http.StatusInternalServerError)
							return
						}
						next.ServeHTTP(w, r)
						return
					}
				}

				// Get the latest token response from the session
				tokenResponse = sess.Values[constants.SessionKeyJwt].(oauth.TokenResponse)
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
	tokenResponse *oauth.TokenResponse,
) (bool, error) {
	sess, err := m.sessionStore.Get(r, constants.SessionName)
	if err != nil {
		return false, fmt.Errorf("unable to get session: %v", err)
	}

	if tokenResponse.RefreshToken == "" {
		return false, nil
	}

	client, err := m.database.GetClientByClientIdentifier(nil, constants.AdminConsoleClientIdentifier)
	if err != nil {
		return false, fmt.Errorf("unable to get client: %v", err)
	}

	settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

	clientSecretDecrypted, err := encryption.DecryptText(client.ClientSecretEncrypted, settings.AESEncryptionKey)
	if err != nil {
		return false, fmt.Errorf("unable to decrypt client secret: %v", err)
	}

	// Prepare the refresh token request
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", tokenResponse.RefreshToken)
	data.Set("client_id", constants.AdminConsoleClientIdentifier)
	data.Set("client_secret", clientSecretDecrypted)

	// Create the HTTP request
	req, err := http.NewRequest("POST", config.AuthServerBaseUrl+"/auth/token", strings.NewReader(data.Encode()))
	if err != nil {
		return false, fmt.Errorf("error creating refresh token request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send the request
	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("error sending refresh token request: %v", err)
	}
	defer resp.Body.Close()

	// Read the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("error reading refresh token response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("error response from server: %s", body)
	}

	// Parse the new token response
	var newTokenResponse oauth.TokenResponse
	err = json.Unmarshal(body, &newTokenResponse)
	if err != nil {
		return false, fmt.Errorf("error parsing refresh token response: %v", err)
	}

	// Update the session with the new token response
	sess.Values[constants.SessionKeyJwt] = newTokenResponse
	err = sess.Save(r, w)
	if err != nil {
		return false, fmt.Errorf("unable to save the session: %v", err)
	}

	return true, nil
}

// RequiresScope is a middleware that checks if the user has the required scope to access the resource.
func (m *MiddlewareJwt) RequiresScope(
	scopesAnyOf []string,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			var jwtInfo oauth.JwtInfo
			var ok bool
			if r.Context().Value(constants.ContextKeyJwtInfo) != nil {
				jwtInfo, ok = r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
				if !ok {
					http.Error(w, "unable to cast the context value to JwtInfo in RequiresScope middleware", http.StatusInternalServerError)
					return
				}
			}

			isAuthorized := m.authHelper.IsAuthorizedToAccessResource(jwtInfo, scopesAnyOf)
			if !isAuthorized {
				err := m.authHelper.RedirToAuthorize(w, r, constants.AdminConsoleClientIdentifier,
					m.buildScopeString(scopesAnyOf),
					config.AdminConsoleBaseUrl+r.RequestURI)
				if err != nil {
					http.Error(w, fmt.Sprintf("unable to redirect to authorize in RequiresScope middleware: %v", err.Error()), http.StatusInternalServerError)
				}
				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (m *MiddlewareJwt) buildScopeString(arr []string) string {
	result := "openid"

	for _, value := range arr {
		result += " " + value
	}

	return result
}
