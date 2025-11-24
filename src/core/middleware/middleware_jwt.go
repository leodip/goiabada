package middleware

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
)

type tokenParser interface {
	DecodeAndValidateTokenResponse(tokenResponse *oauth.TokenResponse) (*oauth.JwtInfo, error)
	DecodeAndValidateTokenString(token string, pubKey *rsa.PublicKey, withExpirationCheck bool) (*oauth.JwtToken, error)
}

type authHelper interface {
	RedirToAuthorize(w http.ResponseWriter, r *http.Request, clientIdentifier string, scope string, redirectBack string) error
	IsAuthorizedToAccessResource(jwtInfo oauth.JwtInfo, scopesAnyOf []string) bool
	IsAuthenticated(jwtInfo oauth.JwtInfo) bool
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type MiddlewareJwt struct {
	sessionStore      sessions.Store
	sessionName       string
	tokenParser       tokenParser
	authHelper        authHelper
	httpClient        HTTPClient
	authServerBaseURL string
	baseURL           string
	clientID          string
	clientSecret      string
}

// NewMiddlewareJwt constructs a DB-free JWT middleware. It uses provided client
// credentials for refresh operations. If credentials are empty, refresh is disabled.
func NewMiddlewareJwt(
	sessionStore sessions.Store,
	sessionName string,
	tokenParser tokenParser,
	authHelper authHelper,
	httpClient HTTPClient,
	authServerBaseURL string,
	baseURL string,
	clientID string,
	clientSecret string,
) *MiddlewareJwt {
	return &MiddlewareJwt{
		sessionStore:      sessionStore,
		sessionName:       sessionName,
		tokenParser:       tokenParser,
		authHelper:        authHelper,
		httpClient:        httpClient,
		authServerBaseURL: authServerBaseURL,
		baseURL:           baseURL,
		clientID:          clientID,
		clientSecret:      clientSecret,
	}
}

// JwtAuthorizationHeaderToContext is a middleware that extracts the JWT token from the Authorization header and stores it in the context.
func (m *MiddlewareJwt) JwtAuthorizationHeaderToContext() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			const BEARER_SCHEMA = "Bearer "
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, BEARER_SCHEMA) && len(authHeader) >= len(BEARER_SCHEMA) {
				tokenStr := authHeader[len(BEARER_SCHEMA):]
				token, err := m.tokenParser.DecodeAndValidateTokenString(tokenStr, nil, true)
				if err == nil {
					ctx = context.WithValue(ctx, constants.ContextKeyBearerToken, *token)
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// JwtSessionHandler is a middleware that checks if the user has a valid JWT session.
// It will also refresh the token if needed.
func (m *MiddlewareJwt) JwtSessionHandler() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			sess, err := m.sessionStore.Get(r, m.sessionName)
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
				_, err := m.tokenParser.DecodeAndValidateTokenString(tokenResponse.AccessToken, nil, true)
				if err != nil {
					refreshed, err := m.refreshToken(w, r, &tokenResponse)
					if err != nil || !refreshed {
						// If refresh failed, clear the session and continue
						delete(sess.Values, constants.SessionKeyJwt)
						err := m.sessionStore.Save(r, w, sess)
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
				jwtInfo, err := m.tokenParser.DecodeAndValidateTokenResponse(&tokenResponse)
				if err == nil {
					settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

					// Check if any token has an invalid issuer
					hasInvalidIssuer := (jwtInfo.IdToken != nil && !jwtInfo.IdToken.IsIssuerValid(settings.Issuer)) ||
						(jwtInfo.AccessToken != nil && !jwtInfo.AccessToken.IsIssuerValid(settings.Issuer)) ||
						(jwtInfo.RefreshToken != nil && !jwtInfo.RefreshToken.IsIssuerValid(settings.Issuer))

					if hasInvalidIssuer {

						slog.Error("Invalid issuer in JWT token. Will clear the session and redirect to root")

						// Clear the session
						delete(sess.Values, constants.SessionKeyJwt)
						err := m.sessionStore.Save(r, w, sess)
						if err != nil {
							http.Error(w, fmt.Sprintf("unable to save the session: %v", err.Error()), http.StatusInternalServerError)
							return
						}

						// Redirect to root
						http.Redirect(w, r, "/", http.StatusFound)
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
	if tokenResponse.RefreshToken == "" {
		return false, nil
	}

	// Require configured confidential client
	clientID := m.clientID
	clientSecret := m.clientSecret
	if strings.TrimSpace(clientID) == "" || strings.TrimSpace(clientSecret) == "" {
		slog.Error("missing client credentials for refreshToken; skipping refresh")
		return false, fmt.Errorf("missing client credentials for refresh")
	}

	// Prepare the refresh token request
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", tokenResponse.RefreshToken)
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)

	// Create the HTTP request
	req, err := http.NewRequest("POST", m.authServerBaseURL+"/auth/token", strings.NewReader(data.Encode()))
	if err != nil {
		return false, fmt.Errorf("error creating refresh token request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send the request
	if m.httpClient == nil {
		slog.Error("http client is nil in refreshToken (middleware_jwt)")
	}
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("error sending refresh token request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

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

	sess, err := m.sessionStore.Get(r, m.sessionName)
	if err != nil {
		return false, fmt.Errorf("unable to get session: %v", err)
	}

	// Update the session with the new token response
	sess.Values[constants.SessionKeyJwt] = newTokenResponse
	err = m.sessionStore.Save(r, w, sess)
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
				if m.authHelper.IsAuthenticated(jwtInfo) {
					// User is authenticated but not authorized
					// Show the unauthorized page
					http.Redirect(w, r, "/unauthorized", http.StatusFound)
				} else {
					// User is not authenticated
					// Redirect to the authorize endpoint
                    clientID := constants.AdminConsoleClientIdentifier
                    if strings.TrimSpace(m.clientID) != "" {
                        clientID = m.clientID
                    }
                    err := m.authHelper.RedirToAuthorize(w, r, clientID,
                        m.buildScopeString(scopesAnyOf),
                        m.baseURL+r.RequestURI)
					if err != nil {
						http.Error(w, fmt.Sprintf("unable to redirect to authorize in RequiresScope middleware: %v", err.Error()), http.StatusInternalServerError)
					}
				}
				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (m *MiddlewareJwt) buildScopeString(customScopes []string) string {

	// Default required scopes
	defaultScopes := []string{
		"openid",
		"email",
		constants.AuthServerResourceIdentifier + ":" + constants.ManageAccountPermissionIdentifier,
		constants.AuthServerResourceIdentifier + ":" + constants.ManagePermissionIdentifier,
	}

	scopeMap := make(map[string]bool)

	// Add default scopes first
	for _, scope := range defaultScopes {
		scopeMap[strings.ToLower(scope)] = true
	}

	// Add custom scopes
	for _, scope := range customScopes {
		scope = strings.ToLower(strings.TrimSpace(scope))
		if scope != "" {
			scopeMap[scope] = true
		}
	}

	var allScopes []string
	for scope := range scopeMap {
		allScopes = append(allScopes, scope)
	}
	sort.Strings(allScopes)

	return strings.Join(allScopes, " ")
}
