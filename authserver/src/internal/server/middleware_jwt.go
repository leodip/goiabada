package server

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"

	"github.com/gorilla/sessions"

	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/security"
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
	authHelper   authHelper
	tokenParser  tokenParser
	sessionStore sessions.Store
}

func NewMiddlewareJwt(authHelper authHelper, tokenParser tokenParser, sessionStore sessions.Store) *MiddlewareJwt {
	return &MiddlewareJwt{
		authHelper:   authHelper,
		tokenParser:  tokenParser,
		sessionStore: sessionStore,
	}
}

// JwtSessionToContext is a middleware that extracts the JWT token from the session and stores it in the context.
func (m *MiddlewareJwt) JwtSessionToContext() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			sess, err := m.sessionStore.Get(r, constants.SessionName)
			if err != nil {
				http.Error(w, fmt.Sprintf("unable to get the session in JwtSessionToContext middleware: %v", err.Error()),
					http.StatusInternalServerError)
				return
			}

			if sess.Values[constants.SessionKeyJwt] != nil {
				tokenResponse, ok := sess.Values[constants.SessionKeyJwt].(security.TokenResponse)
				if !ok {
					http.Error(w, "unable to cast the session value to TokenResponse in JwtSessionToContext middleware",
						http.StatusInternalServerError)
					return
				}
				jwtInfo, err := m.tokenParser.DecodeAndValidateTokenResponse(r.Context(), &tokenResponse)
				if err == nil {
					ctx = context.WithValue(ctx, constants.ContextKeyJwtInfo, *jwtInfo)
				}
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// JwtAuthorizationHeaderToContext is a middleware that extracts the JWT token from the Authorization header and stores it in the context.
func (m *MiddlewareJwt) JwtAuthorizationHeaderToContext() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			const BEARER_SCHEMA = "Bearer "
			authHeader := r.Header.Get("Authorization")
			if len(authHeader) < len(BEARER_SCHEMA) {
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			tokenStr := authHeader[len(BEARER_SCHEMA):]

			token, err := m.tokenParser.DecodeAndValidateTokenString(ctx, tokenStr, nil)
			if err == nil {
				ctx = context.WithValue(ctx, constants.ContextKeyBearerToken, *token)
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

					m.authHelper.RedirToAuthorize(w, r, constants.SystemClientIdentifier, lib.GetBaseUrl()+r.RequestURI)
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
