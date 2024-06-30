package server

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"

	"github.com/gorilla/sessions"

	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/lib"
)

type tokenParser interface {
	DecodeAndValidateTokenResponse(ctx context.Context, tokenResponse *dtos.TokenResponse) (*dtos.JwtInfo, error)
	DecodeAndValidateTokenString(ctx context.Context, token string, pubKey *rsa.PublicKey) (*dtos.JwtToken, error)
}

func MiddlewareJwtSessionToContext(sessionStore sessions.Store, tokenParser tokenParser) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			sess, err := sessionStore.Get(r, constants.SessionName)
			if err != nil {
				http.Error(w, fmt.Sprintf("unable to get the session in JwtSessionToContext middleware: %v", err.Error()), http.StatusInternalServerError)
				return
			}

			if sess.Values[constants.SessionKeyJwt] != nil {
				tokenResponse, ok := sess.Values[constants.SessionKeyJwt].(dtos.TokenResponse)
				if !ok {
					http.Error(w, "unable to cast the session value to TokenResponse in JwtSessionToContext middleware", http.StatusInternalServerError)
					return
				}
				jwtInfo, err := tokenParser.DecodeAndValidateTokenResponse(r.Context(), &tokenResponse)
				if err == nil {
					ctx = context.WithValue(ctx, constants.ContextKeyJwtInfo, *jwtInfo)
				}
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func MiddlewareJwtAuthorizationHeaderToContext(next http.Handler, sessionStore sessions.Store,
	tokenParser tokenParser) http.HandlerFunc {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		const BEARER_SCHEMA = "Bearer "
		authHeader := r.Header.Get("Authorization")
		if len(authHeader) < len(BEARER_SCHEMA) {
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		tokenStr := authHeader[len(BEARER_SCHEMA):]

		token, err := tokenParser.DecodeAndValidateTokenString(ctx, tokenStr, nil)
		if err == nil {
			ctx = context.WithValue(ctx, constants.ContextKeyBearerToken, *token)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func MiddlewareRequiresScope(next http.Handler, server *Server, clientIdentifier string,
	scopesAnyOf []string) http.HandlerFunc {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		var jwtInfo dtos.JwtInfo
		var ok bool
		if r.Context().Value(constants.ContextKeyJwtInfo) != nil {
			jwtInfo, ok = r.Context().Value(constants.ContextKeyJwtInfo).(dtos.JwtInfo)
			if !ok {
				http.Error(w, "unable to cast the context value to JwtInfo in WithAuthorization middleware", http.StatusInternalServerError)
				return
			}
		}

		isAuthorized := server.isAuthorizedToAccessResource(jwtInfo, scopesAnyOf)

		// Ajax request?
		if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
			if !isAuthorized {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error":"unauthorized"}`))
				return
			}
		} else {
			sess, err := server.sessionStore.Get(r, constants.SessionName)
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
					server.handleUnauthorizedGet()(w, r)
					return
				}

				server.redirToAuthorize(w, r, constants.SystemClientIdentifier, lib.GetBaseUrl()+r.RequestURI)
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
