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
				tokenResponse, ok := sess.Values[constants.SessionKeyJwt].(security.TokenResponse)
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

func MiddlewareJwtAuthorizationHeaderToContext(next http.Handler, tokenParser tokenParser) http.HandlerFunc {

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

func MiddlewareRequiresScope(next http.Handler, server *Server, scopesAnyOf []string) http.HandlerFunc {

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

		isAuthorized := server.isAuthorizedToAccessResource(jwtInfo, scopesAnyOf)

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
					// redirect to unauthorized page
					http.Redirect(w, r, "/unauthorized", http.StatusFound)
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
