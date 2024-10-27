package middleware

import (
	"context"
	"net/http"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/oauth"
)

func SessionIdentifierToContext() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			if r.Context().Value(constants.ContextKeyJwtInfo) != nil {
				jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
				if !ok {
					http.Error(w, "unable to cast the context value to JwtInfo in SessionIdentifierToContext", http.StatusInternalServerError)
					return
				}

				if jwtInfo.AccessToken != nil {
					sessionIdentifier := jwtInfo.AccessToken.GetStringClaim("sid")
					if sessionIdentifier != "" {
						// add to context
						ctx = context.WithValue(ctx, constants.ContextKeySessionIdentifier, sessionIdentifier)
					}
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(fn)
	}
}
