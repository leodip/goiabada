package middleware

import (
	"context"
	"net/http"

	"github.com/leodip/goiabada/core/constants"
	custom_middleware "github.com/leodip/goiabada/core/middleware"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pkg/errors"
)

// SessionIdentifierToContext lifts the session identifier out of the validated JWT
// and onto the context.
//
// errorRenderer answers the one failure below. It is core/middleware's interface
// rather than a second copy of the same shape, and the caller passes the same
// *handlerhelpers.HttpHelper it passes to NewMiddlewareJwt. This middleware runs on
// the application branch, after the settings cache and the locale middleware, so
// the error page has both the settings its layout renders from and the localizer it
// translates through.
func SessionIdentifierToContext(errorRenderer custom_middleware.ServerErrorRenderer) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			if r.Context().Value(constants.ContextKeyJwtInfo) != nil {
				jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
				if !ok {
					errorRenderer.InternalServerError(w, r,
						errors.WithStack(errors.New("unable to cast the context value to JwtInfo in SessionIdentifierToContext")))
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
