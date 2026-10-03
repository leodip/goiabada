package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/i18n"
)

// LocaleFromJWT reads the locale claim from the JWT info already on
// the request context (set by SessionHandler) and refines the localizer to
// it. It is the admin console's half of locale resolution: identity here is a
// validated ID token on every authenticated route, so the refinement is a
// middleware, where the auth server does it per handler once a password has
// been checked.
//
// The two things it does not do are both i18n.WithLocale's non-explicit
// contract rather than branches of its own: a request carrying explicit locale
// intent (?ui_locales) keeps it, and a missing claim falls through to the
// previously resolved localizer rather than silently jumping to English (older
// tokens, scope misconfiguration, a third-party admin client without the
// profile scope).
func LocaleFromJWT() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if refined := i18n.WithLocale(ctx, false, localeClaimFromJwt(ctx)); refined != ctx {
				r = r.WithContext(refined)
			}
			next.ServeHTTP(w, r)
		})
	}
}

func localeClaimFromJwt(ctx context.Context) string {
	jwtInfo, ok := reqctx.JwtInfoFrom(ctx)
	if !ok || jwtInfo.IdToken == nil {
		return ""
	}
	return strings.TrimSpace(jwtInfo.IdToken.StringClaim("locale"))
}
