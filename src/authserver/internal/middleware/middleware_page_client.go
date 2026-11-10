package middleware

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
)

// PageClient puts an empty reqctx.PageClient on every page request, which the code that learns the
// client a page is drawn for names it on, and the renderer reads the page's brand from (#812). A page
// whose client nobody names is drawn in the default brand.
//
// It is mounted on the page branch alone: the other branches draw no page, and a page rendered for a
// fault there is drawn in the default.
func PageClient() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(reqctx.WithPageClient(r.Context(), &reqctx.PageClient{})))
		})
	}
}

// signInCeremonies is what SignInPageClient reads: the sign-in a step's request names.
type signInCeremonies interface {
	GetAuthContext(r *http.Request) (*ceremony.AuthContext, error)
}

// SignInPageClient names the client of the sign-in a step's request names, when the browser holds
// it, as the client the request's pages are drawn for: the step's own page, its refusals, its 500
// page, a rate limiter's refusal ahead of it, and the form_post page that delivers its answer (#812).
// It reads the sign-in as the step boundary loads it (ceremony.Store.GetAuthContext), so a page is
// drawn in the brand of the sign-in it acts on, and no other.
//
// A request naming no sign-in the browser holds, or none, names no client, and every page it is
// answered with is drawn in the default brand: the page saying a sign-in is no longer active above
// all. A sign-in that cannot be read is left to the step to answer. It writes nothing and refuses
// nothing.
//
// It is mounted on the sign-in's step routes, ahead of every guard and limiter there, beneath
// PageClient.
func SignInPageClient(ceremonies signInCeremonies) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if authContext, err := ceremonies.GetAuthContext(r); err == nil && authContext != nil {
				reqctx.NamePageClient(r.Context(), authContext.ClientId)
			}
			next.ServeHTTP(w, r)
		})
	}
}
