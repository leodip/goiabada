package middleware

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/handlerhelpers"
)

// LogoutIdTokenHintPresent reports whether this is a POST to the logout endpoint carrying an
// id_token_hint, which is the one shape of /auth/logout that must work cross-site. It is the
// conditional entry of this server's CSRF policy, supplied at the composition root in
// internal/server/server.go.
//
// OpenID Connect RP-Initiated Logout 1.0 section 2 is a MUST here: "OpenID Providers MUST support
// the use of the HTTP GET and POST methods defined in RFC 7231". Without an exemption the origin
// check rejects every cross-origin POST, so the binding exists for relying parties that cannot reach
// it, and an RP that wants a self-submitting form to keep the ID token out of the URL has no way in.
//
// PRESENCE, not a value, and read through the same function the handler classifies the parameter
// with. The two readings must agree in one direction above all: this saying "present" where the
// handler reads "absent" would exempt a cross-site POST and then send it down the hintless branch,
// which tears the whole session down with no consent. Sharing handlerhelpers'
// LookupFromUrlQueryOrFormPost is what makes that agreement structural rather than a promise, and
// it is why "id_token_hint=" is exempt here and Rejected there (#109). Both ends are in this module
// now: the predicate left core/middleware with the policy that named it, and the handler it has to
// agree with is handlers.HandleAccountLogoutPost two packages away (#385).
//
// Presence alone is safe because middleware cannot judge whether a hint is genuine and the handler
// does not trust it to: a POST whose hint fails to validate tears nothing down, it is answered with
// a redirect to the GET binding and ends at the consent page. So the exemption buys an attacker a
// consent page they cannot confirm, which is where a plain link to /auth/logout already lands.
//
// POST only. Everything the origin check refuses is a POST here in practice, and confining it means
// the form parse below happens on one path and one method rather than on requests that have no
// business being read.
//
// Reading the body here does let a foreign origin have its body parsed before it is turned away,
// where the origin check would otherwise have rejected it on the headers alone. That is inherent
// to #109 decision 9 rather than introduced by reading the body: the same origin need only move the
// hint into the query to reach the handler, which parses the body itself to honour ui_locales. Go
// bounds the parse the same way it bounds every other form endpoint here.
func LogoutIdTokenHintPresent(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	// Reads the query first and only then the body, so a hint in the query costs no parse. When it
	// does parse, Go caches the result in r.PostForm and the handler's own r.FormValue reuses it,
	// which is what stops this middleware consuming the body the handler is about to read.
	_, present := handlerhelpers.LookupFromUrlQueryOrFormPost(r, "id_token_hint")
	return present
}
