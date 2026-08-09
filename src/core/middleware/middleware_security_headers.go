package middleware

import "net/http"

// strictTransportSecurityValue is the Strict-Transport-Security value: a one-year
// max-age (the commonly recommended value) plus includeSubDomains. No `preload`
// directive is emitted, since preload is a long-lived commitment that is hard to
// reverse.
const strictTransportSecurityValue = "max-age=31536000; includeSubDomains"

// MiddlewareSecurityHeaders sets baseline security response headers on every
// response. It is installed early in the chain (before Recoverer) so that even
// panic (500) responses carry the headers.
//
// Headers set:
//
//   - X-Frame-Options: DENY and Content-Security-Policy: frame-ancestors 'none'
//     block clickjacking (the login/consent/OTP pages are never meant to be
//     framed). The CSP carries only the frame-ancestors directive, so it does
//     not restrict scripts/styles and cannot break inline template content.
//
//   - X-Content-Type-Options: nosniff stops MIME sniffing (this also protects
//     the image-serving endpoints).
//
//   - Referrer-Policy: same-origin keeps sensitive auth URLs (codes, state) out
//     of Referer headers sent to other origins, which is the case that matters:
//     an authorization code or state value must never travel to a third party.
//     Within our own origin the full URL is still sent, which is harmless.
//
//     It must NOT be no-referrer, even though that looks stricter. Under
//     no-referrer a browser sends "Origin: null" on form POSTs as well as
//     omitting Referer, and an opaque origin has no host for the CSRF origin
//     check to compare against Host. It once broke every cookie-authenticated
//     POST outright: login, OTP, consent and every admin console form.
//
//     The blast radius is narrower now that the check is
//     net/http.CrossOriginProtection (#155). It consults Sec-Fetch-Site first
//     and allows a same-origin POST whatever the Origin header says, so a
//     browser new enough to send fetch metadata (2023 onwards) is unaffected by
//     an opaque origin. Only a browser predating it falls through to the Origin
//     comparison, where "null" still matches no host and is still rejected.
//     Same conclusion, smaller set of victims, and not worth courting for a
//     policy that buys nothing over same-origin. Verified in a browser across
//     four policies; same-origin, strict-origin-when-cross-origin and omitting
//     the header all send a usable Origin, and only no-referrer does not.
//
//   - Strict-Transport-Security is emitted only when secure is true (i.e. the
//     deployment serves over HTTPS); it is meaningless over plain HTTP.
func MiddlewareSecurityHeaders(secure bool) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Frame-Options", "DENY")
			h.Set("Content-Security-Policy", "frame-ancestors 'none'")
			h.Set("X-Content-Type-Options", "nosniff")
			// same-origin, not no-referrer. See the note above: no-referrer makes
			// browsers send "Origin: null" on form POSTs, which fails the CSRF
			// origin check on any browser that sends no Sec-Fetch-Site header.
			h.Set("Referrer-Policy", "same-origin")
			if secure {
				h.Set("Strict-Transport-Security", strictTransportSecurityValue)
			}
			next.ServeHTTP(w, r)
		})
	}
}
