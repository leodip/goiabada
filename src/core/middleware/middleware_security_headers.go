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
//   - X-Frame-Options: DENY and Content-Security-Policy: frame-ancestors 'none'
//     block clickjacking (the login/consent/OTP pages are never meant to be
//     framed). The CSP carries only the frame-ancestors directive, so it does
//     not restrict scripts/styles and cannot break inline template content.
//   - X-Content-Type-Options: nosniff stops MIME sniffing (this also protects
//     the image-serving endpoints).
//   - Referrer-Policy: no-referrer keeps sensitive auth URLs (codes, state) out
//     of Referer headers.
//   - Strict-Transport-Security is emitted only when secure is true (i.e. the
//     deployment serves over HTTPS); it is meaningless over plain HTTP.
func MiddlewareSecurityHeaders(secure bool) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Frame-Options", "DENY")
			h.Set("Content-Security-Policy", "frame-ancestors 'none'")
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "no-referrer")
			if secure {
				h.Set("Strict-Transport-Security", strictTransportSecurityValue)
			}
			next.ServeHTTP(w, r)
		})
	}
}
