package middleware

import "net/http"

// NoStore refuses caching of the response it wraps, with the pair
// RFC 6749 section 5.1 requires:
//
//	Cache-Control: no-store
//	Pragma: no-cache
//
// It heads the API branch, which carries the admin, account and session APIs
// and the public settings. Two responses there carry a credential outright:
// GET /api/v1/account/otp/enrollment serves a TOTP enrolment seed, and
// GET /api/v1/admin/clients/{id} returns a client secret decrypted. RFC 6749 section 5.1's MUST covers "any response
// containing tokens, credentials, or other sensitive information" and is not
// qualified by endpoint, so it reaches both. Without a directive a 200 is
// heuristically cacheable and RFC 9111 section 3 permits a cache to store it;
// RFC 9111 section 4.2.2 says an origin server that wants to prevent that has
// to say so explicitly.
//
// Three properties are load-bearing, and undoing any of them reopens the hole
// without failing a test that names it (#247):
//
//   - Both header fields, not just Cache-Control. RFC 9111 section 5.4
//     deprecates Pragma and OAuth 2.1 draft -13 section 3.2.3 drops it, but
//     RFC 6749 is the standards-track specification this server implements and
//     it says MUST. Every other no-store site in the tree writes the pair.
//
//   - Bare no-store. It is the only value RFC 6749 section 5.1 and OAuth 2.1
//     section 3.2.3 name. RFC 9111 section 5.2.2.5 says no-store already
//     "applies to both private and shared caches", so `private` is redundant;
//     `no-cache` is strictly weaker and `must-revalidate` governs reuse of a
//     stored response, which cannot arise when nothing may be stored.
//
//   - A middleware rather than a header written inside the JSON encoder. The
//     API writes bodies two ways, and 47 of its EncodeJSON call sites commit
//     the status with w.WriteHeader before encoding. A header set after the
//     status is committed is silently dropped, so an encoder-level write would
//     be lost in those 47 places while every test still passed. Running before
//     the handler is what makes this immune.
//
// Mount it FIRST on the branch, ahead of the settings read and of every group's
// debug middleware and auth guards. That is a requirement rather than a
// preference: the 401 and 403 refusals are written by the guard set's refusal
// writer, and the JSON 500 of a settings read that fails or a panic in front of
// the groups by the API's fault writer. Each sets its own Content-Type and calls
// WriteHeader, so anything mounted behind them would never write the pair on
// those answers. A refusal body is within RFC 6749 section 5.1's "other
// sensitive information" too (#825 decision 3).
//
// Handlers that set their own Cache-Control still win, since Header().Set
// replaces. Nothing under /api/ sets one.
//
// It heads both /userinfo chains for the same reason: the endpoint answers a user's claims, and its
// bare 401 to a request with no token is written by a guard (#714).
//
// It also heads the page branch's chain, ahead of the browser session's
// refresh, which can send the session cookie again on any answer there: a
// rendered page, a redirect, or the router's 405, so none of them can be
// stored by a shared cache and replayed to another visitor (#743 decision 9).
func NoStore() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("Cache-Control", "no-store")
			h.Set("Pragma", "no-cache")
			next.ServeHTTP(w, r)
		})
	}
}
