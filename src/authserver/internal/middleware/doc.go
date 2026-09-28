// Package middleware is the auth server's own request middleware, mounted by internal/server: the
// settings and session identifier writers and the bearer and scope guards that put the request's
// values on the context through reqctx, the audit switches read from those settings, the rate
// limiter, CORS for discovery and the endpoints a browser client calls, the logout exemption of
// the CSRF policy, no-store, and the API debug log. The middleware both processes mount is in
// core/middleware (#385, #433).
package middleware
