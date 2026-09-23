// Package middleware holds the request middleware both servers mount: the real
// client IP, the CSRF origin check and its exemption policy, the security
// headers, the request logger and the cookie reset. Each application's own
// middleware, such as its session, JWT and rate-limiting layers, lives in its
// internal/middleware.
package middleware
