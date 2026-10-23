// Package httpmw holds the request middleware both servers mount: the real
// client IP, the CSRF origin check and its exemption policy, the request-body
// limit and its per-route policy, the security headers, the request logger, the
// panic recovery, the one-trailing-slash strip and the cookie reset; and, in
// statuswriter, the writer the request logger and the HTTP metrics read a
// response's status through. Each application's own middleware, such as its
// session, JWT and rate-limiting layers, lives in its internal/middleware. The
// name is not middleware, so a server that mounts all three needs no alias for
// this one.
package httpmw
