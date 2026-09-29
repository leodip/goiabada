package middleware

import (
	"net"
	"net/http"
)

// GetClientIPFromRequest is the one reader of the client IP in this module: the rate limiter's
// key, the address an authorization code and a user session record, and every audit entry that
// names one read it here, so all of them record the same value.
//
// It reads only r.RemoteAddr, which MiddlewareRealIP has already resolved to the
// trustworthy client IP (from the socket peer and, when configured, the trusted
// forwarded headers). It never re-parses X-Forwarded-For / X-Real-IP here, which
// would reintroduce a spoofable path.
//
// In production MiddlewareRealIP has written a bare IP, so the port strip below changes nothing
// there; it is what keeps a request that never passed that middleware, which is every handler
// unit test, from recording "192.0.2.1:1234" where the server records "192.0.2.1". Two readers
// returned r.RemoteAddr as is until #435, so DCR's audit and the authorization code's address
// differed from the other sinks on exactly those requests.
func GetClientIPFromRequest(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
