package middleware

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/httprate"
	"github.com/leodip/goiabada/core/oauth"
)

type AuthHelper interface {
	GetAuthContext(r *http.Request) (*oauth.AuthContext, error)
}

type RateLimiterMiddleware struct {
	authHelper         AuthHelper
	enabled            bool
	pwdLimiter         *httprate.RateLimiter
	pwdIpLimiter       *httprate.RateLimiter
	otpLimiter         *httprate.RateLimiter
	activateLimiter    *httprate.RateLimiter
	resetPwdLimiter    *httprate.RateLimiter
	forgotPwdLimiter   *httprate.RateLimiter
	forgotPwdIpLimiter *httprate.RateLimiter
	dcrLimiter         *httprate.RateLimiter
	ropcLimiter        *httprate.RateLimiter // RFC 6749 §4.3.2 MUST protect against brute force
}

func NewRateLimiterMiddleware(authHelper AuthHelper, enabled bool) *RateLimiterMiddleware {
	return &RateLimiterMiddleware{
		authHelper:      authHelper,
		enabled:         enabled,
		pwdLimiter:      httprate.NewRateLimiter(15, 1*time.Minute), // per-email: bounds brute force on one account
		pwdIpLimiter:    httprate.NewRateLimiter(30, 1*time.Minute), // per-IP: stops one host hammering many accounts
		otpLimiter:      httprate.NewRateLimiter(10, 1*time.Minute),
		// per-IP: 10 activation operations per 5 minutes, at the two requests an activation
		// now costs (the link's GET, the clean GET). The same operation rate as
		// resetPwdLimiter over a chain one request shorter (#112)
		activateLimiter: httprate.NewRateLimiter(20, 5*time.Minute),
		// per-IP: 10 reset operations per 5 minutes, at the three requests a reset now
		// costs (the link's GET, the clean GET, the clean POST). Half of what
		// forgotPwdIpLimiter allows, which is the only other endpoint with an IP tier (#112)
		resetPwdLimiter:    httprate.NewRateLimiter(30, 5*time.Minute),
		forgotPwdLimiter:   httprate.NewRateLimiter(5, 5*time.Minute),  // per-email: mail-bomb protection
		forgotPwdIpLimiter: httprate.NewRateLimiter(20, 5*time.Minute), // per-IP: resource DoS protection
		dcrLimiter:         httprate.NewRateLimiter(10, 1*time.Minute), // RFC 7591 §3 DoS protection
		ropcLimiter:        httprate.NewRateLimiter(5, 1*time.Minute),  // RFC 6749 §4.3.2 brute force protection
	}
}

func (m *RateLimiterMiddleware) LimitPwd(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting if disabled
		if !m.enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Per-IP ceiling first: stops a single host from hammering many distinct
		// accounts. The client IP is trustworthy here (resolved by MiddlewareRealIP).
		clientIP := GetClientIPFromRequest(r)
		if m.pwdIpLimiter.RespondOnLimit(w, r, clientIP) {
			slog.Error("Rate limiter - limit reached (pwd, by IP)", "ip", clientIP)
			return
		}

		// Per-account limit: bounds brute force against a single email.
		email := r.FormValue("email")
		if m.pwdLimiter.RespondOnLimit(w, r, email) {
			slog.Error("Rate limiter - limit reached (pwd, by email)", "email", email)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (m *RateLimiterMiddleware) LimitOtp(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting if disabled
		if !m.enabled {
			next.ServeHTTP(w, r)
			return
		}

		authContext, err := m.authHelper.GetAuthContext(r)
		if err != nil {
			// No readable auth context means there is no user to key a bucket on, so hand
			// the request to the handler, which answers a missing auth context the same way
			// every other step of the auth flow does. It rejects the request before reaching
			// the OTP secret or the database, so the skipped limit costs nothing. Returning
			// here instead writes no response at all, which net/http turns into a blank 200
			// (#114).
			next.ServeHTTP(w, r)
			return
		}

		// Use user ID as rate limit key since we already authenticated the user
		key := fmt.Sprintf("user_%d", authContext.UserId)

		if m.otpLimiter.RespondOnLimit(w, r, key) {
			slog.Error("Rate limiter - limit reached (otp)", "userId", authContext.UserId)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// LimitActivate rate limits the account activation endpoint, on the client IP.
//
// It used to key on ?email=, which the activation link no longer carries: the link holds the
// verification code alone, and the step after it runs on a URL with no query at all (#112).
// Left as it was, every request would key on the empty string and the whole deployment would
// share one bucket, which would stop anyone activating an account once a handful of people
// had.
//
// The threat model moved with it, as it did for LimitResetPwd. The code is the sole
// credential at 193 bits of entropy, so blind guessing is infeasible; what is left to bound is
// one host driving unauthenticated account creation, which an IP key does.
func (m *RateLimiterMiddleware) LimitActivate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting if disabled
		if !m.enabled {
			next.ServeHTTP(w, r)
			return
		}

		// The client IP is trustworthy here (resolved by MiddlewareRealIP).
		clientIP := GetClientIPFromRequest(r)
		if m.activateLimiter.RespondOnLimit(w, r, clientIP) {
			slog.Error("Rate limiter - limit reached (activate, by IP)", "ip", clientIP)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// LimitResetPwd rate limits the password reset endpoint, on the client IP.
//
// It used to key on ?email=, which the reset link no longer carries: the link holds the
// verification code alone, and the two steps after it run on a URL with no query at all
// (#112). Left as it was, every request would key on the empty string and the whole
// deployment would share one bucket, which is a denial of service on password reset.
//
// The threat model moved with it. The code is now the sole credential at 193 bits of
// entropy, so blind guessing is infeasible and the per-account tier was never what bounded
// it; what is left to bound is one host driving unauthenticated work, which an IP key does.
// Matches the pwdIpLimiter and forgotPwdIpLimiter precedent.
func (m *RateLimiterMiddleware) LimitResetPwd(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting if disabled
		if !m.enabled {
			next.ServeHTTP(w, r)
			return
		}

		// The client IP is trustworthy here (resolved by MiddlewareRealIP).
		clientIP := GetClientIPFromRequest(r)
		if m.resetPwdLimiter.RespondOnLimit(w, r, clientIP) {
			slog.Error("Rate limiter - limit reached (resetPwd, by IP)", "ip", clientIP)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// LimitForgotPwd rate limits the forgot-password POST, which for a real user
// triggers a DB write, template render and SMTP send. It bounds both a single
// address (mail-bombing) and a single source IP (resource DoS / spraying many
// addresses).
func (m *RateLimiterMiddleware) LimitForgotPwd(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting if disabled
		if !m.enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Per-IP ceiling: stops one host from mail-bombing many addresses. The
		// client IP is trustworthy here (resolved by MiddlewareRealIP).
		clientIP := GetClientIPFromRequest(r)
		if m.forgotPwdIpLimiter.RespondOnLimit(w, r, clientIP) {
			slog.Error("Rate limiter - limit reached (forgot-password, by IP)", "ip", clientIP)
			return
		}

		// Per-email limit: prevents mail-bombing a specific address.
		email := r.FormValue("email")
		if m.forgotPwdLimiter.RespondOnLimit(w, r, email) {
			slog.Error("Rate limiter - limit reached (forgot-password, by email)", "email", email)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// LimitDCR rate limits Dynamic Client Registration requests (RFC 7591 §3)
func (m *RateLimiterMiddleware) LimitDCR(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting if disabled
		if !m.enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Use IP address as rate limit key
		clientIP := GetClientIPFromRequest(r)

		if m.dcrLimiter.RespondOnLimit(w, r, clientIP) {
			slog.Error("Rate limiter - limit reached (DCR)", "ip", clientIP)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// GetClientIPFromRequest extracts the client IP used as a rate-limit key.
//
// It reads only r.RemoteAddr, which MiddlewareRealIP has already resolved to the
// trustworthy client IP (from the socket peer and, when configured, the trusted
// forwarded headers). It never re-parses X-Forwarded-For / X-Real-IP here, which
// would reintroduce a spoofable path.
//
// Exported because the reset-password handler audits the same value the limiter keys on
// (#112): the failed-reset audit entry no longer has an address to record, so the client IP
// is the identifier an administrator watching for probing has. A second copy of these three
// lines in the handler package would be free to drift from this one.
func GetClientIPFromRequest(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// LimitROPC rate limits Resource Owner Password Credentials requests.
// RFC 6749 Section 4.3.2 MUST: "the authorization server MUST protect the endpoint
// against brute force attacks (e.g., using rate-limitation or generating alerts)."
// SECURITY NOTE: ROPC is deprecated in OAuth 2.1 due to credential exposure risks.
func (m *RateLimiterMiddleware) LimitROPC(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting if disabled
		if !m.enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Only apply to grant_type=password requests
		// Parse form to check grant_type (don't consume body)
		if err := r.ParseForm(); err != nil {
			next.ServeHTTP(w, r)
			return
		}

		if r.PostFormValue("grant_type") != "password" {
			next.ServeHTTP(w, r)
			return
		}

		// Rate limit by combination of username + client_id + IP
		// This prevents:
		// 1. Brute force on a specific user account
		// 2. Enumeration attacks across users from same IP
		// 3. Distributed attacks on a single user
		username := r.PostFormValue("username")
		clientId := r.PostFormValue("client_id")
		clientIP := GetClientIPFromRequest(r)

		// Use composite key for more precise rate limiting
		key := fmt.Sprintf("ropc_%s_%s_%s", clientId, username, clientIP)

		if m.ropcLimiter.RespondOnLimit(w, r, key) {
			slog.Error("Rate limiter - limit reached (ROPC)",
				"username", username,
				"clientId", clientId,
				"ip", clientIP)
			return
		}

		next.ServeHTTP(w, r)
	})
}
