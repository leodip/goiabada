package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/httprate"
	"github.com/leodip/goiabada/core/oauth"
)

type AuthHelper interface {
	GetAuthContext(r *http.Request) (*oauth.AuthContext, error)
}

type RateLimiterMiddleware struct {
	authHelper      AuthHelper
	pwdLimiter      *httprate.RateLimiter
	otpLimiter      *httprate.RateLimiter
	activateLimiter *httprate.RateLimiter
	resetPwdLimiter *httprate.RateLimiter
	dcrLimiter      *httprate.RateLimiter
}

func NewRateLimiterMiddleware(authHelper AuthHelper) *RateLimiterMiddleware {
	return &RateLimiterMiddleware{
		authHelper:      authHelper,
		pwdLimiter:      httprate.NewRateLimiter(10, 1*time.Minute),
		otpLimiter:      httprate.NewRateLimiter(10, 1*time.Minute),
		activateLimiter: httprate.NewRateLimiter(5, 5*time.Minute),
		resetPwdLimiter: httprate.NewRateLimiter(5, 5*time.Minute),
		dcrLimiter:      httprate.NewRateLimiter(10, 1*time.Minute), // RFC 7591 §3 DoS protection
	}
}

func (m *RateLimiterMiddleware) LimitPwd(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email := r.FormValue("email")

		if m.pwdLimiter.RespondOnLimit(w, r, email) {
			slog.Error("Rate limiter - limit reached (pwd)", "email", email)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (m *RateLimiterMiddleware) LimitOtp(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authContext, err := m.authHelper.GetAuthContext(r)
		if err != nil {
			slog.Error("Rate limiter - unable to get auth context", "error", err)
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

func (m *RateLimiterMiddleware) LimitActivate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email := r.URL.Query().Get("email")

		if m.activateLimiter.RespondOnLimit(w, r, email) {
			slog.Error("Rate limiter - limit reached (activate)", "email", email)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (m *RateLimiterMiddleware) LimitResetPwd(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email := r.URL.Query().Get("email")

		if m.resetPwdLimiter.RespondOnLimit(w, r, email) {
			slog.Error("Rate limiter - limit reached (resetPwd)", "email", email)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// LimitDCR rate limits Dynamic Client Registration requests (RFC 7591 §3)
func (m *RateLimiterMiddleware) LimitDCR(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Use IP address as rate limit key
		clientIP := getClientIPFromRequest(r)

		if m.dcrLimiter.RespondOnLimit(w, r, clientIP) {
			slog.Error("Rate limiter - limit reached (DCR)", "ip", clientIP)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// getClientIPFromRequest extracts client IP from request (helper for rate limiting)
func getClientIPFromRequest(r *http.Request) string {
	// Check X-Forwarded-For header (if behind proxy)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fallback to RemoteAddr (strip port if present)
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		// Check if it's IPv6 with port (e.g., [::1]:12345) or IPv4 with port (e.g., 127.0.0.1:12345)
		if strings.HasPrefix(ip, "[") {
			// IPv6 with port: [::1]:12345 -> [::1]
			ip = ip[:idx]
		} else if strings.Count(ip, ":") == 1 {
			// IPv4 with port: 127.0.0.1:12345 -> 127.0.0.1
			ip = ip[:idx]
		}
		// else: IPv6 without port, leave as-is
	}
	return ip
}
