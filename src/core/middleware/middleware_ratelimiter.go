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
	enabled         bool
	pwdLimiter      *httprate.RateLimiter
	otpLimiter      *httprate.RateLimiter
	activateLimiter *httprate.RateLimiter
	resetPwdLimiter *httprate.RateLimiter
	dcrLimiter      *httprate.RateLimiter
	ropcLimiter     *httprate.RateLimiter // RFC 6749 §4.3.2 MUST protect against brute force
}

func NewRateLimiterMiddleware(authHelper AuthHelper, enabled bool) *RateLimiterMiddleware {
	return &RateLimiterMiddleware{
		authHelper:      authHelper,
		enabled:         enabled,
		pwdLimiter:      httprate.NewRateLimiter(10, 1*time.Minute),
		otpLimiter:      httprate.NewRateLimiter(10, 1*time.Minute),
		activateLimiter: httprate.NewRateLimiter(5, 5*time.Minute),
		resetPwdLimiter: httprate.NewRateLimiter(5, 5*time.Minute),
		dcrLimiter:      httprate.NewRateLimiter(10, 1*time.Minute), // RFC 7591 §3 DoS protection
		ropcLimiter:     httprate.NewRateLimiter(5, 1*time.Minute),  // RFC 6749 §4.3.2 brute force protection
	}
}

func (m *RateLimiterMiddleware) LimitPwd(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting if disabled
		if !m.enabled {
			next.ServeHTTP(w, r)
			return
		}

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
		// Skip rate limiting if disabled
		if !m.enabled {
			next.ServeHTTP(w, r)
			return
		}

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
		// Skip rate limiting if disabled
		if !m.enabled {
			next.ServeHTTP(w, r)
			return
		}

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
		// Skip rate limiting if disabled
		if !m.enabled {
			next.ServeHTTP(w, r)
			return
		}

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
		// Skip rate limiting if disabled
		if !m.enabled {
			next.ServeHTTP(w, r)
			return
		}

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
		clientIP := getClientIPFromRequest(r)

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
