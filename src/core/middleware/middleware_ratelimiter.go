package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
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
}

func NewRateLimiterMiddleware(authHelper AuthHelper) *RateLimiterMiddleware {
	return &RateLimiterMiddleware{
		authHelper:      authHelper,
		pwdLimiter:      httprate.NewRateLimiter(10, 1*time.Minute),
		otpLimiter:      httprate.NewRateLimiter(10, 1*time.Minute),
		activateLimiter: httprate.NewRateLimiter(5, 5*time.Minute),
		resetPwdLimiter: httprate.NewRateLimiter(5, 5*time.Minute),
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
