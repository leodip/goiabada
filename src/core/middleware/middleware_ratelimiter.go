package middleware

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/httprate"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/oauth"
)

type AuthHelper interface {
	GetAuthContext(r *http.Request) (*oauth.AuthContext, error)
}

// ErrorRenderer renders an HTML error page. Declared here rather than imported for the
// reason AuthHelper is: the concrete type lives in a module that depends on core, so core
// can only name the shape it needs. *handlerhelpers.HttpHelper satisfies it.
type ErrorRenderer interface {
	RenderTemplate(w http.ResponseWriter, r *http.Request, layoutName string, templateName string,
		data map[string]interface{}) error
}

// AuditLogger records a security event. Same reasoning as ErrorRenderer: the concrete
// logger lives in the authserver module.
type AuditLogger interface {
	Log(auditEvent string, details map[string]interface{})
}

// rejectClass is the shape a rejected caller can parse. A browser gets the error page it
// would get from any other refusal; an OAuth2 or RFC 7591 client gets the JSON error
// object it is already parsing at that endpoint. Answering every route in plain text, as
// httprate's default does, breaks both machine callers (#219).
type rejectClass int

const (
	rejectBrowser rejectClass = iota
	rejectOAuth
)

// tier is one rate-limit bucket plus everything a rejection has to say about it.
//
// The pairing is the point. httprate.WithLimitHandler takes an http.HandlerFunc, so a
// reject reached through it learns neither which limiter tripped nor which bucket, and the
// audit event needs both while the log line needs the name. Holding them together means a
// limiter cannot be wired to another limiter's gate or another route's response shape.
type tier struct {
	rl    *httprate.RateLimiter
	name  string
	class rejectClass
	// keyField is the slog attribute the bucket key is logged under, empty when the key
	// names a person. The request logger in this package establishes that identifiers are
	// kept out of logs by allowlist rather than by denylist, and email is deliberately not
	// on that list, so the account tiers log their limiter name and nothing else. The
	// identifier is carried by the audit event instead, which is the surface built to hold
	// one (#219).
	keyField string
	// auditGate bounds the audit writes to one event per key per window. Its budget is 1
	// over the protected limiter's own window, so OnLimit returns false exactly once per
	// key per window and that first call is the report. Per limiter rather than one shared
	// gate: windows here are 1, 5 and 15 minutes, and a single shared duration would either
	// under-report the short windows by up to 15x or over-report the long ones.
	auditGate *httprate.RateLimiter
}

// rateLimitHeaders leaves Retry-After and blanks the four X-RateLimit-* names, which
// httprate's setHeader skips when the configured name is empty.
//
// They rode every response including successful ones, so any caller could read the exact
// budget, how much of it was left and whether the limiter was switched on at all without
// tripping anything. And on a two-tier limiter the second OnLimit overwrote the first, so
// /auth/pwd reported the per-email budget as though it were the per-IP one (#219).
// Retry-After stays because RFC 6585 Section 4 names it as what a 429 MAY carry.
var rateLimitHeaders = httprate.WithResponseHeaders(httprate.ResponseHeaders{
	RetryAfter: "Retry-After",
})

func newTier(name string, class rejectClass, keyField string, limit int, window time.Duration) *tier {
	return &tier{
		rl:        httprate.NewRateLimiter(limit, window, rateLimitHeaders),
		name:      name,
		class:     class,
		keyField:  keyField,
		auditGate: httprate.NewRateLimiter(1, window, rateLimitHeaders),
	}
}

type RateLimiterMiddleware struct {
	authHelper  AuthHelper
	renderer    ErrorRenderer
	auditLogger AuditLogger
	enabled     bool
	pwdLimiter  *tier
	pwdIp       *tier
	otp         *tier
	activate    *tier
	resetPwd    *tier
	forgotPwd   *tier
	forgotPwdIp *tier
	dcr         *tier
	ropc        *tier // RFC 6749 §4.3.2 MUST protect against brute force
}

func NewRateLimiterMiddleware(authHelper AuthHelper, renderer ErrorRenderer, auditLogger AuditLogger,
	enabled bool) *RateLimiterMiddleware {

	return &RateLimiterMiddleware{
		authHelper:  authHelper,
		renderer:    renderer,
		auditLogger: auditLogger,
		enabled:     enabled,
		// per-email: bounds brute force on one account
		pwdLimiter: newTier("pwd_email", rejectBrowser, "", 15, 1*time.Minute),
		// per-IP: stops one host hammering many accounts
		pwdIp: newTier("pwd_ip", rejectBrowser, "ip", 30, 1*time.Minute),
		otp:   newTier("otp", rejectBrowser, "", 10, 1*time.Minute),
		// per-IP: 10 activation operations per 5 minutes, at the two requests an activation
		// now costs (the link's GET, the clean GET). The same operation rate as
		// resetPwd over a chain one request shorter (#112)
		activate: newTier("activate", rejectBrowser, "ip", 20, 5*time.Minute),
		// per-IP: 10 reset operations per 5 minutes, at the three requests a reset now
		// costs (the link's GET, the clean GET, the clean POST). Half of what
		// forgotPwdIp allows, which is the only other endpoint with an IP tier (#112)
		resetPwd: newTier("reset_pwd", rejectBrowser, "ip", 30, 5*time.Minute),
		// per-email: mail-bomb protection
		forgotPwd: newTier("forgot_pwd_email", rejectBrowser, "", 5, 5*time.Minute),
		// per-IP: resource DoS protection
		forgotPwdIp: newTier("forgot_pwd_ip", rejectBrowser, "ip", 20, 5*time.Minute),
		// RFC 7591 §3 DoS protection
		dcr: newTier("dcr", rejectOAuth, "ip", 10, 1*time.Minute),
		// RFC 6749 §4.3.2 brute force protection
		ropc: newTier("ropc", rejectOAuth, "", 5, 1*time.Minute),
	}
}

// tripped charges one request against the tier's bucket and, when that trips the budget,
// reports the trip and writes the rejection. It returns true when the caller must stop.
//
// OnLimit rather than RespondOnLimit: RespondOnLimit's only addition is httprate's default
// handler, which answers "Too Many Requests\n" as text/plain on every route, and dropping
// it removes that default rather than overriding it. OnLimit sets Retry-After itself on the
// reject path, which is the one header a 429 keeps.
//
// details carries the identifier the audit event records, which is the one this limiter's
// neighbours in the audit log already carry for the same event: the email for account
// tiers, the user id for the OTP tier, the client block for IP tiers.
func (m *RateLimiterMiddleware) tripped(w http.ResponseWriter, r *http.Request, t *tier, key string,
	details map[string]interface{}) bool {

	if !t.rl.OnLimit(w, r, key) {
		return false
	}
	m.reportTrip(r, t, key, details)
	m.reject(w, r, t.class)
	return true
}

// reportTrip writes the two records a rejection leaves: a warning line every time, and an
// audit event at most once per key per window.
//
// Warn rather than Error because a limiter doing its job is an expected event, and an auth
// server whose error log fills with them has no error log left.
func (m *RateLimiterMiddleware) reportTrip(r *http.Request, t *tier, key string,
	details map[string]interface{}) {

	attrs := []any{"limiter", t.name}
	if t.keyField != "" {
		attrs = append(attrs, t.keyField, key)
	}
	slog.Warn("Rate limiter - limit reached", attrs...)

	if m.auditLogger == nil {
		return
	}
	// OnLimit is the only exported call that both reads and increments a bucket, so the
	// gate is asked with a throwaway writer: false means this key has not been reported in
	// this window yet, and that first call is the report.
	if t.auditGate.OnLimit(&discardResponseWriter{}, r, t.name+"|"+key) {
		return
	}
	if details == nil {
		details = map[string]interface{}{}
	}
	details["limiter"] = t.name
	m.auditLogger.Log(constants.AuditRateLimitExceeded, details)
}

// reject writes the 429 in the shape the route's caller parses.
func (m *RateLimiterMiddleware) reject(w http.ResponseWriter, r *http.Request, class rejectClass) {
	// RFC 6585 Section 4's "Responses with the 429 status code MUST NOT be stored by a
	// cache" binds caches rather than this origin. Saying it in the response is free and
	// makes the intent explicit to an intermediary that ignores the status code.
	w.Header().Set("Cache-Control", "no-store")

	if class == rejectOAuth {
		// RFC 6749 Section 5.2 puts the token error parameters in "the "application/json"
		// media type", and RFC 7591 Section 3.2.2 requires a registration error with
		// "content type application/json". Go writes no header for a hand-encoded body, so
		// without this the response would be JSON labelled text/plain.
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Pragma", "no-cache")
		w.WriteHeader(http.StatusTooManyRequests)
		// invalid_request because RFC 6749 Section 5.2 makes error "REQUIRED. A single
		// ASCII error code from the following", a closed list extended only through the
		// IANA registry, and it permits a status other than 400. slow_down is the
		// registry's only token-endpoint entry about request rate and it means "the
		// authorization request is still pending and polling should continue" (RFC 8628
		// Section 3.5), which would tell a conformant client to keep polling a rejected
		// request (#219).
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_request",
			"error_description": "Too many requests. Please wait and try again later.",
		})
		return
	}

	bind := map[string]interface{}{
		"title":       i18n.T(r.Context(), "auth_error.rate_limited.title"),
		"error":       i18n.T(r.Context(), "auth_error.rate_limited.message"),
		"_httpStatus": http.StatusTooManyRequests,
	}
	if err := m.renderer.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/auth_error.html", bind); err != nil {
		slog.Error("Rate limiter - unable to render the rejection page", "error", err)
		http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
	}
}

// discardResponseWriter absorbs what httprate writes when OnLimit is being used purely as
// a counter. The audit gate calls it for its return value alone and must not touch the
// real response.
type discardResponseWriter struct {
	header http.Header
}

func (d *discardResponseWriter) Header() http.Header {
	if d.header == nil {
		d.header = http.Header{}
	}
	return d.header
}

func (d *discardResponseWriter) Write(b []byte) (int, error) { return len(b), nil }

func (d *discardResponseWriter) WriteHeader(int) {}

func (m *RateLimiterMiddleware) LimitPwd(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting if disabled
		if !m.enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Per-IP ceiling first: stops a single host from hammering many distinct
		// accounts. The client IP is trustworthy here (resolved by MiddlewareRealIP).
		ipKey := clientIPRateLimitKey(r)
		if m.tripped(w, r, m.pwdIp, ipKey, map[string]interface{}{"ip": ipKey}) {
			return
		}

		// Per-account limit: bounds brute force against a single email.
		emailKey := accountRateLimitKey(r.FormValue("email"))
		if m.tripped(w, r, m.pwdLimiter, emailKey, map[string]interface{}{"email": emailKey}) {
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

		if m.tripped(w, r, m.otp, key, map[string]interface{}{"userId": authContext.UserId}) {
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
		ipKey := clientIPRateLimitKey(r)
		if m.tripped(w, r, m.activate, ipKey, map[string]interface{}{"ip": ipKey}) {
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
		ipKey := clientIPRateLimitKey(r)
		if m.tripped(w, r, m.resetPwd, ipKey, map[string]interface{}{"ip": ipKey}) {
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
		ipKey := clientIPRateLimitKey(r)
		if m.tripped(w, r, m.forgotPwdIp, ipKey, map[string]interface{}{"ip": ipKey}) {
			return
		}

		// Per-email limit: prevents mail-bombing a specific address.
		emailKey := accountRateLimitKey(r.FormValue("email"))
		if m.tripped(w, r, m.forgotPwd, emailKey, map[string]interface{}{"email": emailKey}) {
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
		ipKey := clientIPRateLimitKey(r)

		if m.tripped(w, r, m.dcr, ipKey, map[string]interface{}{"ip": ipKey}) {
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

// clientIPRateLimitKey buckets a request by the block its client controls: the address
// itself for IPv4, the /64 for IPv6. A host with SLAAC normally owns a whole /64, so
// keying on the full address hands one client 2^64 buckets, which voids every per-IP
// tier (measured: 200 of 200 requests allowed against a 30/min budget, #219).
//
// Separate from GetClientIPFromRequest, not folded into it, because that function also
// feeds two audit sinks that need the address an administrator can act on rather than
// the block it sits in.
//
// MiddlewareRealIP guarantees the input is a real IP: it drops X-Forwarded-For entries
// and an X-Real-IP that net.ParseIP rejects, and net/http guarantees RemoteAddr is
// host:port. That matters because CanonicalizeIP returns anything that is not an IP
// unchanged, "" included, which would put every such request in one global bucket.
func clientIPRateLimitKey(r *http.Request) string {
	return httprate.CanonicalizeIP(GetClientIPFromRequest(r))
}

// accountRateLimitKey buckets by the account an identifier names rather than by the
// spelling submitted. Deliberately stricter than the strictest engine: mysql and mssql
// compare email case-insensitively and postgres and sqlite do not, so without this the
// same account has one bucket on two engines and 2^18 on the other two (#219).
//
// The handlers that look the account up normalize identically, so the limiter and the
// account it protects cannot disagree about who the request is.
func accountRateLimitKey(identifier string) string {
	return strings.ToLower(strings.TrimSpace(identifier))
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
		ipKey := clientIPRateLimitKey(r)

		// Use composite key for more precise rate limiting
		key := fmt.Sprintf("ropc_%s_%s_%s", clientId, username, ipKey)

		if m.tripped(w, r, m.ropc, key, map[string]interface{}{
			"email":    accountRateLimitKey(username),
			"clientId": clientId,
		}) {
			return
		}

		next.ServeHTTP(w, r)
	})
}
