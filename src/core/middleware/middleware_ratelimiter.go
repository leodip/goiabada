package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/httprate"
	"github.com/leodip/goiabada/core/api"
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
// object it is already parsing at that endpoint; a caller of the account or admin API gets
// that API's own error envelope. Answering every route in plain text, as httprate's default
// does, breaks both machine callers (#219).
type rejectClass int

const (
	rejectBrowser rejectClass = iota
	rejectOAuth
	rejectAPI
)

// tier is one rate-limit bucket plus everything a rejection has to say about it.
//
// The pairing is the point. httprate.WithLimitHandler takes an http.HandlerFunc, so a
// reject reached through it learns neither which limiter tripped nor which bucket, and the
// audit event needs both while the log line needs the name.
//
// The reject class is deliberately NOT here, and it used to be. A bucket can serve two
// routes whose callers parse different things: accountFailureGate is shared by the browser
// password form and the ROPC grant, so a class held on the tier would answer the token
// endpoint with an HTML error page. The shape of a refusal belongs to the caller being
// refused, so every refusal names it (#219).
type tier struct {
	rl   *httprate.RateLimiter
	name string
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
	// window is what Retry-After carries, which is the value httprate itself writes.
	// Kept here because a failures-only tier refuses without ever calling OnLimit, so
	// nothing else on that path knows the window (#219).
	window time.Duration
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

func newTier(name string, keyField string, limit int, window time.Duration) *tier {
	return &tier{
		rl:        httprate.NewRateLimiter(limit, window, rateLimitHeaders),
		name:      name,
		keyField:  keyField,
		auditGate: httprate.NewRateLimiter(1, window, rateLimitHeaders),
		window:    window,
	}
}

// failureTier is a tier only a failed credential check can spend.
//
// Every other tier increments in middleware, before the handler knows whether the
// credential was right, which costs a legitimate sign-in from the same allowance an
// attacker spends and is what makes a tight budget unsafe. Counting failures only is what
// lets the budgets here sit one to two orders of magnitude below the request budgets they
// replace: a user who signs in, verifies a code or changes a password successfully never
// touches the counter (#219).
//
// The mutex and inFlight are not bookkeeping. httprate serializes check-and-increment
// inside OnLimit, but Status only reads, so a gate written as read, check credential,
// charge admits every caller that reads before anyone charges: measured at 141 of 1000
// overlapping callers against a budget of 10, and the sample varies between runs because it
// is scheduler-dependent, which is the finding. The attacker picks the concurrency.
type failureTier struct {
	tier
	limit int
	mu    sync.Mutex
	// inFlight counts the reservations currently held per key. It self-cleans: the entry
	// is deleted at zero, so it holds only what is genuinely in flight.
	inFlight map[string]int
}

// newFailureTier takes no keyField, unlike newTier, because a failures-only tier is by
// construction keyed on an identifier that names a person: only a credential check can
// spend one, and the credential names the account. That is exactly the case tier.keyField
// must be empty for, so the empty value is passed here rather than at each call site,
// which makes the invariant structural instead of something every caller has to remember
// (#219).
func newFailureTier(name string, limit int, window time.Duration) *failureTier {
	return &failureTier{
		tier:     *newTier(name, "", limit, window),
		limit:    limit,
		inFlight: map[string]int{},
	}
}

// Reserve claims one slot against key's budget, atomically with reading what is already
// recorded, and reports whether another credential check may proceed.
//
// The predicate is RespondOnLimit's own, round(rate)+1 > limit, plus the in-flight count.
// Deliberately not Status's own bool, which reports over-limit only at rate > limit, one
// attempt looser: taking it would silently grant every failures-only budget an extra
// attempt and falsify the numbers published in the reference documentation.
//
// Returns false when Status errors, so the gate fails closed. That branch is unreachable
// through the middleware, since httprate's in-process counter documents that all its
// methods always return a nil error, but the direction has to be stated because it is the
// one an error path gets wrong.
func (f *failureTier) Reserve(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	_, rate, err := f.rl.Status(key)
	if err != nil {
		return false
	}
	if int(math.Round(rate))+f.inFlight[key]+1 > f.limit {
		return false
	}
	f.inFlight[key]++
	return true
}

// Release hands the slot back, charging it first when the credential was wrong.
//
// OnLimit is the only exported call that increments, so it is asked with a throwaway
// writer purely for its side effect. Charging before dropping the slot keeps recorded plus
// in-flight from ever dipping below what has been spent; the transient double-count that
// produces refuses one extra caller rather than admitting one, which is the safe direction.
func (f *failureTier) Release(r *http.Request, key string, failed bool) {
	if failed {
		f.rl.OnLimit(&discardResponseWriter{}, r, key)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if n := f.inFlight[key]; n <= 1 {
		delete(f.inFlight, key)
	} else {
		f.inFlight[key] = n - 1
	}
}

// accountFailureGate is the two-tier account gate a password check passes through: a tight
// budget per (account, client block) and a loose account-wide backstop, charged from the
// same failure event. Shared by the browser password form and the ROPC grant, because both
// are the same event, a password guessed against one account.
//
// One tier alone cannot do this. A gate consulted before the credential is checked cannot
// know the incoming password is the right one, so a single account-wide budget lets anyone
// who knows an address refuse its owner by spending it, and tightening that budget makes
// the denial cheaper rather than dearer. Splitting it means an ordinary single-source
// attacker burns only their own network's bucket while the owner signs in normally, and the
// account-wide ceiling RFC 6749 Section 4.3.2 makes a MUST still exists.
//
// Residual, accepted: an attacker producing failures from ten or more distinct blocks still
// exhausts the backstop and denies the owner for the rest of the hour. That is the price of
// having an account-wide ceiling at all, and 100 an hour is where NIST SP 800-63B section
// 3.2.2 puts its own "no more than 100" figure (#219).
type accountFailureGate struct {
	tight    *failureTier
	backstop *failureTier
}

// reserve claims a slot on both tiers, or on neither. It returns the tier that refused and
// the key it refused, so the caller can report the trip and answer in that tier's class;
// nil means the request may proceed. The tight slot is handed back when the backstop
// refuses, so a refusal never strands one.
func (g *accountFailureGate) reserve(r *http.Request, networkKey, accountKey string) (*failureTier, string) {
	if !g.tight.Reserve(networkKey) {
		return g.tight, networkKey
	}
	if !g.backstop.Reserve(accountKey) {
		g.tight.Release(r, networkKey, false)
		return g.backstop, accountKey
	}
	return nil, ""
}

// release charges or drops both tiers together, which is what keeps them counting the same
// events.
func (g *accountFailureGate) release(r *http.Request, networkKey, accountKey string, failed bool) {
	g.backstop.Release(r, accountKey, failed)
	g.tight.Release(r, networkKey, failed)
}

// credentialReservation is the slot a failures-only tier holds for the life of one request.
//
// It is what the handler marks instead of naming a bucket. The middleware chooses the key,
// reserves against it and puts the reservation on the request; a handler that finds the
// credential wrong calls RecordCredentialFailure and nothing else. A middleware and a
// handler deriving the account separately and disagreeing about it is precisely the defect
// that voided the per-account tiers in the first place (#219).
type credentialReservation struct {
	failed atomic.Bool
}

type reservationCtxKey struct{}

func withCredentialReservation(r *http.Request, res *credentialReservation) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), reservationCtxKey{}, res))
}

// RecordCredentialFailure marks this request's credential check as failed, so the
// reservation the limiter is holding is charged rather than dropped when the handler
// returns.
//
// A no-op when no reservation was placed, which is the disabled limiter, a route with no
// failures-only tier, and a handler invoked outside its middleware. A method rather than a
// function so a handler can take it as a one-method dependency, the way it takes its audit
// logger.
func (m *RateLimiterMiddleware) RecordCredentialFailure(r *http.Request) {
	if res, ok := r.Context().Value(reservationCtxKey{}).(*credentialReservation); ok {
		res.failed.Store(true)
	}
}

type RateLimiterMiddleware struct {
	authHelper  AuthHelper
	renderer    ErrorRenderer
	auditLogger AuditLogger
	enabled     bool
	// pwdAccount is shared with the ROPC grant: both are a password guessed against one
	// account, so one budget covers them.
	pwdAccount *accountFailureGate
	pwdIp      *tier
	otp        *failureTier
	// emailVerification bounds guessing at the account's own email verification code.
	emailVerification *failureTier
	activate          *tier
	register          *tier
	resetPwd          *tier
	forgotPwd         *tier
	forgotPwdIp       *tier
	dcr               *tier
	ropcIp            *tier // RFC 6749 §4.3.2 MUST protect against brute force
}

func NewRateLimiterMiddleware(authHelper AuthHelper, renderer ErrorRenderer, auditLogger AuditLogger,
	enabled bool) *RateLimiterMiddleware {

	return &RateLimiterMiddleware{
		authHelper:  authHelper,
		renderer:    renderer,
		auditLogger: auditLogger,
		enabled:     enabled,
		// per-account password failures, in two tiers. 10 per 15 minutes against one
		// account from one client block is room for a user working through the passwords
		// they might have used before reaching for recovery, and it is 22x tighter than
		// the 15 requests a minute it replaces. The 100 per hour behind it is the
		// account-wide ceiling RFC 6749 §4.3.2 makes a MUST, at the figure NIST SP
		// 800-63B §3.2.2 names. Both count failures only, so a user who signs in spends
		// nothing (#219).
		pwdAccount: &accountFailureGate{
			tight:    newFailureTier("pwd_account_net", 10, 15*time.Minute),
			backstop: newFailureTier("pwd_account", 100, 60*time.Minute),
		},
		// per-IP: stops one host hammering many accounts
		pwdIp: newTier("pwd_ip", "ip", 30, 1*time.Minute),
		// per-user OTP failures. 5 per 15 minutes is 480 guesses a day against the 14,400
		// the 10 a minute it replaces allowed, which takes the chance of a hit over a
		// month from 72.6% to 4.2% against an attacker who already holds the password.
		// Five rather than three because the same limiter covers enrollment, where
		// pointing the wrong entry in an authenticator app at the form burns codes, and a
		// resubmitted code is refused as a replay and so counts as a failure too (#219).
		otp: newFailureTier("otp", 5, 15*time.Minute),
		// per-subject email verification failures. The code is four letters plus four
		// digits, 26^4 x 10^4, so 5 failures per 15 minutes puts a hit on the far side of a
		// human lifetime. It needs a bound at all because the chain in front of it is short:
		// PUT /api/v1/account/email sets any address not already registered and clears the
		// verified flag, so guessing the code from there buys email_verified: true on an
		// address the attacker does not control. Failures only, so a user reading the code
		// out of their inbox spends nothing (#219).
		emailVerification: newFailureTier("email_verification", 5, 15*time.Minute),
		// per-IP: 10 activation operations per 5 minutes, at the two requests an activation
		// now costs (the link's GET, the clean GET). The same operation rate as
		// resetPwd over a chain one request shorter (#112)
		activate: newTier("activate", "ip", 20, 5*time.Minute),
		// per-IP: self-registration, at the same budget as the activation step that follows
		// it, so a registration and its activation trip at the same rate. It bounds three
		// things at once, all of which are only harmful across distinct addresses: the
		// account-existence oracle the form answers, the mail it sends to any address given
		// to it, and the pre_registrations rows it writes.
		//
		// No per-email tier, and the issue asks for one. A second submission for the same
		// address finds the user or the pre-registration row and renders "already
		// registered" before the password hash, the row write or the mail send, so one
		// address yields at most one mail however often it is submitted. A per-email tier
		// would bound a path that already stops itself.
		//
		// This slows the oracle to 240 addresses an hour per client block rather than
		// closing it. Closing it means answering identically for a taken and a free
		// address, which is a change to what self-registration tells a legitimate user
		// (#219).
		register: newTier("register", "ip", 20, 5*time.Minute),
		// per-IP: 10 reset operations per 5 minutes, at the three requests a reset now
		// costs (the link's GET, the clean GET, the clean POST). Half of what
		// forgotPwdIp allows, which is the only other endpoint with an IP tier (#112)
		resetPwd: newTier("reset_pwd", "ip", 30, 5*time.Minute),
		// per-email: mail-bomb protection
		forgotPwd: newTier("forgot_pwd_email", "", 5, 5*time.Minute),
		// per-IP: resource DoS protection
		forgotPwdIp: newTier("forgot_pwd_ip", "ip", 20, 5*time.Minute),
		// RFC 7591 §3 DoS protection
		dcr: newTier("dcr", "ip", 10, 1*time.Minute),
		// per-IP: stops one host spraying passwords across many accounts through the
		// password grant, exactly as pwdIp does for the browser form, and at the same
		// budget. Its account half is pwdAccount above, shared rather than mirrored: the
		// composite ropc_<clientId>_<username>_<ip> key this replaces gave every client
		// and every source address a fresh budget against one account, so the per-account
		// ceiling RFC 6749 §4.3.2 makes a MUST did not exist at all (#107, #219).
		ropcIp: newTier("ropc_ip", "ip", 30, 1*time.Minute),
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
	class rejectClass, details map[string]interface{}) bool {

	if !t.rl.OnLimit(w, r, key) {
		return false
	}
	m.refuse(w, r, t, key, class, details)
	return true
}

// refuse writes everything a rejection consists of: the Retry-After RFC 6585 Section 4
// names, the two records the trip leaves, and the body the route's caller parses.
//
// Both paths reach it. A tier that counts every request arrives from tripped, where
// httprate's OnLimit has already written the same Retry-After; a failures-only tier arrives
// from its own gate, which never calls OnLimit on the reject path and so would otherwise
// answer without the header. One function rather than two is also what keeps a failures-only
// tier from quietly returning httprate's plain text with everything around it apparently
// wired up (#219).
// class comes from the caller rather than from the tier because one bucket can serve two
// routes: pwdAccount is shared by the browser password form and the ROPC grant, and each has
// to answer in the shape its own caller parses.
func (m *RateLimiterMiddleware) refuse(w http.ResponseWriter, r *http.Request, t *tier, key string,
	class rejectClass, details map[string]interface{}) {

	w.Header().Set("Retry-After", strconv.Itoa(int(t.window.Seconds())))
	m.reportTrip(r, t, key, details)
	m.reject(w, r, class)
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

	if class == rejectAPI {
		// The same envelope every other refusal on these routes writes, so a caller
		// already switching on error_code needs no new shape. The envelope type lives in
		// core/api; the helper that writes it is unexported in the authserver module, so
		// this builds it directly rather than reaching for a function core cannot see.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(api.ErrorResponse{
			ErrorCode:        "TOO_MANY_REQUESTS",
			ErrorDescription: "Too many requests. Please wait and try again later.",
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
		if m.tripped(w, r, m.pwdIp, ipKey, rejectBrowser, map[string]interface{}{"ip": ipKey}) {
			return
		}

		// Per-account limit: bounds password guessing against a single account, in the
		// two tiers accountFailureGate documents. Only a wrong password spends it, so a
		// user signing in normally is never refused by it however often they do.
		accountKey := accountRateLimitKey(r.FormValue("email"))
		networkKey := accountNetworkRateLimitKey(r, accountKey)
		if t, key := m.pwdAccount.reserve(r, networkKey, accountKey); t != nil {
			m.refuse(w, r, &t.tier, key, rejectBrowser, map[string]interface{}{"email": accountKey, "ip": ipKey})
			return
		}

		// The handler converts this reservation by calling RecordCredentialFailure; the
		// defer charges it or drops it. A closure rather than a bare defer call, since the
		// verdict is not known until the handler has returned.
		reservation := &credentialReservation{}
		r = withCredentialReservation(r, reservation)
		defer func() {
			m.pwdAccount.release(r, networkKey, accountKey, reservation.failed.Load())
		}()

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

		// Use user ID as rate limit key since we already authenticated the user. Single
		// tier, unlike the password gate: reaching this form at all requires having
		// already passed the password, so a third party cannot spend this budget without
		// already holding the account's password.
		key := fmt.Sprintf("user_%d", authContext.UserId)

		if !m.otp.Reserve(key) {
			m.refuse(w, r, &m.otp.tier, key, rejectBrowser, map[string]interface{}{"userId": authContext.UserId})
			return
		}

		reservation := &credentialReservation{}
		r = withCredentialReservation(r, reservation)
		defer func() {
			m.otp.Release(r, key, reservation.failed.Load())
		}()

		next.ServeHTTP(w, r)
	})
}

// LimitEmailVerification rate limits the account's own email verification check, on the
// subject of the access token presented.
//
// The endpoint had no bound at all and no failure counter, while comparing a code an
// attacker can request against an address they chose: PUT /api/v1/account/email accepts any
// address not already registered and clears email_verified, so what a guessed code buys is
// a verified claim on somebody else's address (#219).
//
// The subject rather than the client IP because the budget has to follow the account being
// attacked rather than the host attacking it, and reaching this route at all requires a
// valid access token for that account. A request with no readable token passes through to
// the handler, which answers ACCESS_TOKEN_REQUIRED before touching the code, so the skipped
// limit costs nothing: LimitOtp's rule from #114, unchanged.
func (m *RateLimiterMiddleware) LimitEmailVerification(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting if disabled
		if !m.enabled {
			next.ServeHTTP(w, r)
			return
		}

		key, ok := tokenSubjectRateLimitKey(r)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		if !m.emailVerification.Reserve(key) {
			m.refuse(w, r, &m.emailVerification.tier, key, rejectAPI,
				map[string]interface{}{"loggedInUser": key})
			return
		}

		reservation := &credentialReservation{}
		r = withCredentialReservation(r, reservation)
		defer func() {
			m.emailVerification.Release(r, key, reservation.failed.Load())
		}()

		next.ServeHTTP(w, r)
	})
}

// tokenSubjectRateLimitKey buckets by the account a bearer token names. It reads the token
// the API authentication middleware validated and left on the context, which is the same
// value the handler resolves its user from, so the limiter and the handler cannot disagree
// about whose budget is being spent.
//
// The token is stored as a value rather than a pointer, so the type assertion has to match
// (see the authserver middleware's own GetValidatedToken). false means no bucket can be
// derived, which is a request that has no business reaching a credential check anyway.
func tokenSubjectRateLimitKey(r *http.Request) (string, bool) {
	token, ok := r.Context().Value(constants.ContextKeyValidatedToken).(oauth.JwtToken)
	if !ok {
		return "", false
	}
	subject := strings.TrimSpace(token.GetStringClaim("sub"))
	if subject == "" {
		return "", false
	}
	return subject, true
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
		if m.tripped(w, r, m.activate, ipKey, rejectBrowser, map[string]interface{}{"ip": ipKey}) {
			return
		}

		next.ServeHTTP(w, r)
	})
}

// LimitRegister rate limits self-registration, on the client IP.
//
// The endpoint had no limiter at all, while being unauthenticated and enabled by default. The key
// is the client block rather than the submitted address because every harm here is spread across
// distinct addresses: probing which of them already have an account, sending mail to whichever do
// not, and writing a pre_registrations row for each. A per-address key would bucket the attacker's
// own choice of victim and bound nothing (#219).
//
// The POST alone is limited. The GET renders a static form and reaches no probe, no mail and no
// row, so limiting it would only refuse the page to a household behind one address.
func (m *RateLimiterMiddleware) LimitRegister(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting if disabled
		if !m.enabled {
			next.ServeHTTP(w, r)
			return
		}

		// The client IP is trustworthy here (resolved by MiddlewareRealIP).
		ipKey := clientIPRateLimitKey(r)
		if m.tripped(w, r, m.register, ipKey, rejectBrowser, map[string]interface{}{"ip": ipKey}) {
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
		if m.tripped(w, r, m.resetPwd, ipKey, rejectBrowser, map[string]interface{}{"ip": ipKey}) {
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
		if m.tripped(w, r, m.forgotPwdIp, ipKey, rejectBrowser, map[string]interface{}{"ip": ipKey}) {
			return
		}

		// Per-email limit: prevents mail-bombing a specific address.
		emailKey := accountRateLimitKey(r.FormValue("email"))
		if m.tripped(w, r, m.forgotPwd, emailKey, rejectBrowser, map[string]interface{}{"email": emailKey}) {
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

		if m.tripped(w, r, m.dcr, ipKey, rejectOAuth, map[string]interface{}{"ip": ipKey}) {
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

// accountNetworkRateLimitKey buckets by an account as seen from one client block, which is
// the tight half of the password gate: an attacker in another network spends their own
// bucket instead of the owner's.
//
// The network goes first because it cannot contain the separator, so the first '|' is
// unambiguous however exotic the address is. Account-first would let a local part carrying
// '|' collide with a different (network, account) pair (#219).
//
// identifier is expected to have been through accountRateLimitKey already, so the two tiers
// of the gate name the same account.
func accountNetworkRateLimitKey(r *http.Request, identifier string) string {
	return clientIPRateLimitKey(r) + "|" + identifier
}

// LimitROPC rate limits Resource Owner Password Credentials requests.
// RFC 6749 Section 4.3.2 MUST: "the authorization server MUST protect the endpoint
// against brute force attacks (e.g., using rate-limitation or generating alerts)."
// SECURITY NOTE: ROPC is deprecated in OAuth 2.1 due to credential exposure risks.
//
// The same three tiers the browser password form carries, and the account pair is literally
// the same pair of buckets rather than a copy of its budget: a password guessed against one
// account is one event wherever it arrives, so an attacker cannot get a second allowance by
// moving from the form to the grant. It also means the ceiling holds when a deployment turns
// only one of the two paths off.
//
// What it replaces is a key of ropc_<clientId>_<username>_<ip>. Folding the client id into a
// per-account budget meant an attacker escaped the ceiling by naming a second client, and
// folding in the address meant they escaped it by moving host, so the per-account ceiling
// RFC 6749 Section 4.3.2 makes a MUST did not exist at all (#107, #219).
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

		// The other grants carry no resource-owner password, so this limiter has nothing to
		// bound on them and counting them would throttle every token refresh a busy client
		// makes.
		if r.PostFormValue("grant_type") != "password" {
			next.ServeHTTP(w, r)
			return
		}

		// Per-IP ceiling first: stops a single host spraying passwords across many distinct
		// accounts. The client IP is trustworthy here (resolved by MiddlewareRealIP).
		ipKey := clientIPRateLimitKey(r)
		if m.tripped(w, r, m.ropcIp, ipKey, rejectOAuth, map[string]interface{}{"ip": ipKey}) {
			return
		}

		// Per-account limit, in the two tiers accountFailureGate documents. Only a wrong
		// credential spends it, so a machine-driven integration authenticating one account
		// over and over is never refused by it. client_id is deliberately absent from the
		// key: a ceiling an attacker escapes by registering a second client is not a ceiling.
		accountKey := accountRateLimitKey(r.PostFormValue("username"))
		networkKey := accountNetworkRateLimitKey(r, accountKey)
		if t, key := m.pwdAccount.reserve(r, networkKey, accountKey); t != nil {
			m.refuse(w, r, &t.tier, key, rejectOAuth,
				map[string]interface{}{"email": accountKey, "ip": ipKey})
			return
		}

		// HandleTokenPost converts this reservation by calling RecordCredentialFailure, and
		// only where the validator answered invalid_grant for a password grant. The defer
		// charges it or drops it.
		reservation := &credentialReservation{}
		r = withCredentialReservation(r, reservation)
		defer func() {
			m.pwdAccount.release(r, networkKey, accountKey, reservation.failed.Load())
		}()

		next.ServeHTTP(w, r)
	})
}
