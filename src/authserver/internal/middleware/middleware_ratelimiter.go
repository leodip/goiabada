package middleware

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/apiresponse"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/ratelimit"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/i18n"
)

// authContextGetter reads the ceremony a browser is in, whose user keys the OTP budget.
//
// The limiter's three ports are unexported, like every other port in this module: the handler
// helper, the renderer and the audit logger satisfy them structurally, and nothing outside this
// package needs to name them (#386, #433).
type authContextGetter interface {
	GetAuthContext(r *http.Request) (*ceremony.AuthContext, error)
}

// errorRenderer renders an HTML error page: the refusal page a trip answers with, and the 500 page
// a credential tier whose shared count could not be read answers with (#394). The middleware
// declares only the shape it needs rather than depending on the handler helper that satisfies it.
type errorRenderer interface {
	RenderTemplate(w http.ResponseWriter, r *http.Request, layoutName string, templateName string,
		data map[string]interface{}) error
	InternalServerError(w http.ResponseWriter, r *http.Request, err error)
}

// auditEventLogger records a security event. The middleware declares only the shape it needs
// rather than depending on the audit implementation that satisfies it. The context is first and
// carries the request's id, so the trip this audits joins the warning beside it and the request's
// own log line; the shape is kept identical to handlers.AuditLogger, which the same concrete
// logger satisfies (#328).
type auditEventLogger interface {
	Log(ctx context.Context, auditEvent string, details map[string]interface{})
}

// credentialCounter is the database the five credential tiers count in on PostgreSQL, MySQL and SQL
// Server, which every replica shares; ratelimit.NewSharedFailureLimiter records why those tiers and
// no others. The server hands nil on SQLite, and the tiers then count in this process (#394).
type credentialCounter interface {
	ReserveRateLimitHit(ctx context.Context, keyHash string, current, previous, expiresAt time.Time,
		admit func(curr, prev int) bool) (bool, error)
	RefundRateLimitHit(ctx context.Context, tx *sql.Tx, keyHash string, windowStart time.Time) error
}

// rejectClass is the shape a rejected caller can parse. A browser gets the error page it
// would get from any other refusal; an OAuth2 or RFC 7591 client gets the JSON error
// object it is already parsing at that endpoint; a caller of the account or admin API gets
// that API's own error envelope. Answering every route in plain text, which is what a limiter
// that knows only the status code can do, breaks both machine callers (#219).
type rejectClass int

const (
	rejectBrowser rejectClass = iota
	rejectOAuth
	rejectAPI
)

// tier is the HTTP half of one rate-limit bucket: everything a rejection has to say about
// it. The counting half is ratelimit's, and sits beside this in requestTier or failureTier.
//
// The pairing is the point. A counter answers only "over budget or not", so a rejection
// written from inside one learns neither which limiter tripped nor which bucket; the audit
// event needs both while the log line needs the name. Keeping them together here is what
// lets the refusal path have them.
//
// The reject class is deliberately NOT here, and it used to be. A bucket can serve two
// routes whose callers parse different things: accountTiers is shared by the browser
// password form and the ROPC grant, so a class held on the tier would answer the token
// endpoint with an HTML error page. The shape of a refusal belongs to the caller being
// refused, so every refusal names it (#219).
type tier struct {
	name string
	// keyField is the slog attribute the bucket key is logged under, empty when the key
	// names a person. The request logger in this package establishes that identifiers are
	// kept out of logs by allowlist rather than by denylist, and email is deliberately not
	// on that list, so the account tiers log their limiter name and nothing else. The
	// identifier is carried by the audit event instead, which is the surface built to hold
	// one (#219).
	keyField string
	// auditGate bounds the audit writes to exactly one event per key per window. It is taken
	// from the tier's limiter, so it rolls at the same instant the limiter does and its First
	// answers true once per key per that window; that first call is the report. Per limiter
	// rather than one shared gate: windows here are 1, 5 and 15 minutes, and a single shared
	// duration would either under-report the short windows by up to 15x or over-report the
	// long ones.
	auditGate *ratelimit.Gate
	// window is what Retry-After carries. Kept here because a failures-only tier refuses
	// without consulting a request limiter at all, so nothing else on that path knows the
	// window (#219).
	window time.Duration
}

// requestTier is a tier every request spends, admitted or refused by Allow before the
// handler runs.
type requestTier struct {
	tier
	limiter *ratelimit.Limiter
}

// newTier builds the limiter and takes its gate from it, which is the only way the two share
// a phase: a limiter anchors its windows at its own construction instant, so a gate built
// independently would roll at a different one and the guarantee above would weaken to at most
// two events per window length in the worst phase (#276).
//
// No X-RateLimit-* header is written anywhere. They used to ride every response including
// successful ones, so any caller could read the exact budget, how much of it was left and
// whether the limiter was switched on at all without tripping anything; and on a two-tier
// limiter the second write overwrote the first, so /auth/pwd reported the per-email budget as
// though it were the per-IP one (#219). Retry-After is written by refuse and stays, because
// RFC 6585 Section 4 names it as what a 429 MAY carry.
func newTier(name string, keyField string, limit int, window time.Duration) *requestTier {
	limiter := ratelimit.New(limit, window)
	return &requestTier{
		tier: tier{
			name:      name,
			keyField:  keyField,
			auditGate: limiter.Gate(),
			window:    window,
		},
		limiter: limiter,
	}
}

// failureTier is a tier only a failed credential check can spend: ratelimit.FailureLimiter,
// which holds the locking argument that makes reserving before the check and charging after
// it safe, under the name and gate a rejection reports.
type failureTier struct {
	tier
	limiter *ratelimit.FailureLimiter
}

// newFailureTier takes no keyField, unlike newTier, because a failures-only tier is by
// construction keyed on an identifier that names a person: only a credential check can
// spend one, and the credential names the account. That is exactly the case tier.keyField
// must be empty for, so the empty value is passed here rather than at each call site,
// which makes the invariant structural instead of something every caller has to remember
// (#219). The gate is taken from the limiter for newTier's reason.
//
// The tier counts in store under its own name when there is one, which is every server engine,
// and in this process when store is nil, which is SQLite (#394 decision 2). The shared limiter's
// gate follows its epoch-aligned windows, and stays per process: at most one audit event per key,
// per window, per replica.
func newFailureTier(name string, limit int, window time.Duration, store credentialCounter) *failureTier {
	limiter := ratelimit.NewFailureLimiter(limit, window)
	if store != nil {
		limiter = ratelimit.NewSharedFailureLimiter(store, name, limit, window)
	}
	return &failureTier{
		tier: tier{
			name:      name,
			auditGate: limiter.Gate(),
			window:    window,
		},
		limiter: limiter,
	}
}

// accountTiers is the two-tier account limit a password check passes through, the
// ratelimit.AccountLimiter that counts it beside the two tiers a refusal reports against.
// Shared by the browser password form and the ROPC grant, because both are the same event,
// a password guessed against one account.
type accountTiers struct {
	limiter  *ratelimit.AccountLimiter
	tight    *failureTier
	backstop *failureTier
}

func newAccountTiers(tight, backstop *failureTier) *accountTiers {
	return &accountTiers{
		limiter:  ratelimit.NewAccountLimiter(tight.limiter, backstop.limiter),
		tight:    tight,
		backstop: backstop,
	}
}

// reserve claims a slot on both tiers, or on neither. It returns the tier that refused and
// the key it refused, so the caller can report the trip and answer with that tier's window;
// a nil tier and a nil error mean the request may proceed and the reservation is owed a
// release. An error is a count that could not be read, which holds nothing and which the
// caller answers as a fault, never as a trip: the limiter fails closed (#276, #394 decision 4).
func (a *accountTiers) reserve(ctx context.Context, networkKey, accountKey string) (*ratelimit.AccountReservation, *tier, string, error) {
	reservation, refusal, err := a.limiter.Reserve(ctx, networkKey, accountKey)
	if err != nil {
		return nil, nil, "", err
	}
	switch refusal {
	case ratelimit.RefusedTight:
		return nil, &a.tight.tier, networkKey, nil
	case ratelimit.RefusedBackstop:
		return nil, &a.backstop.tier, accountKey, nil
	default:
		return reservation, nil, "", nil
	}
}

// heldReservation is a credential check's slot on either limiter shape: one failures-only
// tier's, or the account limiter's two.
type heldReservation interface {
	Release(ctx context.Context, failed bool) error
}

// releaseCredentialReservation charges or drops what a credential check reserved, once the
// handler has said whether the credential was wrong.
func releaseCredentialReservation(ctx context.Context, reservation heldReservation, failed bool) {
	if err := reservation.Release(ctx, failed); err != nil {
		slog.ErrorContext(ctx, "unable to release a credential rate limit reservation", "error", err)
	}
}

// withCredentialReservation puts a failures-only tier's reservation on the request, through
// reqctx like every other request-scoped value (#439).
func withCredentialReservation(r *http.Request, res *reqctx.CredentialReservation) *http.Request {
	return r.WithContext(reqctx.WithCredentialReservation(r.Context(), res))
}

// RecordCredentialFailure marks this request's credential check as failed, so the
// reservation the limiter is holding is charged rather than dropped when the handler
// returns.
//
// A no-op when no reservation was placed, which is the disabled limiter, a route with no
// failures-only tier, and a handler invoked outside its middleware. A method rather than a
// function so a handler can take it as a one-method dependency, the way it takes its audit
// logger.
func (m *RateLimiter) RecordCredentialFailure(r *http.Request) {
	if res, ok := reqctx.CredentialReservationFrom(r.Context()); ok {
		res.MarkFailed()
	}
}

type RateLimiter struct {
	ceremonyStore authContextGetter
	renderer      errorRenderer
	// jsonWriter is the token endpoint's own error writer, which LimitROPC answers a form that does
	// not parse through, so its refusal and the handler's read the same on the wire.
	jsonWriter  jsonErrorWriter
	auditLogger auditEventLogger
	enabled     bool
	// pwdAccount is shared with the ROPC grant: both are a password guessed against one
	// account, so one budget covers them.
	pwdAccount *accountTiers
	pwdIp      *requestTier
	otp        *failureTier
	// emailVerification bounds guessing at the account's own email verification code.
	emailVerification *failureTier
	// emailVerificationSend bounds the verification mail an account can have sent.
	emailVerificationSend *requestTier
	// accountPassword bounds guessing at the account's own password, at the two account API
	// routes that verify it. One tier rather than two because it is one secret.
	accountPassword *failureTier
	activate        *requestTier
	register        *requestTier
	registerEmail   *requestTier
	resetPwd        *requestTier
	forgotPwd       *requestTier
	forgotPwdIp     *requestTier
	dcr             *requestTier
	ropcIp          *requestTier // RFC 6749 §4.3.2 MUST protect against brute force
}

func NewRateLimiter(ceremonyStore authContextGetter, renderer errorRenderer, jsonWriter jsonErrorWriter,
	auditLogger auditEventLogger, enabled bool, credentialCounts credentialCounter) *RateLimiter {

	return &RateLimiter{
		ceremonyStore: ceremonyStore,
		renderer:      renderer,
		jsonWriter:    jsonWriter,
		auditLogger:   auditLogger,
		enabled:       enabled,
		// per-account password failures, in two tiers. 10 per 15 minutes against one
		// account from one client block is room for a user working through the passwords
		// they might have used before reaching for recovery, and it is 22x tighter than
		// the 15 requests a minute it replaces. The 100 per hour behind it is the
		// account-wide ceiling RFC 6749 §4.3.2 makes a MUST, at the figure NIST SP
		// 800-63B §3.2.2 names. Both count failures only, so a user who signs in spends
		// nothing (#219).
		pwdAccount: newAccountTiers(
			newFailureTier("pwd_account_net", 10, 15*time.Minute, credentialCounts),
			newFailureTier("pwd_account", 100, 60*time.Minute, credentialCounts),
		),
		// per-IP: stops one host hammering many accounts
		pwdIp: newTier("pwd_ip", "ip", 30, 1*time.Minute),
		// per-user OTP failures. 5 per 15 minutes is 480 guesses a day against the 14,400
		// the 10 a minute it replaces allowed, which takes the chance of a hit over a
		// month from 72.6% to 4.2% against an attacker who already holds the password.
		// Five rather than three because the same limiter covers enrollment, where
		// pointing the wrong entry in an authenticator app at the form burns codes, and a
		// resubmitted code is refused as a replay and so counts as a failure too (#219).
		otp: newFailureTier("otp", 5, 15*time.Minute, credentialCounts),
		// per-subject email verification failures. The code is four letters plus four
		// digits, 26^4 x 10^4, so 5 failures per 15 minutes puts a hit on the far side of a
		// human lifetime. It needs a bound at all because the chain in front of it is short:
		// PUT /api/v1/account/email sets any address not already registered and clears the
		// verified flag, so guessing the code from there buys email_verified: true on an
		// address the attacker does not control. That change now needs the account password
		// too (#404), which shortens the chain without removing it. Failures only, so a user reading the code
		// out of their inbox spends nothing (#219).
		emailVerification: newFailureTier("email_verification", 5, 15*time.Minute, credentialCounts),
		// per-subject: verification mails sent, every request counted. The send mails a code to
		// whatever address the account holds, and the account sets that address itself, so
		// what this bounds is one account mailing addresses it does not own. The handler's own
		// cooldown, one code per its five minute lifetime, holds whatever this switch says and
		// allows 12 an hour; this is 5, which is room for a user whose first code went to spam
		// or expired before a slow inbox delivered it (#404).
		emailVerificationSend: newTier("email_verification_send", "", 5, 60*time.Minute),
		// per-subject account password failures, one bucket for the three routes that check
		// that password: PUT /api/v1/account/password, PUT /api/v1/account/otp and
		// PUT /api/v1/account/email (#404). All three verify the same secret, so separate
		// buckets would hand an attacker more guesses by alternating between them.
		//
		// Five rather than the ten the sign-in gate allows because the consequences are
		// asymmetric. A lockout here costs a signed-in user a 15 minute wait on a change they
		// can retry, where a lockout at sign-in denies access outright, and the payoff is
		// higher: the password is the only credential guarding the removal of the account's
		// second factor, since the disable branch takes no OTP code at all. Failures only, so
		// a user changing their password successfully spends nothing (#113, #219).
		accountPassword: newFailureTier("account_password", 5, 15*time.Minute, credentialCounts),
		// per-IP: 10 activation operations per 5 minutes, at the three requests an activation
		// now costs (the link's GET, the clean GET that renders the password form, and its
		// POST), shared by both methods. resetPwd's budget for the same chain (#112, #207
		// decision 9)
		activate: newTier("activate", "ip", 30, 5*time.Minute),
		// per-IP: self-registration, 20 per 5 minutes. It bounds what is only harmful across
		// distinct addresses: the pre_registrations rows and the mail registration with
		// verification sends to any address given to it, and, without verification, the
		// account-existence oracle the form answers. That oracle is closed with verification,
		// which answers every address alike, and cannot be closed without it, where the account
		// is usable at once (#219, #207 decision 3); this slows it to 240 addresses an hour per
		// client block.
		register: newTier("register", "ip", 20, 5*time.Minute),
		// per-email: self-registration, at forgot-password's per-address budget. With
		// verification a registration for an address that has a verified, enabled account mails
		// it a notice, so without this tier one host could mail any account holder 20 notices
		// every 5 minutes, and many hosts without bound. It used to be argued unneeded, when a
		// second submission for an address stopped at "already registered" before any mail; the
		// notice ended that (#207 decision 5).
		registerEmail: newTier("register_email", "", 5, 5*time.Minute),
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
// Allow is check-and-charge under the limiter's own lock, so two concurrent requests on one
// key cannot both read a budget with one left and both spend it. It answers true when the
// request is within budget, which is the case where this function has nothing to do; the
// refusal is everything below.
//
// details carries the identifier the audit event records, which is the one this limiter's
// neighbours in the audit log already carry for the same event: the email for account
// tiers, the user id for the OTP tier, the client block for IP tiers.
func (m *RateLimiter) tripped(w http.ResponseWriter, r *http.Request, t *requestTier, key string,
	class rejectClass, details map[string]interface{}) bool {

	if t.limiter.Allow(key) {
		return false
	}
	m.refuse(w, r, &t.tier, key, class, details)
	return true
}

// refuse writes everything a rejection consists of: the Retry-After RFC 6585 Section 4
// names, the two records the trip leaves, and the body the route's caller parses.
//
// Both paths reach it, and the header is written here for both: a tier that counts every
// request arrives from tripped and a failures-only tier from its own gate, and neither the
// limiter nor the gate touches the response at all. One function rather than two is what
// keeps a rejection from either path from arriving with everything around it apparently
// wired up and the header missing (#219).
// class comes from the caller rather than from the tier because one bucket can serve two
// routes: pwdAccount is shared by the browser password form and the ROPC grant, and each has
// to answer in the shape its own caller parses.
func (m *RateLimiter) refuse(w http.ResponseWriter, r *http.Request, t *tier, key string,
	class rejectClass, details map[string]interface{}) {

	w.Header().Set("Retry-After", strconv.Itoa(int(t.window.Seconds())))
	m.reportTrip(r.Context(), t, key, details)
	m.reject(w, r, class)
}

// reportTrip writes the two records a rejection leaves: a warning line every time, and an
// audit event exactly once per key per window.
//
// Warn rather than Error because a limiter doing its job is an expected event, and an auth
// server whose error log fills with them has no error log left.
// The context is a parameter rather than something this reaches for because a trip is a request
// event: the installed handler reads chi's request id off it, so the warning below joins the
// request log line for the request that was refused. Without it the operator has a rate-limit
// warning and no way to tell which request produced it (#320 decision 2).
func (m *RateLimiter) reportTrip(ctx context.Context, t *tier, key string,
	details map[string]interface{}) {

	attrs := []any{"limiter", t.name}
	if t.keyField != "" {
		attrs = append(attrs, t.keyField, key)
	}
	slog.WarnContext(ctx, "rate limit reached", attrs...)

	if m.auditLogger == nil {
		return
	}
	// First is read-and-record in one call: true means this key has not been reported in
	// this window yet, and that first call is the report. The gate shares the limiter's
	// window and phase, so "this window" is the one the trip happened in.
	if !t.auditGate.First(t.name + "|" + key) {
		return
	}
	if details == nil {
		details = map[string]interface{}{}
	}
	details["limiter"] = t.name
	m.auditLogger.Log(ctx, audit.EventRateLimitExceeded, details)
}

// fault answers a credential check whose count could not be read: the 500 the route already gives
// a fault, in the shape its caller parses, through the writer every other 500 there goes through,
// which writes the one Error record and puts the request id in the body. err names the shared tier
// that failed and why.
//
// Not a trip, so none of what refuse writes: no Retry-After, no "rate limit reached" warning and no
// audit event. A 429 would send a client into a backoff loop and fill the audit log with false
// trips through a database outage, and the audit write would fail with the database anyway. The
// credential is never checked, since the request stops here (#276, #394 decision 4).
func (m *RateLimiter) fault(w http.ResponseWriter, r *http.Request, class rejectClass, err error) {
	switch class {
	case rejectOAuth:
		// RFC 6749 section 5.2's server_error, as the token endpoint answers every other fault.
		m.jsonWriter.JSONError(w, r, err)
	case rejectAPI:
		apiresponse.WriteInternalServerError(w, r, err)
	default:
		m.renderer.InternalServerError(w, r, err)
	}
}

// reject writes the 429 in the shape the route's caller parses.
func (m *RateLimiter) reject(w http.ResponseWriter, r *http.Request, class rejectClass) {
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
		apiresponse.WriteError(w, "Too many requests. Please wait and try again later.",
			"TOO_MANY_REQUESTS", http.StatusTooManyRequests)
		return
	}

	bind := map[string]interface{}{
		"title":       i18n.T(r.Context(), "auth_error.rate_limited.title"),
		"error":       i18n.T(r.Context(), "auth_error.rate_limited.message"),
		"_httpStatus": http.StatusTooManyRequests,
	}
	if err := m.renderer.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/auth_error.html", bind); err != nil {
		slog.ErrorContext(r.Context(), "unable to render the rate limiter rejection page",
			"error", err)
		http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
	}
}

func (m *RateLimiter) LimitPwd(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting if disabled
		if !m.enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Per-IP ceiling first: stops a single host from hammering many distinct
		// accounts. The client IP is trustworthy here (resolved by httpmw.RealIP).
		ipKey := clientIPRateLimitKey(r)
		if m.tripped(w, r, m.pwdIp, ipKey, rejectBrowser, map[string]interface{}{"ip": ipKey}) {
			return
		}

		// Per-account limit: bounds password guessing against a single account, in the
		// two tiers ratelimit.AccountLimiter documents. Only a wrong password spends it, so a
		// user signing in normally is never refused by it however often they do.
		accountKey := ratelimit.AccountKey(r.FormValue("email"))
		networkKey := accountNetworkRateLimitKey(r, accountKey)
		held, t, key, err := m.pwdAccount.reserve(r.Context(), networkKey, accountKey)
		if err != nil {
			m.fault(w, r, rejectBrowser, err)
			return
		}
		if t != nil {
			m.refuse(w, r, t, key, rejectBrowser, map[string]interface{}{"email": accountKey, "ip": ipKey})
			return
		}

		// The handler converts this reservation by calling RecordCredentialFailure; the
		// defer charges it or drops it. A closure rather than a bare defer call, since the
		// verdict is not known until the handler has returned.
		reservation := &reqctx.CredentialReservation{}
		r = withCredentialReservation(r, reservation)
		defer func() {
			releaseCredentialReservation(r.Context(), held, reservation.Failed())
		}()

		next.ServeHTTP(w, r)
	})
}

// subjectFunc names whose credential a request is about to check. It returns the key of the
// bucket the check spends, the details the audit event records if that bucket refuses, and
// false when the request has no subject at all.
//
// The key and the recorded identifier are two values because they differ: the OTP bucket is
// user_<id> while its event records the user id itself, the identifier its neighbours in the
// audit log already carry for the same user. Details are a fresh map per call, since a refusal
// adds the limiter's name to the map it is given.
type subjectFunc func(r *http.Request) (key string, audited map[string]interface{}, ok bool)

// limitFailuresPerSubject writes the body of a limiter only a failed credential check can
// spend, keyed on whoever subject names, refusing in the shape class names. LimitOtp,
// LimitEmailVerification and LimitAccountPassword are this over their own tier and subject
// (#439).
//
// A request with no subject passes through to the handler. No subject means no bucket to key,
// and each of the three handlers answers that request before reaching the credential: a
// missing auth context the way every step of the auth flow does, a missing token with
// ACCESS_TOKEN_REQUIRED. So the skipped limit costs nothing, where returning here instead
// would write no response at all, which net/http turns into a blank 200 (#114).
//
// The reservation is taken before the handler runs and charged or dropped after it, which is
// what ratelimit.FailureLimiter's in-flight count makes safe under concurrency; the handler
// converts it by calling RecordCredentialFailure. A closure rather than a bare defer call,
// since the verdict is not known until the handler has returned.
func (m *RateLimiter) limitFailuresPerSubject(next http.Handler, t *failureTier, class rejectClass,
	subject subjectFunc) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting if disabled
		if !m.enabled {
			next.ServeHTTP(w, r)
			return
		}

		key, audited, ok := subject(r)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		held, err := t.limiter.Reserve(r.Context(), key)
		if err != nil {
			m.fault(w, r, class, err)
			return
		}
		if held == nil {
			m.refuse(w, r, &t.tier, key, class, audited)
			return
		}

		reservation := &reqctx.CredentialReservation{}
		r = withCredentialReservation(r, reservation)
		defer func() {
			releaseCredentialReservation(r.Context(), held, reservation.Failed())
		}()

		next.ServeHTTP(w, r)
	})
}

// LimitOtp rate limits the OTP check, on the user of the sign-in ceremony the browser is in.
func (m *RateLimiter) LimitOtp(next http.Handler) http.Handler {
	return m.limitFailuresPerSubject(next, m.otp, rejectBrowser, m.ceremonyUserSubject)
}

// ceremonyUserSubject is LimitOtp's subject: the user the ceremony has already authenticated
// with a password. Single tier, unlike the password gate: reaching the OTP form at all requires
// having already passed the password, so a third party cannot spend this budget without already
// holding the account's password.
//
// No readable auth context means no user to key a bucket on, and the handler rejects that
// request before reaching the OTP secret or the database.
func (m *RateLimiter) ceremonyUserSubject(r *http.Request) (string, map[string]interface{}, bool) {
	authContext, err := m.ceremonyStore.GetAuthContext(r)
	if err != nil {
		return "", nil, false
	}
	return fmt.Sprintf("user_%d", authContext.UserId), map[string]interface{}{"userId": authContext.UserId}, true
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
func (m *RateLimiter) LimitEmailVerification(next http.Handler) http.Handler {
	return m.limitFailuresPerSubject(next, m.emailVerification, rejectAPI, tokenSubject)
}

// LimitEmailVerificationSend rate limits the account's own verification mail, on the subject of
// the access token presented. Every request counts, as on forgot-password's per-email tier: there
// is no credential here to fail, and the harm is the mail itself.
//
// The subject rather than the address the mail goes to because the account chooses that address:
// a per-address key would bucket the caller's own choice of recipient and bound nothing, the
// reason LimitRegister gives for keying on the client block. A request with no readable token
// passes through to the handler, which answers ACCESS_TOKEN_REQUIRED before sending anything.
func (m *RateLimiter) LimitEmailVerificationSend(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting if disabled
		if !m.enabled {
			next.ServeHTTP(w, r)
			return
		}

		key, audited, ok := tokenSubject(r)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		if m.tripped(w, r, m.emailVerificationSend, key, rejectAPI, audited) {
			return
		}

		next.ServeHTTP(w, r)
	})
}

// LimitAccountPassword rate limits the account's own password check, on the subject of the
// access token presented. One middleware over three routes, PUT /api/v1/account/password,
// PUT /api/v1/account/otp and PUT /api/v1/account/email (#404), which is what makes the bucket
// shared: the sharing is a property of there being one tier rather than of three handlers
// agreeing on a key.
//
// Both routes verified the password with an unbounded bcrypt and no failure counter, and the
// OTP one is the only credential guarding the removal of the account's second factor: its
// disable branch takes no OTP code, so guessing the password there is enough to strip 2FA
// (#113, #219).
//
// The OTP code on the enable branch is deliberately outside this bound. It is verified
// against the secret the caller supplied in the same request, so guessing it gains nothing
// and only the password check spends the budget.
//
// The subject rather than the client IP, for LimitEmailVerification's reason: the budget has
// to follow the account being attacked, and reaching any of them needs a valid access token
// for that account. A request with no readable token passes through to the handler, which
// answers ACCESS_TOKEN_REQUIRED before touching the password.
func (m *RateLimiter) LimitAccountPassword(next http.Handler) http.Handler {
	return m.limitFailuresPerSubject(next, m.accountPassword, rejectAPI, tokenSubject)
}

// tokenSubject is the subject of the three account API limiters. The token's subject keys the
// bucket and is what the event records, under loggedInUser, the name the account API's own
// audit events give the caller.
func tokenSubject(r *http.Request) (string, map[string]interface{}, bool) {
	key, ok := tokenSubjectRateLimitKey(r)
	if !ok {
		return "", nil, false
	}
	return key, map[string]interface{}{"loggedInUser": key}, true
}

// tokenSubjectRateLimitKey buckets by the account a bearer token names. It reads the token
// the API authentication middleware validated and left on the context, which is the same
// value the handler resolves its user from, so the limiter and the handler cannot disagree
// about whose budget is being spent.
//
// false means no bucket can be derived, which is a request that has no business reaching a
// credential check anyway.
func tokenSubjectRateLimitKey(r *http.Request) (string, bool) {
	token, ok := reqctx.ValidatedTokenFrom(r.Context())
	if !ok {
		return "", false
	}
	subject := strings.TrimSpace(token.StringClaim("sub"))
	if subject == "" {
		return "", false
	}
	return subject, true
}

// limitPerIP writes the body of a limiter every request spends, keyed on the client block and
// refusing in the shape class names. LimitActivate, LimitResetPwd and LimitDCR are this over
// their own tier (#439); the event a refusal audits records the block as ip. LimitRegister was
// too, until it gained a per-address tier (#207).
func (m *RateLimiter) limitPerIP(next http.Handler, t *requestTier, class rejectClass) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting if disabled
		if !m.enabled {
			next.ServeHTTP(w, r)
			return
		}

		// The client IP is trustworthy here (resolved by httpmw.RealIP).
		ipKey := clientIPRateLimitKey(r)
		if m.tripped(w, r, t, ipKey, class, map[string]interface{}{"ip": ipKey}) {
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
//
// One tier covers the GET and the POST that creates the account, as one covers both reset
// methods, so the chain is bounded as a whole (#207 decision 9).
func (m *RateLimiter) LimitActivate(next http.Handler) http.Handler {
	return m.limitPerIP(next, m.activate, rejectBrowser)
}

// LimitRegister rate limits self-registration, on the client IP and on the submitted address.
//
// The endpoint had no limiter at all, while being unauthenticated and enabled by default. The IP
// tier is the one that bounds what is spread across distinct addresses: probing which of them
// already have an account, sending mail to each, and writing a pre_registrations row for each new
// one. A per-address key alone would bucket the attacker's own choice of victim and bound none of
// it (#219). The per-address tier beside it bounds the one harm aimed at a single address, the
// notice a registration with verification mails an existing account (#207 decision 5), at the
// budget forgot-password gives the reset mail it sends that same account.
//
// The POST alone is limited. The GET renders a static form and reaches no probe, no mail and no
// row, so limiting it would only refuse the page to a household behind one address.
func (m *RateLimiter) LimitRegister(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting if disabled
		if !m.enabled {
			next.ServeHTTP(w, r)
			return
		}

		// The client IP is trustworthy here (resolved by httpmw.RealIP).
		ipKey := clientIPRateLimitKey(r)
		if m.tripped(w, r, m.register, ipKey, rejectBrowser, map[string]interface{}{"ip": ipKey}) {
			return
		}

		// Normalized as the handler normalizes the address it looks up, so every spelling it
		// treats as one address spends one budget.
		emailKey := ratelimit.AccountKey(r.FormValue("email"))
		if m.tripped(w, r, m.registerEmail, emailKey, rejectBrowser, map[string]interface{}{"email": emailKey}) {
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
func (m *RateLimiter) LimitResetPwd(next http.Handler) http.Handler {
	return m.limitPerIP(next, m.resetPwd, rejectBrowser)
}

// LimitForgotPwd rate limits the forgot-password POST, which for a real user
// triggers a DB write, template render and SMTP send. It bounds both a single
// address (mail-bombing) and a single source IP (resource DoS / spraying many
// addresses).
func (m *RateLimiter) LimitForgotPwd(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting if disabled
		if !m.enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Per-IP ceiling: stops one host from mail-bombing many addresses. The
		// client IP is trustworthy here (resolved by httpmw.RealIP).
		ipKey := clientIPRateLimitKey(r)
		if m.tripped(w, r, m.forgotPwdIp, ipKey, rejectBrowser, map[string]interface{}{"ip": ipKey}) {
			return
		}

		// Per-email limit: prevents mail-bombing a specific address.
		emailKey := ratelimit.AccountKey(r.FormValue("email"))
		if m.tripped(w, r, m.forgotPwd, emailKey, rejectBrowser, map[string]interface{}{"email": emailKey}) {
			return
		}

		next.ServeHTTP(w, r)
	})
}

// LimitDCR rate limits Dynamic Client Registration requests (RFC 7591 §3)
//
// It follows the global switch like every other limit here, and that switch is off by default:
// #219 left it so because many deployments already limit at Cloudflare, a WAF or a reverse proxy,
// which does it better, and recorded that so it is not re-litigated. A limit of its own that ran
// whenever registration is on would, behind a proxy without trusted forwarding headers, be ten
// registrations a minute for the whole deployment, and would need a setting of its own to turn off.
// Each registration is bounded whatever the switch says, by the redirect URI count and length and
// by the request body limit (#219, #426, #428).
func (m *RateLimiter) LimitDCR(next http.Handler) http.Handler {
	return m.limitPerIP(next, m.dcr, rejectOAuth)
}

// clientIPRateLimitKey buckets a request by the block its client controls: the address
// itself for IPv4, the /64 for IPv6. A host with SLAAC normally owns a whole /64, so
// keying on the full address hands one client 2^64 buckets, which voids every per-IP
// tier (measured: 200 of 200 requests allowed against a 30/min budget, #219).
//
// Separate from ClientIP, not folded into it, because that function also
// feeds the audit sinks and the recorded addresses, which need the address an administrator
// can act on rather than the block it sits in.
//
// httpmw.RealIP guarantees the input is a real IP: it drops X-Forwarded-For entries
// and an X-Real-IP that net.ParseIP rejects, and net/http guarantees RemoteAddr is
// host:port. That matters because CanonicalizeIP returns anything that is not an IP
// unchanged, "" included, which would put every such request in one global bucket.
//
// Two keys differ from what the retired library produced (#276). An IPv4-mapped address is
// unmapped first, so a dual-stack proxy reporting ::ffff:203.0.113.7 spends the same bucket
// as one reporting 203.0.113.7, where before every such client shared one bucket with
// loopback and with each other. And a zone is dropped, so fe80::1%eth0 keys as its /64
// rather than getting a bucket of its own; that is reachable only for a direct link-local
// peer, since httpmw.RealIP drops a zoned entry in a forwarded header.
func clientIPRateLimitKey(r *http.Request) string {
	return ratelimit.CanonicalizeIP(ClientIP(r))
}

// accountNetworkRateLimitKey buckets by an account as seen from one client block, which is
// the tight half of the password gate: an attacker in another network spends their own
// bucket instead of the owner's.
//
// The network goes first because it cannot contain the separator, so the first '|' is
// unambiguous however exotic the address is. Account-first would let a local part carrying
// '|' collide with a different (network, account) pair (#219).
//
// identifier is expected to have been through ratelimit.AccountKey already, so the two tiers
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
func (m *RateLimiter) LimitROPC(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting if disabled
		if !m.enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Only apply to grant_type=password requests. The form is parsed here first, so a form that
		// does not parse is answered here, as the token endpoint answers it. It cannot be forwarded:
		// net/http keeps the pairs that did parse and answers the handler's own ParseForm with nil, so
		// the handler would act on part of the request. A password grant beside one malformed pair
		// then reached the password check with neither tier below consulted, and a parameter whose
		// second copy was malformed passed as sent once (#228, #437).
		if err := r.ParseForm(); err != nil {
			m.jsonWriter.JSONError(w, r, protocolvalidation.UnparseableRequest())
			return
		}

		// The other grants carry no resource-owner password, so this limiter has nothing to
		// bound on them and counting them would throttle every token refresh a busy client
		// makes.
		if oidc.GrantType(r.PostFormValue("grant_type")) != oidc.GrantTypePassword {
			next.ServeHTTP(w, r)
			return
		}

		// Per-IP ceiling first: stops a single host spraying passwords across many distinct
		// accounts. The client IP is trustworthy here (resolved by httpmw.RealIP).
		ipKey := clientIPRateLimitKey(r)
		if m.tripped(w, r, m.ropcIp, ipKey, rejectOAuth, map[string]interface{}{"ip": ipKey}) {
			return
		}

		// Per-account limit, in the two tiers ratelimit.AccountLimiter documents. Only a wrong
		// credential spends it, so a machine-driven integration authenticating one account
		// over and over is never refused by it. client_id is deliberately absent from the
		// key: a ceiling an attacker escapes by registering a second client is not a ceiling.
		accountKey := ratelimit.AccountKey(r.PostFormValue("username"))
		networkKey := accountNetworkRateLimitKey(r, accountKey)
		held, t, key, err := m.pwdAccount.reserve(r.Context(), networkKey, accountKey)
		if err != nil {
			m.fault(w, r, rejectOAuth, err)
			return
		}
		if t != nil {
			m.refuse(w, r, t, key, rejectOAuth,
				map[string]interface{}{"email": accountKey, "ip": ipKey})
			return
		}

		// HandleTokenPost converts this reservation by calling RecordCredentialFailure, and
		// only where the validator answered invalid_grant for a password grant. The defer
		// charges it or drops it.
		reservation := &reqctx.CredentialReservation{}
		r = withCredentialReservation(r, reservation)
		defer func() {
			releaseCredentialReservation(r.Context(), held, reservation.Failed())
		}()

		next.ServeHTTP(w, r)
	})
}
