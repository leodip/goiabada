package backchannel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/leodip/goiabada/authserver/internal/afterresponse"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/signingkeys"
	"github.com/leodip/goiabada/authserver/internal/urlmatch"
	"github.com/leodip/goiabada/authserver/internal/uuid"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/metrics"
)

const (
	// tokenLifetime is how long a logout token is valid: Back-Channel Logout 1.0 section 4
	// encourages an exp of at most two minutes, which bounds the replay window and how long a retry
	// is worth anything (#784 decision 4).
	tokenLifetime = 120 * time.Second
	// attemptTimeout bounds one attempt: the connection, TLS and the answer (#784 decision 5).
	attemptTimeout = 5 * time.Second
	// answerBodyCap is how much of an answer's body is read, and discarded, so the connection can be
	// reused without an app holding it open with a body that never ends.
	answerBodyCap = 4 << 10
	// jitterFraction is how far the jitter moves a wait, either way.
	jitterFraction = 0.1

	// logoutEvent is the member of the token's events claim that makes it a logout token
	// (Back-Channel Logout 1.0 section 2.4).
	logoutEvent = "http://schemas.openid.net/event/backchannel-logout"
	// tokenType is the JOSE header typ of a logout token, which section 2.4 recommends and which
	// lets an id_token_hint check refuse it (#784 decisions 4 and 12).
	tokenType = "logout+jwt" //nolint:gosec // G101: a JOSE header typ value, not a credential
)

// attemptOffsets is when each attempt starts, from the first: about 0, 15 and 60 seconds, so an app
// briefly unreachable is retried for about a minute, every attempt within the token's life (#784
// decision 5).
var attemptOffsets = []time.Duration{0, 15 * time.Second, 60 * time.Second}

// Outcome is how one delivery ended, the closed set the metric's outcome label takes and the audit
// event records (#784 decision 8).
type Outcome string

const (
	// Delivered is a 2xx answer.
	Delivered Outcome = "delivered"
	// Refused is a final 3xx or 4xx answer: anything but 408 and 429, which are retried.
	Refused Outcome = "refused"
	// Failed is no success after the last attempt, a certificate the auth server does not trust, or
	// a token that could not be signed.
	Failed Outcome = "failed"
	// Blocked is an address the guard on deliveries to self-registered clients refused (#784
	// decision 7).
	Blocked Outcome = "blocked"
	// Skipped is a stored URI that breaks #784 decision 6's rules for its client when it is sent.
	Skipped Outcome = "skipped"
)

// outcomes is every Outcome, the label's declared set.
var outcomes = []Outcome{Delivered, Refused, Failed, Blocked, Skipped}

// errURINotAllowed is a stored URI that no longer passes the rules for its client: a client made
// public with an http URI stored, for one.
var errURINotAllowed = errors.New("the stored back-channel logout URI is not allowed for this client")

// KeyDatabase is what a delivery reads: the current signing key, which signs ID tokens too (Back-
// Channel Logout 1.0 section 2.4).
type KeyDatabase interface {
	GetCurrentSigningKey(ctx context.Context, tx *sql.Tx) (*record.KeyPair, error)
}

// Jobs runs a job after the response. The server's afterresponse.Jobs is the one implementation.
type Jobs interface {
	Go(ctx context.Context, class afterresponse.Class, job func(ctx context.Context))
}

// AuditLogger records one security event.
type AuditLogger interface {
	Log(ctx context.Context, auditEvent string, details map[string]interface{})
}

// Recorder counts the deliveries by outcome on the metrics listener (#784 decision 8).
type Recorder struct {
	deliveries *metrics.Counter
}

// Register registers the deliveries counter on reg, every outcome at zero from the first scrape, and
// returns the recorder that counts in it. The server registers it once, at startup.
func Register(reg *metrics.Registry) *Recorder {
	names := make([]string, len(outcomes))
	for i, outcome := range outcomes {
		names[i] = string(outcome)
	}
	deliveries := reg.Counter("goiabada_backchannel_logout_deliveries_total",
		"Logout tokens sent to apps' back-channel logout URIs, by how each delivery ended.",
		metrics.Enum("outcome", names...))
	// A labelled series appears only when it is first recorded, and increase() reads nothing over a
	// window in which a series first appears.
	for _, name := range names {
		deliveries.Add(0, name)
	}
	return &Recorder{deliveries: deliveries}
}

// Sender delivers logout tokens. routes.go builds the one the session ends take.
type Sender struct {
	database    KeyDatabase
	dataCipher  *encryption.DataCipher
	jobs        Jobs
	auditLogger AuditLogger
	recorder    *Recorder
	client      *http.Client

	// The schedule and the clock, fields so a test can run the schedule without waiting it out.
	offsets        []time.Duration
	attemptTimeout time.Duration
	now            func() time.Time
	sleep          func(ctx context.Context, d time.Duration)
	jitter         func(d time.Duration) time.Duration
}

// NewSender builds the sender over the signing keys, the data cipher they are sealed under, the
// after-response jobs, the audit log and the deliveries counter.
func NewSender(database KeyDatabase, dataCipher *encryption.DataCipher, jobs Jobs, auditLogger AuditLogger,
	recorder *Recorder) *Sender {

	s := NewCommandSender(database, dataCipher, auditLogger)
	s.jobs, s.recorder = jobs, recorder
	return s
}

// NewCommandSender builds the sender of a process with no after-response jobs and no metrics
// listener, the recover command, which delivers through SendAndWait (#784 decision 11). Its
// deliveries follow the same rules and write the same Warn records and audit events, and are counted
// nowhere.
func NewCommandSender(database KeyDatabase, dataCipher *encryption.DataCipher, auditLogger AuditLogger) *Sender {
	return &Sender{
		database:    database,
		dataCipher:  dataCipher,
		auditLogger: auditLogger,
		// The environment's proxy is honoured, as the Turnstile client honours it, and no redirect is
		// ever followed: a 3xx is the app's answer (#784 decisions 5 and 7). There is no client-wide
		// timeout; each attempt has its own deadline.
		client: &http.Client{
			Transport:     http.DefaultTransport.(*http.Transport).Clone(),
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		offsets:        attemptOffsets,
		attemptTimeout: attemptTimeout,
		now:            func() time.Time { return time.Now().UTC() },
		sleep:          sleepFor,
		jitter:         jitter,
	}
}

// sleepFor waits d, or until ctx is done.
func sleepFor(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}

// jitter moves d by up to a tenth either way, so the retries of many deliveries that failed
// together do not arrive together.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	//nolint:gosec // G404: spreads retries in time, which no one gains by predicting
	return d + time.Duration((rand.Float64()*2-1)*jitterFraction*float64(d))
}

// Send hands each delivery to a job of its own, all of them at once, and returns. issuer is the
// tokens' iss, the issuer setting. The caller calls it once the end that collected the deliveries
// has committed. A delivery past its class's budget is dropped and counted by the jobs, and leaves
// no audit record, since it never ran.
func (s *Sender) Send(ctx context.Context, issuer string, deliveries []Delivery) {
	for _, delivery := range deliveries {
		class := afterresponse.ClassBackchannelLogout
		if delivery.CreatedViaDCR {
			class = afterresponse.ClassBackchannelLogoutSelfRegistered
		}
		s.jobs.Go(ctx, class, func(jobCtx context.Context) {
			s.deliver(jobCtx, issuer, delivery)
		})
	}
}

// SendAndWait starts every delivery at once, as Send does, and returns once each has finished,
// calling finished with each delivery's outcome as it does, one call at a time on the caller's
// goroutine. It is Send for a caller that waits for its deliveries rather than handing them to the
// after-response jobs: the recover command, which says what each came to (#784 decision 11). No job
// budget applies, so none is dropped.
func (s *Sender) SendAndWait(ctx context.Context, issuer string, deliveries []Delivery,
	finished func(Delivery, Outcome)) {

	type done struct {
		delivery Delivery
		outcome  Outcome
	}
	results := make(chan done, len(deliveries))
	for _, delivery := range deliveries {
		go func() {
			results <- done{delivery: delivery, outcome: s.deliver(ctx, issuer, delivery)}
		}()
	}
	for range deliveries {
		result := <-results
		finished(result.delivery, result.outcome)
	}
}

// result is what one delivery came to.
type result struct {
	outcome  Outcome
	attempts int
	// status is the last answer's status code, 0 when none arrived; err is why there was none.
	status int
	err    error
}

// deliver runs one delivery to its end, records it, the metric when the sender has a recorder, a
// Warn record when it did not succeed, and the audit event, and answers how it ended.
func (s *Sender) deliver(ctx context.Context, issuer string, delivery Delivery) Outcome {
	jti := uuid.New()
	res := s.run(ctx, issuer, delivery, jti)

	if s.recorder != nil {
		s.recorder.deliveries.Inc(string(res.outcome))
	}
	// The status when an answer came, the error when none did; never the token.
	switch {
	case res.outcome == Delivered:
	case res.err != nil:
		slog.WarnContext(ctx, "a logout token was not delivered",
			"client_id", delivery.ClientId,
			"client_identifier", delivery.ClientIdentifier,
			"user_id", delivery.UserId,
			"outcome", string(res.outcome),
			"attempts", res.attempts,
			"error", res.err)
	default:
		slog.WarnContext(ctx, "a logout token was not delivered",
			"client_id", delivery.ClientId,
			"client_identifier", delivery.ClientIdentifier,
			"user_id", delivery.UserId,
			"outcome", string(res.outcome),
			"attempts", res.attempts,
			"status", res.status)
	}
	LogSentLogoutToken(ctx, s.auditLogger, delivery, jti, res.outcome, res.attempts)
	return res.outcome
}

// run checks the stored URI again, signs the token once, and makes the attempts: each at its offset,
// the same token every time, and none that could not finish before the token expires.
func (s *Sender) run(ctx context.Context, issuer string, delivery Delivery, jti string) result {
	allowHTTP := !delivery.IsPublic && !delivery.CreatedViaDCR
	if urlmatch.CheckBackchannelLogoutURI(delivery.URI, allowHTTP) != urlmatch.BackchannelLogoutURIAcceptable {
		return result{outcome: Skipped, err: errURINotAllowed}
	}

	issuedAt := s.now()
	expiresAt := issuedAt.Add(tokenLifetime)
	token, err := s.sign(ctx, issuer, delivery, jti, issuedAt, expiresAt)
	if err != nil {
		return result{outcome: Failed, err: err}
	}

	last := result{outcome: Failed}
	for i, offset := range s.offsets {
		if i > 0 {
			if wait := s.jitter(offset) - s.now().Sub(issuedAt); wait > 0 {
				s.sleep(ctx, wait)
			}
		}
		if s.now().Add(s.attemptTimeout).After(expiresAt) {
			break
		}
		attempt := s.attempt(ctx, delivery.URI, token)
		attempt.attempts = last.attempts + 1
		if !attempt.retry {
			return attempt.result
		}
		last = attempt.result
		last.outcome = Failed
	}
	return last
}

// attemptResult is one attempt's result, and whether another is worth making.
type attemptResult struct {
	result
	retry bool
}

// attempt POSTs the token once, within the attempt's deadline, and classifies what came back (#784
// decision 5). Any 2xx is delivered; a 3xx, which is never followed, and any 4xx but 408 and 429
// are refused, as is anything else that is not retried; 408, 429 and 5xx, a timeout and a failed
// connection are retried; a certificate the auth server does not trust is final.
func (s *Sender) attempt(ctx context.Context, uri string, token string) attemptResult {
	ctx, cancel := context.WithTimeout(ctx, s.attemptTimeout)
	defer cancel()

	body := url.Values{"logout_token": {token}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, strings.NewReader(body))
	if err != nil {
		return attemptResult{result: result{outcome: Failed, err: errs.Wrap(err, "unable to build the request")}}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.client.Do(req)
	if err != nil {
		if certificateFailure(err) {
			return attemptResult{result: result{outcome: Failed, err: err}}
		}
		return attemptResult{result: result{outcome: Failed, err: err}, retry: true}
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, answerBodyCap))

	status := resp.StatusCode
	switch {
	case status >= 200 && status < 300:
		return attemptResult{result: result{outcome: Delivered, status: status}}
	case status == http.StatusRequestTimeout, status == http.StatusTooManyRequests, status >= 500:
		return attemptResult{result: result{outcome: Failed, status: status}, retry: true}
	default:
		return attemptResult{result: result{outcome: Refused, status: status}}
	}
}

// certificateFailure reports whether err is the server's certificate failing verification, which a
// retry would meet again.
func certificateFailure(err error) bool {
	var verification *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	return errors.As(err, &verification) || errors.As(err, &unknownAuthority) ||
		errors.As(err, &hostname) || errors.As(err, &invalid)
}

// sign builds the logout token of #784 decision 4 under the current signing key: typed logout+jwt,
// with iss, aud, iat, exp, jti, the logout event, sub, and sid when the delivery names a session. It
// carries no nonce, which Back-Channel Logout 1.0 section 2.4 forbids, and no nbf.
func (s *Sender) sign(ctx context.Context, issuer string, delivery Delivery, jti string,
	issuedAt, expiresAt time.Time) (string, error) {

	keyPair, err := s.database.GetCurrentSigningKey(ctx, nil)
	if err != nil {
		return "", err
	}
	privateKey, err := signingkeys.ParsePrivateKey(s.dataCipher, keyPair)
	if err != nil {
		return "", errs.Wrap(err, "unable to parse private key from PEM")
	}

	claims := jwt.MapClaims{
		"iss":    issuer,
		"aud":    delivery.ClientIdentifier,
		"iat":    issuedAt.Unix(),
		"exp":    expiresAt.Unix(),
		"jti":    jti,
		"events": map[string]interface{}{logoutEvent: map[string]interface{}{}},
		"sub":    delivery.Subject,
	}
	if delivery.SessionIdentifier != "" {
		claims["sid"] = delivery.SessionIdentifier
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyPair.KeyIdentifier
	token.Header["typ"] = tokenType
	signed, err := token.SignedString(privateKey)
	if err != nil {
		return "", errs.Wrap(err, "unable to sign the logout token")
	}
	return signed, nil
}

// LogSentLogoutToken emits EventSentLogoutToken, the record that an app was told, or not, that the
// user's session ended (#784 decision 8). One function so the payload has one place to be asserted
// field by field. session_identifier is empty for a token about every session of the user.
func LogSentLogoutToken(ctx context.Context, auditLogger AuditLogger, delivery Delivery, jti string,
	outcome Outcome, attempts int) {

	auditLogger.Log(ctx, audit.EventSentLogoutToken, map[string]interface{}{
		"client_id":          delivery.ClientId,
		"user_id":            delivery.UserId,
		"session_identifier": delivery.SessionIdentifier,
		"jti":                jti,
		"outcome":            string(outcome),
		"attempts":           attempts,
	})
}
