// Package turnstile verifies the Cloudflare Turnstile challenge on the auth server's forms: the
// token a form's widget left in a submission, checked with Cloudflare's siteverify under the
// settings' secret key (#642). It decides pass, refuse or fail open, logs what an operator must
// see, and counts every check in goiabada_challenge_verifications_total. The forms' handlers
// decide what a refusal looks like.
package turnstile

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/boundedread"
	"github.com/leodip/goiabada/core/metrics"
)

const (
	// ScriptOrigin is where the widget's script comes from, which a page carrying the widget admits
	// to its script-src (#642 decision 9).
	ScriptOrigin = "https://challenges.cloudflare.com"
	// ScriptURL is the widget's script, which renders every element of class cf-turnstile on the
	// page.
	ScriptURL = ScriptOrigin + "/turnstile/v0/api.js"
	// SiteverifyURL is Cloudflare's verification endpoint.
	SiteverifyURL = ScriptOrigin + "/turnstile/v0/siteverify"
	// ResponseField is the form field the widget writes its token into, inside the form it is in.
	ResponseField = "cf-turnstile-response"
)

// Form is a form the challenge is on, spelled as its widget's action.
type Form string

const (
	FormLogin          Form = "login"
	FormForgotPassword Form = "forgot-password"
	FormRegister       Form = "register"
)

// Outcome is what one check decided, spelled as the counter's outcome label.
type Outcome string

const (
	// Passed is a token Cloudflare verified for this site and this form.
	Passed Outcome = "passed"
	// Refused is Cloudflare's verdict against the token, or a token solved on another hostname or
	// for another form.
	Refused Outcome = "refused"
	// Missing is an empty token, or one longer than Cloudflare allows, refused without a call.
	Missing Outcome = "missing"
	// Unavailable is no usable answer from Cloudflare: the challenge fails open.
	Unavailable Outcome = "unavailable"
	// Misconfigured is a fault in the configured secret key: the challenge fails open.
	Misconfigured Outcome = "misconfigured"
)

// Refuses reports whether the submission is refused: Cloudflare's verdict, or no token to ask
// about. Every other outcome lets it go on as with the challenge off.
func (o Outcome) Refuses() bool {
	return o == Refused || o == Missing
}

const (
	// maxTokenLength is the longest token Cloudflare issues. A longer one, like an empty one, is
	// refused without a call (#642 decision 3).
	maxTokenLength = 2048
	// verifyTimeout bounds the one attempt siteverify gets, with no retry (decision 4). Cloudflare
	// answered the probe beside the agreement in about 50 milliseconds; a sign-in waits no longer
	// than this for an answer that is not coming.
	verifyTimeout = 3 * time.Second
	// maxAnswerBytes is the ceiling siteverify's answer is read under. A whole answer is a few
	// hundred bytes; an answer past this is not one, and fails open as unusable.
	maxAnswerBytes = 8 << 10
)

// The error codes siteverify answers that decide the outcome (decision 4). Any other code is no
// usable answer.
var (
	// A verdict on the token.
	verdictCodes = []string{"invalid-input-response", "timeout-or-duplicate"}
	// A fault in the configured secret key.
	secretKeyFaultCodes = []string{"invalid-input-secret", "missing-input-secret"}
)

// Verifier checks a form's token with siteverify, against the auth server's own hostname.
type Verifier struct {
	client        *http.Client
	siteverifyURL string
	hostname      string
	dataCipher    *encryption.DataCipher
	checks        *metrics.Counter
}

// NewVerifier builds the verifier, registering goiabada_challenge_verifications_total on reg. A
// token passes only when it was solved on the host of authServerBaseURL. siteverifyURL is
// SiteverifyURL, which the verifier's own tests replace with a stand-in.
func NewVerifier(reg *metrics.Registry, dataCipher *encryption.DataCipher, authServerBaseURL, siteverifyURL string) *Verifier {
	var hostname string
	if parsed, err := url.Parse(authServerBaseURL); err == nil {
		hostname = strings.ToLower(parsed.Hostname())
	}
	return &Verifier{
		client: &http.Client{
			// A redirect is no answer: following it would send the secret key wherever it
			// pointed.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		siteverifyURL: siteverifyURL,
		hostname:      hostname,
		dataCipher:    dataCipher,
		checks: reg.Counter("goiabada_challenge_verifications_total",
			"Turnstile challenge checks of the forms that carry it, by form and outcome.",
			metrics.Enum("form", FormLogin.label(), FormForgotPassword.label(), FormRegister.label()),
			metrics.Enum("outcome", string(Passed), string(Refused), string(Missing), string(Unavailable),
				string(Misconfigured))),
	}
}

// label is the form's value of the counter's form label.
func (f Form) label() string {
	return strings.ReplaceAll(string(f), "-", "_")
}

// Check checks one submission of form, carrying token, under the secret key settings store, and
// counts it. The token and the secret key are never logged.
func (v *Verifier) Check(ctx context.Context, settings *record.Settings, form Form, token string) Outcome {
	outcome := v.check(ctx, settings, form, token)
	v.checks.Inc(form.label(), string(outcome))
	return outcome
}

func (v *Verifier) check(ctx context.Context, settings *record.Settings, form Form, token string) Outcome {
	if token == "" || len(token) > maxTokenLength {
		return Missing
	}
	if len(settings.TurnstileSecretKeyEncrypted) == 0 {
		slog.ErrorContext(ctx, "the turnstile challenge is on with no secret key stored, the challenge fails open",
			"form", form.label())
		return Misconfigured
	}
	secretKey, err := v.dataCipher.Decrypt(settings.TurnstileSecretKeyEncrypted)
	if err != nil {
		slog.ErrorContext(ctx, "the turnstile secret key does not decrypt, the challenge fails open",
			"form", form.label(), "error", err)
		return Misconfigured
	}
	return v.verify(ctx, form, secretKey, token)
}

// siteverifyAnswer is the part of siteverify's answer the outcome is decided from.
type siteverifyAnswer struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
	Hostname   string   `json:"hostname"`
	Action     string   `json:"action"`
	Metadata   struct {
		ResultWithTestingKey bool `json:"result_with_testing_key"`
	} `json:"metadata"`
}

// verify asks siteverify about token under secretKey, once, sending those two and nothing else
// (decision 3), and decides the outcome from its answer, read whatever its status under the
// bound. No usable answer is logged at error with its reason, and what shows it: the timeout, the
// status, the error codes or the error.
func (v *Verifier) verify(ctx context.Context, form Form, secretKey, token string) Outcome {
	ctx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()

	body := url.Values{"secret": {secretKey}, "response": {token}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.siteverifyURL, strings.NewReader(body))
	if err != nil {
		slog.ErrorContext(ctx, "the turnstile check got no usable answer from cloudflare, the challenge fails open",
			"form", form.label(), "reason", "unreachable", "error", err)
		return Unavailable
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			slog.ErrorContext(ctx, "the turnstile check got no usable answer from cloudflare, the challenge fails open",
				"form", form.label(), "reason", "timeout", "timeout", verifyTimeout.String())
			return Unavailable
		}
		slog.ErrorContext(ctx, "the turnstile check got no usable answer from cloudflare, the challenge fails open",
			"form", form.label(), "reason", "unreachable", "error", err)
		return Unavailable
	}
	defer func() { _ = resp.Body.Close() }()

	raw, readErr := boundedread.Read(resp.Body, maxAnswerBytes)
	var answer siteverifyAnswer
	parseErr := readErr
	if parseErr == nil {
		parseErr = json.Unmarshal(raw, &answer)
	}

	// Cloudflare answers a fault in the secret key with 400, and a verdict on the token with 200.
	// So the secret key's fault is the one answer read off another status: anything else there is
	// no usable answer, a verdict included.
	if resp.StatusCode != http.StatusOK {
		if parseErr == nil && !answer.Success && containsAny(answer.ErrorCodes, secretKeyFaultCodes) {
			return v.judge(ctx, form, &answer)
		}
		slog.ErrorContext(ctx, "the turnstile check got no usable answer from cloudflare, the challenge fails open",
			"form", form.label(), "reason", "status", "status", resp.StatusCode)
		return Unavailable
	}
	if errors.Is(readErr, context.DeadlineExceeded) {
		slog.ErrorContext(ctx, "the turnstile check got no usable answer from cloudflare, the challenge fails open",
			"form", form.label(), "reason", "timeout", "timeout", verifyTimeout.String())
		return Unavailable
	}
	if parseErr != nil {
		slog.ErrorContext(ctx, "the turnstile check got no usable answer from cloudflare, the challenge fails open",
			"form", form.label(), "reason", "unreadable", "error", parseErr)
		return Unavailable
	}
	return v.judge(ctx, form, &answer)
}

// judge decides the outcome of a usable answer: a verdict refuses, a fault in the secret key and
// any other failure fail open, and a success passes when the token was solved on this host for
// this form, or under a test key, which passes every token.
func (v *Verifier) judge(ctx context.Context, form Form, answer *siteverifyAnswer) Outcome {
	if !answer.Success {
		codes := strings.Join(answer.ErrorCodes, ",")
		switch {
		case containsAny(answer.ErrorCodes, secretKeyFaultCodes):
			slog.ErrorContext(ctx, "cloudflare refused the turnstile secret key, the challenge fails open",
				"form", form.label(), "error_codes", codes)
			return Misconfigured
		case containsAny(answer.ErrorCodes, verdictCodes):
			return Refused
		default:
			slog.ErrorContext(ctx, "the turnstile check got no usable answer from cloudflare, the challenge fails open",
				"form", form.label(), "reason", "error_codes", "error_codes", codes)
			return Unavailable
		}
	}

	if answer.Metadata.ResultWithTestingKey {
		slog.WarnContext(ctx, "the turnstile secret key is a cloudflare test key, so every token passes",
			"form", form.label())
		return Passed
	}
	if !strings.EqualFold(answer.Hostname, v.hostname) {
		slog.WarnContext(ctx, "refused a turnstile token solved on another hostname",
			"form", form.label(), "hostname", answer.Hostname, "expected_hostname", v.hostname)
		return Refused
	}
	if answer.Action != string(form) {
		slog.WarnContext(ctx, "refused a turnstile token solved for another form",
			"form", form.label(), "action", answer.Action)
		return Refused
	}
	return Passed
}

func containsAny(codes, wanted []string) bool {
	for _, code := range codes {
		if slices.Contains(wanted, code) {
			return true
		}
	}
	return false
}
