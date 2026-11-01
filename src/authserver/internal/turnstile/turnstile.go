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
	"github.com/leodip/goiabada/core/httpmw"
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

// TemplateRenderer is what WithWidget draws a form with.
type TemplateRenderer interface {
	RenderTemplate(w http.ResponseWriter, r *http.Request, layoutName string, templateName string,
		data map[string]interface{}) error
}

// WithWidget is renderer drawing a form the challenge is on, carrying the widget while it is on:
// the site key its template renders the widget with, and Cloudflare's script admitted to that
// response's script-src alone (#642 decision 9). Every render of such a form goes through it, its
// first and each one beside a refusal, so each carries a fresh widget (decision 2). With the
// challenge off it is renderer, and the form is sent today's policy.
func WithWidget(renderer TemplateRenderer, settings *record.Settings) TemplateRenderer {
	if !settings.TurnstileEnabled {
		return renderer
	}
	return widgetRenderer{renderer: renderer, settings: settings}
}

type widgetRenderer struct {
	renderer TemplateRenderer
	settings *record.Settings
}

// RenderTemplate widens the policy before the render, which writes the response as soon as it
// succeeds. A render that fails leaves the response as it found it, as the renderer's own failures
// do, so the error page the caller draws instead, which carries no widget, is sent the policy it
// would have been sent anyway.
func (wr widgetRenderer) RenderTemplate(w http.ResponseWriter, r *http.Request, layoutName string, templateName string,
	data map[string]interface{}) error {

	data["turnstileSiteKey"] = wr.settings.TurnstileSiteKey
	data["turnstileScriptURL"] = ScriptURL
	header := w.Header()
	policy := header.Values(contentSecurityPolicy)
	httpmw.SetContentSecurityPolicy(header, ScriptOrigin)
	if err := wr.renderer.RenderTemplate(w, r, layoutName, templateName, data); err != nil {
		if policy == nil {
			header.Del(contentSecurityPolicy)
		} else {
			header[contentSecurityPolicy] = policy
		}
		return err
	}
	return nil
}

const contentSecurityPolicy = "Content-Security-Policy"

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
	// maxConcurrentChecks bounds the forms' checks in flight at once, whatever the rate of
	// submissions: a refused token spends no rate-limit budget, because the challenge runs ahead of
	// the limiter, so a flood of made-up tokens is held here instead. A check past it waits for a
	// slot within its own deadline, and fails open when none frees in time, as when Cloudflare
	// does not answer. The idle pool is as large, so connections are reused rather than opened
	// per call. An administrator's check of a secret key takes no slot: it is an authenticated
	// call, not a flood's, and is answered even while the forms' checks fill every slot.
	maxConcurrentChecks = 64
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
	// client asks about the forms' tokens. Its transport's per-host cap of maxConcurrentChecks
	// counts dials in progress, which a canceled call leaves running in the background, so it
	// bounds them where the slots alone would not. It is not a ceiling on every open connection:
	// over HTTP/2, Go stops counting a connection with no stream to spare while it stays open to
	// finish its streams.
	client *http.Client
	// keyClient asks about an administrator's secret key, over its own transport, so a flood that
	// fills the forms' connections cannot hold it up.
	keyClient *http.Client
	// slots holds one entry per form check in flight, up to maxConcurrentChecks.
	slots         chan struct{}
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
	formTransport := http.DefaultTransport.(*http.Transport).Clone()
	formTransport.MaxIdleConnsPerHost = maxConcurrentChecks
	formTransport.MaxConnsPerHost = maxConcurrentChecks
	return &Verifier{
		client:        siteverifyClient(formTransport),
		keyClient:     siteverifyClient(http.DefaultTransport.(*http.Transport).Clone()),
		slots:         make(chan struct{}, maxConcurrentChecks),
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

// siteverifyClient is a client that calls siteverify over transport. A redirect is no answer:
// following it would send the secret key wherever it pointed.
func siteverifyClient(transport *http.Transport) *http.Client {
	return &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
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

// verify asks siteverify about token under secretKey, once a slot is free, and decides the outcome
// from its answer. The deadline covers the wait for a slot as well as the call. A check that finds
// no slot in time, or gets no usable answer, is logged at error with its reason, and what shows
// it: the slots, the timeout, the status or the error.
func (v *Verifier) verify(ctx context.Context, form Form, secretKey, token string) Outcome {
	ctx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()

	if busy := v.takeSlot(ctx); busy != nil {
		if busy.reason == reasonBusy {
			slog.ErrorContext(ctx, "every turnstile check slot stayed busy, the challenge fails open without asking cloudflare",
				slog.String("form", form.label()), slog.String("reason", busy.reason), busy.detail)
			return Unavailable
		}
		slog.ErrorContext(ctx, "the turnstile check got no usable answer from cloudflare, the challenge fails open",
			slog.String("form", form.label()), slog.String("reason", busy.reason), busy.detail)
		return Unavailable
	}
	defer func() { <-v.slots }()

	answer, unusable := v.ask(ctx, v.client, secretKey, token)
	if unusable != nil {
		slog.ErrorContext(ctx, "the turnstile check got no usable answer from cloudflare, the challenge fails open",
			slog.String("form", form.label()), slog.String("reason", unusable.reason), unusable.detail)
		return Unavailable
	}
	return v.judge(ctx, form, answer)
}

// reasonBusy is the reason of a check that found no free slot before its deadline, so siteverify
// was never asked.
const reasonBusy = "busy"

// takeSlot takes one of the forms' check slots, waiting for one until ctx is done. It answers why
// it took none: the slots stayed busy until the deadline, or the request was given up. A free slot
// is taken first without waiting, so busy is answered only after waiting on a full pool, never for
// a context already done while slots were free.
func (v *Verifier) takeSlot(ctx context.Context) *noAnswer {
	select {
	case v.slots <- struct{}{}:
		return nil
	default:
	}
	select {
	case v.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return &noAnswer{reason: reasonBusy, detail: slog.Int("max_concurrent_checks", maxConcurrentChecks)}
		}
		return &noAnswer{reason: "unreachable", detail: slog.Any("error", ctx.Err())}
	}
}

// noAnswer is why siteverify gave no usable answer: the reason, and the attribute that shows it.
type noAnswer struct {
	reason string
	detail slog.Attr
}

// ask posts token under secretKey to siteverify through client, once, sending those two and nothing
// else (decision 3), and reads its answer whatever its status, under the bound. It answers the
// answer, or why there is none to use, within the deadline, or the earlier one ctx carries.
func (v *Verifier) ask(ctx context.Context, client *http.Client, secretKey, token string) (*siteverifyAnswer, *noAnswer) {
	ctx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()

	body := url.Values{"secret": {secretKey}, "response": {token}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.siteverifyURL, strings.NewReader(body))
	if err != nil {
		return nil, &noAnswer{reason: "unreachable", detail: slog.Any("error", err)}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, &noAnswer{reason: "timeout", detail: slog.String("timeout", verifyTimeout.String())}
		}
		return nil, &noAnswer{reason: "unreachable", detail: slog.Any("error", err)}
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
			return &answer, nil
		}
		return nil, &noAnswer{reason: "status", detail: slog.Int("status", resp.StatusCode)}
	}
	if errors.Is(readErr, context.DeadlineExceeded) {
		return nil, &noAnswer{reason: "timeout", detail: slog.String("timeout", verifyTimeout.String())}
	}
	if parseErr != nil {
		return nil, &noAnswer{reason: "unreadable", detail: slog.Any("error", parseErr)}
	}
	return &answer, nil
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

// SecretKeyCheck is what Cloudflare said of a secret key a save of the settings would put in use
// (#642 decision 11).
type SecretKeyCheck string

const (
	// SecretKeyAccepted is a secret key Cloudflare judged the token under, so it knows the key.
	SecretKeyAccepted SecretKeyCheck = "accepted"
	// SecretKeyRejected is a secret key Cloudflare answered invalid-input-secret or
	// missing-input-secret to.
	SecretKeyRejected SecretKeyCheck = "rejected"
	// SecretKeyUnchecked is no usable answer from Cloudflare, so nothing is known of the key.
	SecretKeyUnchecked SecretKeyCheck = "unchecked"
)

// dummyToken is Cloudflare's dummy token, the one its test widgets write. A real secret key answers
// it with a verdict on the token, and a test key with its own answer, so either way Cloudflare's
// answer tells whether it knows the secret key.
const dummyToken = "XXXX.DUMMY.TOKEN.XXXX"

// CheckSecretKey asks siteverify whether Cloudflare knows secretKey, with its dummy token: one call
// under the same deadline and bound as a form's check, taking none of the forms' check slots. A fault in the secret key rejects it; an
// answer about the token, whether it passes the token or not, accepts it; anything else leaves it
// unchecked, and is logged with why, never with the secret key. It is not a form's check, so the
// counter does not count it.
func (v *Verifier) CheckSecretKey(ctx context.Context, secretKey string) SecretKeyCheck {
	answer, unusable := v.ask(ctx, v.keyClient, secretKey, dummyToken)
	if unusable != nil {
		slog.WarnContext(ctx, "could not check a turnstile secret key with cloudflare",
			slog.String("reason", unusable.reason), unusable.detail)
		return SecretKeyUnchecked
	}
	switch {
	case answer.Success:
		return SecretKeyAccepted
	case containsAny(answer.ErrorCodes, secretKeyFaultCodes):
		return SecretKeyRejected
	case containsAny(answer.ErrorCodes, verdictCodes):
		return SecretKeyAccepted
	default:
		slog.WarnContext(ctx, "could not check a turnstile secret key with cloudflare",
			slog.String("reason", "error_codes"), slog.String("error_codes", strings.Join(answer.ErrorCodes, ",")))
		return SecretKeyUnchecked
	}
}
