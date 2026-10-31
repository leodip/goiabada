package turnstile_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/turnstile"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The verifier against a local stand-in for siteverify (#642 decisions 3 and 4): each kind of
// answer is mapped to pass, refuse or fail open, counted under its outcome, and logged when an
// operator must see it, never with the token or the secret key. The deadline and the size bound
// cannot be provoked from the real Cloudflare, which the integration tier calls.

const (
	// The auth server's base URL: the hostname a token must have been solved on is its host, with
	// no scheme, no port and in lower case.
	baseURL  = "https://Auth.Example.com:8443"
	hostname = "auth.example.com"

	secretKey = "0x4AAAAAAAstand-in-secret-key"
	token     = "0.stand-in-token-that-the-widget-wrote"

	dataKey = "0123456789abcdef0123456789abcdef"
)

// standIn is siteverify on this machine: it answers every call with status and body, after
// holding it until release is closed or the call is given up, when hold is set, and records what
// each call carried.
type standIn struct {
	server *httptest.Server

	mu     sync.Mutex
	status int
	body   string
	header http.Header
	hold   chan struct{}
	calls  []call
}

type call struct {
	method      string
	contentType string
	form        url.Values
}

func newStandIn(t *testing.T) *standIn {
	t.Helper()
	s := &standIn{status: http.StatusOK, header: http.Header{}}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(raw))
		s.mu.Lock()
		s.calls = append(s.calls, call{method: r.Method, contentType: r.Header.Get("Content-Type"), form: form})
		status, body, hold := s.status, s.body, s.hold
		for name, values := range s.header {
			w.Header()[name] = values
		}
		s.mu.Unlock()
		if hold != nil {
			select {
			case <-hold:
			case <-r.Context().Done():
				return
			}
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *standIn) answer(status int, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status, s.body = status, body
}

func (s *standIn) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

// harness is a verifier over a stand-in, its own registry and a data cipher, and the settings row
// the challenge is on in, its secret key sealed under that cipher.
type harness struct {
	standIn  *standIn
	registry *metrics.Registry
	verifier *turnstile.Verifier
	settings *record.Settings
	logs     *logtest.SlogCapture
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dataCipher, err := encryption.NewDataCipher([]byte(dataKey))
	require.NoError(t, err)
	sealed, err := dataCipher.Encrypt(secretKey)
	require.NoError(t, err)

	s := newStandIn(t)
	registry := metrics.NewRegistry()
	return &harness{
		standIn:  s,
		registry: registry,
		verifier: turnstile.NewVerifier(registry, dataCipher, baseURL, s.server.URL+"/turnstile/v0/siteverify"),
		settings: &record.Settings{
			TurnstileEnabled:            true,
			TurnstileSiteKey:            "0x4AAAAAAAstand-in-site-key",
			TurnstileSecretKeyEncrypted: sealed,
		},
		logs: logtest.CaptureSlog(t),
	}
}

func (h *harness) check(form turnstile.Form, token string) turnstile.Outcome {
	return h.verifier.Check(context.Background(), h.settings, form, token)
}

// count is the counter's value for form and outcome, read from the registry's exposition.
func (h *harness) count(t *testing.T, form, outcome string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.registry.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	series := `goiabada_challenge_verifications_total{form="` + form + `",outcome="` + outcome + `"} `
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if value, found := strings.CutPrefix(line, series); found {
			return value
		}
	}
	return "0"
}

// errorRecords are the records logged at error level.
func (h *harness) recordsAt(level slog.Level) []logtest.CapturedRecord {
	var at []logtest.CapturedRecord
	for _, r := range h.logs.Records() {
		if r.Level == level {
			at = append(at, r)
		}
	}
	return at
}

// assertNothingSecretLogged holds every record to carrying neither the token nor the secret key.
func (h *harness) assertNothingSecretLogged(t *testing.T, token string) {
	t.Helper()
	text := h.logs.Text()
	assert.NotContains(t, text, secretKey, "the secret key is never logged")
	if token != "" {
		assert.NotContains(t, text, token, "the token is never logged")
	}
}

const passingLogin = `{"success":true,"challenge_ts":"2026-10-31T19:54:09.112Z","hostname":"auth.example.com","action":"login","error-codes":[],"cdata":""}`

func TestCheck_ATokenVerifiedForThisHostAndFormPasses(t *testing.T) {
	h := newHarness(t)
	h.standIn.answer(http.StatusOK, passingLogin)

	assert.Equal(t, turnstile.Passed, h.check(turnstile.FormLogin, token))
	assert.False(t, turnstile.Passed.Refuses())

	require.Equal(t, 1, h.standIn.callCount(), "one attempt, no retry")
	got := h.standIn.calls[0]
	assert.Equal(t, http.MethodPost, got.method)
	assert.Equal(t, "application/x-www-form-urlencoded", got.contentType)
	assert.Equal(t, url.Values{"secret": {secretKey}, "response": {token}}, got.form,
		"the call sends the secret key and the token, and nothing else: no remoteip, no idempotency_key")

	assert.Equal(t, "1", h.count(t, "login", "passed"))
	assert.Empty(t, h.recordsAt(slog.LevelError))
	assert.Empty(t, h.recordsAt(slog.LevelWarn))
}

// The hostname is compared as a host name, in any case Cloudflare spells it.
func TestCheck_TheHostnameIsComparedWithoutCase(t *testing.T) {
	h := newHarness(t)
	h.standIn.answer(http.StatusOK, strings.Replace(passingLogin, "auth.example.com", "AUTH.example.COM", 1))

	assert.Equal(t, turnstile.Passed, h.check(turnstile.FormLogin, token))
}

// An empty token, or one longer than the 2048 characters Cloudflare allows, is refused without a
// call: a flood that never passes the challenge costs no outbound call (decision 3).
func TestCheck_AMissingOrOversizedTokenIsRefusedWithoutACall(t *testing.T) {
	for _, tt := range []struct {
		name  string
		token string
	}{
		{"an empty token", ""},
		{"a token of 2049 characters", strings.Repeat("a", 2049)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.standIn.answer(http.StatusOK, passingLogin)

			outcome := h.check(turnstile.FormLogin, tt.token)

			assert.Equal(t, turnstile.Missing, outcome)
			assert.True(t, outcome.Refuses())
			assert.Zero(t, h.standIn.callCount(), "no call to siteverify")
			assert.Equal(t, "1", h.count(t, "login", "missing"))
			assert.Empty(t, h.recordsAt(slog.LevelError))
		})
	}

	t.Run("a token of exactly 2048 characters is checked", func(t *testing.T) {
		h := newHarness(t)
		h.standIn.answer(http.StatusOK, passingLogin)

		assert.Equal(t, turnstile.Passed, h.check(turnstile.FormLogin, strings.Repeat("a", 2048)))
		assert.Equal(t, 1, h.standIn.callCount())
	})
}

// Cloudflare's verdict against the token is always refused, and so is a token solved on another
// site sharing the widget or for another of the three forms (decisions 3 and 4).
func TestCheck_AVerdictOnTheTokenIsRefused(t *testing.T) {
	for _, tt := range []struct {
		name string
		form turnstile.Form
		body string
	}{
		{"invalid-input-response", turnstile.FormLogin,
			`{"success":false,"error-codes":["invalid-input-response"],"messages":[]}`},
		{"timeout-or-duplicate", turnstile.FormLogin,
			`{"success":false,"error-codes":["timeout-or-duplicate"],"messages":[]}`},
		{"a test key's always-fail answer", turnstile.FormLogin,
			`{"error-codes":["invalid-input-response"],"success":false,"messages":[],"metadata":{"result_with_testing_key":true}}`},
		{"a token solved on another hostname", turnstile.FormLogin,
			`{"success":true,"hostname":"other.example.com","action":"login","error-codes":[]}`},
		{"a token solved on a subdomain of the host", turnstile.FormLogin,
			`{"success":true,"hostname":"evil.auth.example.com","action":"login","error-codes":[]}`},
		{"a token with no hostname", turnstile.FormLogin,
			`{"success":true,"action":"login","error-codes":[]}`},
		{"a token solved for the registration form, submitted to sign-in", turnstile.FormLogin,
			`{"success":true,"hostname":"auth.example.com","action":"register","error-codes":[]}`},
		{"a token solved for sign-in, submitted to forgot-password", turnstile.FormForgotPassword,
			`{"success":true,"hostname":"auth.example.com","action":"login","error-codes":[]}`},
		{"a token with no action", turnstile.FormLogin,
			`{"success":true,"hostname":"auth.example.com","error-codes":[]}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.standIn.answer(http.StatusOK, tt.body)

			outcome := h.check(tt.form, token)

			assert.Equal(t, turnstile.Refused, outcome)
			assert.True(t, outcome.Refuses())
			label := strings.ReplaceAll(string(tt.form), "-", "_")
			assert.Equal(t, "1", h.count(t, label, "refused"))
			assert.Empty(t, h.recordsAt(slog.LevelError), "a refusal is not an error an operator is paged for")
			h.assertNothingSecretLogged(t, token)
		})
	}
}

// Each form's action is its own, and the counter's form label is its name with an underscore.
func TestCheck_EachFormPassesOnItsOwnAction(t *testing.T) {
	for _, tt := range []struct {
		form   turnstile.Form
		action string
		label  string
	}{
		{turnstile.FormLogin, "login", "login"},
		{turnstile.FormForgotPassword, "forgot-password", "forgot_password"},
		{turnstile.FormRegister, "register", "register"},
	} {
		t.Run(tt.action, func(t *testing.T) {
			h := newHarness(t)
			h.standIn.answer(http.StatusOK,
				`{"success":true,"hostname":"auth.example.com","action":"`+tt.action+`","error-codes":[]}`)

			assert.Equal(t, turnstile.Passed, h.check(tt.form, token))
			assert.Equal(t, "1", h.count(t, tt.label, "passed"))
		})
	}
}

// Cloudflare's test secret keys pass any token and answer hostname example.com and no action, as
// the probe beside the agreement shows: the hostname and action checks are skipped, and a warning
// says every token passes (decision 3).
func TestCheck_ATestKeysAnswerSkipsTheHostnameAndActionChecksAndWarns(t *testing.T) {
	h := newHarness(t)
	h.standIn.answer(http.StatusOK,
		`{"challenge_ts":"2026-10-31T19:54:09.112Z","error-codes":[],"hostname":"example.com","metadata":{"result_with_testing_key":true},"success":true}`)

	assert.Equal(t, turnstile.Passed, h.check(turnstile.FormLogin, token))
	assert.Equal(t, "1", h.count(t, "login", "passed"))

	warnings := h.recordsAt(slog.LevelWarn)
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0].Message, "test key")
	assert.Contains(t, warnings[0].Message, "every token passes")
	h.assertNothingSecretLogged(t, token)
}

// A fault in the configured secret key fails open, counted apart from an outage so an operator can
// alert on a revoked secret key, and logged at error with Cloudflare's codes (decision 4).
// Cloudflare answers a fault in the secret key with status 400, where it answers a verdict on the
// token with 200, so the codes are read off either.
func TestCheck_AFaultInTheSecretKeyFailsOpenAsMisconfigured(t *testing.T) {
	for _, tt := range []struct {
		code   string
		status int
	}{
		{"invalid-input-secret", http.StatusBadRequest},
		{"missing-input-secret", http.StatusBadRequest},
		{"invalid-input-secret", http.StatusOK},
	} {
		code := tt.code
		t.Run(code+" "+strconv.Itoa(tt.status), func(t *testing.T) {
			h := newHarness(t)
			h.standIn.answer(tt.status, `{"success":false,"error-codes":["`+code+`"],"messages":[]}`)

			outcome := h.check(turnstile.FormLogin, token)

			assert.Equal(t, turnstile.Misconfigured, outcome)
			assert.False(t, outcome.Refuses(), "the submission goes on as with the challenge off")
			assert.Equal(t, "1", h.count(t, "login", "misconfigured"))
			errors := h.recordsAt(slog.LevelError)
			require.Len(t, errors, 1)
			assert.Equal(t, code, errors[0].Attrs["error_codes"])
			assert.Equal(t, "login", errors[0].Attrs["form"])
			h.assertNothingSecretLogged(t, token)
		})
	}
}

// A secret key that cannot be decrypted, or none stored while the challenge is on, is a fault in
// the configuration: it fails open with no call.
func TestCheck_ASecretKeyThatCannotBeOpenedFailsOpenWithoutACall(t *testing.T) {
	otherCipher, err := encryption.NewDataCipher([]byte("fedcba9876543210fedcba9876543210"))
	require.NoError(t, err)
	sealedUnderAnotherKey, err := otherCipher.Encrypt(secretKey)
	require.NoError(t, err)

	for _, tt := range []struct {
		name   string
		sealed []byte
	}{
		{"sealed under another data key", sealedUnderAnotherKey},
		{"none stored", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.standIn.answer(http.StatusOK, passingLogin)
			h.settings.TurnstileSecretKeyEncrypted = tt.sealed

			outcome := h.check(turnstile.FormLogin, token)

			assert.Equal(t, turnstile.Misconfigured, outcome)
			assert.False(t, outcome.Refuses())
			assert.Zero(t, h.standIn.callCount())
			assert.Equal(t, "1", h.count(t, "login", "misconfigured"))
			assert.Len(t, h.recordsAt(slog.LevelError), 1)
			h.assertNothingSecretLogged(t, token)
		})
	}
}

// No usable answer fails open, counted as unavailable and logged at error with its reason
// (decision 4).
func TestCheck_NoUsableAnswerFailsOpenAsUnavailable(t *testing.T) {
	for _, tt := range []struct {
		name   string
		status int
		body   string
		header http.Header
		// The attributes the error record carries.
		attrs map[string]any
	}{
		{name: "internal-error", status: http.StatusOK,
			body:  `{"success":false,"error-codes":["internal-error"],"messages":[]}`,
			attrs: map[string]any{"reason": "error_codes", "error_codes": "internal-error"}},
		{name: "bad-request", status: http.StatusOK,
			body:  `{"success":false,"error-codes":["bad-request"],"messages":[]}`,
			attrs: map[string]any{"reason": "error_codes", "error_codes": "bad-request"}},
		{name: "an error code Cloudflare does not document", status: http.StatusOK,
			body:  `{"success":false,"error-codes":["something-new"],"messages":[]}`,
			attrs: map[string]any{"reason": "error_codes", "error_codes": "something-new"}},
		{name: "success false with no codes", status: http.StatusOK,
			body:  `{"success":false,"error-codes":[]}`,
			attrs: map[string]any{"reason": "error_codes", "error_codes": ""}},
		{name: "a status other than 200", status: http.StatusInternalServerError,
			body:  passingLogin,
			attrs: map[string]any{"reason": "status", "status": int64(500)}},
		{name: "a verdict with a status other than 200, which Cloudflare answers with 200", status: http.StatusBadRequest,
			body:  `{"success":false,"error-codes":["invalid-input-response"],"messages":[]}`,
			attrs: map[string]any{"reason": "status", "status": int64(400)}},
		{name: "a status other than 200 with a body that is not JSON", status: http.StatusBadGateway,
			body:  "<html>bad gateway</html>",
			attrs: map[string]any{"reason": "status", "status": int64(502)}},
		{name: "a redirect, which is not followed", status: http.StatusTemporaryRedirect,
			header: http.Header{"Location": {"https://elsewhere.example.com/siteverify"}},
			attrs:  map[string]any{"reason": "status", "status": int64(307)}},
		{name: "a body that is not JSON", status: http.StatusOK,
			body:  "<html>gateway</html>",
			attrs: map[string]any{"reason": "unreadable"}},
		{name: "a body larger than the ceiling", status: http.StatusOK,
			body:  `{"success":true,"hostname":"auth.example.com","action":"login","cdata":"` + strings.Repeat("x", 64<<10) + `"}`,
			attrs: map[string]any{"reason": "unreadable"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.standIn.answer(tt.status, tt.body)
			h.standIn.header = tt.header

			outcome := h.check(turnstile.FormLogin, token)

			assert.Equal(t, turnstile.Unavailable, outcome)
			assert.False(t, outcome.Refuses(), "the submission goes on as with the challenge off")
			assert.Equal(t, 1, h.standIn.callCount(), "one attempt, no retry")
			assert.Equal(t, "1", h.count(t, "login", "unavailable"))
			errors := h.recordsAt(slog.LevelError)
			require.Len(t, errors, 1)
			for name, want := range tt.attrs {
				assert.Equal(t, want, errors[0].Attrs[name], name)
			}
			h.assertNothingSecretLogged(t, token)
		})
	}
}

// One attempt with a 3-second deadline: a siteverify that does not answer in time is given up and
// the submission goes on.
func TestCheck_ASiteverifyThatDoesNotAnswerInThreeSecondsFailsOpen(t *testing.T) {
	h := newHarness(t)
	h.standIn.answer(http.StatusOK, passingLogin)
	release := make(chan struct{})
	h.standIn.hold = release
	t.Cleanup(func() { close(release) })

	started := time.Now()
	outcome := h.check(turnstile.FormLogin, token)
	elapsed := time.Since(started)

	assert.Equal(t, turnstile.Unavailable, outcome)
	assert.GreaterOrEqual(t, elapsed, 3*time.Second, "the deadline is three seconds")
	assert.Less(t, elapsed, 4*time.Second, "and no more")
	assert.Equal(t, 1, h.standIn.callCount())
	assert.Equal(t, "1", h.count(t, "login", "unavailable"))
	errors := h.recordsAt(slog.LevelError)
	require.Len(t, errors, 1)
	assert.Equal(t, "timeout", errors[0].Attrs["reason"])
	h.assertNothingSecretLogged(t, token)
}

func TestCheck_AnUnreachableSiteverifyFailsOpen(t *testing.T) {
	h := newHarness(t)
	h.standIn.server.Close()

	outcome := h.check(turnstile.FormLogin, token)

	assert.Equal(t, turnstile.Unavailable, outcome)
	assert.Equal(t, "1", h.count(t, "login", "unavailable"))
	errors := h.recordsAt(slog.LevelError)
	require.Len(t, errors, 1)
	assert.Equal(t, "unreachable", errors[0].Attrs["reason"])
	h.assertNothingSecretLogged(t, token)
}

// The counter's label sets are closed and declared, every series there from the start.
func TestNewVerifier_RegistersTheCounterWithItsClosedLabelSets(t *testing.T) {
	registry := metrics.NewRegistry()
	turnstile.NewVerifier(registry, nil, baseURL, turnstile.SiteverifyURL)

	var found *metrics.Family
	for _, family := range registry.Families() {
		if family.Name == "goiabada_challenge_verifications_total" {
			found = &family
		}
	}
	require.NotNil(t, found, "the counter is registered")
	assert.Equal(t, "counter", found.Type)
	var labels []string
	values := map[string][]string{}
	for _, label := range found.Labels {
		labels = append(labels, label.Name())
		values[label.Name()] = label.Values()
	}
	assert.Equal(t, []string{"form", "outcome"}, labels)
	assert.ElementsMatch(t, []string{"login", "forgot_password", "register"}, values["form"])
	assert.ElementsMatch(t, []string{"passed", "refused", "missing", "unavailable", "misconfigured"}, values["outcome"])
}

// The secret key a save offers is checked with siteverify, through the same stand-in (#642 decision
// 11): Cloudflare's answer about the secret key, not about the token, decides it. A real secret key
// answers Cloudflare's dummy token with a verdict on the token, which accepts the key; a test key
// passes the token, which accepts it too.

const offeredSecretKey = "0x4AAAAAAAoffered-secret-key"

func (h *harness) checkSecretKey() turnstile.SecretKeyCheck {
	return h.verifier.CheckSecretKey(context.Background(), offeredSecretKey)
}

// assertNoFormCounted holds the secret key's check to counting nothing: the counter counts the
// forms' checks, and a save is none of them.
func (h *harness) assertNoFormCounted(t *testing.T) {
	t.Helper()
	for _, form := range []string{"login", "forgot_password", "register"} {
		for _, outcome := range []string{"passed", "refused", "missing", "unavailable", "misconfigured"} {
			assert.Equal(t, "0", h.count(t, form, outcome), "%s %s", form, outcome)
		}
	}
}

func TestCheckSecretKey_ASecretKeyCloudflareAnswersAboutTheTokenIsAccepted(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"a verdict on the dummy token", http.StatusOK, `{"success":false,"error-codes":["invalid-input-response"],"messages":[]}`},
		{"a spent token", http.StatusOK, `{"success":false,"error-codes":["timeout-or-duplicate"],"messages":[]}`},
		{"a test key passing every token", http.StatusOK,
			`{"challenge_ts":"2026-10-31T19:54:09.112Z","error-codes":[],"hostname":"example.com","metadata":{"result_with_testing_key":true},"success":true}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			h.standIn.answer(c.status, c.body)

			assert.Equal(t, turnstile.SecretKeyAccepted, h.checkSecretKey())

			require.Equal(t, 1, h.standIn.callCount(), "one attempt, no retry")
			got := h.standIn.calls[0]
			assert.Equal(t, http.MethodPost, got.method)
			assert.Equal(t, "application/x-www-form-urlencoded", got.contentType)
			assert.Equal(t, url.Values{"secret": {offeredSecretKey}, "response": {"XXXX.DUMMY.TOKEN.XXXX"}}, got.form,
				"the offered secret key and Cloudflare's dummy token, and nothing else")
			h.assertNoFormCounted(t)
			assert.Empty(t, h.recordsAt(slog.LevelError))
			assert.NotContains(t, h.logs.Text(), offeredSecretKey, "the secret key is never logged")
		})
	}
}

// Cloudflare's fault in the secret key rejects it, whatever the status it comes with: it answers
// these with 400.
func TestCheckSecretKey_AFaultInTheSecretKeyRejectsIt(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusOK} {
		for _, code := range []string{"invalid-input-secret", "missing-input-secret"} {
			t.Run(code+" "+strconv.Itoa(status), func(t *testing.T) {
				h := newHarness(t)
				h.standIn.answer(status, `{"success":false,"error-codes":["`+code+`"],"messages":[]}`)

				assert.Equal(t, turnstile.SecretKeyRejected, h.checkSecretKey())
				assert.Equal(t, 1, h.standIn.callCount())
				h.assertNoFormCounted(t)
				assert.NotContains(t, h.logs.Text(), offeredSecretKey, "the secret key is never logged")
			})
		}
	}
}

// No usable answer leaves the secret key unchecked, and logs why, never with the secret key.
func TestCheckSecretKey_NoUsableAnswerLeavesItUnchecked(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		wantReason string
	}{
		{"a status other than 200", http.StatusInternalServerError, `{"success":false,"error-codes":["internal-error"]}`, "status"},
		{"a verdict under another status", http.StatusBadRequest, `{"success":false,"error-codes":["invalid-input-response"]}`, "status"},
		{"internal-error", http.StatusOK, `{"success":false,"error-codes":["internal-error"],"messages":[]}`, "error_codes"},
		{"bad-request", http.StatusOK, `{"success":false,"error-codes":["bad-request"],"messages":[]}`, "error_codes"},
		{"an unreadable body", http.StatusOK, `<html>not json</html>`, "unreadable"},
		{"an oversized body", http.StatusOK, `{"success":false,"error-codes":["invalid-input-response"],"pad":"` + strings.Repeat("x", 9<<10) + `"}`, "unreadable"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			h.standIn.answer(c.status, c.body)

			assert.Equal(t, turnstile.SecretKeyUnchecked, h.checkSecretKey())
			h.assertNoFormCounted(t)
			warnings := h.recordsAt(slog.LevelWarn)
			require.Len(t, warnings, 1)
			assert.Equal(t, c.wantReason, warnings[0].Attrs["reason"])
			assert.NotContains(t, h.logs.Text(), offeredSecretKey, "the secret key is never logged")
		})
	}
}

func TestCheckSecretKey_AnUnreachableSiteverifyLeavesItUnchecked(t *testing.T) {
	h := newHarness(t)
	h.standIn.server.Close()

	assert.Equal(t, turnstile.SecretKeyUnchecked, h.checkSecretKey())
	warnings := h.recordsAt(slog.LevelWarn)
	require.Len(t, warnings, 1)
	assert.Equal(t, "unreachable", warnings[0].Attrs["reason"])
	assert.NotContains(t, h.logs.Text(), offeredSecretKey, "the secret key is never logged")
}
