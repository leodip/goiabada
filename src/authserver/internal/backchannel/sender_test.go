package backchannel

import (
	"context"
	"crypto/rsa"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/afterresponse"
	"github.com/leodip/goiabada/authserver/internal/audit"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/signingkeys"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/metrics"
)

const testIssuer = "https://auth.example.com"

// syncJobs runs each job at once on the caller's goroutine, recording the class it was admitted
// under, so a test reads the delivery's outcome as soon as Send returns.
type syncJobs struct {
	classes []afterresponse.Class
}

func (j *syncJobs) Go(ctx context.Context, class afterresponse.Class, job func(ctx context.Context)) {
	j.classes = append(j.classes, class)
	job(ctx)
}

// recordingAudit keeps every event it is given.
type recordingAudit struct {
	mu     sync.Mutex
	events []auditEvent
}

type auditEvent struct {
	name    string
	details map[string]interface{}
}

func (a *recordingAudit) Log(_ context.Context, name string, details map[string]interface{}) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, auditEvent{name: name, details: details})
}

// receiver is the app's back-channel logout endpoint: it answers each POST with the next scripted
// status, the last one repeated, and keeps what arrived.
type receiver struct {
	t        *testing.T
	server   *httptest.Server
	mu       sync.Mutex
	statuses []int
	posts    []post
	// stall, when set, holds every request this long before it answers.
	stall time.Duration
}

type post struct {
	method      string
	contentType string
	token       string
}

func newReceiver(t *testing.T, statuses ...int) *receiver {
	t.Helper()
	rc := &receiver{t: t, statuses: statuses}
	rc.server = httptest.NewServer(http.HandlerFunc(rc.serve))
	t.Cleanup(rc.server.Close)
	return rc
}

func (rc *receiver) serve(w http.ResponseWriter, r *http.Request) {
	rc.mu.Lock()
	assert.NoError(rc.t, r.ParseForm())
	rc.posts = append(rc.posts, post{method: r.Method, contentType: r.Header.Get("Content-Type"),
		token: r.PostForm.Get("logout_token")})
	status := http.StatusOK
	if len(rc.statuses) > 0 {
		status = rc.statuses[0]
		if len(rc.statuses) > 1 {
			rc.statuses = rc.statuses[1:]
		}
	}
	stall := rc.stall
	rc.mu.Unlock()
	if stall > 0 {
		select {
		case <-time.After(stall):
		case <-r.Context().Done():
			return
		}
	}
	if status >= 300 && status < 400 {
		w.Header().Set("Location", "/elsewhere")
	}
	w.WriteHeader(status)
}

func (rc *receiver) received() []post {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return append([]post(nil), rc.posts...)
}

// harness is a Sender over a real signing key, with a clock the test owns: every sleep moves the
// clock on by its length and returns at once, and the jitter is none, so the waits it records are
// the schedule itself.
type harness struct {
	sender  *Sender
	jobs    *syncJobs
	audit   *recordingAudit
	reg     *metrics.Registry
	public  *rsa.PublicKey
	kid     string
	clock   time.Time
	slept   []time.Duration
	started time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	dataCipher, err := encryption.NewDataCipher([]byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	keyPair, err := signingkeys.NewKeyPair(dataCipher, record.KeyStateCurrent, 2048)
	require.NoError(t, err)
	public, err := jwt.ParseRSAPublicKeyFromPEM(keyPair.PublicKeyPEM)
	require.NoError(t, err)

	db := datamocks.NewDatabase(t)
	db.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(keyPair, nil).Maybe()

	h := &harness{
		jobs:    &syncJobs{},
		audit:   &recordingAudit{},
		reg:     metrics.NewRegistry(),
		public:  public,
		kid:     keyPair.KeyIdentifier,
		clock:   time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC),
		started: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC),
	}
	h.sender = NewSender(db, dataCipher, h.jobs, h.audit, Register(h.reg))
	h.sender.now = func() time.Time { return h.clock }
	h.sender.sleep = func(_ context.Context, d time.Duration) {
		h.slept = append(h.slept, d)
		h.clock = h.clock.Add(d)
	}
	h.sender.jitter = func(d time.Duration) time.Duration { return d }
	return h
}

// confidential is a delivery to an administrator's confidential client at uri, about one session.
func confidential(uri string) Delivery {
	return Delivery{
		ClientId:          7,
		ClientIdentifier:  "app-web",
		URI:               uri,
		UserId:            42,
		Subject:           "5b9f4d3e-6c1a-4b7e-9a2d-0f3c8e1b2a44",
		SessionIdentifier: "c0ffee00-1111-4222-8333-444455556666",
	}
}

// sent is the one sent_logout_token event the delivery wrote.
func (h *harness) sent(t *testing.T) map[string]interface{} {
	t.Helper()
	require.Len(t, h.audit.events, 1)
	require.Equal(t, audit.EventSentLogoutToken, h.audit.events[0].name)
	return h.audit.events[0].details
}

func (h *harness) samples(t *testing.T) []string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	var out []string
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if strings.HasPrefix(line, "goiabada_backchannel_logout_deliveries_total{") {
			out = append(out, line)
		}
	}
	return out
}

// TestSend_PostsASignedLogoutToken holds the token to Back-Channel Logout 1.0 section 2.4 and #784
// decision 4: a form POST of logout_token, typed logout+jwt, signed RS256 under the current key's
// kid, with iss, aud, iat, exp two minutes on, a jti, the back-channel logout event with the value
// {}, sub and sid, and no nonce.
func TestSend_PostsASignedLogoutToken(t *testing.T) {
	h := newHarness(t)
	rc := newReceiver(t, http.StatusOK)
	delivery := confidential(rc.server.URL + "/backchannel-logout?app=web")

	h.sender.Send(context.Background(), testIssuer, []Delivery{delivery})

	posts := rc.received()
	require.Len(t, posts, 1)
	assert.Equal(t, http.MethodPost, posts[0].method)
	assert.Equal(t, "application/x-www-form-urlencoded", posts[0].contentType)

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(posts[0].token, claims, func(*jwt.Token) (interface{}, error) {
		return h.public, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithTimeFunc(func() time.Time { return h.clock }))
	require.NoError(t, err)

	assert.Equal(t, map[string]interface{}{"alg": "RS256", "kid": h.kid, "typ": "logout+jwt"}, token.Header)

	jti, _ := claims["jti"].(string)
	assert.Regexp(t, `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`, jti)
	assert.Equal(t, jwt.MapClaims{
		"iss":    testIssuer,
		"aud":    "app-web",
		"iat":    float64(h.started.Unix()),
		"exp":    float64(h.started.Unix() + 120),
		"jti":    jti,
		"events": map[string]interface{}{"http://schemas.openid.net/event/backchannel-logout": map[string]interface{}{}},
		"sub":    "5b9f4d3e-6c1a-4b7e-9a2d-0f3c8e1b2a44",
		"sid":    "c0ffee00-1111-4222-8333-444455556666",
	}, claims)
	assert.NotContains(t, claims, "nonce")

	assert.Equal(t, []afterresponse.Class{afterresponse.ClassBackchannelLogout}, h.jobs.classes)
	assert.Equal(t, map[string]interface{}{
		"client_id":          int64(7),
		"user_id":            int64(42),
		"session_identifier": "c0ffee00-1111-4222-8333-444455556666",
		"jti":                jti,
		"outcome":            "delivered",
		"attempts":           1,
	}, h.sent(t))
}

// TestSend_ASubjectOnlyDeliveryHasNoSid is decision 3's other shape: no session identifier, no sid
// claim, and an empty session_identifier on the audit event.
func TestSend_ASubjectOnlyDeliveryHasNoSid(t *testing.T) {
	h := newHarness(t)
	rc := newReceiver(t, http.StatusOK)
	delivery := confidential(rc.server.URL)
	delivery.SessionIdentifier = ""

	h.sender.Send(context.Background(), testIssuer, []Delivery{delivery})

	posts := rc.received()
	require.Len(t, posts, 1)
	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(posts[0].token, claims)
	require.NoError(t, err)
	assert.NotContains(t, claims, "sid")
	assert.Equal(t, "5b9f4d3e-6c1a-4b7e-9a2d-0f3c8e1b2a44", claims["sub"])
	assert.Contains(t, h.sent(t), "session_identifier")
	assert.Empty(t, h.sent(t)["session_identifier"])
}

// TestSend_EachDeliveryIsAJobOfItsClientsClass: one job per delivery, admitted against the
// self-registered class for a client created through DCR and the other class otherwise (#784
// decision 5), so a registrant's slow endpoint never takes another app's slot.
func TestSend_EachDeliveryIsAJobOfItsClientsClass(t *testing.T) {
	h := newHarness(t)
	rc := newReceiver(t, http.StatusOK)
	admin := confidential(rc.server.URL)
	selfRegistered := confidential(strings.Replace(rc.server.URL, "http://", "https://", 1))
	selfRegistered.CreatedViaDCR = true
	selfRegistered.ClientId = 8

	h.sender.Send(context.Background(), testIssuer, []Delivery{admin, selfRegistered})

	assert.Equal(t, []afterresponse.Class{afterresponse.ClassBackchannelLogout,
		afterresponse.ClassBackchannelLogoutSelfRegistered}, h.jobs.classes)
}

// TestSend_StatusClasses is decision 5's classification: a 2xx is delivered at once; a 3xx, a 400
// and any other 4xx but 408 and 429 are final, refused after one attempt; 408, 429 and 5xx are
// retried, at most three attempts in all, at about 0, 15 and 60 seconds.
func TestSend_StatusClasses(t *testing.T) {
	testCases := []struct {
		name     string
		statuses []int
		outcome  string
		attempts int
		slept    []time.Duration
	}{
		{"200", []int{200}, "delivered", 1, nil},
		{"204", []int{204}, "delivered", 1, nil},
		{"400 is final", []int{400}, "refused", 1, nil},
		{"401 is final", []int{401}, "refused", 1, nil},
		{"404 is final", []int{404}, "refused", 1, nil},
		{"302 is final", []int{302}, "refused", 1, nil},
		{"301 is final", []int{301}, "refused", 1, nil},
		{"500 then 200", []int{500, 200}, "delivered", 2, []time.Duration{15 * time.Second}},
		{"503, 502, then 200", []int{503, 502, 200}, "delivered", 3, []time.Duration{15 * time.Second, 45 * time.Second}},
		{"408 is retried", []int{408, 204}, "delivered", 2, []time.Duration{15 * time.Second}},
		{"429 is retried", []int{429, 200}, "delivered", 2, []time.Duration{15 * time.Second}},
		{"500 then 400", []int{500, 400}, "refused", 2, []time.Duration{15 * time.Second}},
		{"500 three times", []int{500}, "failed", 3, []time.Duration{15 * time.Second, 45 * time.Second}},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			rc := newReceiver(t, tc.statuses...)

			h.sender.Send(context.Background(), testIssuer, []Delivery{confidential(rc.server.URL)})

			posts := rc.received()
			require.Len(t, posts, tc.attempts)
			// Every attempt resends the same token, so the app sees one jti however many arrive.
			for _, p := range posts {
				assert.Equal(t, posts[0].token, p.token)
			}
			sent := h.sent(t)
			assert.Equal(t, tc.outcome, sent["outcome"])
			assert.Equal(t, tc.attempts, sent["attempts"])
			assert.Equal(t, tc.slept, h.slept)
		})
	}
}

// TestSend_ARedirectIsNeverFollowed: a 3xx is refused where it is answered, and its Location is
// never asked (#784 decision 5).
func TestSend_ARedirectIsNeverFollowed(t *testing.T) {
	h := newHarness(t)
	target := newReceiver(t, http.StatusOK)
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.server.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirecting.Close)

	h.sender.Send(context.Background(), testIssuer, []Delivery{confidential(redirecting.URL)})

	assert.Empty(t, target.received())
	assert.Equal(t, "refused", h.sent(t)["outcome"])
	assert.Equal(t, 1, h.sent(t)["attempts"])
}

// TestSend_EachAttemptHasAFiveSecondDeadline: an app that does not answer in time is abandoned and
// retried, and after the last attempt the delivery has failed.
func TestSend_EachAttemptHasAFiveSecondDeadline(t *testing.T) {
	assert.Equal(t, 5*time.Second, NewSender(nil, nil, nil, nil, Register(metrics.NewRegistry())).attemptTimeout)

	h := newHarness(t)
	h.sender.attemptTimeout = 50 * time.Millisecond
	rc := newReceiver(t, http.StatusOK)
	rc.stall = 2 * time.Second

	started := time.Now()
	h.sender.Send(context.Background(), testIssuer, []Delivery{confidential(rc.server.URL)})

	assert.Less(t, time.Since(started), 1500*time.Millisecond, "each attempt is cut at its deadline")
	assert.Len(t, rc.received(), 3)
	assert.Equal(t, "failed", h.sent(t)["outcome"])
	assert.Equal(t, 3, h.sent(t)["attempts"])
}

// TestSend_AConnectionFailureIsRetried: nothing listening is a failure worth retrying.
func TestSend_AConnectionFailureIsRetried(t *testing.T) {
	h := newHarness(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())

	h.sender.Send(context.Background(), testIssuer, []Delivery{confidential("http://" + address + "/bc")})

	assert.Equal(t, "failed", h.sent(t)["outcome"])
	assert.Equal(t, 3, h.sent(t)["attempts"])
	assert.Equal(t, []time.Duration{15 * time.Second, 45 * time.Second}, h.slept)
}

// TestSend_ACertificateFailureIsFinal: a certificate the auth server does not trust will not be
// trusted fifteen seconds later, so it is not retried, and the delivery has failed.
func TestSend_ACertificateFailureIsFinal(t *testing.T) {
	h := newHarness(t)
	reached := false
	untrusted := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(untrusted.Close)

	h.sender.Send(context.Background(), testIssuer, []Delivery{confidential(untrusted.URL)})

	assert.False(t, reached)
	assert.Equal(t, "failed", h.sent(t)["outcome"])
	assert.Equal(t, 1, h.sent(t)["attempts"])
	assert.Empty(t, h.slept)
}

// TestSend_NoAttemptOutlivesTheToken: an attempt that could not finish before the token's exp is
// never started, however the schedule reads (#784 decision 5).
func TestSend_NoAttemptOutlivesTheToken(t *testing.T) {
	h := newHarness(t)
	h.sender.offsets = []time.Duration{0, 15 * time.Second, 116 * time.Second}
	rc := newReceiver(t, http.StatusServiceUnavailable)

	h.sender.Send(context.Background(), testIssuer, []Delivery{confidential(rc.server.URL)})

	assert.Len(t, rc.received(), 2, "an attempt at 116 seconds with a 5-second deadline would outlive the token")
	assert.Equal(t, "failed", h.sent(t)["outcome"])
	assert.Equal(t, 2, h.sent(t)["attempts"])
}

// TestSend_TheJitterStaysNearTheSchedule: the default jitter moves a wait by at most a tenth.
func TestSend_TheJitterStaysNearTheSchedule(t *testing.T) {
	jitter := NewSender(nil, nil, nil, nil, Register(metrics.NewRegistry())).jitter
	for range 200 {
		got := jitter(60 * time.Second)
		assert.GreaterOrEqual(t, got, 54*time.Second)
		assert.LessOrEqual(t, got, 66*time.Second)
	}
	assert.Equal(t, time.Duration(0), jitter(0))
}

// TestSend_AStoredURIBreakingTheRulesIsSkipped: decision 6's rules are checked again before each
// delivery, so a client that became public with an http URI stored, or a self-registered one with
// an http URI, is sent nothing, and that is recorded as skipped.
func TestSend_AStoredURIBreakingTheRulesIsSkipped(t *testing.T) {
	rc := newReceiver(t, http.StatusOK)
	public := confidential(rc.server.URL)
	public.IsPublic = true
	selfRegistered := confidential(rc.server.URL)
	selfRegistered.CreatedViaDCR = true
	malformed := confidential("not a uri")

	for name, delivery := range map[string]Delivery{"public": public, "self-registered": selfRegistered, "malformed": malformed} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.sender.Send(context.Background(), testIssuer, []Delivery{delivery})

			assert.Empty(t, rc.received())
			assert.Equal(t, "skipped", h.sent(t)["outcome"])
			assert.Equal(t, 0, h.sent(t)["attempts"])
		})
	}
}

// TestSend_CountsEachDeliveryByOutcome is decision 8's metric: one closed label, every series at
// zero from the first scrape.
func TestSend_CountsEachDeliveryByOutcome(t *testing.T) {
	h := newHarness(t)
	assert.Equal(t, []string{
		`goiabada_backchannel_logout_deliveries_total{outcome="blocked"} 0`,
		`goiabada_backchannel_logout_deliveries_total{outcome="delivered"} 0`,
		`goiabada_backchannel_logout_deliveries_total{outcome="failed"} 0`,
		`goiabada_backchannel_logout_deliveries_total{outcome="refused"} 0`,
		`goiabada_backchannel_logout_deliveries_total{outcome="skipped"} 0`,
	}, h.samples(t))

	ok := newReceiver(t, http.StatusOK)
	bad := newReceiver(t, http.StatusBadRequest)
	public := confidential(ok.server.URL)
	public.IsPublic = true
	h.sender.Send(context.Background(), testIssuer, []Delivery{confidential(ok.server.URL), confidential(ok.server.URL),
		confidential(bad.server.URL), public})

	assert.Equal(t, []string{
		`goiabada_backchannel_logout_deliveries_total{outcome="blocked"} 0`,
		`goiabada_backchannel_logout_deliveries_total{outcome="delivered"} 2`,
		`goiabada_backchannel_logout_deliveries_total{outcome="failed"} 0`,
		`goiabada_backchannel_logout_deliveries_total{outcome="refused"} 1`,
		`goiabada_backchannel_logout_deliveries_total{outcome="skipped"} 1`,
	}, h.samples(t))
}

// TestSend_ADeliveryThatDoesNotSucceedWritesOneWarnRecord: naming the client, the user, the outcome
// and the status, and never the token. A delivered one writes none.
func TestSend_ADeliveryThatDoesNotSucceedWritesOneWarnRecord(t *testing.T) {
	capture := logtest.CaptureSlog(t)
	h := newHarness(t)
	ok := newReceiver(t, http.StatusOK)
	bad := newReceiver(t, http.StatusBadRequest)

	h.sender.Send(context.Background(), testIssuer, []Delivery{confidential(ok.server.URL), confidential(bad.server.URL)})

	var warns []logtest.CapturedRecord
	for _, rec := range capture.Records() {
		if rec.Level == slog.LevelWarn {
			warns = append(warns, rec)
		}
	}
	require.Len(t, warns, 1)
	assert.Equal(t, "a logout token was not delivered", warns[0].Message)
	assert.EqualValues(t, 7, warns[0].Attrs["client_id"])
	assert.Equal(t, "app-web", warns[0].Attrs["client_identifier"])
	assert.EqualValues(t, 42, warns[0].Attrs["user_id"])
	assert.Equal(t, "refused", warns[0].Attrs["outcome"])
	assert.EqualValues(t, 400, warns[0].Attrs["status"])
	assert.EqualValues(t, 1, warns[0].Attrs["attempts"])

	token := bad.received()[0].token
	require.NotEmpty(t, token)
	assert.NotContains(t, capture.Text(), token)
}

// TestLogSentLogoutToken holds the sent_logout_token payload field by field (#784 decision 8).
func TestLogSentLogoutToken(t *testing.T) {
	auditLogger := &recordingAudit{}
	delivery := confidential("https://app.example.com/bc")

	LogSentLogoutToken(context.Background(), auditLogger, delivery, "1b4e28ba-2fa1-41d2-883f-0016d3cca427", Refused, 2)

	require.Len(t, auditLogger.events, 1)
	assert.Equal(t, "sent_logout_token", auditLogger.events[0].name)
	assert.Equal(t, map[string]interface{}{
		"client_id":          int64(7),
		"user_id":            int64(42),
		"session_identifier": "c0ffee00-1111-4222-8333-444455556666",
		"jti":                "1b4e28ba-2fa1-41d2-883f-0016d3cca427",
		"outcome":            "refused",
		"attempts":           2,
	}, auditLogger.events[0].details)
}

// TestSendAndWait_StartsEveryDeliveryAtOnceAndReportsEachAsItFinishes: the recover command's sender
// starts all of an end's deliveries at once, as Send does (#784 decision 5), and returns only once
// each has finished, having reported each one's outcome. It has no metrics listener, so nothing is
// counted, and each delivery still writes its audit event (#784 decision 11).
func TestSendAndWait_StartsEveryDeliveryAtOnceAndReportsEachAsItFinishes(t *testing.T) {
	h := newHarness(t)
	sender := NewCommandSender(h.sender.database, h.sender.dataCipher, h.audit)

	// Each request is held until both have arrived, so the deliveries finish only when they ran
	// together. One run after the other, the first is answered 400 once the wait gives up.
	var arrived sync.WaitGroup
	arrived.Add(2)
	together := make(chan struct{})
	go func() { arrived.Wait(); close(together) }()
	statuses := map[string]int{"/accepts": http.StatusOK, "/refuses": http.StatusBadRequest}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived.Done()
		select {
		case <-together:
			w.WriteHeader(statuses[r.URL.Path])
		case <-time.After(3 * time.Second):
			w.WriteHeader(http.StatusConflict)
		}
	}))
	t.Cleanup(server.Close)

	accepts, refuses := confidential(server.URL+"/accepts"), confidential(server.URL+"/refuses")
	accepts.ClientIdentifier, refuses.ClientIdentifier = "app-accepts", "app-refuses"
	accepts.ClientId, refuses.ClientId = 1, 2

	got := map[string]Outcome{}
	sender.SendAndWait(context.Background(), testIssuer, []Delivery{accepts, refuses}, func(d Delivery, o Outcome) {
		got[d.ClientIdentifier] = o
	})

	assert.Equal(t, map[string]Outcome{"app-accepts": Delivered, "app-refuses": Refused}, got)
	require.Len(t, h.audit.events, 2)
	outcomes := map[interface{}]interface{}{}
	for _, event := range h.audit.events {
		assert.Equal(t, audit.EventSentLogoutToken, event.name)
		outcomes[event.details["client_id"]] = event.details["outcome"]
	}
	assert.Equal(t, map[interface{}]interface{}{int64(1): "delivered", int64(2): "refused"}, outcomes)
}
