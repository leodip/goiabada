package apiclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/adminconsole/internal/noredirect"
	"github.com/leodip/goiabada/adminconsole/internal/upstreammetrics"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/boundedread"
	"github.com/leodip/goiabada/core/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Seam 3 for the executor itself (#386).
//
// The 106 wire rows next door own what each method says about itself. This file owns what the
// executor does with it: the ceiling, the deadline, the cancellation and the decode. Every case
// drives a real method rather than the unexported executor, so what is asserted is what a handler
// would see.

// settingsGeneralBodyOf returns a valid SettingsGeneralResponse whose encoding is exactly size
// bytes, by padding the one field the case reads.
func settingsGeneralBodyOf(t *testing.T, size int) string {
	t.Helper()

	const envelope = `{"appName":""}`
	require.Greater(t, size, len(envelope), "the body cannot be shorter than its own envelope")

	return `{"appName":"` + strings.Repeat("a", size-len(envelope)) + `"}`
}

func TestExecutor_ABodyExactlyAtTheCeilingIsAccepted(t *testing.T) {
	body := settingsGeneralBodyOf(t, maxAPIResponseBytes)
	require.Len(t, body, maxAPIResponseBytes)

	client, _ := charServer(t, http.StatusOK, body)

	got, err := client.GetSettingsGeneral(context.Background(), charAccessToken)
	require.NoError(t, err, "the ceiling is inclusive: a body of exactly that many bytes is answered")
	assert.Len(t, got.AppName, maxAPIResponseBytes-len(`{"appName":""}`))
}

// Decision 4: the answer is refused rather than cut, so the overrun is its own classified failure
// and no prefix reaches a decoder. One byte is the whole difference, which is why the case above
// exists beside this one.
func TestExecutor_ABodyOneByteOverTheCeilingIsRefusedAndNeverDecoded(t *testing.T) {
	body := settingsGeneralBodyOf(t, maxAPIResponseBytes+1)
	require.Len(t, body, maxAPIResponseBytes+1)

	client, _ := charServer(t, http.StatusOK, body)

	got, err := client.GetSettingsGeneral(context.Background(), charAccessToken)
	require.Error(t, err)
	assert.Nil(t, got, "nothing decoded out of an oversized answer")
	assert.ErrorIs(t, err, boundedread.ErrResponseTooLarge,
		"an overrun is its own failure, not a parse failure: got %v", err)
}

// The oversized answer must not arrive looking like the auth server's own refusal, because the
// console routes on *APIError and would otherwise show the administrator a status the auth server
// never sent.
func TestExecutor_AnOversizedAnswerIsNotAnAPIError(t *testing.T) {
	client, _ := charServer(t, http.StatusOK, settingsGeneralBodyOf(t, maxAPIResponseBytes+1))

	_, err := client.GetSettingsGeneral(context.Background(), charAccessToken)
	require.Error(t, err)

	var apiErr *APIError
	assert.NotErrorAs(t, err, &apiErr, "it falls through to the console's generic 500")
}

// An oversized *failure* body is refused on the same terms: parseAPIError never sees a prefix
// either, so a 500 with a megabyte of text behind it cannot become a plausible-looking error.
func TestExecutor_AnOversizedFailureBodyIsRefusedBeforeClassification(t *testing.T) {
	client, _ := charServer(t, http.StatusInternalServerError,
		settingsGeneralBodyOf(t, maxAPIResponseBytes+1))

	_, err := client.GetSettingsGeneral(context.Background(), charAccessToken)
	require.Error(t, err)
	assert.ErrorIs(t, err, boundedread.ErrResponseTooLarge)
}

func TestExecutor_MalformedJSONOnASuccessStatusIsADecodeFailure(t *testing.T) {
	client, _ := charServer(t, http.StatusOK, `{"appName":`)

	got, err := client.GetSettingsGeneral(context.Background(), charAccessToken)
	require.Error(t, err)
	assert.Nil(t, got)

	var apiErr *APIError
	assert.NotErrorAs(t, err, &apiErr, "a 200 that will not parse is not the auth server's refusal")
	assert.NotErrorIs(t, err, boundedread.ErrResponseTooLarge)
}

// The request's cancellation reaches the transport. This is the whole point of carrying a context
// down from the handler: an administrator who navigates away must not leave a goroutine waiting on
// an auth server that has stopped answering.
func TestExecutor_ACancelledRequestContextStopsTheCall(t *testing.T) {
	released := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-released
	}))
	t.Cleanup(func() {
		close(released)
		server.Close()
	})

	client := NewAuthServerClient(server.URL, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.GetSettingsGeneral(ctx, charAccessToken)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled, "got %v", err)
}

func TestExecutor_ARequestDeadlineStopsACallTheAuthServerNeverAnswers(t *testing.T) {
	released := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-released
	}))
	t.Cleanup(func() {
		close(released)
		server.Close()
	})

	client := NewAuthServerClient(server.URL, nil, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err := client.GetSettingsGeneral(ctx, charAccessToken)
	require.Error(t, err)

	require.ErrorIs(t, err, context.DeadlineExceeded, "got %v", err)
	assert.Less(t, time.Since(started), 5*time.Second, "the call returned on its deadline")
}

// client/no-timeout closed. The general client was a bare &http.Client{}, with no deadline of any
// kind, so a request the auth server accepted and then stopped answering held an admin console
// handler goroutine for as long as the connection stayed open.
//
// The deadline is read off rather than waited out: the case above already shows that a deadline
// of this kind cuts a request the server never answers, and proving the same thing again at the
// real value would cost the suite ten seconds of sleeping on every run, forever. The executor sets
// it on each call rather than on the client (#718 decision 8); the mail-sending calls' longer one
// and the 10 seconds every other call keeps are held by the two cases below.
func TestNewAuthServerClient_CarriesADeadline(t *testing.T) {
	assert.Equal(t, 10*time.Second, apiRequest{method: "GET"}.deadline(),
		"every request this client makes is bounded, by decision 6's value, matching the three request-path clients already in the tree")
}

// #718 decision 8. The three calls that make the auth server send mail during the request wait
// 50 seconds: the test email, creating a user with a setup email, and sending an email
// verification code. Every other call keeps the console's 10 seconds.
//
// The slow server answers each call 10.75 seconds after it arrives, a little past the general
// deadline and far inside the long one. The cases run side by side, so the whole test waits that
// long once. A mail-sending call gets the server's answer; every other call, creating a user who
// is given a password among them, ends on its 10-second deadline before the answer comes.
func TestExecutor_TheCallsThatSendMailOutlastTenSeconds(t *testing.T) {
	const generalDeadline = 10 * time.Second
	const answersAfter = generalDeadline + 750*time.Millisecond

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(answersAfter):
		case <-r.Context().Done():
			return
		}
		if r.URL.Path == "/api/v1/admin/users/create" {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"user":{"id":7,"email":"new@example.com"}}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)

	client := NewAuthServerClient(server.URL, nil, nil)

	cases := []struct {
		name      string
		call      func(ctx context.Context) error
		sendsMail bool
	}{
		{
			name: "the test email",
			call: func(ctx context.Context) error {
				return client.SendTestEmail(ctx, charAccessToken, &api.SendTestEmailRequest{To: "jane@example.com"})
			},
			sendsMail: true,
		},
		{
			name: "creating a user with a setup email",
			call: func(ctx context.Context) error {
				_, err := client.CreateUserAdmin(ctx, charAccessToken, &api.CreateUserAdminRequest{
					Email:           "new@example.com",
					SetPasswordType: api.SetPasswordTypeEmail,
				})
				return err
			},
			sendsMail: true,
		},
		{
			name: "sending an email verification code",
			call: func(ctx context.Context) error {
				_, err := client.SendAccountEmailVerification(ctx, charAccessToken)
				return err
			},
			sendsMail: true,
		},
		{
			name: "creating a user with a password",
			call: func(ctx context.Context) error {
				_, err := client.CreateUserAdmin(ctx, charAccessToken, &api.CreateUserAdminRequest{
					Email:           "new@example.com",
					SetPasswordType: api.SetPasswordTypeNow,
					Password:        "a-long-enough-password",
				})
				return err
			},
		},
		{
			name: "creating a user without a password type",
			call: func(ctx context.Context) error {
				_, err := client.CreateUserAdmin(ctx, charAccessToken, &api.CreateUserAdminRequest{
					Email:    "new@example.com",
					Password: "a-long-enough-password",
				})
				return err
			},
		},
		{
			name: "saving the email settings",
			call: func(ctx context.Context) error {
				_, err := client.UpdateSettingsEmail(ctx, charAccessToken, &api.UpdateSettingsEmailRequest{})
				return err
			},
		},
		{
			name: "verifying the email address",
			call: func(ctx context.Context) error {
				_, err := client.VerifyAccountEmail(ctx, charAccessToken, &api.VerifyAccountEmailRequest{})
				return err
			},
		},
		{
			name: "reading the general settings",
			call: func(ctx context.Context) error {
				_, err := client.GetSettingsGeneral(ctx, charAccessToken)
				return err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			started := time.Now()
			err := tc.call(context.Background())
			elapsed := time.Since(started)

			if tc.sendsMail {
				require.NoError(t, err, "a call that sends mail waits past 10 seconds for the answer")
				assert.GreaterOrEqual(t, elapsed, answersAfter, "the answer came after the general deadline")
				return
			}
			require.Error(t, err, "every other call ends on the general deadline")
			require.ErrorIs(t, err, context.DeadlineExceeded, "a deadline, not another failure")
			assert.GreaterOrEqual(t, elapsed, generalDeadline, "not before 10 seconds")
			assert.Less(t, elapsed, answersAfter, "before the slow server answers")
		})
	}
}

// The long deadline is read off rather than waited out, as TestNewAuthServerClient_CarriesADeadline
// reads the general one: the case above shows the mail-sending calls take it, and sleeping 50
// seconds on every run would show nothing more.
func TestExecutor_TheMailSendingDeadlineIsFiftySeconds(t *testing.T) {
	assert.Equal(t, 50*time.Second, mailSendingAPITimeout,
		"decision 8's value: longer than the sender's 40 seconds, shorter than the console's 60-second write timeout")
}

// Every call the executor makes is recorded under the admin_api target, whatever method made it,
// by the status the auth server answered, a refusal included, as a scrape reports it (#400
// decision 6). No method or path is a label, so two methods share one series.
func TestExecutor_RecordsEveryCallUnderTheAdminAPITarget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/account/profile" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error_code":"FORBIDDEN","error_description":"no"}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	reg := metrics.NewRegistry()
	client := NewAuthServerClient(server.URL, nil, upstreammetrics.Register(reg))

	_, err := client.GetSettingsGeneral(context.Background(), charAccessToken)
	require.NoError(t, err)
	_, err = client.GetAccountOTPEnrollment(context.Background(), charAccessToken)
	require.NoError(t, err)
	_, err = client.GetAccountProfile(context.Background(), charAccessToken)
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)

	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	exposition := rec.Body.String()
	assert.Contains(t, exposition, `goiabada_upstream_requests_total{target="admin_api",status="200"} 2`+"\n")
	assert.Contains(t, exposition, `goiabada_upstream_requests_total{target="admin_api",status="403"} 1`+"\n")
	assert.Contains(t, exposition, `goiabada_upstream_request_duration_seconds_count{target="admin_api"} 3`+"\n")
}

// The executor refuses a redirect from the auth server, whichever of the five net/http follows,
// and sends nothing to its target (#715 decision 13): the call fails naming the target's origin
// and the internal URL setting, and the redirect is recorded under the status it arrived with.
func TestExecutor_RefusesARedirect(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var followed int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/admin/settings/general" {
					followed++
					_, _ = w.Write([]byte(`{}`))
					return
				}
				w.Header().Set("Location", "https://auth.example.com:8443/path-marker?query-marker=1")
				w.WriteHeader(status)
			}))
			defer server.Close()
			reg := metrics.NewRegistry()
			client := NewAuthServerClient(server.URL, nil, upstreammetrics.Register(reg))

			settings, err := client.GetSettingsGeneral(context.Background(), charAccessToken)

			require.Error(t, err)
			assert.Nil(t, settings)
			var refused *noredirect.Error
			require.ErrorAs(t, err, &refused)
			assert.Equal(t, "https://auth.example.com:8443", refused.Origin)
			assert.Contains(t, err.Error(), "https://auth.example.com:8443")
			assert.Contains(t, err.Error(), "GOIABADA_AUTHSERVER_INTERNALBASEURL")
			assert.NotContains(t, err.Error(), "path-marker")
			assert.NotContains(t, err.Error(), "query-marker")
			assert.Zero(t, followed)

			rec := httptest.NewRecorder()
			reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
			assert.Contains(t, rec.Body.String(),
				`goiabada_upstream_requests_total{target="admin_api",status="`+strconv.Itoa(status)+`"} 1`+"\n")
		})
	}
}
