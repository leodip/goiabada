package middleware

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The one-time-code budget an OTP submission spends belongs to the user of the ceremony the
// submitted form names, read through the real ceremony store and ceremony.RequestedId, the one rule
// the step boundary loads the ceremony the code is checked for by. So the user whose budget a
// submission spends is always the user whose code the step checks (#246).

// otpCeremonyBrowser is a browser session holding held, as /auth/authorize stores it, behind the real
// ceremony store, and the cookies naming it.
func otpCeremonyBrowser(t *testing.T, held *ceremony.AuthContext) (*ceremony.Store, []*http.Cookie) {
	t.Helper()
	backend := sessiontest.NewMemoryBackend()
	store, err := sessionstore.NewServerSideStore(backend, sessionkeys.SessionIdentifier, false,
		sessionstore.PersistentCookie, sessionstore.KeyPair{
			AuthenticationKey: []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
			EncryptionKey:     []byte("0123456789abcdef0123456789abcdef"),
		}, nil)
	require.NoError(t, err)
	conditional, err := sessionstore.NewConditionalStore(store, backend)
	require.NoError(t, err)
	ceremonyStore := ceremony.NewStore(conditional, "goiabada-auth-test")

	seed := httptest.NewRecorder()
	require.NoError(t, ceremonyStore.ReplaceAuthContext(seed, httptest.NewRequest(http.MethodGet, "/auth/authorize", nil), held))
	cookies := seed.Result().Cookies()
	require.Len(t, cookies, 1)
	return ceremonyStore, cookies
}

func TestLimitOtp_SpendsTheBudgetOfTheCeremonyTheFormNames(t *testing.T) {
	const budget = 5
	const heldId, otherId = "ceremony-held-0123456789abcdefgh", "ceremony-other-0123456789abcdefg"

	// submit posts a wrong code naming ceremonyId in the form, as the OTP page's form does, to the URL
	// that page was loaded with, and reports the status and whether the handler ran. The handler reads
	// the form after the limiter has, as the OTP handler does.
	submit := func(t *testing.T, m *RateLimiter, cookies []*http.Cookie, ceremonyId string) (int, bool) {
		t.Helper()
		form := url.Values{ceremony.IdField: {ceremonyId}, "otp": {"000000"}}
		req := limiterRequest(http.MethodPost, "/auth/otp?"+url.Values{ceremony.QueryParameter: {heldId}}.Encode(),
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		reached := false
		m.LimitOtp(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			assert.Equal(t, "000000", r.PostFormValue("otp"), "the handler reads the code the limiter left in the form")
			assert.Equal(t, ceremonyId, ceremony.RequestedId(r), "and the ceremony the form names")
			m.RecordCredentialFailure(r)
			w.WriteHeader(http.StatusTeapot)
		})).ServeHTTP(rr, req)
		return rr.Code, reached
	}

	t.Run("a form naming a ceremony the browser does not hold spends no one's budget", func(t *testing.T) {
		ceremonyStore, cookies := otpCeremonyBrowser(t, &ceremony.AuthContext{
			CeremonyId: heldId, UserId: 7, AuthState: ceremony.AuthStateLevel2OTP,
		})
		m := newTestMiddleware(ceremonyStore, true)

		// Well past the budget. The step answers each of these with the "no longer active" page
		// before it checks any code, so there is no one whose code they guess.
		for i := 0; i < budget*2; i++ {
			if code, reached := submit(t, m, cookies, otherId); code != http.StatusTeapot || !reached {
				t.Fatalf("submission %d naming another ceremony: got code %d, handler reached %v; want %d and true",
					i+1, code, reached, http.StatusTeapot)
			}
		}

		// The held ceremony's user still has the whole budget.
		for i := 0; i < budget; i++ {
			if code, reached := submit(t, m, cookies, heldId); code != http.StatusTeapot || !reached {
				t.Fatalf("failure %d naming the held ceremony: got code %d, handler reached %v; want %d and true",
					i+1, code, reached, http.StatusTeapot)
			}
		}
		if code, reached := submit(t, m, cookies, heldId); code != http.StatusTooManyRequests || reached {
			t.Errorf("failure %d naming the held ceremony: got code %d, handler reached %v; want %d and false",
				budget+1, code, reached, http.StatusTooManyRequests)
		}
	})

	t.Run("a form naming the held ceremony spends its user's budget", func(t *testing.T) {
		ceremonyStore, cookies := otpCeremonyBrowser(t, &ceremony.AuthContext{
			CeremonyId: heldId, UserId: 7, AuthState: ceremony.AuthStateLevel2OTP,
		})
		m, auditLog := newAuditedTestMiddleware(ceremonyStore, true)

		for i := 0; i < budget; i++ {
			if code, _ := submit(t, m, cookies, heldId); code != http.StatusTeapot {
				t.Fatalf("failure %d: got code %d, want %d", i+1, code, http.StatusTeapot)
			}
		}
		code, reached := submit(t, m, cookies, heldId)
		assert.Equal(t, http.StatusTooManyRequests, code)
		assert.False(t, reached)

		auditLog.mu.Lock()
		defer auditLog.mu.Unlock()
		require.Len(t, auditLog.events, 1)
		assert.Equal(t, audit.EventRateLimitExceeded, auditLog.events[0].name)
		assert.Equal(t, int64(7), auditLog.events[0].details["user_id"],
			"the refusal names the user of the ceremony the form names")
	})
}
