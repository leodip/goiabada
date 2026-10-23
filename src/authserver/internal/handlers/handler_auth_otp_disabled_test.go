package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The refusal whose count reached record.OtpConsecutiveFailureLimit disables the authenticator, and
// it is audited once, as otp_authenticator_disabled after the refusal's own events, on both refused
// arms: a wrong code and a replayed one count alike. The submitter is answered exactly as for any
// other refused code (#489 decision 2). The refusals that do not reach the limit audit nothing more,
// which every other refused-code case in this package holds, since the audit double fails on an
// event it was not told to expect.
func TestHandleAuthOtpPost_TheRefusalThatDisablesTheAuthenticatorIsAudited(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "TestApp", AccountName: "test@test.com"})
	require.NoError(t, err)
	matching, err := totp.GenerateCode(key.Secret(), time.Now())
	require.NoError(t, err)

	for _, tc := range []struct {
		name   string
		code   string
		replay bool
		events []string
	}{
		{name: "a wrong code", code: "000000",
			events: []string{audit.EventAuthFailedOtp, audit.EventOTPAuthenticatorDisabled}},
		{name: "a replayed code", code: matching, replay: true,
			events: []string{audit.EventOTPCodeReplayDetected, audit.EventAuthFailedOtp,
				audit.EventOTPAuthenticatorDisabled}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			ceremonyStore := handlersmocks.NewCeremonyStore(t)
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			handler := buildAuthOtpPost(authOtpPostDeps{
				pageRenderer:  pageRenderer,
				ceremonyStore: ceremonyStore,
				database:      database,
				auditLogger:   auditLogger,
			})

			form := url.Values{}
			form.Add(ceremony.IdField, testCeremonyId)
			form.Add("otp", tc.code)
			req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{}))
			rr := httptest.NewRecorder()

			ceremonyStore.On("GetAuthContext", mock.Anything).Return(&ceremony.AuthContext{
				AuthState:  ceremony.AuthStateLevel2OTP,
				CeremonyId: testCeremonyId,
				UserId:     1,
				ClientId:   "test-client",
			}, nil)
			database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(&record.User{
				Id:                     1,
				Enabled:                true,
				OTPEnabled:             true,
				OTPSecretEncrypted:     encryptOTPForTest(t, key.Secret()),
				OtpConfigGeneration:    3,
				OtpConsecutiveFailures: record.OtpConsecutiveFailureLimit - 1,
			}, nil)
			database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
				Return(&record.Client{ClientIdentifier: "test-client"}, nil)
			if tc.replay {
				database.On("TryConsumeEnrolledUserOTPStep", mock.Anything, mock.Anything, int64(1),
					mock.Anything, int64(3)).Return(false, nil).Once()
			}
			// The count's statement reports that this call is the one that reached the limit.
			database.On("IncrementUserOtpConsecutiveFailures", mock.Anything, mock.Anything, int64(1), int64(3)).
				Return(true, nil).Once()

			var events []string
			logged := func(args mock.Arguments) { events = append(events, args.String(1)) }
			for _, event := range tc.events {
				var payload interface{} = map[string]interface{}{"user_id": int64(1)}
				if event == audit.EventOTPCodeReplayDetected {
					payload = mock.Anything // it carries the step too, which other cases pin
				}
				auditLogger.On("Log", mock.Anything, event, payload).Return().Run(logged).Once()
			}

			expectedError := i18n.NewLocalizedError(i18n.ErrCodeOtpIncorrectCode, nil).Localize(req.Context())
			pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_otp.html",
				mock.MatchedBy(func(bind map[string]interface{}) bool {
					return bind["error"] == expectedError
				})).Return(nil)

			handler.ServeHTTP(rr, req)

			assert.Equal(t, tc.events, events,
				"the disable is audited once, after the refusal's own events")
			assert.Empty(t, rr.Header().Get("Location"), "the code is refused like any other")
		})
	}
}
