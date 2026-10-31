package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Signing in with a recovery code (#257 decisions 4, 6, 7 and 10). The code form links to a
// recovery-code form on the same step, GET /auth/otp with form=recovery-code, which posts to the
// same POST /auth/otp under its own field, recoveryCode. A recovery code is a full second factor:
// it records recovery_code on the ceremony, tied to the authenticator's generation as a code is,
// and goes on to /auth/completed. A refusal is charged to the otp tier, whether the code was wrong
// or already used, and the submitter is told the same for both; the authenticator's
// consecutive-failure count is never touched, either way.

const (
	// recoveryCodeTyped is a code as a person might type it: upper case, a space for a hyphen.
	recoveryCodeTyped = "7KQ2 M9XH-4trw-b3np-j6vd-egac"
	// recoveryCodeNormalized is its 24 characters, lowered, with the space and the hyphens taken out;
	// the set stores their SHA-256 (decision 2).
	recoveryCodeNormalized = "7kq2m9xh4trwb3npj6vdegac"

	incorrectRecoveryCodeMessage = "That recovery code isn't right, or it was already used."
	recoveryCodeRequiredMessage  = "Enter one of your recovery codes."
)

func recoveryCodeHashForTest(normalized string) string {
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func recoveryCodePostRequest(code string) *http.Request {
	form := url.Values{}
	form.Add(ceremony.IdField, testCeremonyId)
	form.Add("recoveryCode", code)
	req := httptest.NewRequest(http.MethodPost, "/auth/otp", strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	return req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{}))
}

// enrolledUserForRecovery is a user with an authenticator at generation 3.
func enrolledUserForRecovery(t *testing.T) *record.User {
	return &record.User{
		Id:                  1,
		Enabled:             true,
		OTPEnabled:          true,
		OTPSecretEncrypted:  encryptOTPForTest(t, otpTestMintedSecret(t)),
		OtpConfigGeneration: 3,
	}
}

// The code form for a user with an authenticator links to the recovery-code form, and the link
// asks for it on this same step: GET /auth/otp with form=recovery-code renders it, naming the
// ceremony as every form of the step does.
func TestHandleAuthOtpGet_TheRecoveryCodeForm(t *testing.T) {
	m := newOtpStepMocks(t)
	authContext := m.armOtpCeremony("")
	m.armUser(&record.User{Id: 1, Enabled: true, OTPEnabled: true})
	m.armClient()
	m.ceremonyStore.On("SaveAuthContext", mock.Anything, mock.Anything, authContext).Return(nil).Once()

	req := httptest.NewRequest(http.MethodGet, "/auth/otp?ceremony="+testCeremonyId+"&form=recovery-code", nil)
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{AppName: "TestApp"}))
	rr := httptest.NewRecorder()

	m.pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_otp_recovery_code.html",
		mock.MatchedBy(func(bind map[string]interface{}) bool {
			return bind["ceremonyId"] == testCeremonyId && bind["error"] == nil
		})).Return(nil).Once()

	m.get().ServeHTTP(rr, req)

	m.pageRenderer.AssertExpectations(t)
}

// A user with no authenticator has no codes, so the parameter changes nothing for them: they get
// the setup form, which links to no recovery-code form (decision 7).
func TestHandleAuthOtpGet_TheRecoveryCodeFormIsNeverTheSetupForm(t *testing.T) {
	m := newOtpStepMocks(t)
	m.armOtpCeremony(otpTestKeyURL(otpTestMintedSecret(t)))
	m.armUser(&record.User{Id: 1, Enabled: true, Email: "user@example.com"})
	m.armClient()
	m.ceremonyStore.On("SaveAuthContext", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

	req := httptest.NewRequest(http.MethodGet, "/auth/otp?ceremony="+testCeremonyId+"&form=recovery-code", nil)
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{AppName: "TestApp"}))
	rr := httptest.NewRecorder()

	m.pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_otp_enrollment.html",
		mock.Anything).Return(nil).Once()

	m.get().ServeHTTP(rr, req)

	m.pageRenderer.AssertExpectations(t)
}

// An accepted recovery code claims the code by its hash, once, and the ceremony records
// recovery_code beside the password, tied to the generation of the authenticator the user was read
// with (decision 4), rotates the browser session's identifier before the save, and goes on to
// /auth/completed with no extra page (decision 7). The audit record says how many unused codes are
// left, never the code (decision 10). The mocks carry no step claim and no consecutive-failure
// write, so touching the authenticator fails the case.
func TestHandleAuthOtpPost_AnAcceptedRecoveryCodeSignsIn(t *testing.T) {
	logged := logtest.CaptureSlog(t)
	m := newOtpStepMocks(t)
	authContext := m.armOtpCeremony("")
	authContext.AuthMethods = "pwd"
	m.armUser(enrolledUserForRecovery(t))

	m.database.On("TryUseUserRecoveryCode", mock.Anything, mock.Anything, int64(1),
		recoveryCodeHashForTest(recoveryCodeNormalized)).Return(true, nil).Once()
	m.database.On("CountUnusedUserRecoveryCodes", mock.Anything, mock.Anything, int64(1)).Return(9, nil).Once()
	m.auditLogger.On("Log", mock.Anything, audit.EventAuthSuccessRecoveryCode, map[string]interface{}{
		"user_id":   int64(1),
		"remaining": 9,
	}).Return().Once()

	req := recoveryCodePostRequest(recoveryCodeTyped)
	rr := httptest.NewRecorder()

	saved := false
	m.ceremonyStore.On("RegenerateSession", rr, req, testCeremonyId, int64(1)).Return(nil).Once().
		Run(func(mock.Arguments) {
			assert.False(t, saved, "rotation must run before the auth context recording the code is saved")
		})
	m.ceremonyStore.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
		return ac.AuthState == ceremony.AuthStateAuthenticationCompleted &&
			ac.AuthMethods == "pwd recovery_code" &&
			ac.OtpClaimGeneration != nil && *ac.OtpClaimGeneration == 3 &&
			ac.AuthenticatedAt != nil && !ac.AuthenticatedAt.IsZero() &&
			!ac.Level1AuthCompleted
	})).Return(nil).Once().Run(func(mock.Arguments) { saved = true })

	m.post().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
	assert.Equal(t, testBaseURL+"/auth/completed?ceremony="+testCeremonyId, rr.Header().Get("Location"))
	assert.True(t, saved)
	assert.True(t, authContext.ClaimsOTP(), "a recovery code is a claim the authenticator backs, as a code is")
	assertNoRecoveryCodeLogged(t, logged)
	m.database.AssertExpectations(t)
	m.auditLogger.AssertExpectations(t)
}

// An authenticator disabled after 100 wrong codes still lets a recovery code in, which is the
// self-service way out of the disable, and the count stays where it is: neither a correct
// recovery code nor a wrong one moves it (decision 6). The strict mocks hold both: neither
// IncrementUserOtpConsecutiveFailures nor any clear is armed.
func TestHandleAuthOtpPost_ARecoveryCodeWorksWhileTheAuthenticatorIsDisabled(t *testing.T) {
	t.Run("a correct code signs in", func(t *testing.T) {
		m := newOtpStepMocks(t)
		m.armOtpCeremony("")
		user := enrolledUserForRecovery(t)
		user.OtpConsecutiveFailures = record.OtpConsecutiveFailureLimit
		m.armUser(user)

		m.database.On("TryUseUserRecoveryCode", mock.Anything, mock.Anything, int64(1), mock.Anything).
			Return(true, nil).Once()
		m.database.On("CountUnusedUserRecoveryCodes", mock.Anything, mock.Anything, int64(1)).Return(4, nil).Once()
		m.auditLogger.On("Log", mock.Anything, audit.EventAuthSuccessRecoveryCode, mock.Anything).Return().Once()
		m.ceremonyStore.On("RegenerateSession", mock.Anything, mock.Anything, testCeremonyId, int64(1)).Return(nil).Once()
		m.ceremonyStore.On("SaveAuthContext", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

		rr := httptest.NewRecorder()
		m.post().ServeHTTP(rr, recoveryCodePostRequest(recoveryCodeTyped))

		assert.Equal(t, http.StatusSeeOther, rr.Code)
		assert.EqualValues(t, record.OtpConsecutiveFailureLimit, user.OtpConsecutiveFailures)
	})

	t.Run("a wrong code is refused and counts nothing against the authenticator", func(t *testing.T) {
		m := newOtpStepMocks(t)
		m.armOtpCeremony("")
		user := enrolledUserForRecovery(t)
		user.OtpConsecutiveFailures = 7
		m.armUser(user)
		m.armClient()

		m.database.On("TryUseUserRecoveryCode", mock.Anything, mock.Anything, int64(1), mock.Anything).
			Return(false, nil).Once()
		m.database.On("UserRecoveryCodeExists", mock.Anything, mock.Anything, int64(1), mock.Anything).
			Return(false, nil).Once()
		m.auditLogger.On("Log", mock.Anything, audit.EventAuthFailedRecoveryCode, mock.Anything).Return().Once()

		req := recoveryCodePostRequest(recoveryCodeTyped)
		rr := httptest.NewRecorder()
		m.pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_otp_recovery_code.html",
			mock.Anything).Return(nil).Once()

		m.post().ServeHTTP(rr, req)

		m.database.AssertNotCalled(t, "IncrementUserOtpConsecutiveFailures",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		m.pageRenderer.AssertExpectations(t)
	})
}

// A refused recovery code draws the recovery-code form again with its own message, the same for a
// code that was never in the set, one of a replaced set and one already used, so the submitter
// cannot tell which it was (decision 6). Only a used code of the current set is audited as a
// replay, beside the failure, and before it (decision 10). Nothing is saved.
func TestHandleAuthOtpPost_ARefusedRecoveryCode(t *testing.T) {
	for _, tc := range []struct {
		name string
		// exists is whether the user's current set holds the code, used: false for a wrong code
		// and for one of a replaced set, whose rows are gone.
		exists bool
	}{
		{name: "a wrong code, or one of a replaced set", exists: false},
		{name: "a used code of the current set", exists: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logged := logtest.CaptureSlog(t)
			m := newOtpStepMocks(t)
			m.armOtpCeremony("")
			m.armUser(enrolledUserForRecovery(t))
			m.armClient()

			hash := recoveryCodeHashForTest(recoveryCodeNormalized)
			m.database.On("TryUseUserRecoveryCode", mock.Anything, mock.Anything, int64(1), hash).
				Return(false, nil).Once()
			m.database.On("UserRecoveryCodeExists", mock.Anything, mock.Anything, int64(1), hash).
				Return(tc.exists, nil).Once()

			var events []string
			note := func(args mock.Arguments) { events = append(events, args.String(1)) }
			if tc.exists {
				m.auditLogger.On("Log", mock.Anything, audit.EventRecoveryCodeReplayDetected, map[string]interface{}{
					"user_id": int64(1),
				}).Return().Once().Run(note)
			}
			m.auditLogger.On("Log", mock.Anything, audit.EventAuthFailedRecoveryCode, map[string]interface{}{
				"user_id": int64(1),
			}).Return().Once().Run(note)

			req := recoveryCodePostRequest(recoveryCodeTyped)
			rr := httptest.NewRecorder()
			m.pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_otp_recovery_code.html",
				mock.MatchedBy(func(bind map[string]interface{}) bool {
					return bind["error"] == incorrectRecoveryCodeMessage && bind["ceremonyId"] == testCeremonyId
				})).Return(nil).Once()

			m.post().ServeHTTP(rr, req)

			if tc.exists {
				assert.Equal(t, []string{audit.EventRecoveryCodeReplayDetected, audit.EventAuthFailedRecoveryCode}, events)
			} else {
				assert.Equal(t, []string{audit.EventAuthFailedRecoveryCode}, events)
			}
			m.assertRefusalSavedNothing(t)
			assertNoRecoveryCodeLogged(t, logged)
			m.pageRenderer.AssertExpectations(t)
			m.auditLogger.AssertExpectations(t)
		})
	}
}

// A blank recovery-code form is asked for a code, on the recovery-code form, and nothing is looked
// up, charged or audited.
func TestHandleAuthOtpPost_ABlankRecoveryCodeIsAskedForOne(t *testing.T) {
	for _, blank := range []string{"", "  - -  "} {
		m := newOtpStepMocks(t)
		m.armOtpCeremony("")
		m.armUser(enrolledUserForRecovery(t))
		m.armClient()

		req := recoveryCodePostRequest(blank)
		rr := httptest.NewRecorder()
		m.pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_otp_recovery_code.html",
			mock.MatchedBy(func(bind map[string]interface{}) bool {
				return bind["error"] == recoveryCodeRequiredMessage
			})).Return(nil).Once()

		m.post().ServeHTTP(rr, req)

		m.pageRenderer.AssertExpectations(t)
		m.assertRefusalSavedNothing(t)
	}
}

// A user with no authenticator has no recovery codes, so a recovery code posted for them is a
// wrong one, refused without a lookup: the setup form offers no recovery-code form (decision 7).
func TestHandleAuthOtpPost_ARecoveryCodeForAUserWithNoAuthenticatorIsRefused(t *testing.T) {
	m := newOtpStepMocks(t)
	m.armOtpCeremony("")
	m.armUser(&record.User{Id: 1, Enabled: true, OtpConfigGeneration: 2})
	m.armClient()
	m.auditLogger.On("Log", mock.Anything, audit.EventAuthFailedRecoveryCode, map[string]interface{}{
		"user_id": int64(1),
	}).Return().Once()

	req := recoveryCodePostRequest(recoveryCodeTyped)
	rr := httptest.NewRecorder()
	m.pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_otp_recovery_code.html",
		mock.MatchedBy(func(bind map[string]interface{}) bool {
			return bind["error"] == incorrectRecoveryCodeMessage
		})).Return(nil).Once()

	m.post().ServeHTTP(rr, req)

	m.database.AssertNotCalled(t, "TryUseUserRecoveryCode", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	m.pageRenderer.AssertExpectations(t)
	m.assertRefusalSavedNothing(t)
}

// A disabled account is answered on the recovery-code form as on the code form, before any code is
// looked at.
func TestHandleAuthOtpPost_ARecoveryCodeForADisabledAccount(t *testing.T) {
	m := newOtpStepMocks(t)
	m.armOtpCeremony("")
	user := enrolledUserForRecovery(t)
	user.Enabled = false
	m.armUser(user)
	m.armClient()
	m.auditLogger.On("Log", mock.Anything, audit.EventUserDisabled, mock.Anything).Return().Once()

	req := recoveryCodePostRequest(recoveryCodeTyped)
	rr := httptest.NewRecorder()
	m.pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_otp_recovery_code.html",
		mock.MatchedBy(func(bind map[string]interface{}) bool {
			return bind["error"] == "Your account is disabled."
		})).Return(nil).Once()

	m.post().ServeHTTP(rr, req)

	m.database.AssertNotCalled(t, "TryUseUserRecoveryCode", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	m.pageRenderer.AssertExpectations(t)
}

// Wrong and used recovery codes spend the otp tier's budget, the one authenticator codes spend, so
// alternating between the two buys no extra guesses; a correct one spends nothing (decision 6).
// Driven through a real limiter for the reason TestHandleAuthOtpPost_SpendsTheLimiterBudgetOnFailuresOnly
// gives.
func TestHandleAuthOtpPost_RecoveryCodesSpendTheOtpBudgetOnFailuresOnly(t *testing.T) {
	const budget = 5

	newHandler := func(t *testing.T, used bool, exists bool) (http.Handler, *ceremony.AuthContext) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		ceremonyStore := handlersmocks.NewCeremonyStore(t)
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)

		authContext := &ceremony.AuthContext{
			AuthState:  ceremony.AuthStateLevel2OTP,
			CeremonyId: testCeremonyId,
			UserId:     1,
			ClientId:   "test-client",
		}
		ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)
		ceremonyStore.On("SaveAuthContext", mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
		ceremonyStore.On("RegenerateSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
		database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(enrolledUserForRecovery(t), nil)
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
			Return(&record.Client{ClientIdentifier: "test-client"}, nil).Maybe()
		database.On("TryUseUserRecoveryCode", mock.Anything, mock.Anything, int64(1), mock.Anything).Return(used, nil)
		database.On("UserRecoveryCodeExists", mock.Anything, mock.Anything, int64(1), mock.Anything).
			Return(exists, nil).Maybe()
		database.On("CountUnusedUserRecoveryCodes", mock.Anything, mock.Anything, int64(1)).Return(5, nil).Maybe()
		auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Return().Maybe()
		pageRenderer.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/auth_layout.html",
			"/auth_otp_recovery_code.html", mock.Anything).Return(nil).Maybe()

		rateLimiter := newTestRateLimiter(ceremonyStore)
		handler := buildAuthOtpPost(authOtpPostDeps{
			pageRenderer:       pageRenderer,
			ceremonyStore:      ceremonyStore,
			database:           database,
			auditLogger:        auditLogger,
			credentialFailures: rateLimiter,
		})
		return rateLimiter.LimitOtp(handler), authContext
	}

	post := func(handler http.Handler) int {
		req := recoveryCodePostRequest(recoveryCodeTyped)
		req.RemoteAddr = "203.0.113.7:5000"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr.Code
	}

	for _, tc := range []struct {
		name   string
		exists bool
	}{
		{name: "wrong recovery codes fill the budget", exists: false},
		{name: "used recovery codes fill the budget", exists: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler, _ := newHandler(t, false, tc.exists)
			for i := 0; i < budget; i++ {
				require.Equal(t, http.StatusOK, post(handler), "attempt %d should reach the handler", i+1)
			}
			assert.Equal(t, http.StatusTooManyRequests, post(handler),
				"attempt %d should be refused by the limiter", budget+1)
		})
	}

	t.Run("a correct recovery code spends nothing", func(t *testing.T) {
		handler, authContext := newHandler(t, true, true)
		for i := 0; i < budget*2; i++ {
			authContext.AuthState = ceremony.AuthStateLevel2OTP
			assert.Equal(t, http.StatusSeeOther, post(handler), "sign-in %d should succeed", i+1)
		}
	})
}

// assertRefusalSavedNothing is what a refused submission leaves: no rotation, no save.
func (m otpStepMocks) assertRefusalSavedNothing(t *testing.T) {
	t.Helper()
	m.ceremonyStore.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
	m.ceremonyStore.AssertNotCalled(t, "RegenerateSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// assertNoRecoveryCodeLogged holds that no log record carries the code, as typed or as compared, or
// its hash (#257 decision 10).
func assertNoRecoveryCodeLogged(t *testing.T, logged *logtest.SlogCapture) {
	t.Helper()
	text := strings.ToLower(logged.Text())
	for _, secret := range []string{strings.ToLower(recoveryCodeTyped), recoveryCodeNormalized,
		recoveryCodeHashForTest(recoveryCodeNormalized), "egac"} {
		assert.NotContains(t, text, secret)
	}
}
