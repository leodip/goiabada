package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/accountnotice"
	"github.com/leodip/goiabada/authserver/internal/afterresponse"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/otp/otptest"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The sign-in code step's notices belong to the change that committed (#724, #737): the refusal
// that disabled the authenticator is told even when the form it would show again cannot be drawn,
// and every notice goes to the user's row as the change's own transaction read it under the row's
// lock, not as the step read it first.

// The lockout's refusal committed the disable, so a client block that then fails to load answers
// 500 and still tells the user (#724 decision 7). Only that refusal reports the lockout, so a notice
// lost here would never be sent.
func TestHandleAuthOtpPost_TellsTheLockoutWhenTheRefusalCannotBeShown(t *testing.T) {
	pageRenderer := handlersmocks.NewPageRenderer(t)
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	emailSender := accounthandlersmocks.NewEmailSender(t)
	jobs := &signInNoticeJobs{}
	handler := buildAuthOtpPost(authOtpPostDeps{
		pageRenderer:  pageRenderer,
		ceremonyStore: ceremonyStore,
		database:      database,
		auditLogger:   auditLogger,
		notifier:      accountnotice.New(pageRenderer, emailSender, jobs),
	})
	user := enrolledNoticeUser(t, "en")
	user.OtpConsecutiveFailures = record.OtpConsecutiveFailureLimit - 1
	req := otpCodeNoticeRequest(t, "000000")
	rr := httptest.NewRecorder()
	ceremonyStore.On("GetAuthContext", mock.Anything).Return(otpNoticeCeremony(), nil)
	database.On("GetUserById", mock.Anything, mock.Anything, user.Id).Return(user, nil).Once()
	expectOTPWriteTransactions(database)
	expectUserRowLocked(database, user)
	database.On("IncrementUserOtpConsecutiveFailures", mock.Anything, otpWriteTx, user.Id, user.OtpConfigGeneration).
		Return(true, nil).Once()
	database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
		Return((*record.Client)(nil), errors.New("client read unavailable")).Once()
	auditLogger.On("Log", mock.Anything, audit.EventAuthFailedOtp, mock.Anything).Return().Once()
	auditLogger.On("Log", mock.Anything, audit.EventOTPAuthenticatorDisabled, mock.Anything).Return().Once()
	pageRenderer.On("InternalServerError", rr, req, mock.Anything).
		Run(func(mock.Arguments) { rr.WriteHeader(http.StatusInternalServerError) }).Return().Once()

	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusInternalServerError, rr.Code)
	require.Len(t, jobs.jobs, 1, "the disable committed, so a failed read for the form loses no notice")
	assert.Equal(t, afterresponse.ClassSecurityNotice, jobs.classes[0])
	captured := expectSignInNotice(pageRenderer, emailSender, "/emails/email_otp_lockout.html")
	jobs.jobs[0](jobs.ctxs[0])
	require.NotNil(t, captured.sent)
	assert.Equal(t, signInNoticeAddress, captured.sent.To)
}

// answerSignInLockedRead makes the change's locking read of the user's row answer current.
func answerSignInLockedRead(t *testing.T, database *datamocks.Database, current *record.User) {
	t.Helper()
	found := false
	for _, call := range database.ExpectedCalls {
		if call.Method == "GetUserByIdForUpdate" {
			call.ReturnArguments = mock.Arguments{current, nil}
			found = true
		}
	}
	require.True(t, found, "the step reads the user's row in the change's transaction")
}

func TestHandleAuthOtpPost_NoticesGoToTheRowTheChangeCommittedBeside(t *testing.T) {
	const currentAddress = "current-address@example.com"
	for _, path := range []struct {
		name string
		page string
		// arm stubs the change for before, the user the step reads first, and returns the request.
		arm func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger,
			ceremonyStore *handlersmocks.CeremonyStore, pageRenderer *handlersmocks.PageRenderer,
			rr *httptest.ResponseRecorder, before *record.User) *http.Request
		user func(t *testing.T) *record.User
	}{
		{
			name: "an authenticator set up while signing in", page: "/emails/email_otp_enabled.html",
			user: func(*testing.T) *record.User { return signInNoticeUser() },
			arm: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger,
				ceremonyStore *handlersmocks.CeremonyStore, pageRenderer *handlersmocks.PageRenderer,
				rr *httptest.ResponseRecorder, before *record.User) *http.Request {
				secret := otpTestMintedSecret(t)
				req := signInNoticeRequest(t, signInNoticeSettings(), otptest.Code(t, secret, time.Now()))
				ceremonyStore.On("GetAuthContext", mock.Anything).Return(&ceremony.AuthContext{
					AuthState:  ceremony.AuthStateLevel2OTP,
					CeremonyId: testCeremonyId,
					UserId:     1,
					ClientId:   "test-client",
					OTPKeyURL:  otpTestKeyURL(secret),
				}, nil)
				stubSignInEnrolment(database, auditLogger, before)
				ceremonyStore.On("RegenerateSession", rr, req, testCeremonyId, int64(1)).Return(nil).Once()
				ceremonyStore.On("SaveAuthContext", rr, req, mock.Anything).Return(nil).Once()
				return req
			},
		},
		{
			name: "the refusal that disabled the authenticator", page: "/emails/email_otp_lockout.html",
			user: func(t *testing.T) *record.User {
				user := enrolledNoticeUser(t, "en")
				user.OtpConsecutiveFailures = record.OtpConsecutiveFailureLimit - 1
				return user
			},
			arm: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger,
				ceremonyStore *handlersmocks.CeremonyStore, pageRenderer *handlersmocks.PageRenderer,
				rr *httptest.ResponseRecorder, before *record.User) *http.Request {
				req := otpCodeNoticeRequest(t, "000000")
				ceremonyStore.On("GetAuthContext", mock.Anything).Return(otpNoticeCeremony(), nil)
				stubRefusedCode(database, auditLogger, pageRenderer, rr, req, before, false, true)
				return req
			},
		},
		{
			name: "a recovery code that signed in", page: "/emails/email_recovery_code_used.html",
			user: func(t *testing.T) *record.User { return enrolledNoticeUser(t, "en") },
			arm: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger,
				ceremonyStore *handlersmocks.CeremonyStore, pageRenderer *handlersmocks.PageRenderer,
				rr *httptest.ResponseRecorder, before *record.User) *http.Request {
				req := recoveryNoticeRequest(t, signInNoticeSettings(), recoveryCodeTyped)
				ceremonyStore.On("GetAuthContext", mock.Anything).Return(otpNoticeCeremony(), nil)
				stubAcceptedRecoveryCode(database, auditLogger, before, 3)
				ceremonyStore.On("RegenerateSession", rr, req, testCeremonyId, int64(1)).Return(nil).Once()
				ceremonyStore.On("SaveAuthContext", rr, req, mock.Anything).Return(nil).Once()
				return req
			},
		},
	} {
		for _, tc := range []struct {
			name            string
			beforeVerified  bool
			currentVerified bool
			wantSent        bool
		}{
			{"the address changed before the change committed", true, true, true},
			{"the address was verified before the change committed", false, true, true},
			{"the address's verification was revoked before the change committed", true, false, false},
		} {
			t.Run(path.name+", "+tc.name, func(t *testing.T) {
				pageRenderer := handlersmocks.NewPageRenderer(t)
				ceremonyStore := handlersmocks.NewCeremonyStore(t)
				database := datamocks.NewDatabase(t)
				auditLogger := handlersmocks.NewAuditLogger(t)
				emailSender := accounthandlersmocks.NewEmailSender(t)
				jobs := &signInNoticeJobs{}
				handler := buildAuthOtpPost(authOtpPostDeps{
					pageRenderer:  pageRenderer,
					ceremonyStore: ceremonyStore,
					database:      database,
					auditLogger:   auditLogger,
					notifier:      accountnotice.New(pageRenderer, emailSender, jobs),
				})
				before := path.user(t)
				before.EmailVerified = tc.beforeVerified
				rr := httptest.NewRecorder()
				req := path.arm(t, database, auditLogger, ceremonyStore, pageRenderer, rr, before)
				current := *before
				current.Email = currentAddress
				current.EmailVerified = tc.currentVerified
				answerSignInLockedRead(t, database, &current)

				handler.ServeHTTP(rr, req)

				if !tc.wantSent {
					assert.Empty(t, jobs.jobs, "the address the change committed beside is unverified")
					return
				}
				require.Len(t, jobs.jobs, 1, "the step hands off exactly one notice")
				captured := expectSignInNotice(pageRenderer, emailSender, path.page)
				jobs.jobs[0](jobs.ctxs[0])
				require.NotNil(t, captured.sent)
				assert.Equal(t, currentAddress, captured.sent.To,
					"the notice goes to the address the account had when the change committed")
			})
		}
	}
}
