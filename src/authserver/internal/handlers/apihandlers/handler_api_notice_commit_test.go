package apihandlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/afterresponse"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/emailtemplate"
	"github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// A credential notice belongs to the change that committed, not to how its response was then built
// or to what the request read before the change's transaction (#724, #737). Two properties, across
// every Account and administrator route that notifies:
//
//   - A change that committed is told even when the read the response is built from fails: the
//     request answers 500 and the notice still goes.
//   - The notice goes to the user's row as the change's own transaction read it under the row's
//     lock. An address changed, verified or unverified between the request's first read and the
//     write is the one the change committed beside.

// noticeRoute is one notifying route, armed for a change that commits.
type noticeRoute struct {
	name string
	// page is the notice's email page, the one literal the route's notice renders.
	email *emailtemplate.Email
	// arm stubs the change for before, the user the request reads first, and returns the handler
	// and the request that make it.
	arm func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger,
		before *record.User, jobs *heldJobs, pageRenderer *handlersmocks.PageRenderer,
		emailSender *accounthandlersmocks.EmailSender) (http.Handler, *http.Request)
	// user is the route's caller, or target, as the request first reads them.
	user func(t *testing.T) *record.User
}

func noticeRoutes() []noticeRoute {
	return []noticeRoute{
		{
			name: "an administrator's password", email: emailtemplate.PasswordChangedByAdministrator,
			user: func(*testing.T) *record.User { return adminPasswordNoticeRow("old-hash") },
			arm: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, before *record.User,
				jobs *heldJobs, pageRenderer *handlersmocks.PageRenderer, emailSender *accounthandlersmocks.EmailSender) (http.Handler, *http.Request) {
				replaced := *before
				stubAdminPasswordSet(database, auditLogger, before, &replaced)
				return adminPasswordNoticeHandler(database, auditLogger, jobs, pageRenderer, emailSender),
					adminPasswordNoticeRequest(t, passwordNoticeSettings(), adminPasswordNoticeNew)
			},
		},
		{
			name: "the account's password", email: emailtemplate.PasswordChanged,
			user: passwordNoticeUser,
			arm: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, before *record.User,
				jobs *heldJobs, pageRenderer *handlersmocks.PageRenderer, emailSender *accounthandlersmocks.EmailSender) (http.Handler, *http.Request) {
				stubPasswordChange(database, auditLogger, before)
				return passwordNoticeHandler(database, auditLogger, jobs, pageRenderer, emailSender),
					passwordNoticeRequest(t, passwordNoticeSettings(), passwordNoticeCurrent)
			},
		},
		{
			name: "an authenticator set up on the account", email: emailtemplate.OTPEnabled,
			user: otpNoticeUser,
			arm: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, before *record.User,
				jobs *heldJobs, pageRenderer *handlersmocks.PageRenderer, emailSender *accounthandlersmocks.EmailSender) (http.Handler, *http.Request) {
				stubOTPEnable(database, auditLogger, before)
				return accountOTPNoticeHandler(database, auditLogger, jobs, pageRenderer, emailSender),
					withNoticeContext(accountOTPEnableRequest(t, otpNoticeSubject, otpNoticePassword, currentOtpCode(t)),
						passwordNoticeSettings())
			},
		},
		{
			name: "an authenticator removed on the account", email: emailtemplate.OTPDisabled,
			user: enrolledOTPNoticeUser,
			arm: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, before *record.User,
				jobs *heldJobs, pageRenderer *handlersmocks.PageRenderer, emailSender *accounthandlersmocks.EmailSender) (http.Handler, *http.Request) {
				stubOTPRemove(database, auditLogger, before, "GetUserBySubject", otpNoticeSubject)
				return accountOTPNoticeHandler(database, auditLogger, jobs, pageRenderer, emailSender),
					withNoticeContext(accountOTPDisableRequest(t, otpNoticeSubject, otpNoticePassword), passwordNoticeSettings())
			},
		},
		{
			name: "an authenticator an administrator removed", email: emailtemplate.OTPDisabledByAdministrator,
			user: enrolledOTPNoticeUser,
			arm: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, before *record.User,
				jobs *heldJobs, pageRenderer *handlersmocks.PageRenderer, emailSender *accounthandlersmocks.EmailSender) (http.Handler, *http.Request) {
				stubOTPRemove(database, auditLogger, before, "GetUserById", before.Id)
				return adminOTPNoticeHandler(database, auditLogger, jobs, pageRenderer, emailSender),
					adminOTPNoticeRequest(t, passwordNoticeSettings(), before.Id)
			},
		},
		{
			name: "an administrator's deletion", email: emailtemplate.AccountDeletedByAdministrator,
			user: func(*testing.T) *record.User { return adminDeletionNoticeRow() },
			arm: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, before *record.User,
				jobs *heldJobs, pageRenderer *handlersmocks.PageRenderer, emailSender *accounthandlersmocks.EmailSender) (http.Handler, *http.Request) {
				locked := *before
				stubAdminDeletion(database, auditLogger, before, &locked)
				return adminDeletionNoticeHandler(database, auditLogger, jobs, pageRenderer, emailSender),
					adminDeletionNoticeRequest(passwordNoticeSettings())
			},
		},
		{
			name: "a new set of recovery codes", email: emailtemplate.RecoveryCodesReplaced,
			user: recoveryNoticeUser,
			arm: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, before *record.User,
				jobs *heldJobs, pageRenderer *handlersmocks.PageRenderer, emailSender *accounthandlersmocks.EmailSender) (http.Handler, *http.Request) {
				stubNewRecoveryCodes(database, auditLogger, before)
				return recoveryNoticeHandler(database, auditLogger, jobs, pageRenderer, emailSender),
					recoveryNoticeRequest(t, passwordNoticeSettings(), recoveryCodesPassword)
			},
		},
	}
}

// enrolledOTPNoticeUser is otpNoticeUser with an authenticator, whose removal the route makes.
func enrolledOTPNoticeUser(t *testing.T) *record.User {
	user := otpNoticeUser(t)
	user.OTPEnabled = true
	return user
}

// answerLockedRead makes the change's locking read of the user's row answer current.
func answerLockedRead(t *testing.T, database *datamocks.Database, current *record.User) {
	t.Helper()
	found := false
	for _, call := range database.ExpectedCalls {
		if call.Method == "GetUserByIdForUpdate" {
			call.ReturnArguments = mock.Arguments{current, nil}
			found = true
		}
	}
	require.True(t, found, "the route reads the user's row in the change's transaction")
}

func TestCredentialNotices_ACommittedChangeIsToldWhenItsResponseCannotBeRead(t *testing.T) {
	routes := noticeRoutes()
	for _, route := range routes {
		if route.email == emailtemplate.PasswordChanged || route.email == emailtemplate.RecoveryCodesReplaced ||
			route.email == emailtemplate.AccountDeletedByAdministrator {
			// Answered from what was read before the change, or with no read at all: no read after
			// it to fail.
			continue
		}
		t.Run(route.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			pageRenderer := handlersmocks.NewPageRenderer(t)
			emailSender := accounthandlersmocks.NewEmailSender(t)
			jobs := &heldJobs{}
			before := route.user(t)
			handler, req := route.arm(t, database, auditLogger, before, jobs, pageRenderer, emailSender)

			// The response's read is the last GetUserById the route makes, after the commit.
			var responseRead *mock.Call
			for _, call := range database.ExpectedCalls {
				if call.Method == "GetUserById" {
					responseRead = call
				}
			}
			require.NotNil(t, responseRead)
			responseRead.ReturnArguments = mock.Arguments{(*record.User)(nil), errors.New("response read unavailable")}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			require.Equal(t, http.StatusInternalServerError, rr.Code)
			require.Len(t, jobs.jobs, 1, "the change committed, so a failed read for its response loses no notice")
			captured := expectNotice(pageRenderer, emailSender, route.email)
			jobs.runAll(t, afterresponse.ClassSecurityNotice)
			require.NotNil(t, captured.sent)
			assert.Equal(t, before.Email, captured.sent.To)
		})
	}
}

func TestCredentialNotices_GoToTheRowTheChangeCommittedBeside(t *testing.T) {
	const currentAddress = "current-address@example.com"
	for _, route := range noticeRoutes() {
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
			t.Run(route.name+", "+tc.name, func(t *testing.T) {
				database := datamocks.NewDatabase(t)
				auditLogger := handlersmocks.NewAuditLogger(t)
				pageRenderer := handlersmocks.NewPageRenderer(t)
				emailSender := accounthandlersmocks.NewEmailSender(t)
				jobs := &heldJobs{}
				before := route.user(t)
				before.EmailVerified = tc.beforeVerified
				handler, req := route.arm(t, database, auditLogger, before, jobs, pageRenderer, emailSender)
				current := *before
				current.Email = currentAddress
				current.EmailVerified = tc.currentVerified
				current.PasswordHash = "replaced-hash" // a password was there to replace
				answerLockedRead(t, database, &current)

				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, req)

				require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
				if !tc.wantSent {
					assert.Empty(t, jobs.jobs, "the address the change committed beside is unverified")
					return
				}
				captured := expectNotice(pageRenderer, emailSender, route.email)
				jobs.runAll(t, afterresponse.ClassSecurityNotice)
				require.NotNil(t, captured.sent)
				assert.Equal(t, currentAddress, captured.sent.To,
					"the notice goes to the address the account had when the change committed")
			})
		}
	}
}
