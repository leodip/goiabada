package apihandlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/accountnotice"
	"github.com/leodip/goiabada/authserver/internal/afterresponse"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/otp/otptest"
	"github.com/leodip/goiabada/authserver/internal/otpcredential"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/requestid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// POST /api/v1/account/deletion (#783 decisions 2, 3, 4, 7 and 9): a user deletes their own account
// with their password and, while two-factor authentication is on, an authenticator code or a
// recovery code. The refusals come in decision 3's order: the setting off, the last administrator,
// checked before any credential and again under the administrators' lock, the password, then the
// second factor. A wrong password, authenticator code or recovery code spends the account_password
// budget; a blank one spends nothing, and a refused deletion spends no recovery code. The deletion
// is DeleteUser in a transaction whose first statement takes the administrators' lock; after the
// commit it writes deleted_own_account and hands off the "Your account was deleted" notice.
//
// The mocks are strict, so a write the case does not name, an audit entry it does not expect or a
// notice handed off by a refusal fails it.

const (
	deletionSubject      = "the-deleting-subject"
	deletionPassword     = "D3lete!Me-now"
	deletionAddress      = "rui.costa@example.com"
	deletionRequestId    = "req-deletion-0001"
	deletionRecoveryCode = "abcd-efgh-jkmn-pqrs-tvwx-yz01"
	deletionUserId       = int64(91)
)

// deletionCheckTx is the early check's transaction and deletionTx the deletion's. Distinct and not
// nil, so a statement made on the wrong one, or outside both, is an unexpected call.
var (
	deletionCheckTx = &sql.Tx{}
	deletionTx      = &sql.Tx{}
)

// deletionUser is the caller: an ordinary enabled user with a verified address, a name and
// deletionPassword, and no authenticator.
func deletionUser(t *testing.T) *record.User {
	t.Helper()
	hash, err := passwordhash.Hash(deletionPassword)
	require.NoError(t, err)
	return &record.User{
		Id: deletionUserId, Subject: deletionSubject, Enabled: true,
		GivenName: "Rui", FamilyName: "Costa", Email: deletionAddress, EmailVerified: true,
		PasswordHash: hash,
	}
}

// enrolledDeletionUser is deletionUser with an authenticator on otpTestSecret.
func enrolledDeletionUser(t *testing.T) *record.User {
	t.Helper()
	user := deletionUser(t)
	secret, err := testDataCipher.Encrypt(otpTestSecret)
	require.NoError(t, err)
	user.OTPEnabled = true
	user.OTPSecretEncrypted = secret
	user.OtpConfigGeneration = 6
	return user
}

// deletionSettings are the request's settings: deletion on, and SMTP on so a case that expects no
// notice asserts it where one could have been sent.
func deletionSettings() *record.Settings {
	settings := passwordNoticeSettings()
	settings.AccountDeletionEnabled = true
	return settings
}

// deletionRequest is the deletion as the console sends it, carrying the caller's token, the
// request's id and settings.
func deletionRequest(t *testing.T, settings *record.Settings, body map[string]string) *http.Request {
	t.Helper()
	encoded, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/account/deletion", bytes.NewReader(encoded))
	req.Header.Set("Content-Type", "application/json")
	req = setTokenContextWithClaims(req, map[string]interface{}{"sub": deletionSubject})
	ctx := requestid.NewContext(req.Context(), deletionRequestId)
	return req.WithContext(reqctx.WithSettings(ctx, settings))
}

// deletionFixture is one case's doubles.
type deletionFixture struct {
	database     *datamocks.Database
	auditLogger  *handlersmocks.AuditLogger
	credentials  *countingCredentials
	jobs         *heldJobs
	pageRenderer *handlersmocks.PageRenderer
	emailSender  *accounthandlersmocks.EmailSender
}

func newDeletionFixture(t *testing.T) *deletionFixture {
	return &deletionFixture{
		database:     datamocks.NewDatabase(t),
		auditLogger:  handlersmocks.NewAuditLogger(t),
		credentials:  &countingCredentials{},
		jobs:         &heldJobs{},
		pageRenderer: handlersmocks.NewPageRenderer(t),
		emailSender:  accounthandlersmocks.NewEmailSender(t),
	}
}

func (f *deletionFixture) serve(req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	HandleAccountDeletionPost(f.database, f.auditLogger, f.credentials, testDataCipher,
		accountnotice.New(f.pageRenderer, f.emailSender, f.jobs)).ServeHTTP(rr, req)
	return rr
}

// expectCaller answers the request's read of the caller.
func (f *deletionFixture) expectCaller(user *record.User) {
	f.database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), deletionSubject).Return(user, nil).Once()
}

// expectGuardReads answers the reads, on tx, that decide whether the user holds manage: a direct
// grant when holdsManage, else no grant and no group.
func (f *deletionFixture) expectGuardReads(tx *sql.Tx, holdsManage bool) {
	if holdsManage {
		f.database.On("GetUserPermissionByUserIdAndPermissionId", mock.Anything, tx, deletionUserId, permManage).
			Return(&record.UserPermission{UserId: deletionUserId, PermissionId: permManage}, nil).Once()
		return
	}
	f.database.On("GetUserPermissionByUserIdAndPermissionId", mock.Anything, tx, deletionUserId, permManage).
		Return((*record.UserPermission)(nil), nil).Once()
	f.database.On("GetUserGroupsByUserId", mock.Anything, tx, deletionUserId).Return([]record.UserGroup{}, nil).Once()
}

// expectEarlyCheck answers the last-administrator check made before any credential, in a
// transaction of its own that writes nothing: an ordinary user, or a holder of manage among
// holders enabled holders.
func (f *deletionFixture) expectEarlyCheck(holdsManage bool, holders int) *datamocks.RunInTransactionStub {
	stub := datamocks.ExpectRunInTransaction(f.database, deletionCheckTx)
	expectAdministratorsLock(f.database, deletionCheckTx)
	f.expectGuardReads(deletionCheckTx, holdsManage)
	if holdsManage {
		f.database.On("CountEnabledUsersHoldingPermission", mock.Anything, deletionCheckTx, permManage).
			Return(holders, nil).Once()
	}
	return stub
}

// expectDeletionOpened answers the deletion's transaction up to the user's row, read under its lock
// after the administrators' lock, which is the first statement.
func (f *deletionFixture) expectDeletionOpened(current *record.User, note ...func(string)) *datamocks.RunInTransactionStub {
	stub := datamocks.ExpectRunInTransaction(f.database, deletionTx, note...)
	expectAdministratorsLock(f.database, deletionTx)
	f.database.On("GetUserByIdForUpdate", mock.Anything, deletionTx, deletionUserId).Return(current, nil).Once()
	return stub
}

// expectDeletionCompleted answers the rest of a deletion of an ordinary user that commits.
func (f *deletionFixture) expectDeletionCompleted(note ...func(string)) {
	f.expectGuardReads(deletionTx, false)
	f.database.On("DeleteUser", mock.Anything, deletionTx, deletionUserId).Return(nil).
		Run(func(mock.Arguments) {
			for _, n := range note {
				n("delete")
			}
		}).Once()
	f.auditLogger.On("Log", mock.Anything, audit.EventDeletedOwnAccount, map[string]interface{}{
		"user_id":        deletionUserId,
		"logged_in_user": deletionSubject,
	}).Return().Run(func(mock.Arguments) {
		for _, n := range note {
			n("audit")
		}
	}).Once()
}

// assertDeleted checks the 200 and that the deletion committed, and runs the one notice it handed
// off, answering what was sent.
func (f *deletionFixture) assertDeleted(t *testing.T, rr *httptest.ResponseRecorder, stub *datamocks.RunInTransactionStub) *capturedNotice {
	t.Helper()
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.JSONEq(t, `{"success":true}`, rr.Body.String())
	require.NoError(t, stub.BodyErr, "the deletion commits")
	assert.Equal(t, "AcquireManagePermissionRow", firstCallOn(f.database, deletionTx),
		"the administrators' lock is the deletion's first statement")
	// The renderer and the sender had no expectation until now, so a notice sent inside the
	// request would already have failed the case.
	captured := expectNotice(f.pageRenderer, f.emailSender, "/emails/email_account_deleted.html")
	f.jobs.runAll(t, afterresponse.ClassSecurityNotice)
	return captured
}

func TestHandleAccountDeletionPost_DeletesTheAccountWithThePassword(t *testing.T) {
	f := newDeletionFixture(t)
	user := deletionUser(t)
	f.expectCaller(user)
	f.expectEarlyCheck(false, 0)
	var order []string
	note := func(edge string) { order = append(order, edge) }
	stub := f.expectDeletionOpened(user, note)
	f.expectDeletionCompleted(note)

	rr := f.serve(deletionRequest(t, deletionSettings(), map[string]string{"password": deletionPassword}))

	captured := f.assertDeleted(t, rr, stub)
	assert.Equal(t, []string{"begin", "delete", "commit", "audit"}, order,
		"deleted_own_account is written after the commit")
	assert.Zero(t, f.credentials.failures, "the right password spends nothing")
	require.NotNil(t, captured.sent)
	assert.Equal(t, deletionAddress, captured.sent.To)
	assert.Equal(t, "Your account was deleted", captured.sent.Subject)
	assert.Equal(t, "Rui Costa", captured.bound["name"])
	assert.NotContains(t, captured.bound, "link", "the notice carries no link")
}

// The notice is in the user's language, the subject from the catalog of each built-in language.
func TestHandleAccountDeletionPost_TellsTheUserInTheirLanguage(t *testing.T) {
	for _, tc := range []struct{ locale, subject string }{
		{"pt-BR", "Sua conta foi excluída"},
		{"de", "Ihr Konto wurde gelöscht"},
		{"es", "Se ha eliminado tu cuenta"},
		{"fr", "Votre compte a été supprimé"},
		{"it", "Il tuo account è stato eliminato"}, //nolint:misspell // the it catalog's text: "eliminato" is Italian, not a misspelling of "elimination"
	} {
		t.Run(tc.locale, func(t *testing.T) {
			f := newDeletionFixture(t)
			user := deletionUser(t)
			user.Locale = tc.locale
			f.expectCaller(user)
			f.expectEarlyCheck(false, 0)
			stub := f.expectDeletionOpened(user)
			f.expectDeletionCompleted()

			rr := f.serve(deletionRequest(t, deletionSettings(), map[string]string{"password": deletionPassword}))

			captured := f.assertDeleted(t, rr, stub)
			assert.Equal(t, tc.locale, captured.renderLocale)
			assert.Equal(t, tc.subject, captured.sent.Subject)
		})
	}
}

// The notice goes to the user's row as the deletion's transaction read it under the row's lock,
// not as read before the password was checked.
func TestHandleAccountDeletionPost_TellsTheAddressTheDeletionRead(t *testing.T) {
	for _, tc := range []struct {
		name     string
		verified bool
		wantSent bool
	}{
		{"an address changed and verified before the deletion", true, true},
		{"an address whose verification was revoked before the deletion", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDeletionFixture(t)
			user := deletionUser(t)
			f.expectCaller(user)
			f.expectEarlyCheck(false, 0)
			current := *user
			current.Email = "current-address@example.com"
			current.EmailVerified = tc.verified
			stub := f.expectDeletionOpened(&current)
			f.expectDeletionCompleted()

			rr := f.serve(deletionRequest(t, deletionSettings(), map[string]string{"password": deletionPassword}))

			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			require.NoError(t, stub.BodyErr)
			if !tc.wantSent {
				assert.Empty(t, f.jobs.jobs, "an unverified address is sent nothing")
				return
			}
			captured := expectNotice(f.pageRenderer, f.emailSender, "/emails/email_account_deleted.html")
			f.jobs.runAll(t, afterresponse.ClassSecurityNotice)
			assert.Equal(t, "current-address@example.com", captured.sent.To)
		})
	}
}

// With SMTP off the deletion is made and nothing is handed off.
func TestHandleAccountDeletionPost_SendsNoNoticeWithSMTPOff(t *testing.T) {
	f := newDeletionFixture(t)
	user := deletionUser(t)
	f.expectCaller(user)
	f.expectEarlyCheck(false, 0)
	stub := f.expectDeletionOpened(user)
	f.expectDeletionCompleted()
	settings := deletionSettings()
	settings.SMTPEnabled = false

	rr := f.serve(deletionRequest(t, settings, map[string]string{"password": deletionPassword}))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.NoError(t, stub.BodyErr)
	assert.Empty(t, f.jobs.jobs)
}

func TestHandleAccountDeletionPost_DeletesWithAnAuthenticatorCode(t *testing.T) {
	f := newDeletionFixture(t)
	user := enrolledDeletionUser(t)
	f.expectCaller(user)
	f.expectEarlyCheck(false, 0)
	// The code is claimed against the authenticator it was checked against: the generation read
	// with the seed.
	f.database.On("TryConsumeEnrolledUserOTPStep", mock.Anything, (*sql.Tx)(nil), deletionUserId, mock.Anything,
		user.OtpConfigGeneration).Return(true, nil).Once()
	stub := f.expectDeletionOpened(user)
	f.expectDeletionCompleted()

	rr := f.serve(deletionRequest(t, deletionSettings(), map[string]string{
		"password": deletionPassword, "otpCode": currentOtpCode(t)}))

	f.assertDeleted(t, rr, stub)
	assert.Zero(t, f.credentials.failures)
}

// A recovery code stands in for the authenticator code (decision 2). It is claimed inside the
// deletion's transaction, so a deletion that does not commit leaves it unspent, and one that does
// deletes it with the account. The user is sent one email, the deletion's, and no recovery-code
// notice beside it.
func TestHandleAccountDeletionPost_DeletesWithARecoveryCode(t *testing.T) {
	f := newDeletionFixture(t)
	user := enrolledDeletionUser(t)
	f.expectCaller(user)
	f.expectEarlyCheck(false, 0)
	var order []string
	note := func(edge string) { order = append(order, edge) }
	stub := f.expectDeletionOpened(user, note)
	f.database.On("TryUseUserRecoveryCode", mock.Anything, deletionTx, deletionUserId,
		otpcredential.HashRecoveryCode(deletionRecoveryCode)).Return(true, nil).
		Run(func(mock.Arguments) { order = append(order, "claim") }).Once()
	f.expectDeletionCompleted(note)

	rr := f.serve(deletionRequest(t, deletionSettings(), map[string]string{
		"password": deletionPassword, "recoveryCode": deletionRecoveryCode}))

	captured := f.assertDeleted(t, rr, stub)
	assert.Equal(t, []string{"begin", "claim", "delete", "commit", "audit"}, order,
		"the code is claimed on the deletion's transaction, before the delete")
	assert.Equal(t, "Your account was deleted", captured.sent.Subject)
	assert.Zero(t, f.credentials.failures)
}

// A holder of manage deletes their own account while another enabled holder remains.
func TestHandleAccountDeletionPost_AnAdministratorDeletesWhileAnotherRemains(t *testing.T) {
	f := newDeletionFixture(t)
	user := deletionUser(t)
	f.expectCaller(user)
	f.expectEarlyCheck(true, 2)
	stub := f.expectDeletionOpened(user)
	f.expectGuardReads(deletionTx, true)
	expectHoldersCounted(f.database, deletionTx, 2, 1)
	f.database.On("DeleteUser", mock.Anything, deletionTx, deletionUserId).Return(nil).Once()
	f.auditLogger.On("Log", mock.Anything, audit.EventDeletedOwnAccount, mock.Anything).Return().Once()

	rr := f.serve(deletionRequest(t, deletionSettings(), map[string]string{"password": deletionPassword}))

	f.assertDeleted(t, rr, stub)
}

// The refusals answered before the deletion's transaction, in decision 3's order. Each case sends
// what would also be refused later in the order, so answering a later refusal first fails it.
func TestHandleAccountDeletionPost_RefusesInDecisionThreesOrder(t *testing.T) {
	disabled := "Account deletion is turned off. Ask your administrator to delete your account."
	lastAdministrator := "You're the last administrator, so you can't delete your account. Give another user authserver:manage first."
	wrongPassword := "That password isn't right. Try again."
	codeRequired := "Enter the 6-digit code from your authenticator app."
	wrongCode := "That code isn't right. Codes change every 30 seconds, so enter the one your app shows now."
	clockAhead := "Your device's clock seems to be ahead. Check that its date and time are set automatically, then enter the code your app shows."

	for _, tc := range []struct {
		name        string
		settingOff  bool
		body        func(t *testing.T) map[string]string
		arrange     func(t *testing.T, f *deletionFixture)
		status      int
		code        string
		description string
		failures    int
	}{
		{
			name: "the setting off, before the body is read", settingOff: true,
			body:   func(*testing.T) map[string]string { return map[string]string{"password": "Wr0ng!pass"} },
			status: http.StatusForbidden, code: "ACCOUNT_DELETION_DISABLED", description: disabled,
		},
		{
			name: "the last administrator, before the password is checked",
			body: func(*testing.T) map[string]string { return map[string]string{"password": "Wr0ng!pass"} },
			arrange: func(t *testing.T, f *deletionFixture) {
				f.expectCaller(deletionUser(t))
				f.expectEarlyCheck(true, 1)
			},
			status: http.StatusConflict, code: "LAST_ADMINISTRATOR", description: lastAdministrator,
		},
		{
			name: "a blank password spends nothing",
			body: func(*testing.T) map[string]string { return map[string]string{"password": "  "} },
			arrange: func(t *testing.T, f *deletionFixture) {
				f.expectCaller(deletionUser(t))
				f.expectEarlyCheck(false, 0)
			},
			status: http.StatusBadRequest, code: "AUTHENTICATION_FAILED", description: wrongPassword,
		},
		{
			name: "a wrong password, before the code",
			body: func(t *testing.T) map[string]string {
				return map[string]string{"password": "Wr0ng!pass", "otpCode": currentOtpCode(t)}
			},
			arrange: func(t *testing.T, f *deletionFixture) {
				f.expectCaller(enrolledDeletionUser(t))
				f.expectEarlyCheck(false, 0)
			},
			status: http.StatusBadRequest, code: "AUTHENTICATION_FAILED", description: wrongPassword, failures: 1,
		},
		{
			name: "two-factor on and no code spends nothing",
			body: func(*testing.T) map[string]string {
				return map[string]string{"password": deletionPassword, "recoveryCode": " - "}
			},
			arrange: func(t *testing.T, f *deletionFixture) {
				f.expectCaller(enrolledDeletionUser(t))
				f.expectEarlyCheck(false, 0)
			},
			status: http.StatusBadRequest, code: "OTP_CODE_REQUIRED", description: codeRequired,
		},
		{
			name: "a wrong authenticator code advances the authenticator's failure count",
			body: func(t *testing.T) map[string]string {
				return map[string]string{"password": deletionPassword, "otpCode": wrongButWellFormedCode(t)}
			},
			arrange: func(t *testing.T, f *deletionFixture) {
				user := enrolledDeletionUser(t)
				f.expectCaller(user)
				f.expectEarlyCheck(false, 0)
				countTx := &sql.Tx{}
				datamocks.ExpectRunInTransaction(f.database, countTx)
				f.database.On("IncrementUserOtpConsecutiveFailures", mock.Anything, countTx, deletionUserId,
					user.OtpConfigGeneration).Return(false, nil).Once()
			},
			status: http.StatusBadRequest, code: "INVALID_OTP_CODE", description: wrongCode, failures: 1,
		},
		{
			name: "a replayed authenticator code is answered as a wrong one, and audited",
			body: func(t *testing.T) map[string]string {
				return map[string]string{"password": deletionPassword, "otpCode": currentOtpCode(t)}
			},
			arrange: func(t *testing.T, f *deletionFixture) {
				user := enrolledDeletionUser(t)
				f.expectCaller(user)
				f.expectEarlyCheck(false, 0)
				f.database.On("TryConsumeEnrolledUserOTPStep", mock.Anything, (*sql.Tx)(nil), deletionUserId,
					mock.Anything, user.OtpConfigGeneration).Return(false, nil).Once()
				countTx := &sql.Tx{}
				datamocks.ExpectRunInTransaction(f.database, countTx)
				f.database.On("IncrementUserOtpConsecutiveFailures", mock.Anything, countTx, deletionUserId,
					user.OtpConfigGeneration).Return(false, nil).Once()
				f.auditLogger.On("Log", mock.Anything, audit.EventOTPCodeReplayDetected, mock.MatchedBy(
					func(details map[string]interface{}) bool {
						return details["user_id"] == deletionUserId && details["logged_in_user"] == deletionSubject &&
							details["step"] != nil
					})).Return().Once()
			},
			status: http.StatusBadRequest, code: "INVALID_OTP_CODE", description: wrongCode, failures: 1,
		},
		{
			name: "a code from the next step is no guess, so it spends nothing",
			body: func(t *testing.T) map[string]string {
				return map[string]string{"password": deletionPassword, "otpCode": otptest.NextStepCode(t, otpTestSecret)}
			},
			arrange: func(t *testing.T, f *deletionFixture) {
				f.expectCaller(enrolledDeletionUser(t))
				f.expectEarlyCheck(false, 0)
				f.auditLogger.On("Log", mock.Anything, audit.EventAuthFailedOtp, map[string]interface{}{
					"user_id": deletionUserId, "logged_in_user": deletionSubject, "reason": audit.AuthFailedOtpClockAhead,
				}).Return().Once()
			},
			status: http.StatusBadRequest, code: "OTP_CLOCK_AHEAD", description: clockAhead,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDeletionFixture(t)
			if tc.arrange != nil {
				tc.arrange(t, f)
			}
			settings := deletionSettings()
			settings.AccountDeletionEnabled = !tc.settingOff

			rr := f.serve(deletionRequest(t, settings, tc.body(t)))

			require.Equal(t, tc.status, rr.Code, rr.Body.String())
			assert.Equal(t, tc.code, errorCodeOf(t, rr))
			assert.Equal(t, tc.description, descriptionOf(t, rr))
			assert.Equal(t, tc.failures, f.credentials.failures, "the failure budget spent")
			assert.Empty(t, f.jobs.jobs, "a refusal tells nobody")
		})
	}
}

// The refusals are in the request's language, as the other account refusals are (#559).
func TestHandleAccountDeletionPost_RefusalsAreInTheRequestsLanguage(t *testing.T) {
	f := newDeletionFixture(t)
	f.expectCaller(deletionUser(t))
	f.expectEarlyCheck(true, 1)
	req := deletionRequest(t, deletionSettings(), map[string]string{"password": deletionPassword})
	req = inRequestLanguage(req, "pt-BR")

	rr := f.serve(req)

	require.Equal(t, http.StatusConflict, rr.Code, rr.Body.String())
	assert.Equal(t, "Você é o último administrador, então não pode excluir a sua conta. Conceda authserver:manage a outro usuário primeiro.",
		descriptionOf(t, rr))
}

// Both codes at once is a request the caller has to fix, refused before anything is read.
func TestHandleAccountDeletionPost_BothCodesAtOnceIsRefused(t *testing.T) {
	f := newDeletionFixture(t)

	rr := f.serve(deletionRequest(t, deletionSettings(), map[string]string{
		"password": deletionPassword, "otpCode": "123456", "recoveryCode": deletionRecoveryCode}))

	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	assert.Equal(t, "VALIDATION_ERROR", errorCodeOf(t, rr))
	assert.Equal(t, "Send an authentication code or a recovery code, not both.", descriptionOf(t, rr))
	assert.Zero(t, f.credentials.failures)
}

// A wrong recovery code and a used one get the same answer (decision 2), and each spends the
// budget; a used one is audited as a replay. The claim is on the deletion's transaction, which
// rolls back, so nothing is deleted.
func TestHandleAccountDeletionPost_AWrongOrUsedRecoveryCodeIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		used bool
	}{
		{"a wrong recovery code", false},
		{"a used recovery code", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDeletionFixture(t)
			user := enrolledDeletionUser(t)
			f.expectCaller(user)
			f.expectEarlyCheck(false, 0)
			stub := f.expectDeletionOpened(user)
			codeHash := otpcredential.HashRecoveryCode(deletionRecoveryCode)
			f.database.On("TryUseUserRecoveryCode", mock.Anything, deletionTx, deletionUserId, codeHash).
				Return(false, nil).Once()
			f.database.On("UserRecoveryCodeExists", mock.Anything, (*sql.Tx)(nil), deletionUserId, codeHash).
				Return(tc.used, nil).Once()
			if tc.used {
				f.auditLogger.On("Log", mock.Anything, audit.EventRecoveryCodeReplayDetected, map[string]interface{}{
					"user_id": deletionUserId, "logged_in_user": deletionSubject,
				}).Return().Once()
			}

			rr := f.serve(deletionRequest(t, deletionSettings(), map[string]string{
				"password": deletionPassword, "recoveryCode": deletionRecoveryCode}))

			require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
			assert.Equal(t, "INVALID_RECOVERY_CODE", errorCodeOf(t, rr))
			assert.Equal(t, "That recovery code isn't right, or it was already used.", descriptionOf(t, rr))
			assert.Equal(t, 1, f.credentials.failures)
			require.Error(t, stub.BodyErr, "the deletion's transaction rolls back")
			assert.Empty(t, f.jobs.jobs)
		})
	}
}

// The last administrator is checked again under the lock: a holder whose fellow administrator was
// removed after the early check is refused there, with the deletion and the recovery code's claim
// rolled back, nothing audited and no notice.
func TestHandleAccountDeletionPost_TheLastAdministratorUnderTheLockIsRefused(t *testing.T) {
	f := newDeletionFixture(t)
	user := enrolledDeletionUser(t)
	f.expectCaller(user)
	f.expectEarlyCheck(true, 2)
	stub := f.expectDeletionOpened(user)
	f.database.On("TryUseUserRecoveryCode", mock.Anything, deletionTx, deletionUserId,
		otpcredential.HashRecoveryCode(deletionRecoveryCode)).Return(true, nil).Once()
	f.expectGuardReads(deletionTx, true)
	expectHoldersCounted(f.database, deletionTx, 1, 0)
	f.database.On("DeleteUser", mock.Anything, deletionTx, deletionUserId).Return(nil).Once()

	rr := f.serve(deletionRequest(t, deletionSettings(), map[string]string{
		"password": deletionPassword, "recoveryCode": deletionRecoveryCode}))

	require.Equal(t, http.StatusConflict, rr.Code, rr.Body.String())
	assert.Equal(t, "LAST_ADMINISTRATOR", errorCodeOf(t, rr))
	assert.Equal(t, "You're the last administrator, so you can't delete your account. Give another user authserver:manage first.",
		descriptionOf(t, rr))
	require.ErrorIs(t, stub.BodyErr, errLastAdministrator,
		"the body refuses, so the deletion and the code's claim roll back")
	assert.Zero(t, f.credentials.failures)
	assert.Empty(t, f.jobs.jobs)
}

// Two-factor authentication turned on after the request read the account, with no code sent: the
// deletion is refused as a request arriving a moment later would be, and rolled back.
func TestHandleAccountDeletionPost_TwoFactorTurnedOnMeanwhileNeedsACode(t *testing.T) {
	f := newDeletionFixture(t)
	user := deletionUser(t)
	f.expectCaller(user)
	f.expectEarlyCheck(false, 0)
	enrolled := *user
	enrolled.OTPEnabled = true
	stub := f.expectDeletionOpened(&enrolled)

	rr := f.serve(deletionRequest(t, deletionSettings(), map[string]string{"password": deletionPassword}))

	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	assert.Equal(t, "OTP_CODE_REQUIRED", errorCodeOf(t, rr))
	require.Error(t, stub.BodyErr, "nothing is deleted")
	assert.Empty(t, f.jobs.jobs)
}

// A deletion that rolls back answers the one 500, audits nothing and tells nobody.
func TestHandleAccountDeletionPost_ARolledBackDeletionTellsNobody(t *testing.T) {
	f := newDeletionFixture(t)
	user := deletionUser(t)
	f.expectCaller(user)
	f.expectEarlyCheck(false, 0)
	stub := f.expectDeletionOpened(user)
	f.expectGuardReads(deletionTx, false)
	f.database.On("DeleteUser", mock.Anything, deletionTx, deletionUserId).Return(errors.New("delete failed")).Once()

	rr := f.serve(deletionRequest(t, deletionSettings(), map[string]string{"password": deletionPassword}))

	require.Equal(t, http.StatusInternalServerError, rr.Code, rr.Body.String())
	require.Error(t, stub.BodyErr)
	assert.Empty(t, f.jobs.jobs)
}

// The wrong code that disables the authenticator is audited and told once, as at sign-in (#489,
// #724 decision 7), and the deletion is refused.
func TestHandleAccountDeletionPost_TheCodeThatDisablesTheAuthenticatorIsTold(t *testing.T) {
	f := newDeletionFixture(t)
	user := enrolledDeletionUser(t)
	f.expectCaller(user)
	f.expectEarlyCheck(false, 0)
	countTx := &sql.Tx{}
	datamocks.ExpectRunInTransaction(f.database, countTx)
	f.database.On("IncrementUserOtpConsecutiveFailures", mock.Anything, countTx, deletionUserId,
		user.OtpConfigGeneration).Return(true, nil).Once()
	f.database.On("GetUserByIdForUpdate", mock.Anything, countTx, deletionUserId).Return(user, nil).Once()
	f.auditLogger.On("Log", mock.Anything, audit.EventOTPAuthenticatorDisabled, map[string]interface{}{
		"user_id": deletionUserId, "logged_in_user": deletionSubject,
	}).Return().Once()

	rr := f.serve(deletionRequest(t, deletionSettings(), map[string]string{
		"password": deletionPassword, "otpCode": wrongButWellFormedCode(t)}))

	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	assert.Equal(t, "INVALID_OTP_CODE", errorCodeOf(t, rr))
	assert.Equal(t, 1, f.credentials.failures)
	captured := expectNotice(f.pageRenderer, f.emailSender, "/emails/email_otp_lockout.html")
	f.jobs.runAll(t, afterresponse.ClassSecurityNotice)
	assert.Equal(t, deletionAddress, captured.sent.To)
}
