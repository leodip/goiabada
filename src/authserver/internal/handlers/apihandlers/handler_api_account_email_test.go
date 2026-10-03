package apihandlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/audit"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	mocks_accounthandlers "github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	mocks_handlers "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Seam 4 of #425 for the self-service twin of HandleUserEmailPut, which carried the same defect
// and which #414 named only as the racing party. The fixture and requireEmailTaken are
// handler_api_users_email_test.go's.

// accountEmailTestPassword is the caller's current password in every case here.
const accountEmailTestPassword = "C0rrect!Pass"

func accountEmailTestPasswordHash(t *testing.T) string {
	t.Helper()
	hash, err := passwordhash.Hash(accountEmailTestPassword)
	require.NoError(t, err)
	return hash
}

// accountEmailPut builds the request: the body as the account API's caller sends it, and a token
// naming the caller.
func accountEmailPut(t *testing.T, body any) *http.Request {
	t.Helper()
	encoded, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/account/email", bytes.NewReader(encoded))
	ctx := context.WithValue(req.Context(), chimiddleware.RequestIDKey, accountEmailRequestId)
	req = req.WithContext(reqctx.WithSettings(ctx, accountEmailSettings()))
	return setTokenContextWithClaims(req, map[string]interface{}{"sub": emailTestSubject})
}

// accountEmailRequestId is the request id accountEmailPut carries, as chi's RequestID middleware
// puts one on every request.
const accountEmailRequestId = "req-email-0001"

// accountEmailSettings are the settings middleware.Settings puts on the request, with SMTP on, so
// every case that expects no notice is asserting it where one could have been sent.
func accountEmailSettings() *models.Settings {
	return &models.Settings{
		AppName:       "TestApp",
		SMTPEnabled:   true,
		SMTPHost:      "smtp.example.com",
		SMTPPort:      587,
		SMTPFromEmail: "noreply@example.com",
	}
}

// accountEmailHandler is the handler as routes.go wires it, with a renderer and a sender that
// expect nothing: a case that expects the notice sets their expectations before running the job.
func accountEmailHandler(t *testing.T, database *mocks_data.Database, auditLogger *mocks_handlers.AuditLogger,
	credentials CredentialFailureRecorder, jobs *heldJobs) http.Handler {
	t.Helper()
	return accountEmailHandlerWith(database, auditLogger, credentials, jobs,
		mocks_handlers.NewPageRenderer(t), mocks_accounthandlers.NewEmailSender(t))
}

func accountEmailHandlerWith(database *mocks_data.Database, auditLogger *mocks_handlers.AuditLogger,
	credentials CredentialFailureRecorder, jobs *heldJobs, pageRenderer *mocks_handlers.PageRenderer,
	emailSender *mocks_accounthandlers.EmailSender) http.Handler {
	return HandleAccountEmailPut(pageRenderer, database, accountvalidation.NewEmailValidator(database),
		emailSender, auditLogger, credentials, jobs)
}

// heldJobs is the after-response runner as these tests drive it: it holds every job handed to it
// rather than starting it, so a case asserts what the request did before its response, and then
// runs the jobs and asserts what they did. Each job runs under the context it was handed, which is
// the request's.
type heldJobs struct {
	ctxs []context.Context
	jobs []func(ctx context.Context)
}

func (h *heldJobs) Go(ctx context.Context, job func(ctx context.Context)) {
	h.ctxs = append(h.ctxs, ctx)
	h.jobs = append(h.jobs, job)
}

// runAll runs every job held and requires exactly one: an email change hands off the one notice
// or nothing.
func (h *heldJobs) runAll(t *testing.T) {
	t.Helper()
	require.Len(t, h.jobs, 1, "a completed change hands exactly one job to run after its response")
	for i, job := range h.jobs {
		job(h.ctxs[i])
	}
}

func accountEmailPutRequest(t *testing.T) *http.Request {
	t.Helper()
	return accountEmailPut(t, api.UpdateAccountEmailRequest{
		Email: emailTestAddress, CurrentPassword: accountEmailTestPassword})
}

// stubAccountEmailUpdate answers the handler's own read and the validator's, and the address as
// held by nobody, then the narrow write with updateErr.
func stubAccountEmailUpdate(t *testing.T, database *mocks_data.Database, updateErr error) {
	t.Helper()
	database.On("GetUserBySubject", mock.Anything, mock.Anything, emailTestSubject).
		Return(&models.User{Id: emailTestUserId, Subject: emailTestSubject, Email: "old@example.com",
			PasswordHash: accountEmailTestPasswordHash(t)}, nil).Twice()
	database.On("GetUserByEmail", mock.Anything, mock.Anything, emailTestAddress).Return(nil, nil).Once()
	database.On("TrySetUserEmail", mock.Anything, mock.Anything, emailTestUserId, "old@example.com", false, emailTestAddress).
		Return(updateErr == nil, updateErr).Once()
}

// TestHandleAccountEmailPut_SavesThroughTheNarrowWrite is #404 decision 4: the change writes
// the address, the cleared verified flag and the cleared verification code through TrySetUserEmail,
// keyed on the caller's own id, and never writes back the user row it loaded at the start of the
// request, which would undo a concurrent disable, password change or OTP change.
func TestHandleAccountEmailPut_SavesThroughTheNarrowWrite(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)
	jobs := &heldJobs{}
	database.On("GetUserBySubject", mock.Anything, mock.Anything, emailTestSubject).
		Return(&models.User{
			Id:                             emailTestUserId,
			Subject:                        emailTestSubject,
			Enabled:                        true,
			Email:                          "old@example.com",
			EmailVerified:                  true,
			EmailVerificationCodeEncrypted: []byte("pending-code"),
			EmailVerificationCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC(), Valid: true},
			PasswordHash:                   accountEmailTestPasswordHash(t),
		}, nil).Twice()
	database.On("GetUserByEmail", mock.Anything, mock.Anything, "new@example.com").Return(nil, nil).Once()
	// Conditional on the address and the verified flag the request read.
	database.On("TrySetUserEmail", mock.Anything, (*sql.Tx)(nil), emailTestUserId, "old@example.com", true, "new@example.com").
		Return(true, nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedOwnEmail, map[string]interface{}{
		"userId":       emailTestUserId,
		"loggedInUser": emailTestSubject,
	}).Return().Once()
	credentials := &countingCredentials{}

	rr := httptest.NewRecorder()
	accountEmailHandler(t, database, auditLogger, credentials, jobs).
		ServeHTTP(rr, accountEmailPut(t, api.UpdateAccountEmailRequest{
			Email: "  New@Example.COM ", CurrentPassword: accountEmailTestPassword}))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var resp api.UpdateUserResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.Equal(t, "new@example.com", resp.User.Email)
	require.False(t, resp.User.EmailVerified, "the new address has not been verified")
	require.NotNil(t, resp.User.UpdatedAt, "the response still reports when the row changed")
	assert.Equal(t, 0, credentials.failures, "the right password spends nothing")
	database.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything, mock.Anything)
	assert.Len(t, jobs.jobs, 1, "the notice to the previous address waits for after the response")
}

func TestHandleAccountEmailPut_ALostRaceForTheAddressAnswers409(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)
	jobs := &heldJobs{}
	stubAccountEmailUpdate(t, database, uniqueViolationOnUpdate)

	rr := httptest.NewRecorder()
	accountEmailHandler(t, database, auditLogger, unlimitedCredentials{}, jobs).
		ServeHTTP(rr, accountEmailPutRequest(t))

	requireEmailTaken(t, rr)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	assert.Empty(t, jobs.jobs, "a change that lost the race tells nobody it happened")
}

func TestHandleAccountEmailPut_AnyOtherWriteFailureAnswers500(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)
	jobs := &heldJobs{}
	stubAccountEmailUpdate(t, database, errs.New("the connection was reset"))

	rr := httptest.NewRecorder()
	accountEmailHandler(t, database, auditLogger, unlimitedCredentials{}, jobs).
		ServeHTTP(rr, accountEmailPutRequest(t))

	require.Equal(t, http.StatusInternalServerError, rr.Code)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	assert.Empty(t, jobs.jobs, "a change that was not saved tells nobody it happened")
}

// TestHandleAccountEmailPut_ABlankCurrentPasswordIsRefusedAndChargesNothing is #404 decision
// 3: a request carrying no password is refused 400 VALIDATION_ERROR before the account is read,
// and spends nothing of the budget, since no password was compared (#219). The mock database has
// no expectations, so a read or a write fails the case.
func TestHandleAccountEmailPut_ABlankCurrentPasswordIsRefusedAndChargesNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		body any
	}{
		{"absent", map[string]string{"email": "new@example.com"}},
		{"empty", api.UpdateAccountEmailRequest{Email: "new@example.com", CurrentPassword: ""}},
		{"whitespace", api.UpdateAccountEmailRequest{Email: "new@example.com", CurrentPassword: "   "}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_handlers.NewAuditLogger(t)
			jobs := &heldJobs{}
			credentials := &countingCredentials{}

			rr := httptest.NewRecorder()
			accountEmailHandler(t, database, auditLogger, credentials, jobs).
				ServeHTTP(rr, accountEmailPut(t, tc.body))

			require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
			assert.Equal(t, "VALIDATION_ERROR", errorCodeOf(t, rr))
			assert.Equal(t, "Current password is required.", descriptionOf(t, rr))
			assert.Equal(t, 0, credentials.failures, "no password was compared, so nothing is charged")
			database.AssertNotCalled(t, "TrySetUserEmail", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
			assert.Empty(t, jobs.jobs, "a refused change sends no notice")
		})
	}
}

// TestHandleAccountEmailPut_AWrongPasswordIsRefusedBeforeTheAddressIsLookedAt is #404
// decision 3: a wrong password is refused 400 AUTHENTICATION_FAILED and charged exactly once,
// and it is checked before the address, so a caller without the password learns nothing about
// the address: whether another account holds it, whether it is well formed, or whether it is the
// account's own. Nothing beyond the caller's own row is read (GetUserByEmail has no expectation),
// and nothing is written.
func TestHandleAccountEmailPut_AWrongPasswordIsRefusedBeforeTheAddressIsLookedAt(t *testing.T) {
	for _, tc := range []struct {
		name    string
		address string
	}{
		{"an address another account holds", emailTestAddress},
		{"a malformed address", "not-an-address"},
		{"a blank address", ""},
		{"the account's own address", "old@example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_handlers.NewAuditLogger(t)
			jobs := &heldJobs{}
			database.On("GetUserBySubject", mock.Anything, mock.Anything, emailTestSubject).
				Return(&models.User{Id: emailTestUserId, Subject: emailTestSubject, Email: "old@example.com",
					PasswordHash: accountEmailTestPasswordHash(t)}, nil).Once()
			credentials := &countingCredentials{}

			rr := httptest.NewRecorder()
			accountEmailHandler(t, database, auditLogger, credentials, jobs).
				ServeHTTP(rr, accountEmailPut(t, api.UpdateAccountEmailRequest{
					Email: tc.address, CurrentPassword: "wrong-password"}))

			require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
			assert.Equal(t, "AUTHENTICATION_FAILED", errorCodeOf(t, rr))
			assert.Equal(t, "Authentication failed. Check your current password and try again.", descriptionOf(t, rr))
			assert.Equal(t, 1, credentials.failures, "a wrong password is charged exactly once")
			database.AssertNotCalled(t, "TrySetUserEmail", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
			assert.Empty(t, jobs.jobs, "a refused change sends no notice")
		})
	}
}

// TestHandleAccountEmailPut_ResubmittingTheCurrentAddressChangesNothing is #404 decision 10:
// the address the account already has, trimmed and lowercased as the handler normalizes it, is
// answered 200 with the user as stored. Nothing is written, so the verified flag and a pending
// verification code survive, and no audit event is logged. The validator is not consulted
// (GetUserByEmail has no expectation), so the account's own address is never refused as taken.
func TestHandleAccountEmailPut_ResubmittingTheCurrentAddressChangesNothing(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)
	jobs := &heldJobs{}
	database.On("GetUserBySubject", mock.Anything, mock.Anything, emailTestSubject).
		Return(&models.User{
			Id:                             emailTestUserId,
			Subject:                        emailTestSubject,
			Enabled:                        true,
			Email:                          "same@example.com",
			EmailVerified:                  true,
			EmailVerificationCodeEncrypted: []byte("pending-code"),
			EmailVerificationCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC(), Valid: true},
			PasswordHash:                   accountEmailTestPasswordHash(t),
		}, nil).Once()
	credentials := &countingCredentials{}

	rr := httptest.NewRecorder()
	accountEmailHandler(t, database, auditLogger, credentials, jobs).
		ServeHTTP(rr, accountEmailPut(t, api.UpdateAccountEmailRequest{
			Email: "  Same@Example.COM ", CurrentPassword: accountEmailTestPassword}))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var resp api.UpdateUserResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, emailTestUserId, resp.User.Id)
	assert.Equal(t, "same@example.com", resp.User.Email)
	assert.True(t, resp.User.EmailVerified, "re-saving the address keeps it verified")
	assert.Equal(t, 0, credentials.failures)
	database.AssertNotCalled(t, "TrySetUserEmail", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything, mock.Anything)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	assert.Empty(t, jobs.jobs, "a change that did not happen sends no notice, with SMTP on")
}

// changingUser is the caller's row as the handler loads it for a change from old@example.com to
// new@example.com, in the given locale.
func changingUser(t *testing.T, locale string) *models.User {
	t.Helper()
	return &models.User{
		Id:            emailTestUserId,
		Subject:       emailTestSubject,
		Enabled:       true,
		GivenName:     "Ana",
		FamilyName:    "Silva",
		Locale:        locale,
		Email:         "old@example.com",
		EmailVerified: true,
		PasswordHash:  accountEmailTestPasswordHash(t),
	}
}

// stubSuccessfulChange answers a change from old@example.com to new@example.com: the reads, the
// narrow write, and the one updated_own_email entry. The audit expectation is the only one the
// logger has, so an entry the notice wrote of its own would fail the case.
func stubSuccessfulChange(t *testing.T, database *mocks_data.Database, auditLogger *mocks_handlers.AuditLogger, user *models.User) {
	t.Helper()
	database.On("GetUserBySubject", mock.Anything, mock.Anything, emailTestSubject).Return(user, nil).Twice()
	database.On("GetUserByEmail", mock.Anything, mock.Anything, "new@example.com").Return(nil, nil).Once()
	database.On("TrySetUserEmail", mock.Anything, (*sql.Tx)(nil), emailTestUserId, user.Email, user.EmailVerified, "new@example.com").
		Return(true, nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedOwnEmail, mock.Anything).Return().Once()
}

func changeToNewAddress(t *testing.T) *http.Request {
	t.Helper()
	return accountEmailPut(t, api.UpdateAccountEmailRequest{
		Email: "new@example.com", CurrentPassword: accountEmailTestPassword})
}

// TestHandleAccountEmailPut_TellsThePreviousAddressAfterTheResponse is #404 decisions 9 and
// 11: once the change is saved and answered, a job sends the previous address a notice, rendered
// in the user's stored locale with English as the fallback, whose subject is the catalog's and
// which names neither the new address nor carries a link. Nothing is sent before the response,
// and the job carries the request's id.
func TestHandleAccountEmailPut_TellsThePreviousAddressAfterTheResponse(t *testing.T) {
	for _, tc := range []struct {
		name          string
		locale        string
		renderLocale  string
		expectSubject string
	}{
		{"an English user", "en", "en", "Your email address was changed"},
		{"a Brazilian Portuguese user", "pt-BR", "pt-BR", "Seu endereço de e-mail foi alterado"},
		{"a user with no stored locale", "", "en", "Your email address was changed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_handlers.NewAuditLogger(t)
			pageRenderer := mocks_handlers.NewPageRenderer(t)
			emailSender := mocks_accounthandlers.NewEmailSender(t)
			jobs := &heldJobs{}
			stubSuccessfulChange(t, database, auditLogger, changingUser(t, tc.locale))

			rr := httptest.NewRecorder()
			accountEmailHandlerWith(database, auditLogger, &countingCredentials{}, jobs, pageRenderer, emailSender).
				ServeHTTP(rr, changeToNewAddress(t))

			// The renderer and the sender have no expectations yet, so a notice sent inside the
			// request would already have failed the case.
			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			var resp api.UpdateUserResponse
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
			require.Equal(t, "new@example.com", resp.User.Email)

			var renderLocale string
			var bound map[string]interface{}
			pageRenderer.On("RenderTemplateToBuffer", mock.Anything, "/layouts/email_layout.html",
				"/emails/email_address_changed.html", mock.Anything).
				Run(func(args mock.Arguments) {
					renderLocale = i18n.LocaleTag(args.Get(0).(*http.Request).Context())
					bound = args.Get(3).(map[string]interface{})
				}).Return(bytes.NewBufferString("<p>rendered notice</p>"), nil).Once()
			var sendCtx context.Context
			var sent *emaildelivery.SendEmailInput
			emailSender.On("SendEmail", mock.Anything,
				emaildelivery.SMTPConfig{Host: "smtp.example.com", Port: 587, FromEmail: "noreply@example.com"},
				mock.Anything).
				Run(func(args mock.Arguments) {
					sendCtx = args.Get(0).(context.Context)
					sent = args.Get(2).(*emaildelivery.SendEmailInput)
				}).Return(nil).Once()

			jobs.runAll(t)

			require.NotNil(t, sent)
			assert.Equal(t, "old@example.com", sent.To, "the notice goes to the address the account had")
			assert.Equal(t, tc.expectSubject, sent.Subject)
			assert.Equal(t, "<p>rendered notice</p>", sent.HtmlBody)
			assert.Equal(t, tc.renderLocale, renderLocale, "the notice is rendered in the user's locale")
			assert.Equal(t, "Ana Silva", bound["name"])
			assert.NotContains(t, bound, "link", "the notice carries no link")
			for key, value := range bound {
				assert.NotContains(t, strings.ToLower(fmt.Sprint(value)), "new@example.com",
					"the notice must not name the new address, found under %q", key)
			}
			assert.Equal(t, accountEmailRequestId, chimiddleware.GetReqID(sendCtx),
				"the job's records carry the request's id")
		})
	}
}

// TestHandleAccountEmailPut_SendsNoNoticeWithSMTPOff is #404 decision 11: with SMTP disabled
// the change is saved and answered, and nothing is left to run after it.
func TestHandleAccountEmailPut_SendsNoNoticeWithSMTPOff(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)
	jobs := &heldJobs{}
	stubSuccessfulChange(t, database, auditLogger, changingUser(t, "en"))

	req := changeToNewAddress(t)
	settings := accountEmailSettings()
	settings.SMTPEnabled = false
	req = req.WithContext(reqctx.WithSettings(req.Context(), settings))

	rr := httptest.NewRecorder()
	accountEmailHandler(t, database, auditLogger, &countingCredentials{}, jobs).ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Empty(t, jobs.jobs, "with SMTP off there is no notice to send")
}

// TestHandleAccountEmailPut_AChangeThatLostTheRowAnswers409AndTellsNobody is the notice's
// bound under concurrency (#404). The write is conditional on the address and the verified flag
// the request read, so of concurrent changes from one read only one matches the row. Each of the
// others writes nothing, answers 409 CONCURRENT_UPDATE, audits nothing and queues no notice: with
// an unconditional write every one of them notified the previous address, so one verification
// bought as many mails as requests sent at once.
func TestHandleAccountEmailPut_AChangeThatLostTheRowAnswers409AndTellsNobody(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)
	jobs := &heldJobs{}
	user := changingUser(t, "en")
	database.On("GetUserBySubject", mock.Anything, mock.Anything, emailTestSubject).Return(user, nil).Twice()
	database.On("GetUserByEmail", mock.Anything, mock.Anything, "new@example.com").Return(nil, nil).Once()
	database.On("TrySetUserEmail", mock.Anything, (*sql.Tx)(nil), emailTestUserId, "old@example.com", true, "new@example.com").
		Return(false, nil).Once()
	credentials := &countingCredentials{}

	rr := httptest.NewRecorder()
	accountEmailHandler(t, database, auditLogger, credentials, jobs).ServeHTTP(rr, changeToNewAddress(t))

	require.Equal(t, http.StatusConflict, rr.Code, rr.Body.String())
	var body map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, "CONCURRENT_UPDATE", body["error_code"])
	assert.Empty(t, jobs.jobs, "a change that was not made notifies nobody")
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	assert.Equal(t, 0, credentials.failures, "the password was right; losing the row is not a failure")
}

// TestHandleAccountEmailPut_SendsNoNoticeToAnUnverifiedAddress is the notice's bound: an
// address the account never verified is told nothing, because a caller may set any address they
// do not hold and change away from it again, which would otherwise mail that address once per
// request. The change itself is saved and answered as any other.
func TestHandleAccountEmailPut_SendsNoNoticeToAnUnverifiedAddress(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)
	jobs := &heldJobs{}
	user := changingUser(t, "en")
	user.EmailVerified = false
	stubSuccessfulChange(t, database, auditLogger, user)

	rr := httptest.NewRecorder()
	accountEmailHandler(t, database, auditLogger, &countingCredentials{}, jobs).ServeHTTP(rr, changeToNewAddress(t))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var resp api.UpdateUserResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, "new@example.com", resp.User.Email)
	assert.Empty(t, jobs.jobs, "an unverified previous address is sent no notice")
}

// TestHandleAccountEmailPut_AFailedNoticeIsAnErrorRecordAndNothingElse is #404 decision 11: a
// notice that cannot be rendered or sent never fails or undoes the change, which was answered 200
// before the job ran. It is one Error record on the request's id, and no audit entry of its own.
func TestHandleAccountEmailPut_AFailedNoticeIsAnErrorRecordAndNothingElse(t *testing.T) {
	for _, tc := range []struct {
		name      string
		renderErr error
		sendErr   error
	}{
		{"the render fails", assert.AnError, nil},
		{"the send fails", nil, assert.AnError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			capture := logtest.CaptureSlog(t)
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_handlers.NewAuditLogger(t)
			pageRenderer := mocks_handlers.NewPageRenderer(t)
			emailSender := mocks_accounthandlers.NewEmailSender(t)
			jobs := &heldJobs{}
			stubSuccessfulChange(t, database, auditLogger, changingUser(t, "en"))

			rr := httptest.NewRecorder()
			accountEmailHandlerWith(database, auditLogger, &countingCredentials{}, jobs, pageRenderer, emailSender).
				ServeHTTP(rr, changeToNewAddress(t))
			require.Equal(t, http.StatusOK, rr.Code, "the change is answered before the notice is attempted")

			if tc.renderErr != nil {
				pageRenderer.On("RenderTemplateToBuffer", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil, tc.renderErr).Once()
			} else {
				pageRenderer.On("RenderTemplateToBuffer", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(&bytes.Buffer{}, nil).Once()
				emailSender.On("SendEmail", mock.Anything, mock.Anything, mock.Anything).Return(tc.sendErr).Once()
			}
			jobs.runAll(t)

			records := capture.Records()
			require.Len(t, records, 1, capture.Text())
			assert.Equal(t, slog.LevelError, records[0].Level)
			assert.Equal(t, accountEmailRequestId, records[0].Attrs["request_id"])
			assert.Equal(t, emailTestUserId, records[0].Attrs["user_id"])
			assert.NotNil(t, records[0].Attrs["error"])
			if tc.renderErr != nil {
				emailSender.AssertNotCalled(t, "SendEmail", mock.Anything, mock.Anything, mock.Anything)
			}
		})
	}
}
