package accounthandlers

import (
	"bytes"
	"database/sql"
	"github.com/leodip/goiabada/authserver/internal/afterresponse"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/usercreation"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// A pending registration can complete until 10 minutes after its link was sent: the code's
// 5-minute lifetime, then the marker's fresh 5-minute window for the password form. Past that it
// is dead, and every reader treats it as absent (#207 decision 6). These tests place a row on
// either side of that line with a margin the test cannot cross while it runs.

// pendingRegistrationLifetime is the 10 minutes #207 decision 6 sets, written here as a literal
// rather than read from the code under test.
const pendingRegistrationLifetime = 10 * time.Minute

// deadRegistrationCode is the code a dead pending registration was issued with.
const deadRegistrationCode = "dead-code-0123456789abcdefghijklm"

// pendingRegistrationIssuedAgo is a pending registration for registerSomeoneEmail whose link was
// sent the given time ago.
func pendingRegistrationIssuedAgo(age time.Duration) *record.PreRegistration {
	return &record.PreRegistration{
		Id:                       42,
		Email:                    registerSomeoneEmail,
		VerificationCodeHash:     hashutil.HashString(deadRegistrationCode),
		VerificationCodeIssuedAt: sql.NullTime{Time: time.Now().UTC().Add(-age), Valid: true},
	}
}

// A row that can still complete is never replaced: inside the code's lifetime, after it while the
// marker's window may still be open, and just inside the 10 minutes. Replacing once the code alone
// has expired would change the code under a form already on screen (#207 decision 6).
func TestHandleRegisterPost_WithVerificationARowThatCanStillCompleteIsLeftAlone(t *testing.T) {
	for _, tc := range []struct {
		name string
		age  time.Duration
	}{
		{name: "its code still live", age: time.Minute},
		{name: "its code expired, the password form possibly still open", age: 6 * time.Minute},
		{name: "just inside the 10 minutes", age: pendingRegistrationLifetime - 30*time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRegisterHarness(t)
			req := registrationRequest(registerSomeoneEmail)
			rr := httptest.NewRecorder()

			h.expectLookups(registerSomeoneEmail, nil, pendingRegistrationIssuedAgo(tc.age))
			h.expectCheckEmailPage(rr, req)
			details, _ := captureRequestedRegistration(h.auditLogger, nil)

			h.handler.ServeHTTP(rr, req)
			h.jobs.runAll(t, afterresponse.ClassRegistration)

			assert.Equal(t, map[string]interface{}{
				"ip":                  testClientIP,
				"email_digest":        someoneDigest,
				"pre_registration_id": int64(42),
				"outcome":             "link_pending",
			}, *details)
			h.database.AssertNotCalled(t, "TryReplacePreRegistrationCode", mock.Anything, mock.Anything,
				mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			h.assertNothingWrittenOrSent(t)
		})
	}
}

// A dead row is replaced with a fresh code, by a write conditional on the row still holding the
// dead code, and a new link is mailed: link_issued, naming the row it replaced.
func TestHandleRegisterPost_WithVerificationADeadRowIsReplacedWithAFreshLink(t *testing.T) {
	h := newRegisterHarness(t)
	req := registrationRequest(registerSomeoneEmail)
	rr := httptest.NewRecorder()

	dead := pendingRegistrationIssuedAgo(pendingRegistrationLifetime + 30*time.Second)
	h.expectLookups(registerSomeoneEmail, nil, dead)
	h.expectCheckEmailPage(rr, req)

	order := []string{}
	var codeEncrypted []byte
	var codeHash string
	var issuedAt time.Time
	before := time.Now().UTC()
	h.database.On("TryReplacePreRegistrationCode", mock.Anything, (*sql.Tx)(nil), int64(42),
		hashutil.HashString(deadRegistrationCode), mock.AnythingOfType("[]uint8"), mock.AnythingOfType("string"),
		mock.AnythingOfType("time.Time")).
		Run(func(args mock.Arguments) {
			codeEncrypted = args.Get(4).([]byte)
			codeHash = args.Get(5).(string)
			issuedAt = args.Get(6).(time.Time)
			order = append(order, "replace")
		}).Return(true, nil).Once()
	details, _ := captureRequestedRegistration(h.auditLogger, &order)

	var mailBind map[string]interface{}
	h.pageRenderer.On("RenderTemplateToBuffer", mock.Anything, "/layouts/email_layout.html",
		"/emails/email_register_activate.html", mock.Anything).
		Run(func(args mock.Arguments) { mailBind = args.Get(3).(map[string]interface{}) }).
		Return(bytes.NewBufferString("activation mail"), nil).Once()
	var sent *emaildelivery.SendEmailInput
	h.emailSender.On("SendEmail", mock.Anything, emaildelivery.SMTPConfig{Host: "smtp.example.com"}, mock.Anything).
		Run(func(args mock.Arguments) {
			sent = args.Get(2).(*emaildelivery.SendEmailInput)
			order = append(order, "send")
		}).Return(nil).Once()

	h.handler.ServeHTTP(rr, req)
	assert.Empty(t, order, "the row is replaced after the response")
	h.jobs.runAll(t, afterresponse.ClassRegistration)

	code, err := testDataCipher.Decrypt(codeEncrypted)
	require.NoError(t, err)
	assert.Len(t, code, 32)
	assert.NotEqual(t, deadRegistrationCode, code, "the code is a fresh one")
	assert.Equal(t, hashutil.HashString(code), codeHash, "the stored hash is of the code that was issued")
	assert.False(t, issuedAt.Before(before), "the fresh code is issued now, so the row can complete again")

	assert.Equal(t, map[string]interface{}{
		"ip":                  testClientIP,
		"email_digest":        someoneDigest,
		"pre_registration_id": int64(42),
		"outcome":             "link_issued",
	}, *details)
	assert.Equal(t, []string{"replace", "audit", "send"}, order,
		"the record is written once the row is replaced, and before the mail is sent")
	assert.Equal(t, testBaseURL+"/account/activate?code="+code, mailBind["link"])
	require.NotNil(t, sent)
	assert.Equal(t, registerSomeoneEmail, sent.To)
	h.database.AssertNotCalled(t, "CreatePreRegistration", mock.Anything, mock.Anything, mock.Anything)
	h.userCreator.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything)
}

// A replacement the conditional write declines, because a concurrent repeat replaced the row
// first or it was consumed meanwhile, sends nothing and is recorded as replacement_lost: of two
// concurrent repeats exactly one sends a link (#207 decisions 6 and 8).
func TestHandleRegisterPost_WithVerificationALostReplacementSendsNothing(t *testing.T) {
	h := newRegisterHarness(t)
	req := registrationRequest(registerSomeoneEmail)
	rr := httptest.NewRecorder()

	h.expectLookups(registerSomeoneEmail, nil, pendingRegistrationIssuedAgo(pendingRegistrationLifetime+30*time.Second))
	h.expectCheckEmailPage(rr, req)
	h.database.On("TryReplacePreRegistrationCode", mock.Anything, (*sql.Tx)(nil), int64(42),
		hashutil.HashString(deadRegistrationCode), mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Once()
	details, _ := captureRequestedRegistration(h.auditLogger, nil)

	h.handler.ServeHTTP(rr, req)
	h.jobs.runAll(t, afterresponse.ClassRegistration)

	assert.Equal(t, map[string]interface{}{
		"ip":                  testClientIP,
		"email_digest":        someoneDigest,
		"pre_registration_id": int64(42),
		"outcome":             "replacement_lost",
	}, *details)
	h.assertNothingWrittenOrSent(t)
}

// A replacement that fails is the server's fault: one server_error record naming the row it found,
// one Error line on the request id, and nothing sent.
func TestHandleRegisterPost_WithVerificationAFailedReplacementIsAServerError(t *testing.T) {
	capture := logtest.CaptureSlog(t)
	h := newRegisterHarness(t)
	req := registrationRequest(registerSomeoneEmail)
	rr := httptest.NewRecorder()

	h.expectLookups(registerSomeoneEmail, nil, pendingRegistrationIssuedAgo(pendingRegistrationLifetime+30*time.Second))
	h.expectCheckEmailPage(rr, req)
	h.database.On("TryReplacePreRegistrationCode", mock.Anything, (*sql.Tx)(nil), int64(42),
		hashutil.HashString(deadRegistrationCode), mock.Anything, mock.Anything, mock.Anything).
		Return(false, assert.AnError).Once()
	details, _ := captureRequestedRegistration(h.auditLogger, nil)

	h.handler.ServeHTTP(rr, req)
	h.jobs.runAll(t, afterresponse.ClassRegistration)

	assert.Equal(t, http.StatusOK, rr.Code, "the response has gone before the row is replaced")
	assert.Equal(t, map[string]interface{}{
		"ip":                  testClientIP,
		"email_digest":        someoneDigest,
		"pre_registration_id": int64(42),
		"outcome":             "server_error",
	}, *details)
	h.assertNothingWrittenOrSent(t)
	assertOneErrorRecordOnRegistration(t, capture)
}

// Without verification a pending registration that can still complete keeps the address taken, as
// it always has, and a dead one is treated as absent: the account is created (#207 decisions 3
// and 6).
func TestHandleRegisterPost_WithoutVerificationADeadPendingRegistrationIsAbsent(t *testing.T) {
	newHandler := func(t *testing.T) (http.HandlerFunc, *handlersmocks.PageRenderer, *datamocks.Database,
		*accounthandlersmocks.UserCreator, *accounthandlersmocks.EmailValidator, *accounthandlersmocks.PasswordValidator,
		*handlersmocks.AuditLogger) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		userCreator := accounthandlersmocks.NewUserCreator(t)
		emailValidator := accounthandlersmocks.NewEmailValidator(t)
		passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator,
			accounthandlersmocks.NewEmailSender(t), auditLogger, &heldJobs{}, testDataCipher, testBaseURL,
			testAdminConsoleBaseURL)
		return handler, pageRenderer, database, userCreator, emailValidator, passwordValidator, auditLogger
	}
	newRequest := func() *http.Request {
		form := url.Values{"email": {registerSomeoneEmail}, "password": {"Str0ngP4ss!"}, "passwordConfirmation": {"Str0ngP4ss!"}}
		req := httptest.NewRequest(http.MethodPost, "/account/register", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{SelfRegistrationEnabled: true}))
	}

	t.Run("just inside the 10 minutes, the address is still taken", func(t *testing.T) {
		handler, pageRenderer, database, userCreator, emailValidator, _, _ := newHandler(t)
		req := newRequest()
		rr := httptest.NewRecorder()

		emailValidator.On("ValidateEmailAddress", registerSomeoneEmail).Return(nil).Once()
		database.On("GetUserByEmail", mock.Anything, (*sql.Tx)(nil), registerSomeoneEmail).Return(nil, nil).Once()
		database.On("GetPreRegistrationByEmail", mock.Anything, (*sql.Tx)(nil), registerSomeoneEmail).
			Return(pendingRegistrationIssuedAgo(pendingRegistrationLifetime-30*time.Second), nil).Once()
		var bound map[string]interface{}
		pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).
			Run(func(args mock.Arguments) { bound = args.Get(4).(map[string]interface{}) }).Return(nil).Once()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, "Apologies, but this email address is already registered.", bound["error"])
		userCreator.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything)
	})

	t.Run("past the 10 minutes, the account is created", func(t *testing.T) {
		handler, pageRenderer, database, userCreator, emailValidator, passwordValidator, auditLogger := newHandler(t)
		req := newRequest()
		rr := httptest.NewRecorder()

		emailValidator.On("ValidateEmailAddress", registerSomeoneEmail).Return(nil).Once()
		database.On("GetUserByEmail", mock.Anything, (*sql.Tx)(nil), registerSomeoneEmail).Return(nil, nil).Once()
		database.On("GetPreRegistrationByEmail", mock.Anything, (*sql.Tx)(nil), registerSomeoneEmail).
			Return(pendingRegistrationIssuedAgo(pendingRegistrationLifetime+30*time.Second), nil).Once()
		passwordValidator.On("ValidatePassword", mock.Anything, "Str0ngP4ss!").Return(nil).Once()
		var input *usercreation.Input
		userCreator.On("CreateUser", mock.Anything, mock.AnythingOfType("*usercreation.Input")).
			Run(func(args mock.Arguments) { input = args.Get(1).(*usercreation.Input) }).
			Return(&record.User{Id: 9, Email: registerSomeoneEmail}, nil).Once()
		auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Return().Once()
		pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register_success.html", mock.Anything).
			Return(nil).Once()

		handler.ServeHTTP(rr, req)

		require.NotNil(t, input, "a dead pending registration does not keep the address taken")
		assert.Equal(t, registerSomeoneEmail, input.Email)
		assert.False(t, input.EmailVerified)
	})
}
