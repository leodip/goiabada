package accounthandlers

import (
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Registration with email verification answers every well-formed address alike (#207 decisions
// 4, 5 and 8): the format and length checks and both lookups before the answer, then the one
// "check your email" page, and everything that depends on what the lookups found in the job after
// it. These tests drive that seam the way the forgot-password tests drive theirs: the job is held,
// what the request did before its response is asserted, then the job is run and what it did is.

// registerRequestId is the request id registrationRequest carries, as chi's RequestID middleware
// puts one on every request.
const registerRequestId = "req-register-0001"

// registerSomeoneEmail is the address most of these tests register, whose digest is
// someoneDigest.
const registerSomeoneEmail = "someone@example.com"

// checkEmailPage is the one page every well-formed registration with verification is answered
// with, whatever the address is.
const checkEmailPage = "/account_register_check_email.html"

// verificationSettings is registration with verification: self-registration on, SMTP on and
// "requires email verification" on.
func verificationSettings() *record.Settings {
	return &record.Settings{
		AppName:                 "TestApp",
		SelfRegistrationEnabled: true,
		SMTPEnabled:             true,
		SMTPHost:                "smtp.example.com",
		SelfRegistrationRequiresEmailVerification: true,
	}
}

// registrationRequest is a submission of the register form with verification for an address,
// carrying the settings and a request id. A password submitted anyway is in the body, so a test
// shows it is ignored.
func registrationRequest(email string) *http.Request {
	form := url.Values{"email": {email}, "password": {"Str0ngP4ss!"}, "passwordConfirmation": {"Str0ngP4ss!"}}
	req := httptest.NewRequest(http.MethodPost, "/account/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := context.WithValue(req.Context(), chimiddleware.RequestIDKey, registerRequestId)
	return req.WithContext(reqctx.WithSettings(ctx, verificationSettings()))
}

// registerHarness is the handler with verification and every port it takes.
type registerHarness struct {
	pageRenderer      *handlersmocks.PageRenderer
	database          *datamocks.Database
	userCreator       *accounthandlersmocks.UserCreator
	emailValidator    *accounthandlersmocks.EmailValidator
	passwordValidator *accounthandlersmocks.PasswordValidator
	emailSender       *accounthandlersmocks.EmailSender
	auditLogger       *handlersmocks.AuditLogger
	jobs              *heldJobs
	handler           http.HandlerFunc
}

func newRegisterHarness(t *testing.T) *registerHarness {
	h := &registerHarness{
		pageRenderer:      handlersmocks.NewPageRenderer(t),
		database:          datamocks.NewDatabase(t),
		userCreator:       accounthandlersmocks.NewUserCreator(t),
		emailValidator:    accounthandlersmocks.NewEmailValidator(t),
		passwordValidator: accounthandlersmocks.NewPasswordValidator(t),
		emailSender:       accounthandlersmocks.NewEmailSender(t),
		auditLogger:       handlersmocks.NewAuditLogger(t),
		jobs:              &heldJobs{},
	}
	h.handler = HandleRegisterPost(h.pageRenderer, h.database, h.userCreator, h.emailValidator,
		h.passwordValidator, h.emailSender, h.auditLogger, h.jobs, testDataCipher, testBaseURL,
		testAdminConsoleBaseURL)
	return h
}

// expectLookups answers both lookups for an address, once each.
func (h *registerHarness) expectLookups(email string, user *record.User, preRegistration *record.PreRegistration) {
	h.emailValidator.On("ValidateEmailAddress", email).Return(nil).Once()
	h.database.On("GetUserByEmail", mock.Anything, (*sql.Tx)(nil), email).Return(user, nil).Once()
	h.database.On("GetPreRegistrationByEmail", mock.Anything, (*sql.Tx)(nil), email).Return(preRegistration, nil).Once()
}

// expectCheckEmailPage expects the one page and hands back what it was bound with.
func (h *registerHarness) expectCheckEmailPage(rr *httptest.ResponseRecorder, req *http.Request) *map[string]interface{} {
	bound := map[string]interface{}{}
	h.pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", checkEmailPage, mock.Anything).
		Run(func(args mock.Arguments) {
			bound = args.Get(4).(map[string]interface{})
		}).Return(nil).Once()
	return &bound
}

// assertNothingWrittenOrSent holds a request to having created no account and no pending
// registration, and rendered and sent no mail.
func (h *registerHarness) assertNothingWrittenOrSent(t *testing.T) {
	t.Helper()
	h.database.AssertNotCalled(t, "CreatePreRegistration", mock.Anything, mock.Anything, mock.Anything)
	h.userCreator.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything)
	h.pageRenderer.AssertNotCalled(t, "RenderTemplateToBuffer", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	h.emailSender.AssertNotCalled(t, "SendEmail", mock.Anything, mock.Anything, mock.Anything)
}

// captureRequestedRegistration requires exactly one requested_registration record and hands back
// its payload and the context it was written under, so a test compares the whole map.
func captureRequestedRegistration(auditLogger *handlersmocks.AuditLogger, order *[]string) (*map[string]interface{}, *context.Context) {
	details := map[string]interface{}{}
	var auditCtx context.Context
	auditLogger.On("Log", mock.Anything, audit.EventRequestedRegistration, mock.Anything).
		Run(func(args mock.Arguments) {
			auditCtx = args.Get(0).(context.Context)
			details = args.Get(2).(map[string]interface{})
			if order != nil {
				*order = append(*order, "audit")
			}
		}).Return().Once()
	return &details, &auditCtx
}

// The accounts and pending registrations an address can lead to. Every one gets the same page,
// bound with the same values, after the same two lookups, and nothing of what decides between
// them runs before the response.
func registrationAddressCases() []struct {
	name            string
	user            *record.User
	preRegistration *record.PreRegistration
} {
	return []struct {
		name            string
		user            *record.User
		preRegistration *record.PreRegistration
	}{
		{name: "an address with no account and nothing pending"},
		{name: "a verified, enabled account",
			user: &record.User{Id: 7, Enabled: true, EmailVerified: true, Email: registerSomeoneEmail}},
		{name: "an unverified account",
			user: &record.User{Id: 7, Enabled: true, Email: registerSomeoneEmail}},
		{name: "a disabled account",
			user: &record.User{Id: 7, Enabled: false, EmailVerified: true, Email: registerSomeoneEmail}},
		{name: "a pending registration",
			preRegistration: pendingRegistrationIssuedAgo(time.Minute)},
	}
}

func TestHandleRegisterPost_WithVerificationAnswersAfterBothLookupsAlone(t *testing.T) {
	for _, tc := range registrationAddressCases() {
		t.Run(tc.name, func(t *testing.T) {
			h := newRegisterHarness(t)
			// Submitted with a capital and surrounding spaces: the page names the address as
			// it was looked up.
			req := registrationRequest("  Someone@Example.com ")
			rr := httptest.NewRecorder()

			h.expectLookups(registerSomeoneEmail, tc.user, tc.preRegistration)
			bound := h.expectCheckEmailPage(rr, req)

			h.handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, map[string]interface{}{"email": registerSomeoneEmail}, *bound,
				"every address is answered with the same page, bound with the same values")
			h.database.AssertExpectations(t)
			h.pageRenderer.AssertExpectations(t)

			h.assertNothingWrittenOrSent(t)
			h.passwordValidator.AssertNotCalled(t, "ValidatePassword", mock.Anything, mock.Anything)
			h.auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)

			require.Len(t, h.jobs.jobs, 1, "the rest is handed to one job")
			assert.Equal(t, registerRequestId, h.jobs.ctxs[0].Value(chimiddleware.RequestIDKey),
				"the job is handed the request's context, so what it records joins the request")
		})
	}
}

// The job's decision for each case, and the one record it leaves. Only a new address is given a
// pending registration and a link, and only a verified, enabled account a notice; every other
// account and a pending address are sent nothing (#207 decisions 4, 5 and 8).
func TestHandleRegisterPost_WithVerificationTheJobSendsNothingButALinkOrANotice(t *testing.T) {
	for _, tc := range []struct {
		name            string
		user            *record.User
		preRegistration *record.PreRegistration
		wantDetails     map[string]interface{}
	}{
		{
			name: "an unverified account",
			user: &record.User{Id: 7, Enabled: true, Email: registerSomeoneEmail},
			wantDetails: map[string]interface{}{"ip": testClientIP, "emailDigest": someoneDigest,
				"userId": int64(7), "outcome": "unverified_address"},
		},
		{
			name: "a disabled account with a verified address",
			user: &record.User{Id: 7, Enabled: false, EmailVerified: true, Email: registerSomeoneEmail},
			wantDetails: map[string]interface{}{"ip": testClientIP, "emailDigest": someoneDigest,
				"userId": int64(7), "outcome": "account_disabled"},
		},
		{
			name: "a disabled account with an unverified address",
			user: &record.User{Id: 7, Enabled: false, Email: registerSomeoneEmail},
			wantDetails: map[string]interface{}{"ip": testClientIP, "emailDigest": someoneDigest,
				"userId": int64(7), "outcome": "account_disabled"},
		},
		{
			name:            "a pending registration",
			preRegistration: pendingRegistrationIssuedAgo(time.Minute),
			wantDetails: map[string]interface{}{"ip": testClientIP, "emailDigest": someoneDigest,
				"preRegistrationId": int64(42), "outcome": "link_pending"},
		},
		{
			// The account decides, and the pending registration found beside it is named.
			name:            "an unverified account with a pending registration beside it",
			user:            &record.User{Id: 7, Enabled: true, Email: registerSomeoneEmail},
			preRegistration: pendingRegistrationIssuedAgo(time.Minute),
			wantDetails: map[string]interface{}{"ip": testClientIP, "emailDigest": someoneDigest,
				"userId": int64(7), "preRegistrationId": int64(42), "outcome": "unverified_address"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRegisterHarness(t)
			req := registrationRequest(registerSomeoneEmail)
			rr := httptest.NewRecorder()

			h.expectLookups(registerSomeoneEmail, tc.user, tc.preRegistration)
			h.expectCheckEmailPage(rr, req)
			details, auditCtx := captureRequestedRegistration(h.auditLogger, nil)

			h.handler.ServeHTTP(rr, req)
			h.jobs.runAll(t)

			assert.Equal(t, tc.wantDetails, *details)
			assert.Equal(t, registerRequestId, (*auditCtx).Value(chimiddleware.RequestIDKey),
				"the record is written under the job's context, which carries the request's id")
			h.assertNothingWrittenOrSent(t)
		})
	}
}

func TestHandleRegisterPost_WithVerificationANewAddressIsGivenAPendingRegistrationAndALink(t *testing.T) {
	h := newRegisterHarness(t)
	req := registrationRequest(registerSomeoneEmail)
	// The registrant's locale: the activation mail is rendered in it, since the address has no
	// account and so no stored locale.
	req = req.WithContext(i18n.WithLocale(req.Context(), true, "pt-BR"))
	rr := httptest.NewRecorder()

	h.expectLookups(registerSomeoneEmail, nil, nil)
	h.expectCheckEmailPage(rr, req)

	order := []string{}
	var created *record.PreRegistration
	h.database.On("CreatePreRegistration", mock.Anything, (*sql.Tx)(nil), mock.AnythingOfType("*record.PreRegistration")).
		Run(func(args mock.Arguments) {
			created = args.Get(2).(*record.PreRegistration)
			created.Id = 42
			order = append(order, "create")
		}).Return(nil).Once()
	details, _ := captureRequestedRegistration(h.auditLogger, &order)

	var mailBind map[string]interface{}
	var mailReq *http.Request
	h.pageRenderer.On("RenderTemplateToBuffer", mock.Anything, "/layouts/email_layout.html",
		"/emails/email_register_activate.html", mock.Anything).
		Run(func(args mock.Arguments) {
			mailReq = args.Get(0).(*http.Request)
			mailBind = args.Get(3).(map[string]interface{})
		}).Return(bytes.NewBufferString("activation mail"), nil).Once()
	var sent *emaildelivery.SendEmailInput
	h.emailSender.On("SendEmail", mock.Anything, emaildelivery.SMTPConfig{Host: "smtp.example.com"}, mock.Anything).
		Run(func(args mock.Arguments) {
			sent = args.Get(2).(*emaildelivery.SendEmailInput)
			order = append(order, "send")
		}).Return(nil).Once()

	h.handler.ServeHTTP(rr, req)
	assert.Nil(t, created, "the pending registration is written after the response")
	h.jobs.runAll(t)

	require.NotNil(t, created)
	assert.Equal(t, registerSomeoneEmail, created.Email)
	assert.True(t, created.VerificationCodeIssuedAt.Valid)
	code, err := testDataCipher.Decrypt(created.VerificationCodeEncrypted)
	require.NoError(t, err)
	assert.Len(t, code, 32)
	assert.Equal(t, hashutil.HashString(code), created.VerificationCodeHash,
		"the stored hash is of the code that was issued, which is how the link finds the row")

	assert.Equal(t, map[string]interface{}{
		"ip":                testClientIP,
		"emailDigest":       someoneDigest,
		"preRegistrationId": int64(42),
		"outcome":           "link_issued",
	}, *details)
	assert.Equal(t, []string{"create", "audit", "send"}, order,
		"the record is written once the row is, and before the mail is sent")

	assert.Equal(t, testBaseURL+"/account/activate?code="+code, mailBind["link"])
	assert.Equal(t, "pt-BR", i18n.LocaleTag(mailReq.Context()), "the mail is rendered in the registrant's locale")
	require.NotNil(t, sent)
	assert.Equal(t, registerSomeoneEmail, sent.To)
	assert.Equal(t, "Ative sua conta", sent.Subject)
	assert.Equal(t, "activation mail", sent.HtmlBody)
	h.userCreator.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything)
}

// A verified, enabled account is sent the notice: no code, a pointer to the forgot-password page,
// rendered in the account's stored locale and falling back to English (#207 decisions 5 and 13).
func TestHandleRegisterPost_WithVerificationAVerifiedEnabledAccountIsSentTheNotice(t *testing.T) {
	for _, tc := range []struct {
		name        string
		locale      string
		wantLocale  string
		wantSubject string
	}{
		{name: "in the account's stored locale", locale: "pt-BR", wantLocale: "pt-BR", wantSubject: "Você já tem uma conta"},
		{name: "in English when the account stores none", locale: "", wantLocale: "en", wantSubject: "You already have an account"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRegisterHarness(t)
			req := registrationRequest(registerSomeoneEmail)
			rr := httptest.NewRecorder()

			user := &record.User{Id: 7, Enabled: true, EmailVerified: true, Email: registerSomeoneEmail, Locale: tc.locale}
			h.expectLookups(registerSomeoneEmail, user, nil)
			h.expectCheckEmailPage(rr, req)

			order := []string{}
			details, _ := captureRequestedRegistration(h.auditLogger, &order)
			var mailBind map[string]interface{}
			var mailReq *http.Request
			h.pageRenderer.On("RenderTemplateToBuffer", mock.Anything, "/layouts/email_layout.html",
				"/emails/email_register_existing_account.html", mock.Anything).
				Run(func(args mock.Arguments) {
					mailReq = args.Get(0).(*http.Request)
					mailBind = args.Get(3).(map[string]interface{})
				}).Return(bytes.NewBufferString("notice"), nil).Once()
			var sent *emaildelivery.SendEmailInput
			h.emailSender.On("SendEmail", mock.Anything, emaildelivery.SMTPConfig{Host: "smtp.example.com"}, mock.Anything).
				Run(func(args mock.Arguments) {
					sent = args.Get(2).(*emaildelivery.SendEmailInput)
					order = append(order, "send")
				}).Return(nil).Once()

			h.handler.ServeHTTP(rr, req)
			h.jobs.runAll(t)

			assert.Equal(t, map[string]interface{}{
				"ip":          testClientIP,
				"emailDigest": someoneDigest,
				"userId":      int64(7),
				"outcome":     "notice_issued",
			}, *details)
			assert.Equal(t, []string{"audit", "send"}, order, "the record is written before the mail is sent")

			assert.Equal(t, map[string]interface{}{"link": testBaseURL + "/forgot-password"}, mailBind,
				"the notice carries the forgot-password page and no code")
			assert.Equal(t, tc.wantLocale, i18n.LocaleTag(mailReq.Context()))
			require.NotNil(t, sent)
			assert.Equal(t, registerSomeoneEmail, sent.To)
			assert.Equal(t, tc.wantSubject, sent.Subject)
			assert.Equal(t, "notice", sent.HtmlBody)

			h.database.AssertNotCalled(t, "CreatePreRegistration", mock.Anything, mock.Anything, mock.Anything)
			h.userCreator.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything)
		})
	}
}

// A malformed address, or one over 60 characters, redraws the form at once, as it always has, and
// is recorded as invalid_address with the digest of the address as submitted, lowercased and
// trimmed. It looks nothing up and leaves nothing for after the response (#207 decisions 8 and 11).
func TestHandleRegisterPost_WithVerificationAnInvalidAddressIsRecordedAndRedrawn(t *testing.T) {
	for _, tc := range []struct {
		name       string
		submitted  string
		normalized string
		validator  error
		wantError  string
		wantDigest string
	}{
		{name: "no address", submitted: "", normalized: "",
			wantError: "Email is required.", wantDigest: emptyAddressDigest},
		{name: "a malformed address", submitted: " Not-An-Address ", normalized: "not-an-address",
			validator: i18n.NewLocalizedError(i18n.ErrCodeEmailInvalidFormat, nil),
			wantError: "Please enter a valid email address.", wantDigest: notAnAddressDigest},
		{name: "an address over 60 characters",
			submitted:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@example.com",
			normalized: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@example.com",
			wantError:  "The email address cannot exceed a maximum length of 60 characters.",
			wantDigest: "668eb6ae99d19dca4cd41e4c10b4d123ad2eecd27fb6a483c1c23a5af15240a4"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRegisterHarness(t)
			req := registrationRequest(tc.submitted)
			rr := httptest.NewRecorder()

			if tc.submitted != "" {
				h.emailValidator.On("ValidateEmailAddress", tc.normalized).Return(tc.validator).Once()
			}
			var bound map[string]interface{}
			h.pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).
				Run(func(args mock.Arguments) { bound = args.Get(4).(map[string]interface{}) }).Return(nil).Once()
			details, _ := captureRequestedRegistration(h.auditLogger, nil)

			h.handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, tc.wantError, bound["error"])
			assert.Equal(t, map[string]interface{}{
				"ip":          testClientIP,
				"emailDigest": tc.wantDigest,
				"outcome":     "invalid_address",
			}, *details)
			assert.Empty(t, h.jobs.jobs, "an invalid address leaves no work for after the response")
			h.database.AssertNotCalled(t, "GetUserByEmail", mock.Anything, mock.Anything, mock.Anything)
			h.database.AssertNotCalled(t, "GetPreRegistrationByEmail", mock.Anything, mock.Anything, mock.Anything)
			h.assertNothingWrittenOrSent(t)
		})
	}
}

// A lookup that fails answers the 500 page, which says nothing about the address, and is recorded
// as server_error, naming an account only when the user lookup found one (#207 decisions 4 and 8).
func TestHandleRegisterPost_WithVerificationAFailedLookupIsAServerError(t *testing.T) {
	t.Run("the user lookup", func(t *testing.T) {
		h := newRegisterHarness(t)
		req := registrationRequest(registerSomeoneEmail)
		rr := httptest.NewRecorder()

		h.emailValidator.On("ValidateEmailAddress", registerSomeoneEmail).Return(nil).Once()
		h.database.On("GetUserByEmail", mock.Anything, (*sql.Tx)(nil), registerSomeoneEmail).Return(nil, assert.AnError).Once()
		h.pageRenderer.On("InternalServerError", rr, req, assert.AnError).Return().Once()
		details, _ := captureRequestedRegistration(h.auditLogger, nil)

		h.handler.ServeHTTP(rr, req)

		assert.Equal(t, map[string]interface{}{
			"ip":          testClientIP,
			"emailDigest": someoneDigest,
			"outcome":     "server_error",
		}, *details)
		assert.Empty(t, h.jobs.jobs)
		h.database.AssertNotCalled(t, "GetPreRegistrationByEmail", mock.Anything, mock.Anything, mock.Anything)
		h.pageRenderer.AssertNotCalled(t, "RenderTemplate", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		h.assertNothingWrittenOrSent(t)
	})

	t.Run("the pending registration lookup, after an account was found", func(t *testing.T) {
		h := newRegisterHarness(t)
		req := registrationRequest(registerSomeoneEmail)
		rr := httptest.NewRecorder()

		h.emailValidator.On("ValidateEmailAddress", registerSomeoneEmail).Return(nil).Once()
		h.database.On("GetUserByEmail", mock.Anything, (*sql.Tx)(nil), registerSomeoneEmail).
			Return(&record.User{Id: 7, Enabled: true, EmailVerified: true, Email: registerSomeoneEmail}, nil).Once()
		h.database.On("GetPreRegistrationByEmail", mock.Anything, (*sql.Tx)(nil), registerSomeoneEmail).
			Return(nil, assert.AnError).Once()
		h.pageRenderer.On("InternalServerError", rr, req, assert.AnError).Return().Once()
		details, _ := captureRequestedRegistration(h.auditLogger, nil)

		h.handler.ServeHTTP(rr, req)

		assert.Equal(t, map[string]interface{}{
			"ip":          testClientIP,
			"emailDigest": someoneDigest,
			"userId":      int64(7),
			"outcome":     "server_error",
		}, *details)
		assert.Empty(t, h.jobs.jobs)
		h.pageRenderer.AssertNotCalled(t, "RenderTemplate", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		h.assertNothingWrittenOrSent(t)
	})
}

// The job's faults are the server's: the requester has been answered already, so each is an Error
// record on the request's id and, before anything was issued, the one server_error record.
func TestHandleRegisterPost_WithVerificationTheJobsFaultsAreErrorRecords(t *testing.T) {
	t.Run("writing the pending registration fails", func(t *testing.T) {
		capture := logtest.CaptureSlog(t)
		h := newRegisterHarness(t)
		req := registrationRequest(registerSomeoneEmail)
		rr := httptest.NewRecorder()

		h.expectLookups(registerSomeoneEmail, nil, nil)
		h.expectCheckEmailPage(rr, req)
		h.database.On("CreatePreRegistration", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(assert.AnError).Once()
		details, _ := captureRequestedRegistration(h.auditLogger, nil)

		h.handler.ServeHTTP(rr, req)
		h.jobs.runAll(t)

		assert.Equal(t, http.StatusOK, rr.Code, "the response has gone before the row is written")
		assert.Equal(t, map[string]interface{}{
			"ip":          testClientIP,
			"emailDigest": someoneDigest,
			"outcome":     "server_error",
		}, *details)
		h.pageRenderer.AssertNotCalled(t, "InternalServerError", mock.Anything, mock.Anything, mock.Anything)
		h.emailSender.AssertNotCalled(t, "SendEmail", mock.Anything, mock.Anything, mock.Anything)
		assertOneErrorRecordOnRegistration(t, capture)
	})

	t.Run("a link that fails to send leaves the one link_issued record and an Error line", func(t *testing.T) {
		capture := logtest.CaptureSlog(t)
		h := newRegisterHarness(t)
		req := registrationRequest(registerSomeoneEmail)
		rr := httptest.NewRecorder()

		h.expectLookups(registerSomeoneEmail, nil, nil)
		h.expectCheckEmailPage(rr, req)
		h.database.On("CreatePreRegistration", mock.Anything, (*sql.Tx)(nil), mock.Anything).
			Run(func(args mock.Arguments) { args.Get(2).(*record.PreRegistration).Id = 42 }).Return(nil).Once()
		details, _ := captureRequestedRegistration(h.auditLogger, nil)
		h.pageRenderer.On("RenderTemplateToBuffer", mock.Anything, "/layouts/email_layout.html",
			"/emails/email_register_activate.html", mock.Anything).Return(&bytes.Buffer{}, nil).Once()
		h.emailSender.On("SendEmail", mock.Anything, mock.Anything, mock.Anything).Return(assert.AnError).Once()

		h.handler.ServeHTTP(rr, req)
		h.jobs.runAll(t)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "link_issued", (*details)["outcome"])
		h.pageRenderer.AssertNotCalled(t, "InternalServerError", mock.Anything, mock.Anything, mock.Anything)
		assertOneErrorRecordOnRegistration(t, capture)
	})

	t.Run("a notice that fails to send leaves the one notice_issued record and an Error line", func(t *testing.T) {
		capture := logtest.CaptureSlog(t)
		h := newRegisterHarness(t)
		req := registrationRequest(registerSomeoneEmail)
		rr := httptest.NewRecorder()

		h.expectLookups(registerSomeoneEmail,
			&record.User{Id: 7, Enabled: true, EmailVerified: true, Email: registerSomeoneEmail}, nil)
		h.expectCheckEmailPage(rr, req)
		details, _ := captureRequestedRegistration(h.auditLogger, nil)
		h.pageRenderer.On("RenderTemplateToBuffer", mock.Anything, "/layouts/email_layout.html",
			"/emails/email_register_existing_account.html", mock.Anything).Return(&bytes.Buffer{}, nil).Once()
		h.emailSender.On("SendEmail", mock.Anything, mock.Anything, mock.Anything).Return(assert.AnError).Once()

		h.handler.ServeHTTP(rr, req)
		h.jobs.runAll(t)

		assert.Equal(t, "notice_issued", (*details)["outcome"])
		h.pageRenderer.AssertNotCalled(t, "InternalServerError", mock.Anything, mock.Anything, mock.Anything)
		assertOneErrorRecordOnRegistration(t, capture)
	})
}

// assertOneErrorRecordOnRegistration requires that the job wrote exactly one record, at Error,
// carrying the id of the registration request that started it.
func assertOneErrorRecordOnRegistration(t *testing.T, capture *logtest.SlogCapture) {
	t.Helper()
	records := capture.Records()
	require.Len(t, records, 1, capture.Text())
	assert.Equal(t, "ERROR", records[0].Level.String())
	assert.Equal(t, registerRequestId, records[0].Attrs["request_id"])
	assert.NotNil(t, records[0].Attrs["error"])
}

// Registration without verification is unchanged by all of this: it writes no
// requested_registration record and hands nothing to a job (#207 decision 3).
func TestHandleRegisterPost_WithoutVerificationRecordsNoRequestedRegistration(t *testing.T) {
	h := newRegisterHarness(t)
	req := registrationRequest("existing@example.com")
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{SelfRegistrationEnabled: true}))
	rr := httptest.NewRecorder()

	h.emailValidator.On("ValidateEmailAddress", "existing@example.com").Return(nil).Once()
	h.database.On("GetUserByEmail", mock.Anything, mock.Anything, "existing@example.com").Return(&record.User{Id: 7}, nil).Once()
	var bound map[string]interface{}
	h.pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).
		Run(func(args mock.Arguments) { bound = args.Get(4).(map[string]interface{}) }).Return(nil).Once()

	h.handler.ServeHTTP(rr, req)

	assert.Equal(t, "Apologies, but this email address is already registered.", bound["error"])
	assert.Empty(t, h.jobs.jobs)
	h.auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}
