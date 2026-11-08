package accounthandlers

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/accountnotice"
	"github.com/leodip/goiabada/authserver/internal/afterresponse"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/emaillinks"
	"github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/requestid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The notice for a password reset through a forgot-password link (#724): sent after the reset
// commits and after the page, to the account's address, against the security_notice budget. The
// setup link an administrator emails a new user sets the account's first password and sends
// nothing (decision 6). Whether the account had a password is read from the row the claim
// replaces, under the user's row inside the transaction, not from the read before it.

const (
	resetNoticeCodeHash  = "the-code-hash"
	resetNoticePassword  = "Str0ngP4ss!-reset"
	resetNoticeAddress   = "carla.dias@example.com"
	resetNoticeRequestId = "req-reset-0001"
	resetNoticeUserId    = int64(31)
)

// resetHeldJobs holds every job handed to it rather than starting it, so a case asserts what the
// request did before its response, then runs the jobs and asserts what they did.
type resetHeldJobs struct {
	ctxs    []context.Context
	classes []afterresponse.Class
	jobs    []func(ctx context.Context)
}

func (h *resetHeldJobs) Go(ctx context.Context, class afterresponse.Class, job func(ctx context.Context)) {
	h.ctxs = append(h.ctxs, ctx)
	h.classes = append(h.classes, class)
	h.jobs = append(h.jobs, job)
}

// runAll runs the one job held, which must have been admitted against class.
func (h *resetHeldJobs) runAll(t *testing.T, class afterresponse.Class) {
	t.Helper()
	require.Len(t, h.jobs, 1, "a completed reset hands exactly one job to run after its response")
	for i, job := range h.jobs {
		assert.Equal(t, class, h.classes[i], "the notice is admitted against its class's budget")
		job(h.ctxs[i])
	}
}

// heldResetNotifier is the notifier the reset tests that assert no notice take: its jobs are held
// and never run, and its sender expects nothing.
func heldResetNotifier(t *testing.T, pageRenderer *handlersmocks.PageRenderer) *accountnotice.Notifier {
	t.Helper()
	return accountnotice.New(pageRenderer, accounthandlersmocks.NewEmailSender(t), &resetHeldJobs{})
}

// resetNoticeRow is the account as a read finds it, with the password hash given ("" while its
// setup link is pending) and the verified flag given.
func resetNoticeRow(passwordHash string, verified bool) *record.User {
	return &record.User{
		Id:            resetNoticeUserId,
		Enabled:       true,
		GivenName:     "Carla",
		FamilyName:    "Dias",
		Email:         resetNoticeAddress,
		EmailVerified: verified,
		PasswordHash:  passwordHash,
	}
}

// resetNoticeSettings are the request's settings with SMTP on, so a case that expects no notice
// asserts it where one could have been sent.
func resetNoticeSettings() *record.Settings {
	return &record.Settings{
		AppName:        "Goiabada",
		PasswordPolicy: resetPasswordSettings.PasswordPolicy,
		SMTPEnabled:    true,
		SMTPHost:       "smtp.example.com",
		SMTPPort:       587,
		SMTPFromEmail:  "noreply@example.com",
	}
}

// resetNoticeTest is one reset submission's collaborators.
type resetNoticeTest struct {
	pageRenderer *handlersmocks.PageRenderer
	database     *datamocks.Database
	auditLogger  *handlersmocks.AuditLogger
	emailSender  *accounthandlersmocks.EmailSender
	jobs         *resetHeldJobs
	// renderErr is what drawing the success page answers: nil, or the error a client that dropped
	// the connection makes RenderTemplate return.
	renderErr error
}

func newResetNoticeTest(t *testing.T) *resetNoticeTest {
	return &resetNoticeTest{
		pageRenderer: handlersmocks.NewPageRenderer(t),
		database:     datamocks.NewDatabase(t),
		auditLogger:  handlersmocks.NewAuditLogger(t),
		emailSender:  accounthandlersmocks.NewEmailSender(t),
		jobs:         &resetHeldJobs{},
	}
}

// serve submits the reset form for the marker's code, with settings.
func (rt *resetNoticeTest) serve(t *testing.T, settings *record.Settings) {
	t.Helper()
	store := newMarkerTestStore()
	passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
	passwordValidator.On("ValidatePassword", settings.PasswordPolicy, resetNoticePassword, mock.Anything).Return(nil).Maybe()

	req := postWithMarker(t, store, resetNoticePassword, resetNoticePassword,
		emaillinks.LinkMarkerFlowResetPassword, resetNoticeUserId, resetNoticeCodeHash)
	ctx := requestid.NewContext(req.Context(), resetNoticeRequestId)
	req = req.WithContext(reqctx.WithSettings(ctx, settings))

	HandleResetPasswordPost(rt.pageRenderer, store, rt.database, passwordValidator, rt.auditLogger,
		testAdminConsoleBaseURL, accountnotice.New(rt.pageRenderer, rt.emailSender, rt.jobs), &recordingLogoutTokens{}).
		ServeHTTP(httptest.NewRecorder(), req)
}

// stubReset answers a reset that commits: the marker's lookup (before), the row the claim replaces,
// read under the user's row (replaced), the claim, the sweep and the audit events, and the success
// page. The audit events are the logger's only expectations, so a notice that wrote an audit entry
// of its own would fail the case.
func (rt *resetNoticeTest) stubReset(before *record.User, replaced *record.User) {
	rt.database.On("GetUserByForgotPasswordCodeHash", mock.Anything, (*sql.Tx)(nil), resetNoticeCodeHash).Return(before, nil).Once()
	rt.database.On("AcquireUserRow", mock.Anything, revokeTx, resetNoticeUserId).Return(nil).Once()
	rt.database.On("GetUserById", mock.Anything, revokeTx, resetNoticeUserId).Return(replaced, nil).Once()
	rt.database.On("TryConsumeForgotPasswordCode", mock.Anything, revokeTx, resetNoticeUserId, resetNoticeCodeHash, mock.Anything).
		Return(true, nil).Once()
	stubRevocationSweepTx(rt.database, resetNoticeUserId, 6)
	rt.auditLogger.On("Log", mock.Anything, audit.EventRevokedUserAuthState, mock.Anything).Return().Once()
	if !replaced.EmailVerified {
		rt.auditLogger.On("Log", mock.Anything, audit.EventVerifiedEmail, mock.Anything).Return().Once()
	}
	rt.pageRenderer.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/auth_layout.html", "/reset_password.html",
		mock.MatchedBy(func(data map[string]interface{}) bool {
			done, ok := data["passwordReset"].(bool)
			return ok && done
		})).Return(rt.renderErr).Once()
	if rt.renderErr != nil {
		rt.pageRenderer.On("InternalServerError", mock.Anything, mock.Anything, rt.renderErr).Return().Once()
	}
}

func TestHandleResetPasswordPost_TellsTheUserTheirPasswordWasReset(t *testing.T) {
	for _, tc := range []struct {
		name          string
		before        *record.User
		replaced      func() *record.User
		renderLocale  string
		expectSubject string
		renderErr     error
	}{
		{
			name:          "an English user",
			before:        resetNoticeRow("the-old-hash", true),
			replaced:      func() *record.User { return resetNoticeRow("the-old-hash", true) },
			renderLocale:  "en",
			expectSubject: "Your password was reset",
		},
		{
			name:   "a Brazilian Portuguese user",
			before: resetNoticeRow("the-old-hash", true),
			replaced: func() *record.User {
				row := resetNoticeRow("the-old-hash", true)
				row.Locale = "pt-BR"
				return row
			},
			renderLocale:  "pt-BR",
			expectSubject: "Sua senha foi redefinida",
		},
		{
			// The read before the transaction found no password, but one was set before the
			// claim took the row: the reset replaces it, so the user is told.
			name:          "a password set meanwhile is replaced",
			before:        resetNoticeRow("", true),
			replaced:      func() *record.User { return resetNoticeRow("the-hash-set-meanwhile", true) },
			renderLocale:  "en",
			expectSubject: "Your password was reset",
		},
		{
			// An administrator unverified the address after the link was sent. Redeeming the link
			// proves the user reads that mailbox, and the claim marks the address verified, so the
			// address the reset leaves verified is told.
			name:          "the claim verifies the address",
			before:        resetNoticeRow("the-old-hash", true),
			replaced:      func() *record.User { return resetNoticeRow("the-old-hash", false) },
			renderLocale:  "en",
			expectSubject: "Your password was reset",
		},
		{
			// The reset committed, so the user is told even when its page can't be drawn, as a
			// client that dropped the connection makes it: the 500 answers the browser, and the
			// notice still goes.
			name:          "the success page can't be drawn",
			before:        resetNoticeRow("the-old-hash", true),
			replaced:      func() *record.User { return resetNoticeRow("the-old-hash", true) },
			renderLocale:  "en",
			expectSubject: "Your password was reset",
			renderErr:     errors.New("the client went away"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := newResetNoticeTest(t)
			rt.renderErr = tc.renderErr
			rt.stubReset(tc.before, tc.replaced())

			rt.serve(t, resetNoticeSettings())

			// The page was rendered with the sender having no expectations yet, so a notice sent
			// inside the request would already have failed the case.
			var renderLocale string
			var bound map[string]interface{}
			rt.pageRenderer.On("RenderTemplateToBuffer", mock.Anything, "/layouts/email_layout.html",
				"/emails/email_password_reset.html", mock.Anything).
				Run(func(args mock.Arguments) {
					renderLocale = i18n.LocaleTag(args.Get(0).(*http.Request).Context())
					bound = args.Get(3).(map[string]interface{})
				}).Return(bytes.NewBufferString("<p>rendered notice</p>"), nil).Once()
			var sendCtx context.Context
			var sent *emaildelivery.SendEmailInput
			rt.emailSender.On("SendEmail", mock.Anything,
				emaildelivery.SMTPConfig{Host: "smtp.example.com", Port: 587, FromEmail: "noreply@example.com"},
				mock.Anything).
				Run(func(args mock.Arguments) {
					sendCtx = args.Get(0).(context.Context)
					sent = args.Get(2).(*emaildelivery.SendEmailInput)
				}).Return(emaildelivery.SendResult{}, nil).Once()

			rt.jobs.runAll(t, afterresponse.ClassSecurityNotice)

			require.NotNil(t, sent)
			assert.Equal(t, resetNoticeAddress, sent.To, "the notice goes to the account's own address")
			assert.Equal(t, tc.expectSubject, sent.Subject)
			assert.Equal(t, tc.renderLocale, renderLocale, "the notice is rendered in the user's language")
			assert.Equal(t, "Carla Dias", bound["name"])
			assert.NotContains(t, bound, "link", "the notice carries no link")
			for key, value := range bound {
				assert.NotContains(t, fmt.Sprint(value), resetNoticePassword, "the notice carries no password, found under %q", key)
			}
			assert.Equal(t, resetNoticeRequestId, requestid.FromContext(sendCtx), "the job's records carry the request's id")
		})
	}
}

// Where no notice may go, the request hands nothing off: the setup link's first password,
// whichever read saw it, SMTP off with the reset made, and a lost claim or a rollback with no reset.
func TestHandleResetPasswordPost_SendsNoNoticeWhereNoneMayGo(t *testing.T) {
	for _, tc := range []struct {
		name    string
		arrange func(rt *resetNoticeTest, settings *record.Settings)
	}{
		{"the setup link sets the account's first password", func(rt *resetNoticeTest, settings *record.Settings) {
			rt.stubReset(resetNoticeRow("", false), resetNoticeRow("", false))
		}},
		{"the row the claim replaces has no password, whatever the earlier read saw", func(rt *resetNoticeTest, settings *record.Settings) {
			rt.stubReset(resetNoticeRow("the-old-hash", true), resetNoticeRow("", true))
		}},
		{"SMTP is off", func(rt *resetNoticeTest, settings *record.Settings) {
			settings.SMTPEnabled = false
			rt.stubReset(resetNoticeRow("the-old-hash", true), resetNoticeRow("the-old-hash", true))
		}},
		{"the claim is lost", func(rt *resetNoticeTest, settings *record.Settings) {
			rt.database.On("GetUserByForgotPasswordCodeHash", mock.Anything, (*sql.Tx)(nil), resetNoticeCodeHash).
				Return(resetNoticeRow("the-old-hash", true), nil).Once()
			datamocks.ExpectRunInTransaction(rt.database, revokeTx)
			rt.database.On("AcquireUserRow", mock.Anything, revokeTx, resetNoticeUserId).Return(nil).Once()
			rt.database.On("GetUserById", mock.Anything, revokeTx, resetNoticeUserId).
				Return(resetNoticeRow("the-old-hash", true), nil).Once()
			rt.database.On("TryConsumeForgotPasswordCode", mock.Anything, revokeTx, resetNoticeUserId, resetNoticeCodeHash, mock.Anything).
				Return(false, nil).Once()
			rt.auditLogger.On("Log", mock.Anything, audit.EventFailedResetPasswordCode, mock.Anything).Return().Once()
			expectRenderedCodeInvalid(rt.pageRenderer, http.StatusBadRequest)
		}},
		{"the reset rolls back", func(rt *resetNoticeTest, settings *record.Settings) {
			rt.database.On("GetUserByForgotPasswordCodeHash", mock.Anything, (*sql.Tx)(nil), resetNoticeCodeHash).
				Return(resetNoticeRow("the-old-hash", true), nil).Once()
			datamocks.ExpectRunInTransaction(rt.database, revokeTx)
			rt.database.On("AcquireUserRow", mock.Anything, revokeTx, resetNoticeUserId).Return(nil).Once()
			rt.database.On("GetUserById", mock.Anything, revokeTx, resetNoticeUserId).
				Return(resetNoticeRow("the-old-hash", true), nil).Once()
			rt.database.On("TryConsumeForgotPasswordCode", mock.Anything, revokeTx, resetNoticeUserId, resetNoticeCodeHash, mock.Anything).
				Return(true, nil).Once()
			rt.database.On("IncrementUserAuthStateGeneration", mock.Anything, revokeTx, resetNoticeUserId).
				Return(int64(0), errors.New("increment failed")).Once()
			rt.pageRenderer.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Return().Once()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := newResetNoticeTest(t)
			settings := resetNoticeSettings()
			tc.arrange(rt, settings)

			rt.serve(t, settings)

			assert.Empty(t, rt.jobs.jobs, "no notice is handed off")
		})
	}
}
