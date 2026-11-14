package accounthandlers

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/afterresponse"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/emailtemplate"
	"github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/usercreation"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/requestid"
)

// With registration on and email verification off, the welcome email is sent in a job after the
// response, as the activation link and the "this address already has an account" notice are: a
// send or a render that fails is one Error record on the request's id, and the person is signed in
// to the app they came from, or shown the "account created" page, as when it goes out (#817
// decision 13). A relay that was down used to answer a registration that had succeeded with the
// error page.

// welcomeRequestId is the request id a registration without verification carries, as
// requestid.Middleware puts one on every request.
const welcomeRequestId = "req-welcome-0001"

// jobsAfterTheResponse holds the jobs handed to it, as heldJobs does, and notes for each whether
// the response had been written when it was handed over: a redirect's Location, or a page's body.
type jobsAfterTheResponse struct {
	heldJobs
	rr       *httptest.ResponseRecorder
	answered []bool
}

func (j *jobsAfterTheResponse) Go(ctx context.Context, class afterresponse.Class, job func(ctx context.Context)) {
	j.answered = append(j.answered, j.rr.Header().Get("Location") != "" || j.rr.Body.Len() > 0)
	j.heldJobs.Go(ctx, class, job)
}

// welcomeRegistration is HandleRegisterPost, email on and verification off, with the mocks a
// submission that creates an account calls.
type welcomeRegistration struct {
	pageRenderer *handlersmocks.PageRenderer
	emailSender  *accounthandlersmocks.EmailSender
	jobs         *jobsAfterTheResponse
	handler      http.HandlerFunc
}

func newWelcomeRegistration(t *testing.T, signIns signInCeremonies, rr *httptest.ResponseRecorder) *welcomeRegistration {
	database := datamocks.NewDatabase(t)
	userCreator := accounthandlersmocks.NewUserCreator(t)
	emailValidator := accounthandlersmocks.NewEmailValidator(t)
	passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	w := &welcomeRegistration{
		pageRenderer: handlersmocks.NewPageRenderer(t),
		emailSender:  accounthandlersmocks.NewEmailSender(t),
		jobs:         &jobsAfterTheResponse{rr: rr},
	}

	emailValidator.On("ValidateEmailAddress", newAccountEmail).Return(nil).Once()
	database.On("GetUserByEmail", mock.Anything, (*sql.Tx)(nil), newAccountEmail).Return(nil, nil).Once()
	database.On("GetPreRegistrationByEmail", mock.Anything, (*sql.Tx)(nil), newAccountEmail).Return(nil, nil).Once()
	passwordValidator.On("ValidatePassword", mock.Anything, newAccountPassword, mock.Anything).Return(nil).Once()
	userCreator.On("CreateUser", mock.Anything, mock.MatchedBy(func(input *usercreation.Input) bool {
		return input.Email == newAccountEmail
	})).Return(&record.User{Id: newAccountId, Email: newAccountEmail, Enabled: true}, nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventCreatedUser, mock.Anything).Return().Once()
	auditLogger.On("Log", mock.Anything, audit.EventAuthSuccessPwd, mock.Anything).Return().Maybe()

	w.handler = HandleRegisterPost(w.pageRenderer, signIns, legalDocumentsInEffect{}, database, userCreator,
		emailValidator, passwordValidator, w.emailSender, auditLogger, w.jobs,
		testDataCipher, testBaseURL, testAdminConsoleBaseURL)
	return w
}

// welcomeRequest is registerWithoutVerification with email on and a request id.
func welcomeRequest(query string, smtpEnabled bool) *http.Request {
	req := registerWithoutVerification(query)
	ctx := requestid.NewContext(req.Context(), welcomeRequestId)
	return req.WithContext(reqctx.WithSettings(ctx, &record.Settings{
		AppName:                 "TestApp",
		SelfRegistrationEnabled: true,
		SMTPEnabled:             smtpEnabled,
		SMTPHost:                "smtp.example.com",
		SMTPPort:                2525,
	}))
}

// expectAccountCreatedPage expects the "account created" page, which writes its body.
func (w *welcomeRegistration) expectAccountCreatedPage() {
	w.pageRenderer.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/auth_layout.html",
		"/account_register_success.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["email"] == newAccountEmail
		})).
		Run(func(args mock.Arguments) {
			_, _ = args.Get(0).(http.ResponseWriter).Write([]byte("account created"))
		}).Return(nil).Once()
}

func TestHandleRegisterPost_TheWelcomeEmailIsSentAfterTheResponse(t *testing.T) {
	type outcome struct {
		name   string
		expect func(w *welcomeRegistration)
	}
	outcomes := []outcome{
		{name: "the send fails", expect: func(w *welcomeRegistration) {
			w.pageRenderer.On("RenderEmail", mock.Anything, emailtemplate.Welcome, mock.Anything).
				Return(emailtemplate.Message{Subject: "Welcome!", HTML: "welcome"}, nil).Once()
			w.emailSender.On("SendEmail", mock.Anything, emaildelivery.SMTPConfig{Host: "smtp.example.com", Port: 2525},
				mock.MatchedBy(func(input *emaildelivery.SendEmailInput) bool {
					return input.To == newAccountEmail && input.Subject == "Welcome!"
				})).Return(emaildelivery.SendResult{}, assert.AnError).Once()
		}},
		{name: "the render fails", expect: func(w *welcomeRegistration) {
			w.pageRenderer.On("RenderEmail", mock.Anything, emailtemplate.Welcome, mock.Anything).
				Return(emailtemplate.Message{}, assert.AnError).Once()
		}},
	}
	type landing struct {
		name         string
		query        string
		signIns      func() signInCeremonies
		expectPage   bool
		wantCode     int
		wantLocation string
	}
	landings := []landing{
		{name: "signed in to the app", query: "?ceremony=" + aCeremonyId,
			signIns: func() signInCeremonies {
				return &signInsHeld{held: map[string]*ceremony.AuthContext{aCeremonyId: atThePasswordStep()}}
			},
			wantCode: http.StatusSeeOther, wantLocation: continuedSignIn},
		{name: "shown the account created page", query: "",
			signIns:    func() signInCeremonies { return heldCeremonies{} },
			expectPage: true, wantCode: http.StatusOK},
	}

	for _, l := range landings {
		for _, o := range outcomes {
			t.Run(l.name+", "+o.name, func(t *testing.T) {
				capture := logtest.CaptureSlog(t)
				rr := httptest.NewRecorder()
				w := newWelcomeRegistration(t, l.signIns(), rr)
				if l.expectPage {
					w.expectAccountCreatedPage()
				}

				w.handler.ServeHTTP(rr, welcomeRequest(l.query, true))

				assert.Equal(t, l.wantCode, rr.Code, "answered as when the email goes out")
				assert.Equal(t, l.wantLocation, rr.Header().Get("Location"))
				w.pageRenderer.AssertNotCalled(t, "InternalServerError", mock.Anything, mock.Anything, mock.Anything)
				w.pageRenderer.AssertNotCalled(t, "RenderTemplateToBuffer", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
				w.emailSender.AssertNotCalled(t, "SendEmail", mock.Anything, mock.Anything, mock.Anything)
				assert.Equal(t, []bool{true}, w.jobs.answered, "the one job is handed over once the response is written")
				assert.Empty(t, capture.Records(), "the response writes no record: %s", capture.Text())

				o.expect(w)
				w.jobs.runAll(t, afterresponse.ClassRegistration)

				records := capture.Records()
				require.Len(t, records, 1, capture.Text())
				assert.Equal(t, "ERROR", records[0].Level.String())
				assert.Equal(t, welcomeRequestId, records[0].Attrs["request_id"])
				assert.Equal(t, newAccountId, records[0].Attrs["user_id"])
				assert.NotNil(t, records[0].Attrs["error"])
			})
		}
	}
}

// The job sends the welcome email and writes nothing when it goes out, and email off hands nothing
// to a job.
func TestHandleRegisterPost_TheWelcomeEmailJob(t *testing.T) {
	t.Run("sends the welcome email", func(t *testing.T) {
		capture := logtest.CaptureSlog(t)
		rr := httptest.NewRecorder()
		w := newWelcomeRegistration(t, heldCeremonies{}, rr)
		w.expectAccountCreatedPage()

		w.handler.ServeHTTP(rr, welcomeRequest("", true))

		w.pageRenderer.On("RenderEmail", mock.Anything, emailtemplate.Welcome,
			emailtemplate.Values{Link: testAdminConsoleBaseURL + "/account/profile"}).
			Return(emailtemplate.Message{Subject: "Welcome!", HTML: "welcome"}, nil).Once()
		w.emailSender.On("SendEmail", mock.Anything, emaildelivery.SMTPConfig{Host: "smtp.example.com", Port: 2525},
			&emaildelivery.SendEmailInput{To: newAccountEmail, Subject: "Welcome!", HtmlBody: "welcome"}).
			Return(emaildelivery.SendResult{}, nil).Once()
		w.jobs.runAll(t, afterresponse.ClassRegistration)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Empty(t, capture.Records(), capture.Text())
	})

	t.Run("email off hands nothing to a job", func(t *testing.T) {
		rr := httptest.NewRecorder()
		w := newWelcomeRegistration(t, heldCeremonies{}, rr)
		w.expectAccountCreatedPage()

		w.handler.ServeHTTP(rr, welcomeRequest("", false))

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Empty(t, w.jobs.jobs)
	})
}
