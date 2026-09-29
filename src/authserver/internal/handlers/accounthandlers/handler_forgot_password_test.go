package accounthandlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	mocks_accounthandlers "github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	mocks_handlers "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/reqctx"

	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/emaillinks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHandleForgotPasswordGet(t *testing.T) {
	t.Run("Successful render", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)

		handler := HandleForgotPasswordGet(pageRenderer)

		req, err := http.NewRequest("GET", "/forgot-password", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		pageRenderer.On("RenderTemplate",
			rr,
			req,
			"/layouts/auth_layout.html",
			"/forgot_password.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				_, hasError := data["error"]
				return hasError
			}),
		).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		pageRenderer.AssertExpectations(t)
	})

	t.Run("RenderTemplate error", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)

		handler := HandleForgotPasswordGet(pageRenderer)

		req, err := http.NewRequest("GET", "/forgot-password", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		expectedError := assert.AnError
		pageRenderer.On("RenderTemplate",
			rr,
			req,
			"/layouts/auth_layout.html",
			"/forgot_password.html",
			mock.Anything,
		).Return(expectedError)

		pageRenderer.On("InternalServerError",
			rr,
			req,
			expectedError,
		).Return()

		handler.ServeHTTP(rr, req)

		pageRenderer.AssertExpectations(t)
	})
}

func TestHandleForgotPasswordPost(t *testing.T) {
	t.Run("Email not given", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		database := mocks_data.NewDatabase(t)
		emailSender := mocks_accounthandlers.NewEmailSender(t)

		handler := HandleForgotPasswordPost(pageRenderer, database, emailSender, testDataCipher, testBaseURL)

		req, err := http.NewRequest("POST", "/forgot-password", strings.NewReader(""))
		assert.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rr := httptest.NewRecorder()

		pageRenderer.On("RenderTemplate",
			rr,
			req,
			"/layouts/auth_layout.html",
			"/forgot_password.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				errorMsg, ok := data["error"].(string)
				return ok && errorMsg == "Please enter a valid email address."
			}),
		).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		pageRenderer.AssertExpectations(t)
		database.AssertExpectations(t)
		emailSender.AssertExpectations(t)
	})

	t.Run("User not found", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		database := mocks_data.NewDatabase(t)
		emailSender := mocks_accounthandlers.NewEmailSender(t)

		handler := HandleForgotPasswordPost(pageRenderer, database, emailSender, testDataCipher, testBaseURL)

		form := url.Values{}
		form.Add("email", "nonexistent@example.com")
		req, err := http.NewRequest("POST", "/forgot-password", strings.NewReader(form.Encode()))
		assert.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		settings := &models.Settings{}
		ctx := req.Context()
		ctx = reqctx.WithSettings(ctx, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		database.On("GetUserByEmail", mock.Anything, mock.Anything, "nonexistent@example.com").Return(nil, nil)

		pageRenderer.On("RenderTemplate",
			rr,
			req,
			"/layouts/auth_layout.html",
			"/forgot_password.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				linkSent, ok := data["linkSent"].(bool)
				return ok && linkSent
			}),
		).Return(nil)

		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)

		pageRenderer.AssertExpectations(t)
		database.AssertExpectations(t)
		emailSender.AssertExpectations(t)
	})

	t.Run("Success path, email is sent", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		database := mocks_data.NewDatabase(t)
		emailSender := mocks_accounthandlers.NewEmailSender(t)

		handler := HandleForgotPasswordPost(pageRenderer, database, emailSender, testDataCipher, testBaseURL)

		form := url.Values{}
		form.Add("email", "existing@example.com")
		req, err := http.NewRequest("POST", "/forgot-password", strings.NewReader(form.Encode()))
		assert.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		settings := &models.Settings{
			AppName:       "TestApp",
			SMTPHost:      "smtp.example.com",
			SMTPPort:      587,
			SMTPFromEmail: "noreply@example.com",
		}
		ctx := req.Context()
		ctx = reqctx.WithSettings(ctx, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		user := &models.User{
			Id:    1,
			Email: "existing@example.com",
		}
		database.On("GetUserByEmail", mock.Anything, mock.Anything, "existing@example.com").Return(user, nil)
		database.On("UpdateUser", mock.Anything, mock.Anything, mock.MatchedBy(func(u *models.User) bool {
			return u.Id == 1 && u.ForgotPasswordCodeEncrypted != nil && u.ForgotPasswordCodeIssuedAt.Valid
		})).Return(nil)

		// The handler now wraps the request with a recipient-locale context
		// (i18n.WithLocale) before rendering the email body, so the request
		// pointer differs from the original. mock.Anything keeps the
		// expectation focused on the layout / template / bind args.
		var emailedLink string
		pageRenderer.On("RenderTemplateToBuffer", mock.Anything, "/layouts/email_layout.html", "/emails/email_forgot_password.html", mock.Anything).
			Run(func(args mock.Arguments) {
				emailedLink, _ = args.Get(3).(map[string]interface{})["link"].(string)
			}).Return(&bytes.Buffer{}, nil)

		// The relay is the request's settings, which is the whole of what the handler now reads
		// for the send (#433).
		emailSender.On("SendEmail", mock.Anything,
			emaildelivery.SMTPConfig{Host: "smtp.example.com", Port: 587, FromEmail: "noreply@example.com"},
			mock.MatchedBy(func(input *emaildelivery.SendEmailInput) bool {
				return input.To == "existing@example.com" && input.Subject == "Password reset"
			})).Return(nil)

		pageRenderer.On("RenderTemplate",
			rr,
			req,
			"/layouts/auth_layout.html",
			"/forgot_password.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				linkSent, ok := data["linkSent"].(bool)
				return ok && linkSent
			}),
		).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		// The hash stored beside the encrypted code is the only thing that will find this
		// row when the link comes back, since the link carries the code and no address
		// (#112). Derived from the code the handler actually issued, decrypted out of the
		// column it wrote, rather than from a value the test chose: a hash of anything
		// else would leave the user unable to reset at all.
		issuedCode, err := testDataCipher.Decrypt(user.ForgotPasswordCodeEncrypted)
		assert.NoError(t, err)
		expectedHash := hashutil.HashString(issuedCode)
		assert.Equal(t, expectedHash, user.ForgotPasswordCodeHash,
			"the stored hash must be the hash of the code that was issued")

		// This site's only job is to hand the issued code to the shared builder; the link's
		// shape and the absence of an address in it belong to emaillinks.ResetPasswordLink's own tests
		// (#112 decision 5). Asserting the exact string here would pin the shape in a
		// second place and let the two disagree.
		assert.Equal(t, emaillinks.ResetPasswordLink(testBaseURL, issuedCode), emailedLink,
			"the emailed link must be the shared builder's output for the code that was issued")

		pageRenderer.AssertExpectations(t)
		database.AssertExpectations(t)
		emailSender.AssertExpectations(t)
	})
}
