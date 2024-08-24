package handlers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/authserver/internal/communication"
	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHandleForgotPasswordGet(t *testing.T) {
	t.Run("Successful render", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)

		handler := HandleForgotPasswordGet(httpHelper)

		req, err := http.NewRequest("GET", "/forgot-password", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		httpHelper.On("RenderTemplate",
			rr,
			req,
			"/layouts/auth_layout.html",
			"/forgot_password.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				_, hasError := data["error"]
				csrfField, hasCsrfField := data["csrfField"]
				return hasError && hasCsrfField && csrfField != nil
			}),
		).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertExpectations(t)
	})

	t.Run("RenderTemplate error", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)

		handler := HandleForgotPasswordGet(httpHelper)

		req, err := http.NewRequest("GET", "/forgot-password", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		expectedError := assert.AnError
		httpHelper.On("RenderTemplate",
			rr,
			req,
			"/layouts/auth_layout.html",
			"/forgot_password.html",
			mock.Anything,
		).Return(expectedError)

		httpHelper.On("InternalServerError",
			rr,
			req,
			expectedError,
		).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
	})

	t.Run("CSRF field is included", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)

		handler := HandleForgotPasswordGet(httpHelper)

		req, err := http.NewRequest("GET", "/forgot-password", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		httpHelper.On("RenderTemplate",
			rr,
			req,
			"/layouts/auth_layout.html",
			"/forgot_password.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				csrfField, hasCsrfField := data["csrfField"]
				return hasCsrfField && csrfField == csrf.TemplateField(req)
			}),
		).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertExpectations(t)
	})
}

func TestHandleForgotPasswordPost(t *testing.T) {
	t.Run("Email not given", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		database := mocks.NewDatabase(t)
		emailSender := mocks.NewEmailSender(t)

		handler := HandleForgotPasswordPost(httpHelper, database, emailSender)

		req, err := http.NewRequest("POST", "/forgot-password", strings.NewReader(""))
		assert.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rr := httptest.NewRecorder()

		httpHelper.On("RenderTemplate",
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

		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		emailSender.AssertExpectations(t)
	})

	t.Run("User not found", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		database := mocks.NewDatabase(t)
		emailSender := mocks.NewEmailSender(t)

		handler := HandleForgotPasswordPost(httpHelper, database, emailSender)

		form := url.Values{}
		form.Add("email", "nonexistent@example.com")
		req, err := http.NewRequest("POST", "/forgot-password", strings.NewReader(form.Encode()))
		assert.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		settings := &models.Settings{}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		database.On("GetUserByEmail", mock.Anything, "nonexistent@example.com").Return(nil, nil)

		httpHelper.On("RenderTemplate",
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

		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		emailSender.AssertExpectations(t)
	})

	t.Run("Success path, email is sent", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		database := mocks.NewDatabase(t)
		emailSender := mocks.NewEmailSender(t)

		handler := HandleForgotPasswordPost(httpHelper, database, emailSender)

		form := url.Values{}
		form.Add("email", "existing@example.com")
		req, err := http.NewRequest("POST", "/forgot-password", strings.NewReader(form.Encode()))
		assert.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		settings := &models.Settings{
			AppName:          "TestApp",
			AESEncryptionKey: []byte("test-encryption-key-000000000000"),
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		user := &models.User{
			Id:    1,
			Email: "existing@example.com",
		}
		database.On("GetUserByEmail", mock.Anything, "existing@example.com").Return(user, nil)
		database.On("UpdateUser", mock.Anything, mock.MatchedBy(func(u *models.User) bool {
			return u.Id == 1 && u.ForgotPasswordCodeEncrypted != nil && u.ForgotPasswordCodeIssuedAt.Valid
		})).Return(nil)

		httpHelper.On("RenderTemplateToBuffer", req, "/layouts/email_layout.html", "/emails/email_forgot_password.html", mock.Anything).Return(&bytes.Buffer{}, nil)

		emailSender.On("SendEmail", mock.Anything, mock.MatchedBy(func(input *communication.SendEmailInput) bool {
			return input.To == "existing@example.com" && input.Subject == "Password reset"
		})).Return(nil)

		httpHelper.On("RenderTemplate",
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

		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		emailSender.AssertExpectations(t)
	})
}
