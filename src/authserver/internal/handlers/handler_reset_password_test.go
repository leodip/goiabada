package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/constants"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/encryption"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHandleResetPasswordGet(t *testing.T) {
	t.Run("No code provided", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleResetPasswordGet(httpHelper, database)

		req, _ := http.NewRequest("GET", "/reset-password", nil)
		rr := httptest.NewRecorder()

		httpHelper.On("InternalServerError",
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(func(err error) bool { return err.Error() == "expecting code to reset the password, but it's empty." }),
		).Return().Once()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
	})

	t.Run("No email provided", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleResetPasswordGet(httpHelper, database)

		req, _ := http.NewRequest("GET", "/reset-password?code=123", nil)
		rr := httptest.NewRecorder()

		httpHelper.On("InternalServerError",
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(func(err error) bool { return err.Error() == "expecting email to reset the password, but it's empty." }),
		).Return().Once()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
	})

	t.Run("User not found", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleResetPasswordGet(httpHelper, database)

		req, _ := http.NewRequest("GET", "/reset-password?code=123456&email=test@example.com", nil)
		rr := httptest.NewRecorder()

		database.On("GetUserByEmail", (*sql.Tx)(nil), "test@example.com").Return(nil, nil)
		httpHelper.On("InternalServerError",
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(func(err error) bool { return err.Error() == "user with email test@example.com does not exist" }),
		).Return().Once()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
	})

	t.Run("DecryptText error", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleResetPasswordGet(httpHelper, database)

		req, _ := http.NewRequest("GET", "/reset-password?code=123456&email=test@example.com", nil)
		rr := httptest.NewRecorder()

		user := &models.User{
			Id:                          1,
			Email:                       "test@example.com",
			ForgotPasswordCodeEncrypted: []byte("encrypted_code"),
			ForgotPasswordCodeIssuedAt:  sql.NullTime{Time: time.Now(), Valid: true},
		}

		settings := &models.Settings{
			AESEncryptionKey: []byte("invalid_key"), // This will cause DecryptText to fail
		}

		// Set up the context with the settings
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		database.On("GetUserByEmail", (*sql.Tx)(nil), "test@example.com").Return(user, nil)

		httpHelper.On("InternalServerError",
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(func(err error) bool {
				return strings.Contains(err.Error(), "unable to decrypt forgot password code")
			}),
		).Return().Once()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Forgot password code doesn't match", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleResetPasswordGet(httpHelper, database)

		// The code in the request
		requestCode := "123456"
		req, _ := http.NewRequest("GET", "/reset-password?code="+requestCode+"&email=test@example.com", nil)
		rr := httptest.NewRecorder()

		// The actual forgot password code (different from the request)
		actualCode := "654321"

		// Create a valid encryption key (32 bytes)
		encryptionKey := []byte("12345678901234567890123456789012")

		// Encrypt the actual code
		encryptedCode, err := encryption.EncryptText(actualCode, encryptionKey)
		assert.NoError(t, err)

		user := &models.User{
			Id:                          1,
			Email:                       "test@example.com",
			ForgotPasswordCodeEncrypted: encryptedCode,
			ForgotPasswordCodeIssuedAt:  sql.NullTime{Time: time.Now(), Valid: true},
		}

		settings := &models.Settings{
			AESEncryptionKey: encryptionKey,
		}

		// Set up the context with the settings
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		database.On("GetUserByEmail", (*sql.Tx)(nil), "test@example.com").Return(user, nil)

		httpHelper.On("RenderTemplate",
			mock.Anything,
			mock.Anything,
			"/layouts/auth_layout.html",
			"/reset_password.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				codeInvalidOrExpired, ok := data["codeInvalidOrExpired"].(bool)
				return ok && codeInvalidOrExpired
			}),
		).Return(nil).Once()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Forgot password code is expired", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleResetPasswordGet(httpHelper, database)

		// The code in the request
		requestCode := "123456"
		req, _ := http.NewRequest("GET", "/reset-password?code="+requestCode+"&email=test@example.com", nil)
		rr := httptest.NewRecorder()

		// Create a valid encryption key (32 bytes)
		encryptionKey := []byte("12345678901234567890123456789012")

		// Encrypt the request code
		encryptedCode, err := encryption.EncryptText(requestCode, encryptionKey)
		assert.NoError(t, err)

		// Set the issued time to 6 minutes ago (exceeding the 5-minute expiration)
		issuedTime := time.Now().Add(-6 * time.Minute)

		user := &models.User{
			Id:                          1,
			Email:                       "test@example.com",
			ForgotPasswordCodeEncrypted: encryptedCode,
			ForgotPasswordCodeIssuedAt:  sql.NullTime{Time: issuedTime, Valid: true},
		}

		settings := &models.Settings{
			AESEncryptionKey: encryptionKey,
		}

		// Set up the context with the settings
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		database.On("GetUserByEmail", (*sql.Tx)(nil), "test@example.com").Return(user, nil)

		httpHelper.On("RenderTemplate",
			mock.Anything,
			mock.Anything,
			"/layouts/auth_layout.html",
			"/reset_password.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				codeInvalidOrExpired, ok := data["codeInvalidOrExpired"].(bool)
				return ok && codeInvalidOrExpired
			}),
		).Return(nil).Once()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Happy path - valid code and not expired", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleResetPasswordGet(httpHelper, database)

		// The code in the request
		requestCode := "123456"
		req, _ := http.NewRequest("GET", "/reset-password?code="+requestCode+"&email=test@example.com", nil)
		rr := httptest.NewRecorder()

		// Create a valid encryption key (32 bytes)
		encryptionKey := []byte("12345678901234567890123456789012")

		// Encrypt the request code
		encryptedCode, err := encryption.EncryptText(requestCode, encryptionKey)
		assert.NoError(t, err)

		// Set the issued time to 4 minutes ago (within the 5-minute expiration)
		issuedTime := time.Now().Add(-4 * time.Minute)

		user := &models.User{
			Id:                          1,
			Email:                       "test@example.com",
			ForgotPasswordCodeEncrypted: encryptedCode,
			ForgotPasswordCodeIssuedAt:  sql.NullTime{Time: issuedTime, Valid: true},
		}

		settings := &models.Settings{
			AESEncryptionKey: encryptionKey,
		}

		// Set up the context with the settings
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		database.On("GetUserByEmail", (*sql.Tx)(nil), "test@example.com").Return(user, nil)

		httpHelper.On("RenderTemplate",
			mock.Anything,
			mock.Anything,
			"/layouts/auth_layout.html",
			"/reset_password.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				// Ensure that codeInvalidOrExpired is not set or is false
				codeInvalidOrExpired, ok := data["codeInvalidOrExpired"].(bool)
				return !ok || !codeInvalidOrExpired
			}),
		).Return(nil).Once()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})
}
