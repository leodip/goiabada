package accounthandlers

import (
	"context"
	"database/sql"
	"net/http/httptest"
	"testing"
	"time"

	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/authserver/internal/handlers/handlerhelpers/mocks"
	mocks_users "github.com/leodip/goiabada/authserver/internal/users/mocks"

	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/encryption"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/users"
	"github.com/stretchr/testify/mock"
)

func TestHandleAccountActivateGet(t *testing.T) {
	t.Run("missing email", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_users.NewUserCreator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		req := httptest.NewRequest("GET", "/?code=123", nil)
		w := httptest.NewRecorder()

		httpHelper.On("InternalServerError", w, req, mock.AnythingOfType("*errors.withStack")).Once()

		handler := HandleAccountActivateGet(httpHelper, database, userCreator, auditLogger)
		handler.ServeHTTP(w, req)

		httpHelper.AssertExpectations(t)
	})

	t.Run("missing code", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_users.NewUserCreator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		req := httptest.NewRequest("GET", "/?email=test@example.com", nil)
		w := httptest.NewRecorder()

		httpHelper.On("InternalServerError", w, req, mock.AnythingOfType("*errors.withStack")).Once()

		handler := HandleAccountActivateGet(httpHelper, database, userCreator, auditLogger)
		handler.ServeHTTP(w, req)

		httpHelper.AssertExpectations(t)
	})

	t.Run("pre-registration not found", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_users.NewUserCreator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		req := httptest.NewRequest("GET", "/?email=test@example.com&code=123", nil)
		w := httptest.NewRecorder()

		database.On("GetPreRegistrationByEmail", (*sql.Tx)(nil), "test@example.com").Return(nil, nil).Once()
		httpHelper.On("InternalServerError", w, req, mock.AnythingOfType("*errors.withStack")).Once()

		handler := HandleAccountActivateGet(httpHelper, database, userCreator, auditLogger)
		handler.ServeHTTP(w, req)

		database.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})

	t.Run("verification code mismatch", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_users.NewUserCreator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		req := httptest.NewRequest("GET", "/?email=test@example.com&code=123", nil)
		w := httptest.NewRecorder()

		key := []byte("test_key_00000000000000000000000")

		preReg := &models.PreRegistration{
			Id:                        1,
			Email:                     "test@example.com",
			VerificationCodeEncrypted: key,
			VerificationCodeIssuedAt:  sql.NullTime{Valid: true, Time: time.Now()},
			PasswordHash:              "password_hash",
		}
		database.On("GetPreRegistrationByEmail", (*sql.Tx)(nil), "test@example.com").Return(preReg, nil).Once()

		settings := &models.Settings{AESEncryptionKey: key}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		httpHelper.On("InternalServerError", w, req, mock.AnythingOfType("*errors.withStack")).Once()

		handler := HandleAccountActivateGet(httpHelper, database, userCreator, auditLogger)
		handler.ServeHTTP(w, req)

		database.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})

	t.Run("verification code expired", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_users.NewUserCreator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		req := httptest.NewRequest("GET", "/?email=test@example.com&code=123", nil)
		w := httptest.NewRecorder()

		key := []byte("test_key_00000000000000000000000")
		codeEncrypted, err := encryption.EncryptText("123", key)
		if err != nil {
			t.Fatal(err)
		}

		preReg := &models.PreRegistration{
			Id:                        1,
			Email:                     "test@example.com",
			VerificationCodeEncrypted: codeEncrypted,
			VerificationCodeIssuedAt:  sql.NullTime{Valid: true, Time: time.Now().Add(-6 * time.Minute)},
			PasswordHash:              "password_hash",
		}
		database.On("GetPreRegistrationByEmail", (*sql.Tx)(nil), "test@example.com").Return(preReg, nil).Once()

		settings := &models.Settings{AESEncryptionKey: key}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		database.On("DeletePreRegistration", (*sql.Tx)(nil), int64(1)).Return(nil).Once()
		httpHelper.On("RenderTemplate", w, req, "/layouts/auth_layout.html", "/account_register_activation_result.html", mock.Anything).Return(nil).Once()

		handler := HandleAccountActivateGet(httpHelper, database, userCreator, auditLogger)
		handler.ServeHTTP(w, req)

		database.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})

	t.Run("successful activation", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_users.NewUserCreator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		req := httptest.NewRequest("GET", "/?email=test@example.com&code=123", nil)
		w := httptest.NewRecorder()

		key := []byte("test_key_00000000000000000000000")
		codeEncrypted, err := encryption.EncryptText("123", key)
		if err != nil {
			t.Fatal(err)
		}

		preReg := &models.PreRegistration{
			Id:                        1,
			Email:                     "test@example.com",
			VerificationCodeEncrypted: codeEncrypted,
			VerificationCodeIssuedAt:  sql.NullTime{Valid: true, Time: time.Now()},
			PasswordHash:              "password_hash",
		}
		database.On("GetPreRegistrationByEmail", (*sql.Tx)(nil), "test@example.com").Return(preReg, nil).Once()

		settings := &models.Settings{AESEncryptionKey: key}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		createdUser := &models.User{Id: 1, Email: "test@example.com"}
		userCreator.On("CreateUser", &users.CreateUserInput{
			Email:         "test@example.com",
			EmailVerified: true,
			PasswordHash:  "password_hash",
		}).Return(createdUser, nil).Once()

		database.On("DeletePreRegistration", (*sql.Tx)(nil), int64(1)).Return(nil).Once()
		auditLogger.On("Log", constants.AuditCreatedUser, mock.MatchedBy(func(arg map[string]interface{}) bool {
			email, ok := arg["email"].(string)
			return ok && email == "test@example.com"
		})).Once()
		auditLogger.On("Log", constants.AuditActivatedAccount, mock.MatchedBy(func(arg map[string]interface{}) bool {
			email, ok := arg["email"].(string)
			return ok && email == "test@example.com"
		})).Once()
		httpHelper.On("RenderTemplate", w, req, "/layouts/auth_layout.html", "/account_register_activation_result.html", mock.Anything).Return(nil).Once()

		handler := HandleAccountActivateGet(httpHelper, database, userCreator, auditLogger)
		handler.ServeHTTP(w, req)

		database.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
		userCreator.AssertExpectations(t)
	})
}
