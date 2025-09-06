package adminuserhandlers

// TODO: Update tests to use API client instead of direct database access
// This file has been temporarily commented out during the database-to-API migration

/*
import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
)

/*
func TestHandleAdminUserConsentsGet(t *testing.T) {
	t.Run("Valid user and consents", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)

		handler := HandleAdminUserConsentsGet(mockHttpHelper, mockSessionStore, mockDB)

		req, err := http.NewRequest("GET", "/admin/users/123/consents", nil)
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		consents := []models.UserConsent{
			{Id: 1, ClientId: 1, Scope: "openid profile", GrantedAt: sql.NullTime{Time: time.Now(), Valid: true}},
			{Id: 2, ClientId: 2, Scope: "email", GrantedAt: sql.NullTime{Time: time.Now(), Valid: true}},
		}
		mockDB.On("GetConsentsByUserId", mock.Anything, int64(123)).Return(consents, nil)
		mockDB.On("UserConsentsLoadClients", mock.Anything, consents).Return(nil)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/menu_layout.html", "/admin_users_consents.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["user"] == user && len(data["consents"].([]ConsentInfo)) == 2
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		mockDB.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Invalid user ID", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)

		handler := HandleAdminUserConsentsGet(mockHttpHelper, mockSessionStore, mockDB)

		req, err := http.NewRequest("GET", "/admin/users/invalid/consents", nil)
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "invalid")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		mockHttpHelper.On("InternalServerError", rr, req, mock.AnythingOfType("*strconv.NumError")).Return()

		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("User not found", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)

		handler := HandleAdminUserConsentsGet(mockHttpHelper, mockSessionStore, mockDB)

		req, err := http.NewRequest("GET", "/admin/users/123/consents", nil)
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(nil, nil)
		mockHttpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "user not found"
		})).Return()

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})
}

func TestHandleAdminUserConsentsPost(t *testing.T) {
	t.Run("Valid consent revocation", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserConsentsPost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

		reqBody := `{"consentId": 456}`
		req, err := http.NewRequest("POST", "/admin/users/123/consents", strings.NewReader(reqBody))
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		consents := []models.UserConsent{
			{Id: 456, ClientId: 1, Scope: "openid profile"},
		}
		mockDB.On("GetConsentsByUserId", mock.Anything, int64(123)).Return(consents, nil)
		mockDB.On("DeleteUserConsent", mock.Anything, int64(456)).Return(nil)

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin")
		mockAuditLogger.On("Log", constants.AuditDeletedUserConsent, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(123) && details["consentId"] == float64(456) && details["loggedInUser"] == "admin"
		})).Return(nil)

		mockHttpHelper.On("EncodeJson", rr, req, mock.MatchedBy(func(result interface{}) bool {
			return result.(struct{ Success bool }).Success == true
		})).Return()

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockAuditLogger.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Invalid user ID", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserConsentsPost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

		reqBody := `{"consentId": 456}`
		req, err := http.NewRequest("POST", "/admin/users/invalid/consents", strings.NewReader(reqBody))
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "invalid")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		mockHttpHelper.On("JsonError", rr, req, mock.AnythingOfType("*strconv.NumError")).Return()

		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("User not found", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserConsentsPost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

		reqBody := `{"consentId": 456}`
		req, err := http.NewRequest("POST", "/admin/users/123/consents", strings.NewReader(reqBody))
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(nil, nil)
		mockHttpHelper.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "user not found"
		})).Return()

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Consent not found", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserConsentsPost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

		reqBody := `{"consentId": 456}`
		req, err := http.NewRequest("POST", "/admin/users/123/consents", strings.NewReader(reqBody))
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		consents := []models.UserConsent{}
		mockDB.On("GetConsentsByUserId", mock.Anything, int64(123)).Return(consents, nil)

		mockHttpHelper.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "unable to revoke consent with id 456 because it doesn't belong to user id 123")
		})).Return()

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Database error", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserConsentsPost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

		reqBody := `{"consentId": 456}`
		req, err := http.NewRequest("POST", "/admin/users/123/consents", strings.NewReader(reqBody))
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		consents := []models.UserConsent{
			{Id: 456, ClientId: 1, Scope: "openid profile"},
		}
		mockDB.On("GetConsentsByUserId", mock.Anything, int64(123)).Return(consents, nil)
		mockDB.On("DeleteUserConsent", mock.Anything, int64(456)).Return(errors.New("database error"))

		mockHttpHelper.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "database error"
		})).Return()

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})
}
*/
