package adminuserhandlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

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

func TestHandleAdminUserDetailsGet(t *testing.T) {
	t.Run("Valid user", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)

		handler := HandleAdminUserDetailsGet(mockHttpHelper, mockSessionStore, mockDB)

		req, err := http.NewRequest("GET", "/admin/users/123/details", nil)
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/menu_layout.html", "/admin_users_details.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["user"] == user &&
				data["page"] == "" &&
				data["query"] == "" &&
				data["savedSuccessfully"] == false &&
				data["userCreated"] == false &&
				data["csrfField"] != nil
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

		handler := HandleAdminUserDetailsGet(mockHttpHelper, mockSessionStore, mockDB)

		req, err := http.NewRequest("GET", "/admin/users/invalid/details", nil)
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

		handler := HandleAdminUserDetailsGet(mockHttpHelper, mockSessionStore, mockDB)

		req, err := http.NewRequest("GET", "/admin/users/123/details", nil)
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

func TestHandleAdminUserDetailsPost(t *testing.T) {
	t.Run("Valid update", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserDetailsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

		req, err := http.NewRequest("POST", "/admin/users/123/details", nil)
		assert.NoError(t, err)
		req.Form = make(map[string][]string)
		req.Form.Add("enabled", "on")

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com", Enabled: false}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)
		mockDB.On("UpdateUser", mock.Anything, mock.MatchedBy(func(u *models.User) bool {
			return u.Id == 123 && u.Enabled == true
		})).Return(nil)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
		mockSessionStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin")
		mockAuditLogger.On("Log", constants.AuditUpdatedUserDetails, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(123) && details["loggedInUser"] == "admin"
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Contains(t, rr.Header().Get("Location"), "/admin/users/123/details")

		mockDB.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockAuditLogger.AssertExpectations(t)
	})

	t.Run("Invalid user ID", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserDetailsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

		req, err := http.NewRequest("POST", "/admin/users/invalid/details", nil)
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
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserDetailsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

		req, err := http.NewRequest("POST", "/admin/users/123/details", nil)
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

	t.Run("Database error", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserDetailsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

		req, err := http.NewRequest("POST", "/admin/users/123/details", nil)
		assert.NoError(t, err)
		req.Form = make(map[string][]string)
		req.Form.Add("enabled", "on")

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com", Enabled: false}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)
		mockDB.On("UpdateUser", mock.Anything, mock.AnythingOfType("*models.User")).Return(errors.New("database error"))

		mockHttpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "database error"
		})).Return()

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})
}
