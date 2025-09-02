package adminuserhandlers

// Commented out during API migration - will be updated later

// import (
// 	"context"
// 	"errors"
// 	"net/http"
// 	"net/http/httptest"
// 	"testing"

// 	"github.com/go-chi/chi/v5"
// 	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
// 	"github.com/leodip/goiabada/core/constants"
// 	"github.com/leodip/goiabada/core/models"
// 	"github.com/stretchr/testify/assert"
// 	"github.com/stretchr/testify/mock"

// 	mocks_data "github.com/leodip/goiabada/core/data/mocks"
// 	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
// )

// func TestHandleAdminUserAttributesGet(t *testing.T) {
// 	t.Run("Valid user and attributes", func(t *testing.T) {
// 		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
// 		mockDB := mocks_data.NewDatabase(t)

// 		handler := HandleAdminUserAttributesGet(mockHttpHelper, mockDB)

// 		req, err := http.NewRequest("GET", "/admin/users/123/attributes", nil)
// 		assert.NoError(t, err)

// 		rctx := chi.NewRouteContext()
// 		rctx.URLParams.Add("userId", "123")
// 		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

// 		rr := httptest.NewRecorder()

// 		user := &models.User{Id: 123, Email: "test@example.com"}
// 		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

// 		attributes := []models.UserAttribute{
// 			{Id: 1, Key: "attr1", Value: "value1"},
// 			{Id: 2, Key: "attr2", Value: "value2"},
// 		}
// 		mockDB.On("GetUserAttributesByUserId", mock.Anything, int64(123)).Return(attributes, nil)

// 		mockHttpHelper.On("RenderTemplate",
// 			rr,
// 			req,
// 			"/layouts/menu_layout.html",
// 			"/admin_users_attributes.html",
// 			mock.MatchedBy(func(data map[string]interface{}) bool {
// 				return data["user"] == user &&
// 					len(data["attributes"].([]models.UserAttribute)) == 2 &&
// 					data["attributes"].([]models.UserAttribute)[0].Key == "attr1" &&
// 					data["attributes"].([]models.UserAttribute)[1].Key == "attr2"
// 			}),
// 		).Return(nil)

// 		handler.ServeHTTP(rr, req)

// 		assert.Equal(t, http.StatusOK, rr.Code)
// 		mockDB.AssertExpectations(t)
// 		mockHttpHelper.AssertExpectations(t)
// 	})

// 	t.Run("Invalid user ID", func(t *testing.T) {
// 		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
// 		mockDB := mocks_data.NewDatabase(t)

// 		handler := HandleAdminUserAttributesGet(mockHttpHelper, mockDB)

// 		req, err := http.NewRequest("GET", "/admin/users/invalid/attributes", nil)
// 		assert.NoError(t, err)

// 		rctx := chi.NewRouteContext()
// 		rctx.URLParams.Add("userId", "invalid")
// 		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

// 		rr := httptest.NewRecorder()

// 		mockHttpHelper.On("InternalServerError", rr, req, mock.AnythingOfType("*strconv.NumError")).Return()

// 		handler.ServeHTTP(rr, req)

// 		mockHttpHelper.AssertExpectations(t)
// 	})

// 	t.Run("User not found", func(t *testing.T) {
// 		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
// 		mockDB := mocks_data.NewDatabase(t)

// 		handler := HandleAdminUserAttributesGet(mockHttpHelper, mockDB)

// 		req, err := http.NewRequest("GET", "/admin/users/123/attributes", nil)
// 		assert.NoError(t, err)

// 		rctx := chi.NewRouteContext()
// 		rctx.URLParams.Add("userId", "123")
// 		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

// 		rr := httptest.NewRecorder()

// 		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(nil, nil)
// 		mockHttpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
// 			return err.Error() == "user not found"
// 		})).Return()

// 		handler.ServeHTTP(rr, req)

// 		mockDB.AssertExpectations(t)
// 		mockHttpHelper.AssertExpectations(t)
// 	})
// }

// func TestHandleAdminUserAttributesRemovePost(t *testing.T) {
// 	t.Run("Valid removal", func(t *testing.T) {
// 		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
// 		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
// 		mockDB := mocks_data.NewDatabase(t)
// 		mockAuditLogger := mocks_audit.NewAuditLogger(t)

// 		handler := HandleAdminUserAttributesRemovePost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

// 		req, err := http.NewRequest("POST", "/admin/users/123/attributes/456/remove", nil)
// 		assert.NoError(t, err)

// 		rctx := chi.NewRouteContext()
// 		rctx.URLParams.Add("userId", "123")
// 		rctx.URLParams.Add("attributeId", "456")
// 		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

// 		rr := httptest.NewRecorder()

// 		user := &models.User{Id: 123, Email: "test@example.com"}
// 		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

// 		attributes := []models.UserAttribute{
// 			{Id: 456, Key: "attr1", Value: "value1"},
// 		}
// 		mockDB.On("GetUserAttributesByUserId", mock.Anything, int64(123)).Return(attributes, nil)

// 		mockDB.On("DeleteUserAttribute", mock.Anything, int64(456)).Return(nil)

// 		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin")
// 		mockAuditLogger.On("Log", constants.AuditDeleteUserAttribute, mock.MatchedBy(func(details map[string]interface{}) bool {
// 			return details["userId"] == int64(123) &&
// 				details["userAttributeId"] == int64(456) &&
// 				details["loggedInUser"] == "admin"
// 		})).Return(nil)

// 		mockHttpHelper.On("EncodeJson", rr, req, mock.MatchedBy(func(result interface{}) bool {
// 			return result.(struct{ Success bool }).Success == true
// 		})).Return()

// 		handler.ServeHTTP(rr, req)

// 		mockDB.AssertExpectations(t)
// 		mockAuthHelper.AssertExpectations(t)
// 		mockAuditLogger.AssertExpectations(t)
// 		mockHttpHelper.AssertExpectations(t)
// 	})

// 	t.Run("Invalid user ID", func(t *testing.T) {
// 		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
// 		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
// 		mockDB := mocks_data.NewDatabase(t)
// 		mockAuditLogger := mocks_audit.NewAuditLogger(t)

// 		handler := HandleAdminUserAttributesRemovePost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

// 		req, err := http.NewRequest("POST", "/admin/users/invalid/attributes/456/remove", nil)
// 		assert.NoError(t, err)

// 		rctx := chi.NewRouteContext()
// 		rctx.URLParams.Add("userId", "invalid")
// 		rctx.URLParams.Add("attributeId", "456")
// 		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

// 		rr := httptest.NewRecorder()

// 		mockHttpHelper.On("JsonError", rr, req, mock.AnythingOfType("*strconv.NumError")).Return()

// 		handler.ServeHTTP(rr, req)

// 		mockHttpHelper.AssertExpectations(t)
// 	})

// 	t.Run("User not found", func(t *testing.T) {
// 		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
// 		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
// 		mockDB := mocks_data.NewDatabase(t)
// 		mockAuditLogger := mocks_audit.NewAuditLogger(t)

// 		handler := HandleAdminUserAttributesRemovePost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

// 		req, err := http.NewRequest("POST", "/admin/users/123/attributes/456/remove", nil)
// 		assert.NoError(t, err)

// 		rctx := chi.NewRouteContext()
// 		rctx.URLParams.Add("userId", "123")
// 		rctx.URLParams.Add("attributeId", "456")
// 		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

// 		rr := httptest.NewRecorder()

// 		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(nil, nil)
// 		mockHttpHelper.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
// 			return err.Error() == "user not found"
// 		})).Return()

// 		handler.ServeHTTP(rr, req)

// 		mockDB.AssertExpectations(t)
// 		mockHttpHelper.AssertExpectations(t)
// 	})

// 	t.Run("Attribute not found", func(t *testing.T) {
// 		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
// 		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
// 		mockDB := mocks_data.NewDatabase(t)
// 		mockAuditLogger := mocks_audit.NewAuditLogger(t)

// 		handler := HandleAdminUserAttributesRemovePost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

// 		req, err := http.NewRequest("POST", "/admin/users/123/attributes/456/remove", nil)
// 		assert.NoError(t, err)

// 		rctx := chi.NewRouteContext()
// 		rctx.URLParams.Add("userId", "123")
// 		rctx.URLParams.Add("attributeId", "456")
// 		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

// 		rr := httptest.NewRecorder()

// 		user := &models.User{Id: 123, Email: "test@example.com"}
// 		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

// 		attributes := []models.UserAttribute{}
// 		mockDB.On("GetUserAttributesByUserId", mock.Anything, int64(123)).Return(attributes, nil)

// 		mockHttpHelper.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
// 			return err.Error() == "attribute not found"
// 		})).Return()

// 		handler.ServeHTTP(rr, req)

// 		mockDB.AssertExpectations(t)
// 		mockHttpHelper.AssertExpectations(t)
// 	})

// 	t.Run("Database error", func(t *testing.T) {
// 		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
// 		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
// 		mockDB := mocks_data.NewDatabase(t)
// 		mockAuditLogger := mocks_audit.NewAuditLogger(t)

// 		handler := HandleAdminUserAttributesRemovePost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

// 		req, err := http.NewRequest("POST", "/admin/users/123/attributes/456/remove", nil)
// 		assert.NoError(t, err)

// 		rctx := chi.NewRouteContext()
// 		rctx.URLParams.Add("userId", "123")
// 		rctx.URLParams.Add("attributeId", "456")
// 		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

// 		rr := httptest.NewRecorder()

// 		user := &models.User{Id: 123, Email: "test@example.com"}
// 		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

// 		attributes := []models.UserAttribute{
// 			{Id: 456, Key: "attr1", Value: "value1"},
// 		}
// 		mockDB.On("GetUserAttributesByUserId", mock.Anything, int64(123)).Return(attributes, nil)

// 		mockDB.On("DeleteUserAttribute", mock.Anything, int64(456)).Return(errors.New("database error"))
// 		mockHttpHelper.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
// 			return err.Error() == "database error"
// 		})).Return()

// 		handler.ServeHTTP(rr, req)

// 		mockDB.AssertExpectations(t)
// 		mockHttpHelper.AssertExpectations(t)
// 	})
// }
