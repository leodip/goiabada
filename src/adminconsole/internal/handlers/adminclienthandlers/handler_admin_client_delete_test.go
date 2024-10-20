package adminclienthandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
)

func TestHandleAdminClientDeleteGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	client := &models.Client{
		Id:               1,
		ClientIdentifier: "test-client",
	}

	mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_clients_delete.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["client"] == client && data["csrfField"] != nil
	})).Return(nil)

	handler := HandleAdminClientDeleteGet(mockHttpHelper, mockDB)

	req, _ := http.NewRequest("GET", "/admin/clients/1/delete", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("clientId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminClientDeletePost(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	client := &models.Client{
		Id:               1,
		ClientIdentifier: "test-client",
	}

	mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)
	mockDB.On("DeleteClient", mock.Anything, int64(1)).Return(nil)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("test-subject")

	mockAuditLogger.On("Log", constants.AuditDeletedClient, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["clientId"] == int64(1) && details["clientIdentifier"] == "test-client" && details["loggedInUser"] == "test-subject"
	})).Return(nil)

	handler := HandleAdminClientDeletePost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

	form := url.Values{}
	form.Add("clientIdentifier", "test-client")
	req, _ := http.NewRequest("POST", "/admin/clients/1/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("clientId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, config.Get().BaseURL+"/admin/clients", rr.Header().Get("Location"))

	mockHttpHelper.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertExpectations(t)
}

func TestHandleAdminClientDeletePost_InvalidClientIdentifier(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	client := &models.Client{
		Id:               1,
		ClientIdentifier: "test-client",
	}

	mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_clients_delete.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["client"] == client && data["error"] == "Client identifier does not match the client being deleted." && data["csrfField"] != nil
	})).Return(nil)

	handler := HandleAdminClientDeletePost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

	form := url.Values{}
	form.Add("clientIdentifier", "wrong-client")
	req, _ := http.NewRequest("POST", "/admin/clients/1/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("clientId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuthHelper.AssertNotCalled(t, "GetLoggedInSubject")
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAdminClientDeletePost_SystemLevelClient(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	client := &models.Client{
		Id:               1,
		ClientIdentifier: constants.AdminConsoleClientIdentifier,
	}

	mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)

	mockHttpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		return err.Error() == "cannot delete system level client"
	})).Return()

	handler := HandleAdminClientDeletePost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

	form := url.Values{}
	form.Add("clientIdentifier", constants.AdminConsoleClientIdentifier)
	req, _ := http.NewRequest("POST", "/admin/clients/1/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("clientId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuthHelper.AssertNotCalled(t, "GetLoggedInSubject")
	mockAuditLogger.AssertNotCalled(t, "Log")
}
