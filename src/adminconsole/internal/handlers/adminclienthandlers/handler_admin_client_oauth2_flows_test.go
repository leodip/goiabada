package adminclienthandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
)

func TestHandleAdminClientOAuth2Get(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockDB := mocks_data.NewDatabase(t)

	client := &models.Client{
		Id:                       1,
		ClientIdentifier:         "test-client",
		IsPublic:                 false,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}

	mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_clients_oauth2_flows.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		clientData, ok := data["client"].(struct {
			ClientId                 int64
			ClientIdentifier         string
			IsPublic                 bool
			AuthorizationCodeEnabled bool
			ClientCredentialsEnabled bool
			IsSystemLevelClient      bool
		})
		return ok &&
			clientData.ClientId == 1 &&
			clientData.ClientIdentifier == "test-client" &&
			!clientData.IsPublic &&
			clientData.AuthorizationCodeEnabled &&
			!clientData.ClientCredentialsEnabled &&
			!clientData.IsSystemLevelClient
	})).Return(nil)

	handler := HandleAdminClientOAuth2Get(mockHttpHelper, mockSessionStore, mockDB)

	req, _ := http.NewRequest("GET", "/admin/clients/1/oauth2-flows", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("clientId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminClientOAuth2Get_SavedSuccessfully(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockDB := mocks_data.NewDatabase(t)

	client := &models.Client{
		Id:                       1,
		ClientIdentifier:         "test-client",
		IsPublic:                 false,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}

	mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSession.AddFlash("true", "savedSuccessfully")
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
	mockSessionStore.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_clients_oauth2_flows.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		clientData, ok := data["client"].(struct {
			ClientId                 int64
			ClientIdentifier         string
			IsPublic                 bool
			AuthorizationCodeEnabled bool
			ClientCredentialsEnabled bool
			IsSystemLevelClient      bool
		})
		return ok &&
			clientData.ClientId == 1 &&
			clientData.ClientIdentifier == "test-client" &&
			!clientData.IsPublic &&
			clientData.AuthorizationCodeEnabled &&
			!clientData.ClientCredentialsEnabled &&
			!clientData.IsSystemLevelClient &&
			data["savedSuccessfully"] == true
	})).Return(nil)

	handler := HandleAdminClientOAuth2Get(mockHttpHelper, mockSessionStore, mockDB)

	req, _ := http.NewRequest("GET", "/admin/clients/1/oauth2-flows", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("clientId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminClientOAuth2Post(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	client := &models.Client{
		Id:                       1,
		ClientIdentifier:         "test-client",
		IsPublic:                 false,
		AuthorizationCodeEnabled: false,
		ClientCredentialsEnabled: false,
	}

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("test-subject")
	mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)

	mockDB.On("UpdateClient", mock.Anything, mock.MatchedBy(func(c *models.Client) bool {
		return c.Id == 1 &&
			c.ClientIdentifier == "test-client" &&
			!c.IsPublic &&
			c.AuthorizationCodeEnabled &&
			c.ClientCredentialsEnabled
	})).Return(nil)

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
	mockSessionStore.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

	mockAuditLogger.On("Log", constants.AuditUpdatedClientOAuth2Flows, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["clientId"] == int64(1) && details["loggedInUser"] == "test-subject"
	})).Return(nil)

	handler := HandleAdminClientOAuth2Post(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

	form := url.Values{}
	form.Add("authCodeEnabled", "on")
	form.Add("clientCredentialsEnabled", "on")
	req, _ := http.NewRequest("POST", "/admin/clients/1/oauth2-flows", strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("clientId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, config.GetAdminConsole().BaseURL+"/admin/clients/1/oauth2-flows", rr.Header().Get("Location"))

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertExpectations(t)
}

func TestHandleAdminClientOAuth2Post_SystemLevelClient(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	client := &models.Client{
		Id:               1,
		ClientIdentifier: constants.AdminConsoleClientIdentifier,
		IsPublic:         false,
	}

	mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)

	mockHttpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		return err.Error() == "trying to edit a system level client"
	}))

	handler := HandleAdminClientOAuth2Post(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

	form := url.Values{}
	form.Add("authCodeEnabled", "on")
	req, _ := http.NewRequest("POST", "/admin/clients/1/oauth2-flows", strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("clientId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAdminClientOAuth2Post_PublicClient(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	client := &models.Client{
		Id:               1,
		ClientIdentifier: "test-client",
		IsPublic:         true,
	}

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("test-subject")
	mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)

	mockDB.On("UpdateClient", mock.Anything, mock.MatchedBy(func(c *models.Client) bool {
		return c.Id == 1 &&
			c.ClientIdentifier == "test-client" &&
			c.IsPublic &&
			c.AuthorizationCodeEnabled &&
			!c.ClientCredentialsEnabled
	})).Return(nil)

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
	mockSessionStore.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

	mockAuditLogger.On("Log", constants.AuditUpdatedClientOAuth2Flows, mock.Anything).Return(nil)

	handler := HandleAdminClientOAuth2Post(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

	form := url.Values{}
	form.Add("authCodeEnabled", "on")
	form.Add("clientCredentialsEnabled", "on")
	req, _ := http.NewRequest("POST", "/admin/clients/1/oauth2-flows", strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("clientId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, config.GetAdminConsole().BaseURL+"/admin/clients/1/oauth2-flows", rr.Header().Get("Location"))

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertExpectations(t)
}
