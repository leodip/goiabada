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
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
)

func TestHandleAdminClientTokensGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockDB := mocks_data.NewDatabase(t)

	client := &models.Client{
		Id:                                      1,
		ClientIdentifier:                        "test-client",
		TokenExpirationInSeconds:                3600,
		RefreshTokenOfflineIdleTimeoutInSeconds: 86400,
		RefreshTokenOfflineMaxLifetimeInSeconds: 2592000,
		IncludeOpenIDConnectClaimsInAccessToken: enums.ThreeStateSettingDefault.String(),
	}

	mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_clients_tokens.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		settings, ok := data["settings"].(struct {
			TokenExpirationInSeconds                int
			RefreshTokenOfflineIdleTimeoutInSeconds int
			RefreshTokenOfflineMaxLifetimeInSeconds int
			IncludeOpenIDConnectClaimsInAccessToken string
		})
		return ok &&
			settings.TokenExpirationInSeconds == 3600 &&
			settings.RefreshTokenOfflineIdleTimeoutInSeconds == 86400 &&
			settings.RefreshTokenOfflineMaxLifetimeInSeconds == 2592000 &&
			settings.IncludeOpenIDConnectClaimsInAccessToken == enums.ThreeStateSettingDefault.String()
	})).Return(nil)

	handler := HandleAdminClientTokensGet(mockHttpHelper, mockSessionStore, mockDB)

	req, _ := http.NewRequest("GET", "/admin/clients/1/tokens", nil)
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

func TestHandleAdminClientTokensPost(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	client := &models.Client{
		Id:               1,
		ClientIdentifier: "test-client",
	}

	mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)
	mockDB.On("UpdateClient", mock.Anything, mock.MatchedBy(func(c *models.Client) bool {
		return c.Id == 1 &&
			c.TokenExpirationInSeconds == 7200 &&
			c.RefreshTokenOfflineIdleTimeoutInSeconds == 172800 &&
			c.RefreshTokenOfflineMaxLifetimeInSeconds == 5184000 &&
			c.IncludeOpenIDConnectClaimsInAccessToken == enums.ThreeStateSettingOn.String()
	})).Return(nil)

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
	mockSessionStore.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("test-subject")

	mockAuditLogger.On("Log", constants.AuditUpdatedClientTokens, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["clientId"] == int64(1) && details["loggedInUser"] == "test-subject"
	})).Return(nil)

	handler := HandleAdminClientTokensPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

	form := url.Values{}
	form.Add("tokenExpirationInSeconds", "7200")
	form.Add("refreshTokenOfflineIdleTimeoutInSeconds", "172800")
	form.Add("refreshTokenOfflineMaxLifetimeInSeconds", "5184000")
	form.Add("includeOpenIDConnectClaimsInAccessToken", enums.ThreeStateSettingOn.String())

	req, _ := http.NewRequest("POST", "/admin/clients/1/tokens", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("clientId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, config.GetAdminConsole().BaseURL+"/admin/clients/1/tokens", rr.Header().Get("Location"))

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertExpectations(t)
}

func TestHandleAdminClientTokensPost_SystemLevelClient(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	client := &models.Client{
		Id:               1,
		ClientIdentifier: constants.AdminConsoleClientIdentifier,
	}

	mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)

	mockHttpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		return err.Error() == "trying to edit a system level client"
	}))

	handler := HandleAdminClientTokensPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

	form := url.Values{}
	form.Add("tokenExpirationInSeconds", "7200")
	form.Add("refreshTokenOfflineIdleTimeoutInSeconds", "172800")
	form.Add("refreshTokenOfflineMaxLifetimeInSeconds", "5184000")
	form.Add("includeOpenIDConnectClaimsInAccessToken", enums.ThreeStateSettingOn.String())

	req, _ := http.NewRequest("POST", "/admin/clients/1/tokens", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("clientId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAdminClientTokensPost_InvalidTokenExpiration(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	client := &models.Client{
		Id:               1,
		ClientIdentifier: "test-client",
	}

	mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_clients_tokens.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "Invalid value for token expiration in seconds."
	})).Return(nil)

	handler := HandleAdminClientTokensPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

	form := url.Values{}
	form.Add("tokenExpirationInSeconds", "invalid")
	form.Add("refreshTokenOfflineIdleTimeoutInSeconds", "86400")
	form.Add("refreshTokenOfflineMaxLifetimeInSeconds", "2592000")
	form.Add("includeOpenIDConnectClaimsInAccessToken", enums.ThreeStateSettingOn.String())

	req, _ := http.NewRequest("POST", "/admin/clients/1/tokens", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("clientId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAdminClientTokensPost_InvalidRefreshTokenIdleTimeout(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	client := &models.Client{
		Id:               1,
		ClientIdentifier: "test-client",
	}

	mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_clients_tokens.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "Invalid value for refresh token offline - idle timeout in seconds."
	})).Return(nil)

	handler := HandleAdminClientTokensPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

	form := url.Values{}
	form.Add("tokenExpirationInSeconds", "3600")
	form.Add("refreshTokenOfflineIdleTimeoutInSeconds", "invalid")
	form.Add("refreshTokenOfflineMaxLifetimeInSeconds", "2592000")
	form.Add("includeOpenIDConnectClaimsInAccessToken", enums.ThreeStateSettingOn.String())

	req, _ := http.NewRequest("POST", "/admin/clients/1/tokens", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("clientId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAdminClientTokensPost_InvalidRefreshTokenMaxLifetime(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	client := &models.Client{
		Id:               1,
		ClientIdentifier: "test-client",
	}

	mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_clients_tokens.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "Invalid value for refresh token offline - max lifetime in seconds."
	})).Return(nil)

	handler := HandleAdminClientTokensPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

	form := url.Values{}
	form.Add("tokenExpirationInSeconds", "3600")
	form.Add("refreshTokenOfflineIdleTimeoutInSeconds", "86400")
	form.Add("refreshTokenOfflineMaxLifetimeInSeconds", "invalid")
	form.Add("includeOpenIDConnectClaimsInAccessToken", enums.ThreeStateSettingOn.String())

	req, _ := http.NewRequest("POST", "/admin/clients/1/tokens", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("clientId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAdminClientTokensPost_RefreshTokenIdleTimeoutGreaterThanMaxLifetime(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	client := &models.Client{
		Id:               1,
		ClientIdentifier: "test-client",
	}

	mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_clients_tokens.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "Refresh token offline - idle timeout cannot be greater than max lifetime."
	})).Return(nil)

	handler := HandleAdminClientTokensPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

	form := url.Values{}
	form.Add("tokenExpirationInSeconds", "3600")
	form.Add("refreshTokenOfflineIdleTimeoutInSeconds", "172800")
	form.Add("refreshTokenOfflineMaxLifetimeInSeconds", "86400")
	form.Add("includeOpenIDConnectClaimsInAccessToken", enums.ThreeStateSettingOn.String())

	req, _ := http.NewRequest("POST", "/admin/clients/1/tokens", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("clientId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertNotCalled(t, "Log")
}
