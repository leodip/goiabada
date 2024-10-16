package adminclienthandlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestHandleAdminClientRedirectURIsGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockDB := mocks_data.NewDatabase(t)

	client := &models.Client{
		Id:                       1,
		ClientIdentifier:         "test-client",
		AuthorizationCodeEnabled: true,
	}

	redirectURIs := []models.RedirectURI{
		{Id: 1, URI: "http://localhost:8080/callback"},
		{Id: 2, URI: "http://example.com/callback"},
	}

	mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)
	mockDB.On("ClientLoadRedirectURIs", mock.Anything, client).Return(nil).Run(func(args mock.Arguments) {
		client := args.Get(1).(*models.Client)
		client.RedirectURIs = redirectURIs
	})

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_clients_redirect_uris.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		clientData, ok := data["client"].(struct {
			ClientId                 int64
			ClientIdentifier         string
			AuthorizationCodeEnabled bool
			RedirectURIs             map[int64]string
			IsSystemLevelClient      bool
		})
		return ok &&
			clientData.ClientId == 1 &&
			clientData.ClientIdentifier == "test-client" &&
			clientData.AuthorizationCodeEnabled &&
			len(clientData.RedirectURIs) == 2 &&
			clientData.RedirectURIs[1] == "http://localhost:8080/callback" &&
			clientData.RedirectURIs[2] == "http://example.com/callback" &&
			!clientData.IsSystemLevelClient
	})).Return(nil)

	handler := HandleAdminClientRedirectURIsGet(mockHttpHelper, mockSessionStore, mockDB)

	req, _ := http.NewRequest("GET", "/admin/clients/1/redirect-uris", nil)
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

func TestHandleAdminClientRedirectURIsPost(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	client := &models.Client{
		Id:               1,
		ClientIdentifier: "test-client",
	}

	existingRedirectURIs := []models.RedirectURI{
		{Id: 1, URI: "http://localhost:8080/callback", ClientId: 1},
		{Id: 2, URI: "http://example.com/callback", ClientId: 1},
	}

	mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)
	mockDB.On("ClientLoadRedirectURIs", mock.Anything, client).Return(nil).Run(func(args mock.Arguments) {
		client := args.Get(1).(*models.Client)
		client.RedirectURIs = existingRedirectURIs
	})

	mockDB.On("CreateRedirectURI", mock.Anything, mock.MatchedBy(func(r *models.RedirectURI) bool {
		return r.ClientId == 1 && r.URI == "http://newexample.com/callback"
	})).Return(nil)

	mockDB.On("DeleteRedirectURI", mock.Anything, int64(2)).Return(nil)

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
	mockSessionStore.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("test-subject")

	mockAuditLogger.On("Log", constants.AuditUpdatedRedirectURIs, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["clientId"] == int64(1) && details["loggedInUser"] == "test-subject"
	})).Return(nil)

	mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.MatchedBy(func(v interface{}) bool {
		result, ok := v.(struct{ Success bool })
		return ok && result.Success
	})).Run(func(args mock.Arguments) {
		w := args.Get(0).(http.ResponseWriter)
		err := json.NewEncoder(w).Encode(struct{ Success bool }{Success: true})
		assert.NoError(t, err)
	}).Return()

	handler := HandleAdminClientRedirectURIsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

	reqBody := `{"clientId": 1, "redirectURIs": ["http://localhost:8080/callback", "http://newexample.com/callback"], "ids": [1, 0]}`
	req, _ := http.NewRequest("POST", "/admin/clients/1/redirect-uris", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response struct {
		Success bool `json:"success"`
	}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	if assert.NoError(t, err) {
		assert.True(t, response.Success)
	}

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertExpectations(t)

	mockDB.AssertCalled(t, "CreateRedirectURI", mock.Anything, mock.MatchedBy(func(r *models.RedirectURI) bool {
		return r.ClientId == 1 && r.URI == "http://newexample.com/callback"
	}))
	mockDB.AssertCalled(t, "DeleteRedirectURI", mock.Anything, int64(2))
}

func TestHandleAdminClientRedirectURIsPost_SystemLevelClient(t *testing.T) {
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

	mockHttpHelper.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		return err.Error() == "trying to edit a system level client"
	}))

	handler := HandleAdminClientRedirectURIsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

	reqBody := `{"clientId": 1, "redirectURIs": ["http://localhost:8080/callback"], "ids": [1]}`
	req, _ := http.NewRequest("POST", "/admin/clients/1/redirect-uris", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAdminClientRedirectURIsPost_InvalidURI(t *testing.T) {
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
	mockDB.On("ClientLoadRedirectURIs", mock.Anything, client).Return(nil)

	mockHttpHelper.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		return strings.Contains(err.Error(), "invalid URI")
	}))

	handler := HandleAdminClientRedirectURIsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

	reqBody := `{"clientId": 1, "redirectURIs": ["invalid-uri"], "ids": [0]}`
	req, _ := http.NewRequest("POST", "/admin/clients/1/redirect-uris", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertNotCalled(t, "Log")
}
