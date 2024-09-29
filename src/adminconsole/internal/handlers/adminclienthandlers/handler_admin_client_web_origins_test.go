package adminclienthandlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestHandleAdminClientWebOriginsGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockDB := mocks_data.NewDatabase(t)

	client := &models.Client{
		Id:               1,
		ClientIdentifier: "test-client",
	}

	webOrigins := []models.WebOrigin{
		{Id: 1, Origin: "http://localhost:8080"},
		{Id: 2, Origin: "http://example.com"},
	}

	mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)
	mockDB.On("ClientLoadWebOrigins", mock.Anything, client).Return(nil).Run(func(args mock.Arguments) {
		client := args.Get(1).(*models.Client)
		client.WebOrigins = webOrigins
	})

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_clients_web_origins.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		clientData, ok := data["client"].(struct {
			ClientId                 int64
			ClientIdentifier         string
			AuthorizationCodeEnabled bool
			WebOrigins               map[int64]string
			IsSystemLevelClient      bool
		})
		return ok &&
			clientData.ClientId == 1 &&
			clientData.ClientIdentifier == "test-client" &&
			len(clientData.WebOrigins) == 2 &&
			clientData.WebOrigins[1] == "http://localhost:8080" &&
			clientData.WebOrigins[2] == "http://example.com" &&
			!clientData.IsSystemLevelClient
	})).Return(nil)

	handler := HandleAdminClientWebOriginsGet(mockHttpHelper, mockSessionStore, mockDB)

	req, _ := http.NewRequest("GET", "/admin/clients/1/web-origins", nil)
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

func TestHandleAdminClientWebOriginsPost(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	client := &models.Client{
		Id:               1,
		ClientIdentifier: "test-client",
		WebOrigins: []models.WebOrigin{
			{Id: 1, Origin: "http://localhost:8080"},
			{Id: 2, Origin: "http://example.com"},
		},
	}

	mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)
	mockDB.On("ClientLoadWebOrigins", mock.Anything, client).Return(nil)

	// Expect creation of a new web origin
	mockDB.On("CreateWebOrigin", mock.Anything, mock.MatchedBy(func(wo *models.WebOrigin) bool {
		return wo.Origin == "http://newexample.com"
	})).Return(nil)

	// Expect deletion of an existing web origin
	mockDB.On("DeleteWebOrigin", mock.Anything, int64(2)).Return(nil)

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
	mockSessionStore.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("test-subject")

	mockAuditLogger.On("Log", constants.AuditUpdatedWebOrigins, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["clientId"] == int64(1) && details["loggedInUser"] == "test-subject"
	})).Return(nil)

	mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.MatchedBy(func(v interface{}) bool {
		result, ok := v.(struct{ Success bool })
		return ok && result.Success
	})).Run(func(args mock.Arguments) {
		w := args.Get(0).(http.ResponseWriter)
		json.NewEncoder(w).Encode(struct{ Success bool }{Success: true})
	}).Return()

	handler := HandleAdminClientWebOriginsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

	// This request body:
	// - Keeps "http://localhost:8080" (id: 1)
	// - Removes "http://example.com" (id: 2)
	// - Adds "http://newexample.com" (id: 0, indicating a new entry)
	reqBody := `{"clientId": 1, "webOrigins": ["http://localhost:8080", "http://newexample.com"], "ids": [1, 0]}`
	req, _ := http.NewRequest("POST", "/admin/clients/1/web-origins", strings.NewReader(reqBody))
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
}

func TestHandleAdminClientWebOriginsPost_SystemLevelClient(t *testing.T) {
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

	handler := HandleAdminClientWebOriginsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

	reqBody := `{"clientId": 1, "webOrigins": ["http://localhost:8080"], "ids": [1]}`
	req, _ := http.NewRequest("POST", "/admin/clients/1/web-origins", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAdminClientWebOriginsPost_InvalidOrigin(t *testing.T) {
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
	mockDB.On("ClientLoadWebOrigins", mock.Anything, client).Return(nil)

	mockHttpHelper.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		urlErr, ok := err.(*url.Error)
		return ok && urlErr.Op == "parse" && strings.Contains(urlErr.Error(), "invalid URI for request")
	})).Return()

	handler := HandleAdminClientWebOriginsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

	reqBody := `{"clientId": 1, "webOrigins": ["invalid-origin"], "ids": [0]}`
	req, _ := http.NewRequest("POST", "/admin/clients/1/web-origins", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertNotCalled(t, "Log")
}
