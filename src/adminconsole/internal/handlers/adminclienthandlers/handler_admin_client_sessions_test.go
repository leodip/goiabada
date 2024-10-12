package adminclienthandlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
)

func TestHandleAdminClientUserSessionsGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	client := &models.Client{
		Id:               1,
		ClientIdentifier: "test-client",
	}

	userSessions := make([]models.UserSession, 20)
	validSessions := 0
	for i := 0; i < 20; i++ {
		isValid := i < 15 // First 15 sessions are valid, the other 5 are invalid
		lastAccessed := time.Now().Add(-time.Duration(i+1) * time.Second)
		if !isValid {
			// Make invalid sessions appear older
			lastAccessed = time.Now().Add(-25 * time.Hour)
		}

		userSessions[i] = models.UserSession{
			Id:                int64(i + 1),
			SessionIdentifier: fmt.Sprintf("session%d", i+1),
			Started:           time.Now().Add(-time.Duration(i+1) * time.Minute),
			LastAccessed:      lastAccessed,
			IpAddress:         fmt.Sprintf("192.168.1.%d", i+1),
			DeviceName:        fmt.Sprintf("Device%d", i+1),
			UserId:            int64(i + 1),
			User:              models.User{Id: int64(i + 1), Email: fmt.Sprintf("user%d@example.com", i+1)},
			Clients:           []models.UserSessionClient{},
		}
		if isValid {
			validSessions++
		}
	}

	mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)
	mockDB.On("GetUserSessionsByClientIdPaginated", mock.Anything, int64(1), 1, 30).Return(userSessions, 20, nil)
	mockDB.On("UserSessionsLoadClients", mock.Anything, mock.AnythingOfType("[]models.UserSession")).Return(nil)
	mockDB.On("UserSessionsLoadUsers", mock.Anything, mock.AnythingOfType("[]models.UserSession")).Return(nil)
	mockDB.On("UserSessionClientsLoadClients", mock.Anything, mock.AnythingOfType("[]models.UserSessionClient")).Return(nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_clients_usersessions.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		clientData, ok := data["client"].(*models.Client)
		if !ok || clientData.Id != 1 || clientData.ClientIdentifier != "test-client" {
			return false
		}

		sessions, ok := data["sessions"].([]SessionInfo)
		if !ok || len(sessions) != 15 { // Only the first 15 sessions are valid
			return false
		}

		// Check if sessions are sorted by UserSessionId in descending order
		for i := 1; i < len(sessions); i++ {
			if sessions[i-1].UserSessionId <= sessions[i].UserSessionId {
				return false
			}
		}

		// Check details of the first and last session
		firstSession := sessions[0]
		lastSession := sessions[len(sessions)-1]

		// Validate first session
		if firstSession.UserSessionId != 15 ||
			firstSession.UserEmail != "user15@example.com" ||
			firstSession.IpAddress != "192.168.1.15" ||
			firstSession.DeviceName != "Device15" {
			return false
		}

		// Validate last session
		if lastSession.UserSessionId != 1 ||
			lastSession.UserEmail != "user1@example.com" ||
			lastSession.IpAddress != "192.168.1.1" ||
			lastSession.DeviceName != "Device1" {
			return false
		}

		// Check if csrfField is present
		if _, ok := data["csrfField"]; !ok {
			return false
		}

		return true
	})).Return(nil)

	handler := HandleAdminClientUserSessionsGet(mockHttpHelper, mockDB)

	req, _ := http.NewRequest("GET", "/admin/clients/1/user-sessions", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("clientId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{
		UserSessionIdleTimeoutInSeconds: 3600,
		UserSessionMaxLifetimeInSeconds: 86400,
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminClientUserSessionsPost(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	clientId := int64(1)
	client := &models.Client{
		Id:               clientId,
		ClientIdentifier: "test-client",
	}

	userSessionId := int64(100)
	userSession := &models.UserSession{
		Id:        userSessionId,
		UserId:    1,
		IpAddress: "192.168.1.1",
	}

	user := &models.User{
		Id:      1,
		Subject: uuid.New(),
		Email:   "test@example.com",
	}

	mockDB.On("GetClientById", mock.Anything, clientId).Return(client, nil)
	mockDB.On("GetUserSessionById", mock.Anything, userSessionId).Return(userSession, nil)
	mockDB.On("DeleteUserSession", mock.Anything, userSessionId).Return(nil)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())

	mockAuditLogger.On("Log", constants.AuditDeletedUserSession, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["userSessionId"] == float64(userSessionId) && details["loggedInUser"] == user.Subject.String()
	})).Return(nil)

	mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.MatchedBy(func(v interface{}) bool {
		result, ok := v.(struct{ Success bool })
		return ok && result.Success
	})).Run(func(args mock.Arguments) {
		w := args.Get(0).(http.ResponseWriter)
		err := json.NewEncoder(w).Encode(struct{ Success bool }{Success: true})
		assert.NoError(t, err)
	}).Return()

	handler := HandleAdminClientUserSessionsPost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

	reqBody := `{"userSessionId": 100}`
	req, _ := http.NewRequest("POST", "/admin/clients/1/user-sessions", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("clientId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response struct {
		Success bool `json:"success"`
	}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response.Success)

	mockHttpHelper.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertExpectations(t)
}
