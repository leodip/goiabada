package apihandlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/revocation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// assertJSONInternalServerError holds a response to the admin and account API's one 500 shape
// (#279 decision 7): status 500, a JSON body, error_code INTERNAL_SERVER_ERROR, and no HTML. The
// last assertion is the one that matters here. These branches used to answer through
// httpHelper.InternalServerError, which renders error.html, so a database failure on an API route
// gave the admin console's fetch a page to JSON.parse.
func assertJSONInternalServerError(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, rr.Header().Get("Content-Type"), "application/json")

	body := rr.Body.String()
	assert.NotContains(t, body, "<html", "a 500 on the API surface must not render a page: %s", body)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, "INTERNAL_SERVER_ERROR", response["error_code"])
}

func TestHandleUserConsentsGet_Success(t *testing.T) {
	database := datamocks.NewDatabase(t)
	handler := HandleUserConsentsGet(database)

	user := &record.User{Id: 7}
	consents := []record.UserConsent{{Id: 1, UserId: 7, ClientId: 3, Scope: "openid"}}

	req, _ := http.NewRequest("GET", "/api/v1/admin/users/7/consents", nil)
	req = setChiURLParam(req, "id", "7")
	rr := httptest.NewRecorder()

	database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(user, nil)
	database.On("GetConsentsByUserId", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(consents, nil)
	database.On("UserConsentsLoadClients", mock.Anything, (*sql.Tx)(nil), consents).Return(nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var response map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))
	assert.Len(t, response["consents"], 1)
	database.AssertExpectations(t)
}

func TestHandleUserConsentsGet_GetUserFails_JSON500(t *testing.T) {
	database := datamocks.NewDatabase(t)
	handler := HandleUserConsentsGet(database)

	req, _ := http.NewRequest("GET", "/api/v1/admin/users/7/consents", nil)
	req = setChiURLParam(req, "id", "7")
	rr := httptest.NewRecorder()

	database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(nil, assert.AnError)

	handler.ServeHTTP(rr, req)

	assertJSONInternalServerError(t, rr)
	database.AssertExpectations(t)
}

func TestHandleUserConsentsGet_GetConsentsFails_JSON500(t *testing.T) {
	database := datamocks.NewDatabase(t)
	handler := HandleUserConsentsGet(database)

	req, _ := http.NewRequest("GET", "/api/v1/admin/users/7/consents", nil)
	req = setChiURLParam(req, "id", "7")
	rr := httptest.NewRecorder()

	database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(&record.User{Id: 7}, nil)
	database.On("GetConsentsByUserId", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(nil, assert.AnError)

	handler.ServeHTTP(rr, req)

	assertJSONInternalServerError(t, rr)
	database.AssertExpectations(t)
}

func TestHandleUserConsentsGet_LoadClientsFails_JSON500(t *testing.T) {
	database := datamocks.NewDatabase(t)
	handler := HandleUserConsentsGet(database)

	consents := []record.UserConsent{{Id: 1, UserId: 7, ClientId: 3}}

	req, _ := http.NewRequest("GET", "/api/v1/admin/users/7/consents", nil)
	req = setChiURLParam(req, "id", "7")
	rr := httptest.NewRecorder()

	database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(&record.User{Id: 7}, nil)
	database.On("GetConsentsByUserId", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(consents, nil)
	database.On("UserConsentsLoadClients", mock.Anything, (*sql.Tx)(nil), consents).Return(assert.AnError)

	handler.ServeHTTP(rr, req)

	assertJSONInternalServerError(t, rr)
	database.AssertExpectations(t)
}

// consentWithdrawalTx is the transaction the withdrawal's revocation runs in, the counterpart of
// apiTerminateTx. A nil one would let an expectation match a write made outside any transaction.
var consentWithdrawalTx = &sql.Tx{}

func TestHandleUserConsentDelete_Success(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	handler := HandleUserConsentDelete(database, auditLogger)

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/user-consents/5", nil)
	req = setChiURLParam(req, "id", "5")
	// The audit row names the administrator the token belongs to. It read an untyped "subject"
	// key nothing writes, so every such row named nobody (#433).
	req = setTokenContextWithClaims(req, map[string]interface{}{"scope": "authserver:manage", "sub": "admin-subject-1"})
	rr := httptest.NewRecorder()

	database.On("GetUserConsentById", mock.Anything, (*sql.Tx)(nil), int64(5)).
		Return(&record.UserConsent{Id: 5, UserId: 7, ClientId: 3}, nil)
	// The withdrawal deletes the consent and sweeps what it leaves standing inside ONE
	// transaction (#622). One live family token, so the family record is written under the
	// withdrawal's reason and the sweep flips the token before it saves it. The enumeration is
	// expected on exactly this user and client, so a sweep that reached for any other user's
	// tokens would fail as an unexpected call.
	datamocks.ExpectRunInTransaction(database, consentWithdrawalTx)
	database.On("DeleteUserConsent", mock.Anything, consentWithdrawalTx, int64(5)).Return(nil).Once()
	database.On("GetRefreshTokensByUserIdAndClientId", mock.Anything, consentWithdrawalTx, int64(7), int64(3)).
		Return([]*record.RefreshToken{
			{Id: 11, RefreshTokenJti: "rt-live", FirstRefreshTokenJti: "rt-first"},
			{Id: 12, RefreshTokenJti: "rt-already-gone", FirstRefreshTokenJti: "rt-first", Revoked: true},
		}, nil).Once()
	database.On("RecordRefreshTokenFamilyRevoked", mock.Anything, consentWithdrawalTx, "rt-first", revocation.ReasonConsentWithdrawn).
		Return(true, nil).Once()
	database.On("UpdateRefreshToken", mock.Anything, consentWithdrawalTx, mock.MatchedBy(func(rt *record.RefreshToken) bool {
		return rt.RefreshTokenJti == "rt-live" && rt.Revoked
	})).Return(nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventDeletedUserConsent, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["user_id"] == int64(7) && details["consent_id"] == int64(5) &&
			details["logged_in_user"] == "admin-subject-1"
	})).Return()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

func TestHandleUserConsentDelete_GetConsentFails_JSON500(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	handler := HandleUserConsentDelete(database, auditLogger)

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/user-consents/5", nil)
	req = setChiURLParam(req, "id", "5")
	rr := httptest.NewRecorder()

	database.On("GetUserConsentById", mock.Anything, (*sql.Tx)(nil), int64(5)).Return(nil, assert.AnError)

	handler.ServeHTTP(rr, req)

	assertJSONInternalServerError(t, rr)
	database.AssertExpectations(t)
}

func TestHandleUserConsentDelete_DeleteFails_JSON500(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	handler := HandleUserConsentDelete(database, auditLogger)

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/user-consents/5", nil)
	req = setChiURLParam(req, "id", "5")
	rr := httptest.NewRecorder()

	database.On("GetUserConsentById", mock.Anything, (*sql.Tx)(nil), int64(5)).
		Return(&record.UserConsent{Id: 5, UserId: 7, ClientId: 3}, nil)
	// No token: the target ceiling reads what the user holds, and an ordinary user's write goes on.
	expectHoldsNothing(database, 7)
	// The delete runs as the withdrawal's own write, first inside the transaction, and its
	// failure is what the handler reports: nothing after it, neither the enumeration nor the
	// sweep, runs (#622).
	datamocks.ExpectRunInTransaction(database, consentWithdrawalTx)
	database.On("DeleteUserConsent", mock.Anything, consentWithdrawalTx, int64(5)).Return(assert.AnError).Once()

	handler.ServeHTTP(rr, req)

	assertJSONInternalServerError(t, rr)
	database.AssertExpectations(t)
	// Nothing was deleted, so nothing is audited.
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}
