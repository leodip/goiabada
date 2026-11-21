package apihandlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/backchannel"
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

	user := &record.User{ID: 7}
	consents := []record.UserConsent{{ID: 1, UserID: 7, ClientID: 3, Scope: "openid"}}

	req, _ := http.NewRequest("GET", "/api/v1/admin/users/7/consents", nil)
	req.SetPathValue("id", "7")
	rr := httptest.NewRecorder()

	database.On("GetUserByID", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(user, nil)
	database.On("GetConsentsByUserID", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(consents, nil)
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
	req.SetPathValue("id", "7")
	rr := httptest.NewRecorder()

	database.On("GetUserByID", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(nil, assert.AnError)

	handler.ServeHTTP(rr, req)

	assertJSONInternalServerError(t, rr)
	database.AssertExpectations(t)
}

func TestHandleUserConsentsGet_GetConsentsFails_JSON500(t *testing.T) {
	database := datamocks.NewDatabase(t)
	handler := HandleUserConsentsGet(database)

	req, _ := http.NewRequest("GET", "/api/v1/admin/users/7/consents", nil)
	req.SetPathValue("id", "7")
	rr := httptest.NewRecorder()

	database.On("GetUserByID", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(&record.User{ID: 7}, nil)
	database.On("GetConsentsByUserID", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(nil, assert.AnError)

	handler.ServeHTTP(rr, req)

	assertJSONInternalServerError(t, rr)
	database.AssertExpectations(t)
}

func TestHandleUserConsentsGet_LoadClientsFails_JSON500(t *testing.T) {
	database := datamocks.NewDatabase(t)
	handler := HandleUserConsentsGet(database)

	consents := []record.UserConsent{{ID: 1, UserID: 7, ClientID: 3}}

	req, _ := http.NewRequest("GET", "/api/v1/admin/users/7/consents", nil)
	req.SetPathValue("id", "7")
	rr := httptest.NewRecorder()

	database.On("GetUserByID", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(&record.User{ID: 7}, nil)
	database.On("GetConsentsByUserID", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(consents, nil)
	database.On("UserConsentsLoadClients", mock.Anything, (*sql.Tx)(nil), consents).Return(assert.AnError)

	handler.ServeHTTP(rr, req)

	assertJSONInternalServerError(t, rr)
	database.AssertExpectations(t)
}

// consentWithdrawalTx is the transaction the withdrawal's revocation runs in, the counterpart of
// apiTerminateTx. A nil one would let an expectation match a write made outside any transaction.
var consentWithdrawalTx = &sql.Tx{}

// expectWithdrawnClientTellsNobody registers the withdrawal's first read, the consent's client 3,
// which registered no back-channel logout URI, so the withdrawal tells nobody (#135 decision 3).
func expectWithdrawnClientTellsNobody(database *datamocks.Database) {
	database.On("GetClientsByIDs", mock.Anything, consentWithdrawalTx, []int64{3}).
		Return([]record.Client{{ID: 3, ClientIdentifier: "no-logout-uri"}}, nil)
}

func TestHandleUserConsentDelete_Success(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	handler := HandleUserConsentDelete(database, auditLogger, &recordingLogoutTokens{})

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/user-consents/5", nil)
	req.SetPathValue("id", "5")
	// The audit row names the administrator the token belongs to. It read an untyped "subject"
	// key nothing writes, so every such row named nobody (#433).
	req = setTokenContextWithClaims(req, map[string]interface{}{"scope": "authserver:manage", "sub": "admin-subject-1"})
	rr := httptest.NewRecorder()

	database.On("GetUserConsentByID", mock.Anything, (*sql.Tx)(nil), int64(5)).
		Return(&record.UserConsent{ID: 5, UserID: 7, ClientID: 3}, nil)
	// The withdrawal deletes the consent and sweeps what it leaves standing inside ONE
	// transaction (#622). One live family token, so the family record is written under the
	// withdrawal's reason and the sweep flips the token before it saves it. The enumeration is
	// expected on exactly this user and client, so a sweep that reached for any other user's
	// tokens would fail as an unexpected call.
	datamocks.ExpectRunInTransaction(database, consentWithdrawalTx)
	expectWithdrawnClientTellsNobody(database)
	database.On("DeleteUserConsent", mock.Anything, consentWithdrawalTx, int64(5)).Return(true, nil).Once()
	database.On("RevokeUnusedCodesByUserIDAndClientID", mock.Anything, consentWithdrawalTx, int64(7), int64(3)).
		Return(int64(1), nil).Once()
	database.On("GetRefreshTokensByUserIDAndClientID", mock.Anything, consentWithdrawalTx, int64(7), int64(3)).
		Return([]*record.RefreshToken{
			{ID: 11, RefreshTokenJTI: "rt-live", FirstRefreshTokenJTI: "rt-first"},
			{ID: 12, RefreshTokenJTI: "rt-already-gone", FirstRefreshTokenJTI: "rt-first", Revoked: true},
		}, nil).Once()
	database.On("RecordRefreshTokenFamilyRevoked", mock.Anything, consentWithdrawalTx, "rt-first", revocation.ReasonClientDisconnected).
		Return(true, nil).Once()
	database.On("MarkRefreshTokenAsRevoked", mock.Anything, consentWithdrawalTx, int64(11)).Return(true, nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventDeletedUserConsent, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["user_id"] == int64(7) && details["consent_id"] == int64(5) &&
			details["logged_in_user"] == "admin-subject-1"
	})).Return().Once()
	// What the withdrawal revoked, beside the deletion event: the live token alone, since the
	// other was revoked before the call.
	var revokedPayload map[string]interface{}
	auditLogger.On("Log", mock.Anything, audit.EventDisconnectedClient, mock.Anything).
		Run(func(args mock.Arguments) {
			revokedPayload = args.Get(2).(map[string]interface{})
		}).Return().Once()

	handler.ServeHTTP(rr, withSessionSettings(req))

	assert.Equal(t, http.StatusOK, rr.Code)
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
	assert.Equal(t, map[string]interface{}{
		"user_id":                    int64(7),
		"client_id":                  int64(3),
		"logged_in_user":             "admin-subject-1",
		"revoked_code_count":         int64(1),
		"revoked_refresh_token_jtis": []string{"rt-live"},
	}, revokedPayload)
}

func TestHandleUserConsentDelete_GetConsentFails_JSON500(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	handler := HandleUserConsentDelete(database, auditLogger, &recordingLogoutTokens{})

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/user-consents/5", nil)
	req.SetPathValue("id", "5")
	rr := httptest.NewRecorder()

	database.On("GetUserConsentByID", mock.Anything, (*sql.Tx)(nil), int64(5)).Return(nil, assert.AnError)

	handler.ServeHTTP(rr, req)

	assertJSONInternalServerError(t, rr)
	database.AssertExpectations(t)
}

func TestHandleUserConsentDelete_DeleteFails_JSON500(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	handler := HandleUserConsentDelete(database, auditLogger, &recordingLogoutTokens{})

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/user-consents/5", nil)
	req.SetPathValue("id", "5")
	rr := httptest.NewRecorder()

	database.On("GetUserConsentByID", mock.Anything, (*sql.Tx)(nil), int64(5)).
		Return(&record.UserConsent{ID: 5, UserID: 7, ClientID: 3}, nil)
	// No token: the target ceiling reads what the user holds, and an ordinary user's write goes on.
	expectHoldsNothing(database, 7)
	// The delete runs as the withdrawal's own write, first inside the transaction, and its
	// failure is what the handler reports: nothing after it, neither the enumeration nor the
	// sweep, runs (#622).
	datamocks.ExpectRunInTransaction(database, consentWithdrawalTx)
	expectWithdrawnClientTellsNobody(database)
	database.On("DeleteUserConsent", mock.Anything, consentWithdrawalTx, int64(5)).Return(false, assert.AnError).Once()

	handler.ServeHTTP(rr, withSessionSettings(req))

	assertJSONInternalServerError(t, rr)
	database.AssertExpectations(t)
	// Nothing was deleted, so nothing is audited.
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// adminConsentDeleteRaced sets up an administrator's DELETE whose consent another request deleted
// between the handler's read and its transaction's write.
func adminConsentDeleteRaced(database *datamocks.Database) *http.Request {
	req, _ := http.NewRequest("DELETE", "/api/v1/admin/user-consents/5", nil)
	req.SetPathValue("id", "5")
	req = withSessionSettings(setTokenContextWithClaims(req, map[string]interface{}{"scope": "authserver:manage", "sub": "admin-subject-1"}))
	database.On("GetUserConsentByID", mock.Anything, (*sql.Tx)(nil), int64(5)).
		Return(&record.UserConsent{ID: 5, UserID: 7, ClientID: 3}, nil).Once()
	datamocks.ExpectRunInTransaction(database, consentWithdrawalTx)
	expectWithdrawnClientTellsNobody(database)
	database.On("DeleteUserConsent", mock.Anything, consentWithdrawalTx, int64(5)).Return(false, nil).Once()
	database.On("RevokeUnusedCodesByUserIDAndClientID", mock.Anything, consentWithdrawalTx, int64(7), int64(3)).
		Return(int64(0), nil).Once()
	return req
}

// The administrator's DELETE answers a consent another request deleted meanwhile as the account
// one does: 404 with nothing audited when its own transaction changed nothing (#135 decision 2).
func TestHandleUserConsentDelete_AConsentDeletedMeanwhileWithNothingToEndIs404(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	req := adminConsentDeleteRaced(database)
	database.On("GetRefreshTokensByUserIDAndClientID", mock.Anything, consentWithdrawalTx, int64(7), int64(3)).
		Return([]*record.RefreshToken{}, nil).Once()

	rr := httptest.NewRecorder()
	HandleUserConsentDelete(database, auditLogger, &recordingLogoutTokens{}).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, "NOT_FOUND", body["error_code"])
	database.AssertExpectations(t)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// And 200 with disconnected_client alone when its own transaction still changed something, here a
// family it newly recorded whose members were already revoked (#135 decision 2).
func TestHandleUserConsentDelete_AConsentDeletedMeanwhileStillAuditsWhatItRecorded(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	req := adminConsentDeleteRaced(database)
	database.On("GetRefreshTokensByUserIDAndClientID", mock.Anything, consentWithdrawalTx, int64(7), int64(3)).
		Return([]*record.RefreshToken{
			{ID: 11, RefreshTokenJTI: "rt-claimed", FirstRefreshTokenJTI: "rt-first", Revoked: true},
		}, nil).Once()
	database.On("RecordRefreshTokenFamilyRevoked", mock.Anything, consentWithdrawalTx, "rt-first", revocation.ReasonClientDisconnected).
		Return(true, nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventDisconnectedClient, mock.Anything).Return().Once()

	rr := httptest.NewRecorder()
	HandleUserConsentDelete(database, auditLogger, &recordingLogoutTokens{}).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, audit.EventDeletedUserConsent, mock.Anything)
}

// The administrator's withdrawal tells the consent's client once its transaction has committed. A
// client that requires sid is sent a token for each still-valid session of the user it is on, and
// nothing for an expired one (#135 decision 3).
func TestHandleUserConsentDelete_TellsTheClientAfterTheCommit(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/user-consents/5", nil)
	req.SetPathValue("id", "5")
	req = withSessionSettings(setTokenContextWithClaims(req, map[string]interface{}{"scope": "authserver:manage", "sub": "admin-subject-1"}))
	database.On("GetUserConsentByID", mock.Anything, (*sql.Tx)(nil), int64(5)).
		Return(&record.UserConsent{ID: 5, UserID: 7, ClientID: 3}, nil).Once()
	datamocks.ExpectRunInTransaction(database, consentWithdrawalTx)
	client := record.Client{ID: 3, ClientIdentifier: "web", BackchannelLogoutURI: "https://web.example/bc",
		BackchannelLogoutSessionRequired: true}
	database.On("GetClientsByIDs", mock.Anything, consentWithdrawalTx, []int64{3}).Return([]record.Client{client}, nil).Once()
	database.On("GetUserByID", mock.Anything, consentWithdrawalTx, int64(7)).
		Return(&record.User{ID: 7, Subject: "subject-of-7"}, nil).Once()
	// One session within the settings' idle timeout and lifetime, one past its idle timeout.
	now := time.Now().UTC()
	database.On("GetUserSessionsByUserID", mock.Anything, consentWithdrawalTx, int64(7)).Return([]record.UserSession{
		{ID: 20, UserID: 7, SessionIdentifier: "sid-live", Started: now.Add(-time.Hour), LastAccessed: now.Add(-time.Minute)},
		{ID: 21, UserID: 7, SessionIdentifier: "sid-idle", Started: now.Add(-3 * time.Hour), LastAccessed: now.Add(-2 * time.Hour)},
	}, nil).Once()
	database.On("GetUserSessionClientsByUserSessionIDs", mock.Anything, consentWithdrawalTx, []int64{20}).
		Return([]record.UserSessionClient{{UserSessionID: 20, ClientID: 3}}, nil).Once()
	database.On("DeleteUserConsent", mock.Anything, consentWithdrawalTx, int64(5)).Return(true, nil).Once()
	database.On("RevokeUnusedCodesByUserIDAndClientID", mock.Anything, consentWithdrawalTx, int64(7), int64(3)).
		Return(int64(0), nil).Once()
	database.On("GetRefreshTokensByUserIDAndClientID", mock.Anything, consentWithdrawalTx, int64(7), int64(3)).
		Return([]*record.RefreshToken{}, nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventDeletedUserConsent, mock.Anything).Return().Once()
	auditLogger.On("Log", mock.Anything, audit.EventDisconnectedClient, mock.Anything).Return().Once()

	logoutTokens := &recordingLogoutTokens{}
	rr := httptest.NewRecorder()
	HandleUserConsentDelete(database, auditLogger, logoutTokens).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, [][]backchannel.Delivery{{{
		ClientID: 3, ClientIdentifier: "web", URI: "https://web.example/bc", UserID: 7, Subject: "subject-of-7",
		SessionIdentifier: "sid-live",
	}}}, logoutTokens.sent)
	assert.Equal(t, "https://issuer.example", logoutTokens.issuer)
}

// A DELETE answered 404 because its transaction changed nothing sends nothing (#135 decision 2).
func TestHandleUserConsentDelete_A404TellsNobody(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	req := adminConsentDeleteRaced(database)
	database.On("GetRefreshTokensByUserIDAndClientID", mock.Anything, consentWithdrawalTx, int64(7), int64(3)).
		Return([]*record.RefreshToken{}, nil).Once()

	logoutTokens := &recordingLogoutTokens{}
	rr := httptest.NewRecorder()
	HandleUserConsentDelete(database, auditLogger, logoutTokens).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
	assert.Empty(t, logoutTokens.sent)
}
