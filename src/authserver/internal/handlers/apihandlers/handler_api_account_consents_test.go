package apihandlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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

// The self-service half of the consent withdrawal (#622), the path the issue names: Account,
// Manage consents. It shares consentWithdrawalTx with the admin site's tests.

// accountConsentDeleteRequest builds the DELETE with the path value and the validated token
// the handler reads.
func accountConsentDeleteRequest(consentID string, subject string) *http.Request {
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/account/consents/"+consentID, nil)
	req.SetPathValue("id", consentID)
	return withSessionSettings(setTokenContextWithClaims(req, map[string]interface{}{"sub": subject}))
}

// The withdrawal disconnects the consent's client: it deletes the caller's consent and sweeps that
// user's refresh tokens with that client inside one transaction, the enumeration scoped to exactly
// this user and client, and both events name the caller: the deletion event as it was, and
// disconnected_client with what the disconnect revoked (#135 decision 6).
func TestHandleAccountConsentDelete_WithdrawsRevokesAndAuditsBothEvents(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	const subject = "the-user"
	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), subject).
		Return(&record.User{ID: 42, Enabled: true}, nil).Once()
	database.On("GetUserConsentByID", mock.Anything, (*sql.Tx)(nil), int64(5)).
		Return(&record.UserConsent{ID: 5, UserID: 42, ClientID: 3}, nil).Once()
	datamocks.ExpectRunInTransaction(database, consentWithdrawalTx)
	expectWithdrawnClientTellsNobody(database)
	database.On("DeleteUserConsent", mock.Anything, consentWithdrawalTx, int64(5)).Return(true, nil).Once()
	database.On("RevokeUnusedCodesByUserIDAndClientID", mock.Anything, consentWithdrawalTx, int64(42), int64(3)).
		Return(int64(1), nil).Once()
	database.On("GetRefreshTokensByUserIDAndClientID", mock.Anything, consentWithdrawalTx, int64(42), int64(3)).
		Return([]*record.RefreshToken{
			{ID: 11, RefreshTokenJTI: "rt-live", FirstRefreshTokenJTI: "rt-first"},
		}, nil).Once()
	database.On("RecordRefreshTokenFamilyRevoked", mock.Anything, consentWithdrawalTx, "rt-first", revocation.ReasonClientDisconnected).
		Return(true, nil).Once()
	database.On("MarkRefreshTokenAsRevoked", mock.Anything, consentWithdrawalTx, int64(11)).Return(true, nil).Once()

	var deletedPayload, revokedPayload map[string]interface{}
	auditLogger.On("Log", mock.Anything, audit.EventDeletedOwnUserConsent, mock.Anything).
		Run(func(args mock.Arguments) { deletedPayload = args.Get(2).(map[string]interface{}) }).
		Return().Once()
	auditLogger.On("Log", mock.Anything, audit.EventDisconnectedClient, mock.Anything).
		Run(func(args mock.Arguments) { revokedPayload = args.Get(2).(map[string]interface{}) }).
		Return().Once()

	rr := httptest.NewRecorder()
	HandleAccountConsentDelete(database, auditLogger, &recordingLogoutTokens{}).ServeHTTP(rr, accountConsentDeleteRequest("5", subject))

	assert.Equal(t, http.StatusOK, rr.Code)
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
	assert.Equal(t, map[string]interface{}{
		"user_id":        int64(42),
		"consent_id":     int64(5),
		"logged_in_user": subject,
	}, deletedPayload, "the deletion event keeps its payload")
	assert.Equal(t, map[string]interface{}{
		"user_id":                    int64(42),
		"client_id":                  int64(3),
		"logged_in_user":             subject,
		"revoked_code_count":         int64(1),
		"revoked_refresh_token_jtis": []string{"rt-live"},
	}, revokedPayload)
}

// KEEP THIS ROW. Ownership answers before anything is withdrawn: another user's consent is a 403
// with no transaction opened, so nothing of that user's is deleted or revoked. The integration
// case asserts the status and the row, which a handler revoking first and refusing after would
// still satisfy.
func TestHandleAccountConsentDelete_ForbiddenWithdrawsNothing(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	const subject = "the-user"
	// The consent belongs to user 7; the caller is user 42.
	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), subject).
		Return(&record.User{ID: 42, Enabled: true}, nil).Once()
	database.On("GetUserConsentByID", mock.Anything, (*sql.Tx)(nil), int64(5)).
		Return(&record.UserConsent{ID: 5, UserID: 7, ClientID: 3}, nil).Once()

	rr := httptest.NewRecorder()
	HandleAccountConsentDelete(database, auditLogger, &recordingLogoutTokens{}).ServeHTTP(rr, accountConsentDeleteRequest("5", subject))

	assert.Equal(t, http.StatusForbidden, rr.Code)
	database.AssertExpectations(t)
	database.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "DeleteUserConsent", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "RevokeUnusedCodesByUserIDAndClientID", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "GetRefreshTokensByUserIDAndClientID", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// The deletion is the withdrawal's first write inside the transaction, and its failure is a 500
// with nothing after it run and nothing audited.
func TestHandleAccountConsentDelete_DeleteFailsIsA500(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	const subject = "the-user"
	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), subject).
		Return(&record.User{ID: 42, Enabled: true}, nil).Once()
	database.On("GetUserConsentByID", mock.Anything, (*sql.Tx)(nil), int64(5)).
		Return(&record.UserConsent{ID: 5, UserID: 42, ClientID: 3}, nil).Once()
	stub := datamocks.ExpectRunInTransaction(database, consentWithdrawalTx)
	expectWithdrawnClientTellsNobody(database)
	database.On("DeleteUserConsent", mock.Anything, consentWithdrawalTx, int64(5)).Return(false, assert.AnError).Once()

	rr := httptest.NewRecorder()
	HandleAccountConsentDelete(database, auditLogger, &recordingLogoutTokens{}).ServeHTTP(rr, accountConsentDeleteRequest("5", subject))

	assertJSONInternalServerError(t, rr)
	require.ErrorIs(t, stub.BodyErr, assert.AnError)
	database.AssertExpectations(t)
	database.AssertNotCalled(t, "RevokeUnusedCodesByUserIDAndClientID", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "GetRefreshTokensByUserIDAndClientID", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// accountConsentDeleteRaced sets up a DELETE whose consent another request deleted between the
// handler's read and its transaction's write: the read finds the row, the deletion reports it
// deleted nothing.
func accountConsentDeleteRaced(database *datamocks.Database, subject string) {
	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), subject).
		Return(&record.User{ID: 42, Enabled: true}, nil).Once()
	database.On("GetUserConsentByID", mock.Anything, (*sql.Tx)(nil), int64(5)).
		Return(&record.UserConsent{ID: 5, UserID: 42, ClientID: 3}, nil).Once()
	datamocks.ExpectRunInTransaction(database, consentWithdrawalTx)
	expectWithdrawnClientTellsNobody(database)
	database.On("DeleteUserConsent", mock.Anything, consentWithdrawalTx, int64(5)).Return(false, nil).Once()
}

// A DELETE whose own transaction changed nothing, its consent deleted by another request and
// nothing else left to end, answers 404 as a repeated DELETE does, and writes no audit entry: the
// request that did delete it wrote the record (#135 decision 2).
func TestHandleAccountConsentDelete_AConsentDeletedMeanwhileWithNothingToEndIs404(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	const subject = "the-user"
	accountConsentDeleteRaced(database, subject)
	database.On("RevokeUnusedCodesByUserIDAndClientID", mock.Anything, consentWithdrawalTx, int64(42), int64(3)).
		Return(int64(0), nil).Once()
	database.On("GetRefreshTokensByUserIDAndClientID", mock.Anything, consentWithdrawalTx, int64(42), int64(3)).
		Return([]*record.RefreshToken{
			{ID: 11, RefreshTokenJTI: "rt-gone", FirstRefreshTokenJTI: "rt-first", Revoked: true},
		}, nil).Once()
	database.On("RecordRefreshTokenFamilyRevoked", mock.Anything, consentWithdrawalTx, "rt-first", revocation.ReasonClientDisconnected).
		Return(false, nil).Once()

	rr := httptest.NewRecorder()
	HandleAccountConsentDelete(database, auditLogger, &recordingLogoutTokens{}).ServeHTTP(rr, accountConsentDeleteRequest("5", subject))

	assert.Equal(t, http.StatusNotFound, rr.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, "NOT_FOUND", body["error_code"])
	database.AssertExpectations(t)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// A DELETE whose consent another request deleted meanwhile, but whose own transaction still
// revoked a token, answers 200 with disconnected_client and no consent deletion entry: it deleted
// no consent (#135 decision 2).
func TestHandleAccountConsentDelete_AConsentDeletedMeanwhileStillAuditsWhatItRevoked(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	const subject = "the-user"
	accountConsentDeleteRaced(database, subject)
	database.On("RevokeUnusedCodesByUserIDAndClientID", mock.Anything, consentWithdrawalTx, int64(42), int64(3)).
		Return(int64(0), nil).Once()
	database.On("GetRefreshTokensByUserIDAndClientID", mock.Anything, consentWithdrawalTx, int64(42), int64(3)).
		Return([]*record.RefreshToken{
			{ID: 11, RefreshTokenJTI: "rt-inserted-after", FirstRefreshTokenJTI: "rt-first"},
		}, nil).Once()
	database.On("RecordRefreshTokenFamilyRevoked", mock.Anything, consentWithdrawalTx, "rt-first", revocation.ReasonClientDisconnected).
		Return(false, nil).Once()
	database.On("MarkRefreshTokenAsRevoked", mock.Anything, consentWithdrawalTx, int64(11)).Return(true, nil).Once()
	var disconnectedPayload map[string]interface{}
	auditLogger.On("Log", mock.Anything, audit.EventDisconnectedClient, mock.Anything).
		Run(func(args mock.Arguments) { disconnectedPayload = args.Get(2).(map[string]interface{}) }).
		Return().Once()

	rr := httptest.NewRecorder()
	HandleAccountConsentDelete(database, auditLogger, &recordingLogoutTokens{}).ServeHTTP(rr, accountConsentDeleteRequest("5", subject))

	assert.Equal(t, http.StatusOK, rr.Code)
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, audit.EventDeletedOwnUserConsent, mock.Anything)
	assert.Equal(t, []string{"rt-inserted-after"}, disconnectedPayload["revoked_refresh_token_jtis"])
}

// A consent with no grant behind it is still a change, its deletion, so the DELETE answers 200 and
// writes both entries, disconnected_client with nothing revoked (#135 decision 6).
func TestHandleAccountConsentDelete_AConsentWithNoGrantStillAuditsTheDisconnect(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	const subject = "the-user"
	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), subject).
		Return(&record.User{ID: 42, Enabled: true}, nil).Once()
	database.On("GetUserConsentByID", mock.Anything, (*sql.Tx)(nil), int64(5)).
		Return(&record.UserConsent{ID: 5, UserID: 42, ClientID: 3}, nil).Once()
	datamocks.ExpectRunInTransaction(database, consentWithdrawalTx)
	expectWithdrawnClientTellsNobody(database)
	database.On("DeleteUserConsent", mock.Anything, consentWithdrawalTx, int64(5)).Return(true, nil).Once()
	database.On("RevokeUnusedCodesByUserIDAndClientID", mock.Anything, consentWithdrawalTx, int64(42), int64(3)).
		Return(int64(0), nil).Once()
	database.On("GetRefreshTokensByUserIDAndClientID", mock.Anything, consentWithdrawalTx, int64(42), int64(3)).
		Return([]*record.RefreshToken{}, nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventDeletedOwnUserConsent, mock.Anything).Return().Once()
	var disconnectedPayload map[string]interface{}
	auditLogger.On("Log", mock.Anything, audit.EventDisconnectedClient, mock.Anything).
		Run(func(args mock.Arguments) { disconnectedPayload = args.Get(2).(map[string]interface{}) }).
		Return().Once()

	rr := httptest.NewRecorder()
	HandleAccountConsentDelete(database, auditLogger, &recordingLogoutTokens{}).ServeHTTP(rr, accountConsentDeleteRequest("5", subject))

	assert.Equal(t, http.StatusOK, rr.Code)
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
	assert.Equal(t, map[string]interface{}{
		"user_id":                    int64(42),
		"client_id":                  int64(3),
		"logged_in_user":             subject,
		"revoked_code_count":         int64(0),
		"revoked_refresh_token_jtis": []string{},
	}, disconnectedPayload)
}

// The withdrawal tells the consent's client, once its transaction has committed: a client with a
// back-channel logout URI is sent a logout token naming the user alone, with the request's issuer
// as its iss (#135 decision 3).
func TestHandleAccountConsentDelete_TellsTheClientAfterTheCommit(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	const subject = "the-user"
	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), subject).
		Return(&record.User{ID: 42, Subject: subject, Enabled: true}, nil).Once()
	database.On("GetUserConsentByID", mock.Anything, (*sql.Tx)(nil), int64(5)).
		Return(&record.UserConsent{ID: 5, UserID: 42, ClientID: 3}, nil).Once()
	stub := datamocks.ExpectRunInTransaction(database, consentWithdrawalTx)
	database.On("GetClientsByIDs", mock.Anything, consentWithdrawalTx, []int64{3}).
		Return([]record.Client{{ID: 3, ClientIdentifier: "web", BackchannelLogoutURI: "https://web.example/bc"}}, nil).Once()
	database.On("GetUserByID", mock.Anything, consentWithdrawalTx, int64(42)).
		Return(&record.User{ID: 42, Subject: subject}, nil).Once()
	database.On("DeleteUserConsent", mock.Anything, consentWithdrawalTx, int64(5)).Return(true, nil).Once()
	database.On("RevokeUnusedCodesByUserIDAndClientID", mock.Anything, consentWithdrawalTx, int64(42), int64(3)).
		Return(int64(0), nil).Once()
	database.On("GetRefreshTokensByUserIDAndClientID", mock.Anything, consentWithdrawalTx, int64(42), int64(3)).
		Return([]*record.RefreshToken{}, nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventDeletedOwnUserConsent, mock.Anything).Return().Once()
	auditLogger.On("Log", mock.Anything, audit.EventDisconnectedClient, mock.Anything).Return().Once()

	logoutTokens := &recordingLogoutTokens{}
	rr := httptest.NewRecorder()
	HandleAccountConsentDelete(database, auditLogger, logoutTokens).ServeHTTP(rr, accountConsentDeleteRequest("5", subject))

	assert.Equal(t, http.StatusOK, rr.Code)
	require.NoError(t, stub.BodyErr)
	assert.Equal(t, [][]backchannel.Delivery{{{
		ClientID: 3, ClientIdentifier: "web", URI: "https://web.example/bc", UserID: 42, Subject: subject,
	}}}, logoutTokens.sent)
	assert.Equal(t, "https://issuer.example", logoutTokens.issuer)
}

// A DELETE answered 404 because its transaction changed nothing tells nobody, though the client has
// a back-channel logout URI (#135 decision 2).
func TestHandleAccountConsentDelete_A404TellsNobody(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	const subject = "the-user"
	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), subject).
		Return(&record.User{ID: 42, Enabled: true}, nil).Once()
	database.On("GetUserConsentByID", mock.Anything, (*sql.Tx)(nil), int64(5)).
		Return(&record.UserConsent{ID: 5, UserID: 42, ClientID: 3}, nil).Once()
	datamocks.ExpectRunInTransaction(database, consentWithdrawalTx)
	database.On("GetClientsByIDs", mock.Anything, consentWithdrawalTx, []int64{3}).
		Return([]record.Client{{ID: 3, ClientIdentifier: "web", BackchannelLogoutURI: "https://web.example/bc"}}, nil).Once()
	database.On("GetUserByID", mock.Anything, consentWithdrawalTx, int64(42)).
		Return(&record.User{ID: 42, Subject: subject}, nil).Once()
	database.On("DeleteUserConsent", mock.Anything, consentWithdrawalTx, int64(5)).Return(false, nil).Once()
	database.On("RevokeUnusedCodesByUserIDAndClientID", mock.Anything, consentWithdrawalTx, int64(42), int64(3)).
		Return(int64(0), nil).Once()
	database.On("GetRefreshTokensByUserIDAndClientID", mock.Anything, consentWithdrawalTx, int64(42), int64(3)).
		Return([]*record.RefreshToken{}, nil).Once()

	logoutTokens := &recordingLogoutTokens{}
	rr := httptest.NewRecorder()
	HandleAccountConsentDelete(database, auditLogger, logoutTokens).ServeHTTP(rr, accountConsentDeleteRequest("5", subject))

	assert.Equal(t, http.StatusNotFound, rr.Code)
	assert.Empty(t, logoutTokens.sent)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}
