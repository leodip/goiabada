package apihandlers

import (
	"database/sql"
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

// The self-service half of the consent withdrawal (#622), the path the issue names: Account,
// Manage consents. It shares consentWithdrawalTx with the admin site's tests.

// accountConsentDeleteRequest builds the DELETE with the chi URL parameter and the validated token
// the handler reads.
func accountConsentDeleteRequest(consentId string, subject string) *http.Request {
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/account/consents/"+consentId, nil)
	req = setChiURLParam(req, "id", consentId)
	return setTokenContextWithClaims(req, map[string]interface{}{"sub": subject})
}

// The withdrawal deletes the caller's consent and sweeps that user's refresh tokens with that
// client inside one transaction, the enumeration scoped to exactly this user and client, and both
// events name the caller: the deletion event as it was, and what the withdrawal revoked.
func TestHandleAccountConsentDelete_WithdrawsRevokesAndAuditsBothEvents(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	const subject = "the-user"
	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), subject).
		Return(&record.User{Id: 42, Enabled: true}, nil).Once()
	database.On("GetUserConsentById", mock.Anything, (*sql.Tx)(nil), int64(5)).
		Return(&record.UserConsent{Id: 5, UserId: 42, ClientId: 3}, nil).Once()
	datamocks.ExpectRunInTransaction(database, consentWithdrawalTx)
	database.On("DeleteUserConsent", mock.Anything, consentWithdrawalTx, int64(5)).Return(nil).Once()
	database.On("RevokeUnusedCodesByUserIdAndClientId", mock.Anything, consentWithdrawalTx, int64(42), int64(3)).
		Return(int64(1), nil).Once()
	database.On("GetRefreshTokensByUserIdAndClientId", mock.Anything, consentWithdrawalTx, int64(42), int64(3)).
		Return([]*record.RefreshToken{
			{Id: 11, RefreshTokenJti: "rt-live", FirstRefreshTokenJti: "rt-first"},
		}, nil).Once()
	database.On("RecordRefreshTokenFamilyRevoked", mock.Anything, consentWithdrawalTx, "rt-first", revocation.ReasonConsentWithdrawn).
		Return(true, nil).Once()
	database.On("UpdateRefreshToken", mock.Anything, consentWithdrawalTx, mock.MatchedBy(func(rt *record.RefreshToken) bool {
		return rt.RefreshTokenJti == "rt-live" && rt.Revoked
	})).Return(nil).Once()

	var deletedPayload, revokedPayload map[string]interface{}
	auditLogger.On("Log", mock.Anything, audit.EventDeletedOwnUserConsent, mock.Anything).
		Run(func(args mock.Arguments) { deletedPayload = args.Get(2).(map[string]interface{}) }).
		Return().Once()
	auditLogger.On("Log", mock.Anything, audit.EventRevokedConsentGrants, mock.Anything).
		Run(func(args mock.Arguments) { revokedPayload = args.Get(2).(map[string]interface{}) }).
		Return().Once()

	rr := httptest.NewRecorder()
	HandleAccountConsentDelete(database, auditLogger).ServeHTTP(rr, accountConsentDeleteRequest("5", subject))

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
		Return(&record.User{Id: 42, Enabled: true}, nil).Once()
	database.On("GetUserConsentById", mock.Anything, (*sql.Tx)(nil), int64(5)).
		Return(&record.UserConsent{Id: 5, UserId: 7, ClientId: 3}, nil).Once()

	rr := httptest.NewRecorder()
	HandleAccountConsentDelete(database, auditLogger).ServeHTTP(rr, accountConsentDeleteRequest("5", subject))

	assert.Equal(t, http.StatusForbidden, rr.Code)
	database.AssertExpectations(t)
	database.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "DeleteUserConsent", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "RevokeUnusedCodesByUserIdAndClientId", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "GetRefreshTokensByUserIdAndClientId", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// The deletion is the withdrawal's first write inside the transaction, and its failure is a 500
// with nothing after it run and nothing audited.
func TestHandleAccountConsentDelete_DeleteFailsIsA500(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	const subject = "the-user"
	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), subject).
		Return(&record.User{Id: 42, Enabled: true}, nil).Once()
	database.On("GetUserConsentById", mock.Anything, (*sql.Tx)(nil), int64(5)).
		Return(&record.UserConsent{Id: 5, UserId: 42, ClientId: 3}, nil).Once()
	stub := datamocks.ExpectRunInTransaction(database, consentWithdrawalTx)
	database.On("DeleteUserConsent", mock.Anything, consentWithdrawalTx, int64(5)).Return(assert.AnError).Once()

	rr := httptest.NewRecorder()
	HandleAccountConsentDelete(database, auditLogger).ServeHTTP(rr, accountConsentDeleteRequest("5", subject))

	assertJSONInternalServerError(t, rr)
	require.ErrorIs(t, stub.BodyErr, assert.AnError)
	database.AssertExpectations(t)
	database.AssertNotCalled(t, "RevokeUnusedCodesByUserIdAndClientId", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "GetRefreshTokensByUserIdAndClientId", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}
