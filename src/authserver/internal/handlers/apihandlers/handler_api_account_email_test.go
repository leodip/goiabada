package apihandlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/audit"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	mocks_handlers "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Seam 4 of #425 for the self-service twin of HandleAPIUserEmailPut, which carried the same defect
// and which #414 named only as the racing party. The fixture and requireEmailTaken are
// handler_api_users_email_test.go's.

// accountEmailTestPassword is the caller's current password in every case here.
const accountEmailTestPassword = "C0rrect!Pass"

func accountEmailTestPasswordHash(t *testing.T) string {
	t.Helper()
	hash, err := passwordhash.Hash(accountEmailTestPassword)
	require.NoError(t, err)
	return hash
}

// accountEmailPut builds the request: the body as the account API's caller sends it, and a token
// naming the caller.
func accountEmailPut(t *testing.T, body any) *http.Request {
	t.Helper()
	encoded, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/account/email", bytes.NewReader(encoded))
	return setTokenContextWithClaims(req, map[string]interface{}{"sub": emailTestSubject})
}

func accountEmailPutRequest(t *testing.T) *http.Request {
	t.Helper()
	return accountEmailPut(t, api.UpdateAccountEmailRequest{
		Email: emailTestAddress, CurrentPassword: accountEmailTestPassword})
}

// stubAccountEmailUpdate answers the handler's own read and the validator's, and the address as
// held by nobody, then the narrow write with updateErr.
func stubAccountEmailUpdate(t *testing.T, database *mocks_data.Database, updateErr error) {
	t.Helper()
	database.On("GetUserBySubject", mock.Anything, mock.Anything, emailTestSubject).
		Return(&models.User{Id: emailTestUserId, Subject: emailTestSubject, Email: "old@example.com",
			PasswordHash: accountEmailTestPasswordHash(t)}, nil).Twice()
	database.On("GetUserByEmail", mock.Anything, mock.Anything, emailTestAddress).Return(nil, nil).Once()
	database.On("SetUserEmail", mock.Anything, mock.Anything, emailTestUserId, emailTestAddress).Return(updateErr).Once()
}

// TestHandleAPIAccountEmailPut_SavesThroughTheNarrowWrite is #404 decision 4: the change writes
// the address, the cleared verified flag and the cleared verification code through SetUserEmail,
// keyed on the caller's own id, and never writes back the user row it loaded at the start of the
// request, which would undo a concurrent disable, password change or OTP change.
func TestHandleAPIAccountEmailPut_SavesThroughTheNarrowWrite(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)
	database.On("GetUserBySubject", mock.Anything, mock.Anything, emailTestSubject).
		Return(&models.User{
			Id:                             emailTestUserId,
			Subject:                        emailTestSubject,
			Enabled:                        true,
			Email:                          "old@example.com",
			EmailVerified:                  true,
			EmailVerificationCodeEncrypted: []byte("pending-code"),
			EmailVerificationCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC(), Valid: true},
			PasswordHash:                   accountEmailTestPasswordHash(t),
		}, nil).Twice()
	database.On("GetUserByEmail", mock.Anything, mock.Anything, "new@example.com").Return(nil, nil).Once()
	database.On("SetUserEmail", mock.Anything, (*sql.Tx)(nil), emailTestUserId, "new@example.com").Return(nil).Once()
	auditLogger.On("Log", mock.Anything, audit.AuditUpdatedOwnEmail, map[string]interface{}{
		"userId":       emailTestUserId,
		"loggedInUser": emailTestSubject,
	}).Return().Once()
	credentials := &countingCredentials{}

	rr := httptest.NewRecorder()
	HandleAPIAccountEmailPut(database, accountvalidation.NewEmailValidator(database), auditLogger, credentials).
		ServeHTTP(rr, accountEmailPut(t, api.UpdateAccountEmailRequest{
			Email: "  New@Example.COM ", CurrentPassword: accountEmailTestPassword}))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var resp api.UpdateUserResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.Equal(t, "new@example.com", resp.User.Email)
	require.False(t, resp.User.EmailVerified, "the new address has not been verified")
	require.NotNil(t, resp.User.UpdatedAt, "the response still reports when the row changed")
	assert.Equal(t, 0, credentials.failures, "the right password spends nothing")
	database.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything, mock.Anything)
}

func TestHandleAPIAccountEmailPut_ALostRaceForTheAddressAnswers409(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)
	stubAccountEmailUpdate(t, database, uniqueViolationOnUpdate)

	rr := httptest.NewRecorder()
	HandleAPIAccountEmailPut(database, accountvalidation.NewEmailValidator(database), auditLogger, unlimitedCredentials{}).
		ServeHTTP(rr, accountEmailPutRequest(t))

	requireEmailTaken(t, rr)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

func TestHandleAPIAccountEmailPut_AnyOtherWriteFailureAnswers500(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)
	stubAccountEmailUpdate(t, database, errs.New("the connection was reset"))

	rr := httptest.NewRecorder()
	HandleAPIAccountEmailPut(database, accountvalidation.NewEmailValidator(database), auditLogger, unlimitedCredentials{}).
		ServeHTTP(rr, accountEmailPutRequest(t))

	require.Equal(t, http.StatusInternalServerError, rr.Code)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// TestHandleAPIAccountEmailPut_ABlankCurrentPasswordIsRefusedAndChargesNothing is #404 decision
// 3: a request carrying no password is refused 400 VALIDATION_ERROR before the account is read,
// and spends nothing of the budget, since no password was compared (#219). The mock database has
// no expectations, so a read or a write fails the case.
func TestHandleAPIAccountEmailPut_ABlankCurrentPasswordIsRefusedAndChargesNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		body any
	}{
		{"absent", map[string]string{"email": "new@example.com"}},
		{"empty", api.UpdateAccountEmailRequest{Email: "new@example.com", CurrentPassword: ""}},
		{"whitespace", api.UpdateAccountEmailRequest{Email: "new@example.com", CurrentPassword: "   "}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_handlers.NewAuditLogger(t)
			credentials := &countingCredentials{}

			rr := httptest.NewRecorder()
			HandleAPIAccountEmailPut(database, accountvalidation.NewEmailValidator(database), auditLogger, credentials).
				ServeHTTP(rr, accountEmailPut(t, tc.body))

			require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
			assert.Equal(t, "VALIDATION_ERROR", errorCodeOf(t, rr))
			assert.Equal(t, "Current password is required.", descriptionOf(t, rr))
			assert.Equal(t, 0, credentials.failures, "no password was compared, so nothing is charged")
			database.AssertNotCalled(t, "SetUserEmail", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// TestHandleAPIAccountEmailPut_AWrongPasswordIsRefusedBeforeTheAddressIsLookedAt is #404
// decision 3: a wrong password is refused 400 AUTHENTICATION_FAILED and charged exactly once,
// and it is checked before the address, so a caller without the password learns nothing about
// the address: whether another account holds it, whether it is well formed, or whether it is the
// account's own. Nothing beyond the caller's own row is read (GetUserByEmail has no expectation),
// and nothing is written.
func TestHandleAPIAccountEmailPut_AWrongPasswordIsRefusedBeforeTheAddressIsLookedAt(t *testing.T) {
	for _, tc := range []struct {
		name    string
		address string
	}{
		{"an address another account holds", emailTestAddress},
		{"a malformed address", "not-an-address"},
		{"a blank address", ""},
		{"the account's own address", "old@example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_handlers.NewAuditLogger(t)
			database.On("GetUserBySubject", mock.Anything, mock.Anything, emailTestSubject).
				Return(&models.User{Id: emailTestUserId, Subject: emailTestSubject, Email: "old@example.com",
					PasswordHash: accountEmailTestPasswordHash(t)}, nil).Once()
			credentials := &countingCredentials{}

			rr := httptest.NewRecorder()
			HandleAPIAccountEmailPut(database, accountvalidation.NewEmailValidator(database), auditLogger, credentials).
				ServeHTTP(rr, accountEmailPut(t, api.UpdateAccountEmailRequest{
					Email: tc.address, CurrentPassword: "wrong-password"}))

			require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
			assert.Equal(t, "AUTHENTICATION_FAILED", errorCodeOf(t, rr))
			assert.Equal(t, "Authentication failed. Check your current password and try again.", descriptionOf(t, rr))
			assert.Equal(t, 1, credentials.failures, "a wrong password is charged exactly once")
			database.AssertNotCalled(t, "SetUserEmail", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// TestHandleAPIAccountEmailPut_ResubmittingTheCurrentAddressChangesNothing is #404 decision 10:
// the address the account already has, trimmed and lowercased as the handler normalizes it, is
// answered 200 with the user as stored. Nothing is written, so the verified flag and a pending
// verification code survive, and no audit event is logged. The validator is not consulted
// (GetUserByEmail has no expectation), so the account's own address is never refused as taken.
func TestHandleAPIAccountEmailPut_ResubmittingTheCurrentAddressChangesNothing(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)
	database.On("GetUserBySubject", mock.Anything, mock.Anything, emailTestSubject).
		Return(&models.User{
			Id:                             emailTestUserId,
			Subject:                        emailTestSubject,
			Enabled:                        true,
			Email:                          "same@example.com",
			EmailVerified:                  true,
			EmailVerificationCodeEncrypted: []byte("pending-code"),
			EmailVerificationCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC(), Valid: true},
			PasswordHash:                   accountEmailTestPasswordHash(t),
		}, nil).Once()
	credentials := &countingCredentials{}

	rr := httptest.NewRecorder()
	HandleAPIAccountEmailPut(database, accountvalidation.NewEmailValidator(database), auditLogger, credentials).
		ServeHTTP(rr, accountEmailPut(t, api.UpdateAccountEmailRequest{
			Email: "  Same@Example.COM ", CurrentPassword: accountEmailTestPassword}))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var resp api.UpdateUserResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, emailTestUserId, resp.User.Id)
	assert.Equal(t, "same@example.com", resp.User.Email)
	assert.True(t, resp.User.EmailVerified, "re-saving the address keeps it verified")
	assert.Equal(t, 0, credentials.failures)
	database.AssertNotCalled(t, "SetUserEmail", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything, mock.Anything)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}
