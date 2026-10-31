package apihandlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The account API's two recovery-code endpoints (#257 decisions 8 and 9): GET answers how many of
// the caller's codes are unused, and POST, given the caller's password, replaces the set with a new
// one and answers it once. A new set ends no session and moves no generation, since the
// authenticator did not change; the strict mocks below make any such write a failure.

const recoveryCodesSubject = "the-subject"
const recoveryCodesPassword = "P4ss!word"

// recoveryCodesTx is the transaction the stubbed RunInTransaction hands its body, so a write made
// outside it arrives with a nil tx and fails as an unexpected call.
var recoveryCodesTx = &sql.Tx{}

// recoveryCodesUser is a user with an authenticator, whose password is recoveryCodesPassword.
func recoveryCodesUser(t *testing.T) *record.User {
	t.Helper()
	hash, err := passwordhash.Hash(recoveryCodesPassword)
	require.NoError(t, err)
	return &record.User{Id: 81, Enabled: true, PasswordHash: hash, OTPEnabled: true, OtpConfigGeneration: 4}
}

func recoveryCodesGetRequest(t *testing.T) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/account/otp/recovery-codes", nil)
	return setTokenContextWithClaims(req, map[string]interface{}{"sub": recoveryCodesSubject})
}

func recoveryCodesPostRequest(t *testing.T, password string) *http.Request {
	t.Helper()
	body, err := json.Marshal(map[string]string{"password": password})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/account/otp/recovery-codes", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return setTokenContextWithClaims(req, map[string]interface{}{"sub": recoveryCodesSubject})
}

func TestHandleAccountRecoveryCodesGet_AnswersHowManyAreUnused(t *testing.T) {
	database := datamocks.NewDatabase(t)
	user := recoveryCodesUser(t)
	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), recoveryCodesSubject).Return(user, nil).Once()
	database.On("CountUnusedUserRecoveryCodes", mock.Anything, (*sql.Tx)(nil), user.Id).Return(7, nil).Once()

	rr := httptest.NewRecorder()
	HandleAccountRecoveryCodesGet(database).ServeHTTP(rr, recoveryCodesGetRequest(t))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.JSONEq(t, `{"remaining":7}`, rr.Body.String())
}

// None left is answered as 0 rather than left out, so a caller can say a new set is needed.
func TestHandleAccountRecoveryCodesGet_NoneLeftIsZero(t *testing.T) {
	database := datamocks.NewDatabase(t)
	user := recoveryCodesUser(t)
	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), recoveryCodesSubject).Return(user, nil).Once()
	database.On("CountUnusedUserRecoveryCodes", mock.Anything, (*sql.Tx)(nil), user.Id).Return(0, nil).Once()

	rr := httptest.NewRecorder()
	HandleAccountRecoveryCodesGet(database).ServeHTTP(rr, recoveryCodesGetRequest(t))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.JSONEq(t, `{"remaining":0}`, rr.Body.String())
}

func TestHandleAccountRecoveryCodesGet_UnknownUserIs404(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), recoveryCodesSubject).Return(nil, nil).Once()

	rr := httptest.NewRecorder()
	HandleAccountRecoveryCodesGet(database).ServeHTTP(rr, recoveryCodesGetRequest(t))

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// The new set replaces the old one under the user's row, answered once and audited after the
// commit, naming the user and the caller and nothing of the codes (#257 decisions 8 and 10). No
// generation moves and no session is lowered: the mocks hold no expectation for either.
func TestHandleAccountRecoveryCodesPost_ReplacesTheSetAndAnswersItOnce(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	user := recoveryCodesUser(t)
	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), recoveryCodesSubject).Return(user, nil).Once()

	var calls []string
	datamocks.ExpectRunInTransaction(database, recoveryCodesTx, func(edge string) { calls = append(calls, edge) })
	database.On("GetUserByIdForUpdate", mock.Anything, recoveryCodesTx, user.Id).Return(user, nil).
		Run(func(mock.Arguments) { calls = append(calls, "lock") }).Once()
	var stored []string
	database.On("ReplaceUserRecoveryCodes", mock.Anything, recoveryCodesTx, user.Id, mock.Anything).Return(nil).
		Run(func(args mock.Arguments) {
			stored = args.Get(3).([]string)
			calls = append(calls, "replace")
		}).Once()
	auditLogger.On("Log", mock.Anything, audit.EventRecoveryCodesCreated, map[string]interface{}{
		"user_id":        user.Id,
		"logged_in_user": recoveryCodesSubject,
	}).Return().Run(func(mock.Arguments) { calls = append(calls, "audit") }).Once()

	credentials := &countingCredentials{}
	rr := httptest.NewRecorder()
	HandleAccountRecoveryCodesPost(database, auditLogger, credentials).
		ServeHTTP(rr, recoveryCodesPostRequest(t, recoveryCodesPassword))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var body api.CreateAccountRecoveryCodesResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	require.Len(t, body.RecoveryCodes, 10, "a set is ten codes")
	require.Len(t, stored, 10)
	for i, code := range body.RecoveryCodes {
		assert.Regexp(t, `^[0-9a-hjkmnp-tv-z]{4}(-[0-9a-hjkmnp-tv-z]{4}){5}$`, code)
		assert.Equal(t, hashutil.HashString(strings.ReplaceAll(code, "-", "")), stored[i],
			"the codes answered are the ones stored")
	}
	assert.Equal(t, []string{"begin", "lock", "replace", "commit", "audit"}, calls,
		"the set is replaced under the user's row, and audited after the commit")
	assert.Zero(t, credentials.failures, "a right password spends nothing")
}

// A wrong password is AUTHENTICATION_FAILED and spends the budget shared with the account's other
// password checks; nothing is written or audited.
func TestHandleAccountRecoveryCodesPost_WrongPasswordIsRefusedAndCharged(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	user := recoveryCodesUser(t)
	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), recoveryCodesSubject).Return(user, nil).Once()

	credentials := &countingCredentials{}
	rr := httptest.NewRecorder()
	HandleAccountRecoveryCodesPost(database, auditLogger, credentials).
		ServeHTTP(rr, recoveryCodesPostRequest(t, "Wr0ng!pass"))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "AUTHENTICATION_FAILED", errorCodeOf(t, rr))
	assert.Equal(t, 1, credentials.failures, "a wrong password is a guess at it")
}

// A blank password compares nothing, so it is refused as wrong without spending the budget (#219).
func TestHandleAccountRecoveryCodesPost_BlankPasswordIsRefusedUncharged(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	user := recoveryCodesUser(t)
	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), recoveryCodesSubject).Return(user, nil).Once()

	credentials := &countingCredentials{}
	rr := httptest.NewRecorder()
	HandleAccountRecoveryCodesPost(database, auditLogger, credentials).
		ServeHTTP(rr, recoveryCodesPostRequest(t, "  "))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "AUTHENTICATION_FAILED", errorCodeOf(t, rr))
	assert.Zero(t, credentials.failures)
}

// A user without an authenticator has no set to replace: OTP_NOT_ENABLED, nothing written.
func TestHandleAccountRecoveryCodesPost_NoAuthenticatorIsRefused(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	user := recoveryCodesUser(t)
	user.OTPEnabled = false
	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), recoveryCodesSubject).Return(user, nil).Once()

	credentials := &countingCredentials{}
	rr := httptest.NewRecorder()
	HandleAccountRecoveryCodesPost(database, auditLogger, credentials).
		ServeHTTP(rr, recoveryCodesPostRequest(t, recoveryCodesPassword))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "OTP_NOT_ENABLED", errorCodeOf(t, rr))
	assert.Zero(t, credentials.failures)
}

// An authenticator removed between the request's read and its write: the row, read again under its
// lock, has none, so no set is stored for a user whose codes the removal just deleted.
func TestHandleAccountRecoveryCodesPost_AnAuthenticatorRemovedMeanwhileStoresNothing(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	user := recoveryCodesUser(t)
	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), recoveryCodesSubject).Return(user, nil).Once()

	datamocks.ExpectRunInTransaction(database, recoveryCodesTx)
	removed := *user
	removed.OTPEnabled = false
	database.On("GetUserByIdForUpdate", mock.Anything, recoveryCodesTx, user.Id).Return(&removed, nil).Once()

	rr := httptest.NewRecorder()
	HandleAccountRecoveryCodesPost(database, auditLogger, &countingCredentials{}).
		ServeHTTP(rr, recoveryCodesPostRequest(t, recoveryCodesPassword))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "OTP_NOT_ENABLED", errorCodeOf(t, rr))
}

func TestHandleAccountRecoveryCodesPost_InvalidBodyIsRefused(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/account/otp/recovery-codes", strings.NewReader("{"))
	req = setTokenContextWithClaims(req, map[string]interface{}{"sub": recoveryCodesSubject})
	rr := httptest.NewRecorder()
	HandleAccountRecoveryCodesPost(database, auditLogger, &countingCredentials{}).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "INVALID_REQUEST_BODY", errorCodeOf(t, rr))
}
