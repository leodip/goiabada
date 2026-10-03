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
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Seam 4 of #425 for the self-service twin of HandleAPIUserEmailPut, which carried the same defect
// and which #414 named only as the racing party. The fixture and requireEmailTaken are
// handler_api_users_email_test.go's.

func accountEmailPutRequest(t *testing.T) *http.Request {
	t.Helper()
	body, err := json.Marshal(api.UpdateAccountEmailRequest{Email: emailTestAddress})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/account/email", bytes.NewReader(body))
	return setTokenContextWithClaims(req, map[string]interface{}{"sub": emailTestSubject})
}

// stubAccountEmailUpdate answers the handler's own read and the validator's, and the address as
// held by nobody, then the narrow write with updateErr.
func stubAccountEmailUpdate(database *mocks_data.Database, updateErr error) {
	database.On("GetUserBySubject", mock.Anything, mock.Anything, emailTestSubject).
		Return(&models.User{Id: emailTestUserId, Subject: emailTestSubject, Email: "old@example.com"}, nil).Twice()
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
		}, nil).Twice()
	database.On("GetUserByEmail", mock.Anything, mock.Anything, "new@example.com").Return(nil, nil).Once()
	database.On("SetUserEmail", mock.Anything, (*sql.Tx)(nil), emailTestUserId, "new@example.com").Return(nil).Once()
	auditLogger.On("Log", mock.Anything, audit.AuditUpdatedOwnEmail, map[string]interface{}{
		"userId":       emailTestUserId,
		"loggedInUser": emailTestSubject,
	}).Return().Once()

	body, err := json.Marshal(api.UpdateAccountEmailRequest{Email: "  New@Example.COM "})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/account/email", bytes.NewReader(body))
	req = setTokenContextWithClaims(req, map[string]interface{}{"sub": emailTestSubject})

	rr := httptest.NewRecorder()
	HandleAPIAccountEmailPut(database, accountvalidation.NewEmailValidator(database), auditLogger).ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var resp api.UpdateUserResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.Equal(t, "new@example.com", resp.User.Email)
	require.False(t, resp.User.EmailVerified, "the new address has not been verified")
	require.NotNil(t, resp.User.UpdatedAt, "the response still reports when the row changed")
	database.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything, mock.Anything)
}

func TestHandleAPIAccountEmailPut_ALostRaceForTheAddressAnswers409(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)
	stubAccountEmailUpdate(database, uniqueViolationOnUpdate)

	rr := httptest.NewRecorder()
	HandleAPIAccountEmailPut(database, accountvalidation.NewEmailValidator(database), auditLogger).
		ServeHTTP(rr, accountEmailPutRequest(t))

	requireEmailTaken(t, rr)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

func TestHandleAPIAccountEmailPut_AnyOtherWriteFailureAnswers500(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)
	stubAccountEmailUpdate(database, errs.New("the connection was reset"))

	rr := httptest.NewRecorder()
	HandleAPIAccountEmailPut(database, accountvalidation.NewEmailValidator(database), auditLogger).
		ServeHTTP(rr, accountEmailPutRequest(t))

	require.Equal(t, http.StatusInternalServerError, rr.Code)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}
