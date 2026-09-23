package apihandlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
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
// held by nobody, then the write with updateErr.
func stubAccountEmailUpdate(database *mocks_data.Database, updateErr error) {
	database.On("GetUserBySubject", mock.Anything, mock.Anything, emailTestSubject).
		Return(&models.User{Id: emailTestUserId, Subject: emailTestSubject, Email: "old@example.com"}, nil).Twice()
	database.On("GetUserByEmail", mock.Anything, mock.Anything, emailTestAddress).Return(nil, nil).Once()
	database.On("UpdateUser", mock.Anything, mock.Anything, mock.Anything).Return(updateErr).Once()
}

func TestHandleAPIAccountEmailPut_ALostRaceForTheAddressAnswers409(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	stubAccountEmailUpdate(database, uniqueViolationOnUpdate)

	rr := httptest.NewRecorder()
	HandleAPIAccountEmailPut(database, accountvalidation.NewEmailValidator(database), auditLogger).
		ServeHTTP(rr, accountEmailPutRequest(t))

	requireEmailTaken(t, rr)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

func TestHandleAPIAccountEmailPut_AnyOtherWriteFailureAnswers500(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	stubAccountEmailUpdate(database, errs.New("the connection was reset"))

	rr := httptest.NewRecorder()
	HandleAPIAccountEmailPut(database, accountvalidation.NewEmailValidator(database), auditLogger).
		ServeHTTP(rr, accountEmailPutRequest(t))

	require.Equal(t, http.StatusInternalServerError, rr.Code)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}
