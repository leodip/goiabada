package apihandlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	"github.com/leodip/goiabada/authserver/internal/data"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Seam 4 of #425 for the duplicate email (#414 item 1). Both email PUTs check the address before
// they write, and the check answers the ordinary duplicate; these cases are the race it cannot
// close, where the engine refuses the UPDATE on users.email. That arrives as data.ErrUniqueViolation
// on every engine (the data tier's TestUpdateUser_DuplicateEmailIsErrUniqueViolation), and each PUT
// now answers it 409 EMAIL_ALREADY_EXISTS, as user creation does, where it answered 500.

const (
	emailTestUserId  = int64(42)
	emailTestSubject = "sub-42"
	emailTestAddress = "taken@example.com"
)

// uniqueViolationOnUpdate is the shape commondb hands back for a duplicate key: WrapSQLError's
// sentinel join under ExecSql, wrapped again by UpdateUser.
var uniqueViolationOnUpdate = errs.Wrap(
	errs.Errorf("%w: %w", data.ErrUniqueViolation, errs.New("duplicate key value violates unique constraint \"idx_email\"")),
	"unable to update user")

// requireEmailTaken asserts the 409 the create endpoint already answers for the same race.
func requireEmailTaken(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	require.Equal(t, http.StatusConflict, rr.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, "EMAIL_ALREADY_EXISTS", body["error_code"])
	assert.Equal(t, "This email address is already registered", body["error_description"])
}

func adminEmailPutRequest(t *testing.T) *http.Request {
	t.Helper()
	body, err := json.Marshal(api.UpdateUserEmailRequest{Email: emailTestAddress, EmailVerified: true})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/users/42/email", bytes.NewReader(body))
	req = setChiURLParam(req, "id", "42")
	return setTokenContextWithClaims(req, map[string]interface{}{"sub": adminSubject})
}

// stubAdminEmailUpdate answers every read before the write, the validator's included, as an
// address no other user holds, and the write with updateErr.
func stubAdminEmailUpdate(database *mocks_data.Database, updateErr error) {
	database.On("GetUserById", mock.Anything, mock.Anything, emailTestUserId).
		Return(&models.User{Id: emailTestUserId, Subject: emailTestSubject, Email: "old@example.com"}, nil).Once()
	database.On("GetUserBySubject", mock.Anything, mock.Anything, emailTestSubject).
		Return(&models.User{Id: emailTestUserId, Subject: emailTestSubject}, nil).Once()
	database.On("GetUserByEmail", mock.Anything, mock.Anything, emailTestAddress).Return(nil, nil).Once()
	database.On("UpdateUser", mock.Anything, mock.Anything, mock.Anything).Return(updateErr).Once()
}

func TestHandleAPIUserEmailPut_ALostRaceForTheAddressAnswers409(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	stubAdminEmailUpdate(database, uniqueViolationOnUpdate)

	rr := httptest.NewRecorder()
	HandleAPIUserEmailPut(database, accountvalidation.NewEmailValidator(database), auditLogger).
		ServeHTTP(rr, adminEmailPutRequest(t))

	requireEmailTaken(t, rr)
	// Nothing changed, so nothing is recorded as having changed.
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// The reject arm: only the unique-key refusal is a conflict. Any other write failure is the
// server's, and a 409 for it would send the caller to change an address that was never the
// problem.
func TestHandleAPIUserEmailPut_AnyOtherWriteFailureAnswers500(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	stubAdminEmailUpdate(database, errs.New("the connection was reset"))

	rr := httptest.NewRecorder()
	HandleAPIUserEmailPut(database, accountvalidation.NewEmailValidator(database), auditLogger).
		ServeHTTP(rr, adminEmailPutRequest(t))

	require.Equal(t, http.StatusInternalServerError, rr.Code)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}
