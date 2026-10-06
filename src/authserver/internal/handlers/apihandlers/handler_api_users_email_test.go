package apihandlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Seam 4 of #425 for the duplicate email (#414 item 1). Both email PUTs check the address before
// they write, and the check answers the ordinary duplicate; these cases are the race it cannot
// close, where the engine refuses the UPDATE on users.email. That arrives as data.ErrUniqueViolation
// on every engine (the data tier's TestSetUserEmail_Refusals and
// TestTrySetUserEmail_DuplicateEmailIsErrUniqueViolation), and each PUT
// now answers it 409 EMAIL_ALREADY_EXISTS, as user creation does, where it answered 500.

const (
	emailTestUserId  = int64(42)
	emailTestSubject = "sub-42"
	emailTestAddress = "taken@example.com"
)

// uniqueViolationOnUpdate is the shape commondb hands back for a duplicate key: wrapSQLError's
// sentinel join under ExecSQL, wrapped again by the write.
var uniqueViolationOnUpdate = errs.Wrap(
	errs.Errorf("%w: %w", data.ErrUniqueViolation, errs.New("duplicate key value violates unique constraint \"idx_email\"")),
	"unable to set user email")

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
	return setTokenContextWithClaims(req, map[string]interface{}{"scope": "authserver:manage", "sub": adminSubject})
}

// stubAdminEmailUpdate answers every read before the write, the validator's included, as an
// address no other user holds, and the write with updateErr.
func stubAdminEmailUpdate(database *datamocks.Database, updateErr error) {
	database.On("GetUserById", mock.Anything, mock.Anything, emailTestUserId).
		Return(&record.User{Id: emailTestUserId, Subject: emailTestSubject, Email: "old@example.com"}, nil).Once()
	database.On("GetUserBySubject", mock.Anything, mock.Anything, emailTestSubject).
		Return(&record.User{Id: emailTestUserId, Subject: emailTestSubject}, nil).Once()
	database.On("GetUserByEmail", mock.Anything, mock.Anything, emailTestAddress).Return(nil, nil).Once()
	database.On("SetUserEmail", mock.Anything, mock.Anything, mock.Anything).Return(updateErr).Once()
}

func TestHandleUserEmailPut_ALostRaceForTheAddressAnswers409(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	stubAdminEmailUpdate(database, uniqueViolationOnUpdate)

	rr := httptest.NewRecorder()
	HandleUserEmailPut(database, accountvalidation.NewEmailValidator(database), auditLogger).
		ServeHTTP(rr, adminEmailPutRequest(t))

	requireEmailTaken(t, rr)
	// Nothing changed, so nothing is recorded as having changed.
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// The reject arm: only the unique-key refusal is a conflict. Any other write failure is the
// server's, and a 409 for it would send the caller to change an address that was never the
// problem.
func TestHandleUserEmailPut_AnyOtherWriteFailureAnswers500(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	stubAdminEmailUpdate(database, errs.New("the connection was reset"))

	rr := httptest.NewRecorder()
	HandleUserEmailPut(database, accountvalidation.NewEmailValidator(database), auditLogger).
		ServeHTTP(rr, adminEmailPutRequest(t))

	require.Equal(t, http.StatusInternalServerError, rr.Code)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// The administrator's email change stores through SetUserEmail, the narrow write of the address
// group, and never through UpdateUser, which wrote back the row the request read at its start and
// so undid a disable, a password change or an OTP change made while it was in flight (#471). What
// the write leaves untouched, and the reset code it clears, are the data tier's to show
// (tests/data/user_email_writes_test.go); here, the route hands its write the address and the
// verified flag the administrator sent, and answers with them as it always has.
func TestHandleUserEmailPut_SavesTheEmailNarrowly(t *testing.T) {
	for _, verified := range []bool{true, false} {
		t.Run(fmt.Sprintf("emailVerified %v", verified), func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			database.On("GetUserById", mock.Anything, mock.Anything, emailTestUserId).
				Return(&record.User{
					Id:                             emailTestUserId,
					Subject:                        emailTestSubject,
					Email:                          "old@example.com",
					EmailVerified:                  !verified,
					EmailVerificationCodeEncrypted: []byte("a-pending-code"),
					EmailVerificationCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC(), Valid: true},
					Enabled:                        true,
					PasswordHash:                   "the-hash-as-read",
				}, nil).Once()
			database.On("GetUserBySubject", mock.Anything, mock.Anything, emailTestSubject).
				Return(&record.User{Id: emailTestUserId, Subject: emailTestSubject}, nil).Once()
			database.On("GetUserByEmail", mock.Anything, mock.Anything, emailTestAddress).Return(nil, nil).Once()
			saved := expectNarrowSave(database, "SetUserEmail")
			auditLogger.On("Log", mock.Anything, audit.EventUpdatedUserEmail, mock.Anything).Return().Once()

			body, err := json.Marshal(api.UpdateUserEmailRequest{Email: emailTestAddress, EmailVerified: verified})
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/users/42/email", bytes.NewReader(body))
			req = setChiURLParam(req, "id", "42")
			req = setTokenContextWithClaims(req, map[string]interface{}{"scope": "authserver:manage", "sub": adminSubject})

			rr := httptest.NewRecorder()
			HandleUserEmailPut(database, accountvalidation.NewEmailValidator(database), auditLogger).ServeHTTP(rr, req)

			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			database.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything, mock.Anything)
			require.NotNil(t, *saved, "the narrow write was not reached")
			assert.Equal(t, emailTestUserId, (*saved).Id)
			assert.Equal(t, emailTestAddress, (*saved).Email)
			assert.Equal(t, verified, (*saved).EmailVerified)

			var resp api.UpdateUserResponse
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
			assert.Equal(t, emailTestAddress, resp.User.Email)
			assert.Equal(t, verified, resp.User.EmailVerified)
		})
	}
}
