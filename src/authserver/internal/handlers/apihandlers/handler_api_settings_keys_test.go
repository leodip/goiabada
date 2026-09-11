package apihandlers

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5/middleware"
	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	"github.com/leodip/goiabada/core/constants"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/enums"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// This file did not exist before #251 stage 3, and section 1 of the agreement recorded its absence:
// the rotate endpoint had no unit coverage at all, which is how five unsynchronised writes survived
// since v0.7.
//
// What it owns is the mapping from oauth.SigningKeyRotator's outcomes to a status, an error code and
// an audit entry. Deliberately nothing about storage: the rotator's own tests own what reaches the
// key_pairs table, and asserting rows from here would be a side channel that passes with the mapping
// broken.
//
// Every case drives the REAL rotator over a mocked Database, because the handler constructs it and
// the agreement kept the (authHelper, database, auditLogger) signature so routes.go stays untouched.
// That costs one real 4096-bit key generation per case, about 300ms, since the rotator generates the
// replacement before opening the transaction and so on every path including the refusals.

// rotateTx is an opaque non-nil transaction. Handing the rotator a nil one would exercise a shape
// production never runs.
var rotateTx = &sql.Tx{}

// signingKey builds a key_pairs row in the given state. Only Id and State matter here: nothing in
// this file reads key material.
func signingKey(id int64, state enums.KeyState) models.KeyPair {
	return models.KeyPair{Id: id, State: state.String(), Type: "RSA", Algorithm: "RS256"}
}

// stubRotateRead registers the transaction the rotator opens through RunInTransaction and the
// classify read inside it. The commit and the rollback are the helper's and never reach the mock;
// the returned stub records what the body handed the helper, which is how the refusal cases below
// assert that nothing was committed.
func stubRotateRead(database *mocks_data.Database, keys []models.KeyPair) *runInTransactionStub {
	stub := expectRunInTransaction(database, rotateTx)
	database.On("GetAllSigningKeys", rotateTx).Return(keys, nil).Once()
	return stub
}

// rotateKeysRequestId is chi's request id for these rows: the attribute the request logger writes,
// and therefore the one a 500's log record and its body have to agree on.
const rotateKeysRequestId = "req-rotate-keys"

func rotateRequest() *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/admin/settings/keys/rotate", nil)
	return r.WithContext(context.WithValue(r.Context(), middleware.RequestIDKey, rotateKeysRequestId))
}

// TestHandleAPISettingsKeysRotatePost_Success is the wiring test: the whole transition runs and the
// audit entry is written once. It also pins that the audit happens only after a commit, which is the
// property the three refusal cases below assert the other half of.
func TestHandleAPISettingsKeysRotatePost_Success(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	authHelper := mocks_handlerhelpers.NewAuthHelper(t)

	const subject = "the-admin"

	stub := stubRotateRead(database, []models.KeyPair{
		signingKey(1, enums.KeyStatePrevious),
		signingKey(2, enums.KeyStateCurrent),
		signingKey(3, enums.KeyStateNext),
	})
	database.On("DeleteKeyPair", rotateTx, int64(1)).Return(nil).Once()
	database.On("UpdateKeyPairState", rotateTx, int64(2),
		enums.KeyStateCurrent.String(), enums.KeyStatePrevious.String()).Return(true, nil).Once()
	database.On("UpdateKeyPairState", rotateTx, int64(3),
		enums.KeyStateNext.String(), enums.KeyStateCurrent.String()).Return(true, nil).Once()
	database.On("CreateKeyPair", rotateTx, mock.MatchedBy(func(kp *models.KeyPair) bool {
		return kp.State == enums.KeyStateNext.String()
	})).Return(nil).Once()

	authHelper.On("GetLoggedInSubject", mock.Anything).Return(subject)
	var payload map[string]interface{}
	auditLogger.On("Log", constants.AuditRotatedKeys, mock.Anything).
		Run(func(args mock.Arguments) {
			payload = args.Get(1).(map[string]interface{})
		}).Return().Once()

	rr := httptest.NewRecorder()
	HandleAPISettingsKeysRotatePost(authHelper, database, auditLogger).ServeHTTP(rr, rotateRequest())

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.JSONEq(t, `{"success":true}`, rr.Body.String())
	require.NotNil(t, payload)
	assert.Equal(t, subject, payload["loggedInUser"])
	assert.NoError(t, stub.bodyErr, "the body asked the helper to commit")
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

// TestHandleAPISettingsKeysRotatePost_RotationInProgress covers the loser of a race. 409 rather than
// 200 because this call rotated nothing, and no audit entry because the log must carry exactly one
// entry per rotation that happened.
func TestHandleAPISettingsKeysRotatePost_RotationInProgress(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	authHelper := mocks_handlerhelpers.NewAuthHelper(t)

	stub := stubRotateRead(database, []models.KeyPair{
		signingKey(2, enums.KeyStateCurrent),
		signingKey(3, enums.KeyStateNext),
	})
	// The compare-and-set transitions no row: another rotation already moved this key.
	database.On("UpdateKeyPairState", rotateTx, int64(2),
		enums.KeyStateCurrent.String(), enums.KeyStatePrevious.String()).Return(false, nil).Once()

	rr := httptest.NewRecorder()
	HandleAPISettingsKeysRotatePost(authHelper, database, auditLogger).ServeHTTP(rr, rotateRequest())

	assert.Equal(t, http.StatusConflict, rr.Code)
	body := decodeErrorBody(t, rr)
	assert.Equal(t, "ROTATION_IN_PROGRESS", body.ErrorCode)
	assert.Equal(t, "Another key rotation is in progress", body.ErrorDescription)
	// No CreateKeyPair was registered, so the mock fails the test if the rotator went on past the
	// refusal, and the body handed the refusal to the helper, which is what rolls it back rather
	// than committing. auditLogger has no expectation at all, which NewAuditLogger's cleanup turns
	// into a failure on any Log call.
	assert.Error(t, stub.bodyErr)
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

// TestHandleAPISettingsKeysRotatePost_KeySetIncomplete is the defect the issue opens with: a
// deployment with no next key. No DeleteKeyPair expectation is registered, so the mock fails the
// test if the handler destroys the previous key on its way to refusing, which is exactly what the
// old handler did.
func TestHandleAPISettingsKeysRotatePost_KeySetIncomplete(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	authHelper := mocks_handlerhelpers.NewAuthHelper(t)

	stub := stubRotateRead(database, []models.KeyPair{
		signingKey(1, enums.KeyStatePrevious),
		signingKey(2, enums.KeyStateCurrent),
	})

	rr := httptest.NewRecorder()
	capture := testutil.CaptureSlog(t)

	HandleAPISettingsKeysRotatePost(authHelper, database, auditLogger).ServeHTTP(rr, rotateRequest())

	logged := capture.Text()

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	body := decodeErrorBody(t, rr)
	assert.Equal(t, "KEY_SET_INCOMPLETE", body.ErrorCode,
		"the code a caller routes on survives; only the generic 500s were flattened")
	assert.Contains(t, body.ErrorDescription, "Expected current and next keys to exist")

	// The half this branch skipped entirely while it wrote a bare 4xx envelope: a 500 is logged
	// once, with its stack, and names on the wire the request id an operator finds that record by.
	assert.Equal(t, 1, strings.Count(logged, "level=ERROR"), "one record, not none and not two")
	assert.Contains(t, logged, "msg=\"internal server error\"")
	assert.Contains(t, logged, "request_id="+rotateKeysRequestId)
	assert.Contains(t, logged, "handler_api_settings_keys.go",
		"slog's text handler prints an error value with %+v, so the stack rides in the record")
	assert.Contains(t, body.ErrorDescription, rotateKeysRequestId,
		"the id on the wire and the id in the log have to be the same string")

	assert.Error(t, stub.bodyErr, "the refusal reached the helper, which rolls back")
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

// TestHandleAPISettingsKeysRotatePost_InternalError covers everything that is neither sentinel: an
// engine failure keeps the generic code, so a caller cannot mistake a broken database for a lost
// race and retry into it.
func TestHandleAPISettingsKeysRotatePost_InternalError(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	authHelper := mocks_handlerhelpers.NewAuthHelper(t)

	expectRunInTransaction(database, rotateTx)
	database.On("GetAllSigningKeys", rotateTx).
		Return([]models.KeyPair(nil), assert.AnError).Once()

	rr := httptest.NewRecorder()
	HandleAPISettingsKeysRotatePost(authHelper, database, auditLogger).ServeHTTP(rr, rotateRequest())

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "INTERNAL_SERVER_ERROR", decodeErrorBody(t, rr).ErrorCode)
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}
