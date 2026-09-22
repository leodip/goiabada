package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/authserver/internal/audit"
	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// This file did not exist before #251 stage 3, and section 1 of the agreement recorded its absence:
// the rotate endpoint had no unit coverage at all, which is how five unsynchronised writes survived
// since v0.7.
//
// What it owns is the mapping from signingkeys.SigningKeyRotator's outcomes to a status, an error code and
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
func signingKey(id int64, state models.KeyState) models.KeyPair {
	return models.KeyPair{Id: id, State: state.String(), Type: "RSA", Algorithm: "RS256"}
}

// stubRotateRead registers the transaction the rotator opens through RunInTransaction and the
// classify read inside it. The commit and the rollback are the helper's and never reach the mock;
// the returned stub records what the body handed the helper, which is how the refusal cases below
// assert that nothing was committed.
func stubRotateRead(database *mocks_data.Database, keys []models.KeyPair) *mocks_data.RunInTransactionStub {
	stub := mocks_data.ExpectRunInTransaction(database, rotateTx)
	database.On("GetAllSigningKeys", mock.Anything, rotateTx).Return(keys, nil).Once()
	return stub
}

// rotateKeysRequestId is chi's request id for these rows: the attribute the request logger writes,
// and therefore the one a 500's log record and its body have to agree on.
const rotateKeysRequestId = "req-rotate-keys"

func rotateRequest() *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/admin/settings/keys/rotate", nil)
	r = r.WithContext(context.WithValue(r.Context(), middleware.RequestIDKey, rotateKeysRequestId))
	// The validated bearer token the chain puts on the context, which is where the audit
	// payload's "loggedInUser" comes from. It used to come from a mocked
	// AuthHelper.GetLoggedInSubject, which is why nothing here noticed the real accessor read a
	// session key no auth server middleware writes and returned "" at every such site (#385).
	return setTokenContextWithClaims(r, map[string]interface{}{"sub": adminSubject})
}

// TestHandleAPISettingsKeysRotatePost_Success is the wiring test: the whole transition runs and the
// audit entry is written once. It also pins that the audit happens only after a commit, which is the
// property the three refusal cases below assert the other half of.
func TestHandleAPISettingsKeysRotatePost_Success(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	stub := stubRotateRead(database, []models.KeyPair{
		signingKey(1, models.KeyStatePrevious),
		signingKey(2, models.KeyStateCurrent),
		signingKey(3, models.KeyStateNext),
	})
	database.On("DeleteKeyPair", mock.Anything, rotateTx, int64(1)).Return(nil).Once()
	database.On("UpdateKeyPairState", mock.Anything, rotateTx, int64(2),
		models.KeyStateCurrent.String(), models.KeyStatePrevious.String()).Return(true, nil).Once()
	database.On("UpdateKeyPairState", mock.Anything, rotateTx, int64(3),
		models.KeyStateNext.String(), models.KeyStateCurrent.String()).Return(true, nil).Once()
	database.On("CreateKeyPair", mock.Anything, rotateTx, mock.MatchedBy(func(kp *models.KeyPair) bool {
		return kp.State == models.KeyStateNext.String()
	})).Return(nil).Once()

	var payload map[string]interface{}
	auditLogger.On("Log", mock.Anything, audit.AuditRotatedKeys, mock.Anything).
		Run(func(args mock.Arguments) {
			payload = args.Get(2).(map[string]interface{})
		}).Return().Once()

	rr := httptest.NewRecorder()
	HandleAPISettingsKeysRotatePost(database, auditLogger).ServeHTTP(rr, rotateRequest())

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.JSONEq(t, `{"success":true}`, rr.Body.String())
	require.NotNil(t, payload)
	assert.Equal(t, adminSubject, payload["loggedInUser"])
	assert.NoError(t, stub.BodyErr, "the body asked the helper to commit")
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

// TestHandleAPISettingsKeysRotatePost_RotationInProgress covers the loser of a race. 409 rather than
// 200 because this call rotated nothing, and no audit entry because the log must carry exactly one
// entry per rotation that happened.
func TestHandleAPISettingsKeysRotatePost_RotationInProgress(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	stub := stubRotateRead(database, []models.KeyPair{
		signingKey(2, models.KeyStateCurrent),
		signingKey(3, models.KeyStateNext),
	})
	// The compare-and-set transitions no row: another rotation already moved this key.
	database.On("UpdateKeyPairState", mock.Anything, rotateTx, int64(2),
		models.KeyStateCurrent.String(), models.KeyStatePrevious.String()).Return(false, nil).Once()

	rr := httptest.NewRecorder()
	HandleAPISettingsKeysRotatePost(database, auditLogger).ServeHTTP(rr, rotateRequest())

	assert.Equal(t, http.StatusConflict, rr.Code)
	body := decodeErrorBody(t, rr)
	assert.Equal(t, "ROTATION_IN_PROGRESS", body.ErrorCode)
	assert.Equal(t, "Another key rotation is in progress", body.ErrorDescription)
	// No CreateKeyPair was registered, so the mock fails the test if the rotator went on past the
	// refusal, and the body handed the refusal to the helper, which is what rolls it back rather
	// than committing. auditLogger has no expectation at all, which NewAuditLogger's cleanup turns
	// into a failure on any Log call.
	assert.Error(t, stub.BodyErr)
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

	stub := stubRotateRead(database, []models.KeyPair{
		signingKey(1, models.KeyStatePrevious),
		signingKey(2, models.KeyStateCurrent),
	})

	rr := httptest.NewRecorder()
	capture := testutil.CaptureSlog(t)

	HandleAPISettingsKeysRotatePost(database, auditLogger).ServeHTTP(rr, rotateRequest())

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

	assert.Error(t, stub.BodyErr, "the refusal reached the helper, which rolls back")
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

// TestHandleAPISettingsKeysRotatePost_InternalError covers everything that is neither sentinel: an
// engine failure keeps the generic code, so a caller cannot mistake a broken database for a lost
// race and retry into it.
func TestHandleAPISettingsKeysRotatePost_InternalError(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	mocks_data.ExpectRunInTransaction(database, rotateTx)
	database.On("GetAllSigningKeys", mock.Anything, rotateTx).
		Return([]models.KeyPair(nil), assert.AnError).Once()

	rr := httptest.NewRecorder()
	HandleAPISettingsKeysRotatePost(database, auditLogger).ServeHTTP(rr, rotateRequest())

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "INTERNAL_SERVER_ERROR", decodeErrorBody(t, rr).ErrorCode)
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

// TestHandleAPISettingsKeysGet_OrdersNextCurrentPrevious owns the guarantee the admin console now
// relies on. Its page used to re-impose this order with a structurally identical copy of the loop
// below, which is the only reason the console named a signing-key state at all; #385 deleted the
// copy, so the order is this endpoint's claim and has to be tested where it is made. The console's
// own case can only show that it renders what its stub returned.
//
// Every row is fed deliberately unsorted, because a fixture already in the answer's order passes
// with the loop deleted.
func TestHandleAPISettingsKeysGet_OrdersNextCurrentPrevious(t *testing.T) {

	testCases := []struct {
		name  string
		given []models.KeyState
		want  []string
		why   string
	}{
		{
			name:  "reversed",
			given: []models.KeyState{models.KeyStatePrevious, models.KeyStateCurrent, models.KeyStateNext},
			want:  []string{"next", "current", "previous"},
			why:   "the full set, arriving backwards",
		},
		{
			name:  "next last, two previous keys",
			given: []models.KeyState{models.KeyStatePrevious, models.KeyStatePrevious, models.KeyStateCurrent, models.KeyStateNext},
			want:  []string{"next", "current", "previous", "previous"},
			why:   "every previous key is kept, after the single next and current",
		},
		{
			name:  "current first",
			given: []models.KeyState{models.KeyStateCurrent, models.KeyStateNext, models.KeyStatePrevious},
			want:  []string{"next", "current", "previous"},
			why:   "next is hoisted above current",
		},
		{
			name:  "no next key, which is the state a refused rotation leaves",
			given: []models.KeyState{models.KeyStatePrevious, models.KeyStateCurrent},
			want:  []string{"current", "previous"},
			why:   "an absent state contributes no row rather than an empty one",
		},
		{
			name:  "one key only",
			given: []models.KeyState{models.KeyStateCurrent},
			want:  []string{"current"},
			why:   "a freshly seeded deployment before its first rotation",
		},
		{
			name:  "no keys at all",
			given: nil,
			want:  []string{},
			why:   "an empty answer is an empty list, not a null",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)

			keys := make([]models.KeyPair, 0, len(tc.given))
			for i, state := range tc.given {
				keys = append(keys, signingKey(int64(i+1), state))
			}
			// The typed nil the handler passes, not an untyped one: testify compares the
			// argument's dynamic type too, so `nil` here never matches `(*sql.Tx)(nil)`.
			database.On("GetAllSigningKeys", mock.Anything, (*sql.Tx)(nil)).Return(keys, nil).Once()

			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/settings/keys", nil)
			HandleAPISettingsKeysGet(database).ServeHTTP(rr, req)

			require.Equal(t, http.StatusOK, rr.Code)

			var body api.GetSettingsKeysResponse
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))

			states := make([]string, 0, len(body.Keys))
			for _, k := range body.Keys {
				states = append(states, k.State)
			}
			assert.Equal(t, tc.want, states, "%s", tc.why)

			// Every key the database held is in the answer. Without this, a loop that dropped a
			// previous key rather than misordering it would pass every row above except the one
			// carrying two.
			assert.Len(t, body.Keys, len(tc.given), "no key is lost on the way out")

			database.AssertExpectations(t)
		})
	}
}
