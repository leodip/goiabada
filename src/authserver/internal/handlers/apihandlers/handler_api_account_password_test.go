package apihandlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	"github.com/leodip/goiabada/core/constants"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/validators"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// This file did not exist before #106 stage 5. Its absence was a finding of the test-landscape
// sweep rather than an oversight to be fixed silently: the self-service password change endpoint
// had no unit coverage at all, which is why the plan says it "must be created".

// apiRevokeTx is an opaque non-nil transaction, the counterpart of the handlers package's
// revokeTx. RevokeUserAuthState rejects a nil one, so a test that let BeginTransaction return
// nil would exercise a shape production never runs.
var apiRevokeTx = &sql.Tx{}

// stubSweep registers the sweep calls for a user with no sessions and no refresh tokens. Thin on
// purpose: the sweep table is owned exhaustively by revocation_test.go in the handlers package,
// and restating it here would mean two places to update.
func stubSweep(database *mocks_data.Database, userId int64, newGeneration int64) {
	database.On("BeginTransaction").Return(apiRevokeTx, nil).Once()
	database.On("IncrementUserAuthStateGeneration", apiRevokeTx, userId).
		Return(newGeneration, nil).Once()
	database.On("GetRefreshTokensByUserId", apiRevokeTx, userId).
		Return([]*models.RefreshToken{}, nil).Once()
	database.On("PromoteRefreshTokenGenerations", apiRevokeTx, []int64{}, newGeneration).
		Return(nil).Once()
	database.On("GetUserSessionsByUserId", apiRevokeTx, userId).
		Return([]models.UserSession{}, nil).Once()
	database.On("CommitTransaction", apiRevokeTx).Return(nil).Once()
	database.On("RollbackTransaction", apiRevokeTx).Return(nil).Once()
}

func accountPasswordRequest(t *testing.T, claims map[string]interface{}, current, next string) *http.Request {
	t.Helper()
	body, err := json.Marshal(map[string]string{
		"currentPassword": current,
		"newPassword":     next,
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/account/password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// The password validator reads the policy straight off the context, so settings must be
	// there or it panics on the type assertion.
	ctx := context.WithValue(req.Context(), constants.ContextKeySettings,
		&models.Settings{PasswordPolicy: enums.PasswordPolicyLow})
	return setTokenContextWithClaims(req.WithContext(ctx), claims)
}

// TestHandleAPIAccountPasswordPut_PreservesTheCallersSession is the wiring test for the one site
// that passes a non-empty exceptSid (#106 decision 4), and it doubles as the field-by-field
// assertion on the new audit payload (decision 7), because this is the only site where
// preservedSessionIdentifier is non-empty.
func TestHandleAPIAccountPasswordPut_PreservesTheCallersSession(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	passwordValidator := validators.NewPasswordValidator()

	const currentPassword = "0ldP4ss!word"
	const newPassword = "N3wP4ss!word"
	const subject = "the-subject"
	const callerSid = "sid-caller"

	currentHash, err := hashutil.HashPassword(currentPassword)
	require.NoError(t, err)
	user := &models.User{Id: 42, Enabled: true, PasswordHash: currentHash}

	database.On("GetUserBySubject", (*sql.Tx)(nil), subject).Return(user, nil).Once()

	var savedHash string
	database.On("SetUserPasswordHash", apiRevokeTx, int64(42), mock.Anything).
		Run(func(args mock.Arguments) {
			savedHash = args.Get(2).(string)
		}).Return(nil).Once()

	// The sweep, with the caller's session preserved. Registering the sid-scoped query is what
	// proves exceptSid was threaded through: with an empty exceptSid the helper never calls it,
	// and the strict mock would report the expectation unmet.
	database.On("BeginTransaction").Return(apiRevokeTx, nil).Once()
	database.On("IncrementUserAuthStateGeneration", apiRevokeTx, int64(42)).
		Return(int64(8), nil).Once()
	database.On("GetRefreshTokensByUserId", apiRevokeTx, int64(42)).
		Return([]*models.RefreshToken{
			{Id: 1, RefreshTokenJti: "rt-keep", SessionIdentifier: callerSid},
			{Id: 2, RefreshTokenJti: "rt-other", SessionIdentifier: "sid-other"},
		}, nil).Once()
	database.On("GetRefreshTokensBySessionIdentifier", apiRevokeTx, callerSid).
		Return([]*models.RefreshToken{{Id: 1, RefreshTokenJti: "rt-keep", SessionIdentifier: callerSid}}, nil).Once()
	database.On("UpdateRefreshToken", apiRevokeTx, mock.MatchedBy(func(rt *models.RefreshToken) bool {
		return rt.Id == 2
	})).Return(nil).Once()
	database.On("PromoteRefreshTokenGenerations", apiRevokeTx, []int64{1}, int64(8)).Return(nil).Once()
	database.On("GetUserSessionsByUserId", apiRevokeTx, int64(42)).
		Return([]models.UserSession{
			{Id: 100, SessionIdentifier: callerSid},
			{Id: 200, SessionIdentifier: "sid-other"},
		}, nil).Once()
	database.On("PromoteUserSessionGeneration", apiRevokeTx, int64(100), int64(8)).Return(nil).Once()
	database.On("DeleteUserSession", apiRevokeTx, int64(200)).Return(nil).Once()
	database.On("CommitTransaction", apiRevokeTx).Return(nil).Once()
	database.On("RollbackTransaction", apiRevokeTx).Return(nil).Once()

	auditLogger.On("Log", constants.AuditChangedPassword, mock.Anything).Return().Once()
	var payload map[string]interface{}
	auditLogger.On("Log", constants.AuditRevokedUserAuthState, mock.Anything).
		Run(func(args mock.Arguments) {
			payload = args.Get(1).(map[string]interface{})
		}).Return().Once()

	rr := httptest.NewRecorder()
	handler := HandleAPIAccountPasswordPut(database, passwordValidator, auditLogger, unlimitedCredentials{})
	handler.ServeHTTP(rr, accountPasswordRequest(t,
		map[string]interface{}{"sub": subject, "sid": callerSid, "auth_time": float64(1)},
		currentPassword, newPassword))

	assert.Equal(t, http.StatusOK, rr.Code)
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)

	assert.True(t, hashutil.VerifyPasswordHash(savedHash, newPassword))
	database.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything)

	// The audit payload, field by field. Asserted here rather than trusted because the event is
	// the only durable record of what a revocation did, and a missing or renamed field is
	// invisible to every other test.
	require.NotNil(t, payload)
	assert.Equal(t, int64(42), payload["userId"])
	assert.Equal(t, "password_change", payload["reason"])
	assert.Equal(t, subject, payload["loggedInUser"])
	assert.Equal(t, []string{"sid-other"}, payload["terminatedSessionIdentifiers"])
	assert.Equal(t, []string{"rt-other"}, payload["revokedRefreshTokenJtis"])
	assert.Equal(t, callerSid, payload["preservedSessionIdentifier"])
	assert.Equal(t, int64(7), payload["oldGeneration"])
	assert.Equal(t, int64(8), payload["newGeneration"])
	// Exactly these eight keys. A ninth would go unnoticed, and more importantly this pins that
	// none of the eight was dropped, which an individual assertion on a nil map value cannot do.
	assert.Len(t, payload, 8)
}

// TestHandleAPIAccountPasswordPut_SidlessBearerRevokesEverything covers the case that looks like
// a bug and is not. After #106 decision 9 an offline or ROPC access token carries no sid, so
// exceptSid is empty and the change revokes everything including the caller's own grant.
//
// That is the conservative direction and it is deliberate: such a bearer proves no live session
// to preserve. Keep this case. Someone "fixing" it by falling back to another source for the sid
// would let a caller preserve a session they did not authenticate with.
func TestHandleAPIAccountPasswordPut_SidlessBearerRevokesEverything(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	passwordValidator := validators.NewPasswordValidator()

	const currentPassword = "0ldP4ss!word"
	const newPassword = "N3wP4ss!word"
	const subject = "the-subject"

	currentHash, err := hashutil.HashPassword(currentPassword)
	require.NoError(t, err)

	database.On("GetUserBySubject", (*sql.Tx)(nil), subject).
		Return(&models.User{Id: 42, Enabled: true, PasswordHash: currentHash}, nil).Once()
	database.On("SetUserPasswordHash", apiRevokeTx, int64(42), mock.Anything).Return(nil).Once()
	stubSweep(database, 42, 8)

	auditLogger.On("Log", constants.AuditChangedPassword, mock.Anything).Return().Once()
	var payload map[string]interface{}
	auditLogger.On("Log", constants.AuditRevokedUserAuthState, mock.Anything).
		Run(func(args mock.Arguments) {
			payload = args.Get(1).(map[string]interface{})
		}).Return().Once()

	rr := httptest.NewRecorder()
	handler := HandleAPIAccountPasswordPut(database, passwordValidator, auditLogger, unlimitedCredentials{})
	handler.ServeHTTP(rr, accountPasswordRequest(t,
		map[string]interface{}{"sub": subject, "auth_time": float64(1)},
		currentPassword, newPassword))

	assert.Equal(t, http.StatusOK, rr.Code)
	database.AssertExpectations(t)

	// No sid-scoped query, which is what an empty exceptSid means. The strict mock enforces it:
	// no such expectation is registered, so a call would fail the test.
	database.AssertNotCalled(t, "GetRefreshTokensBySessionIdentifier", mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "PromoteUserSessionGeneration", mock.Anything, mock.Anything, mock.Anything)

	// Present and "", never absent and never JSON null (finding 8). Asserting the key exists
	// separately from its value is the only way to tell those apart in a map[string]interface{}.
	value, present := payload["preservedSessionIdentifier"]
	assert.True(t, present, "the key must be present even when nothing was preserved")
	assert.Equal(t, "", value)
}

// TestHandleAPIAccountPasswordPut_RevocationFailureIsA500 keeps this site's failure coverage
// thin: the reset handler owns the three-variant rollback matrix. What this adds is that a
// SECOND site does not emit its pre-existing event either when the revocation fails, since the
// two events are adjacent in the code and it would be easy to leave the first one outside the
// error check.
func TestHandleAPIAccountPasswordPut_RevocationFailureIsA500(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	passwordValidator := validators.NewPasswordValidator()

	const currentPassword = "0ldP4ss!word"
	currentHash, err := hashutil.HashPassword(currentPassword)
	require.NoError(t, err)

	database.On("GetUserBySubject", (*sql.Tx)(nil), "the-subject").
		Return(&models.User{Id: 42, Enabled: true, PasswordHash: currentHash}, nil).Once()
	database.On("BeginTransaction").Return(apiRevokeTx, nil).Once()
	database.On("SetUserPasswordHash", apiRevokeTx, int64(42), mock.Anything).Return(nil).Once()
	database.On("IncrementUserAuthStateGeneration", apiRevokeTx, int64(42)).
		Return(int64(0), errors.New("increment failed")).Once()
	database.On("RollbackTransaction", apiRevokeTx).Return(nil).Once()

	rr := httptest.NewRecorder()
	handler := HandleAPIAccountPasswordPut(database, passwordValidator, auditLogger, unlimitedCredentials{})
	handler.ServeHTTP(rr, accountPasswordRequest(t,
		map[string]interface{}{"sub": "the-subject", "sid": "sid-caller", "auth_time": float64(1)},
		currentPassword, "N3wP4ss!word"))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	database.AssertExpectations(t)
	database.AssertNotCalled(t, "CommitTransaction", mock.Anything)
	// NEITHER event. changed_password would otherwise claim a password change that rolled back.
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything)
}
