package apihandlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	mocks_communication "github.com/leodip/goiabada/core/communication/mocks"
	"github.com/leodip/goiabada/core/constants"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/enums"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	mocks_users "github.com/leodip/goiabada/core/user/mocks"
	"github.com/leodip/goiabada/core/validators"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// This file did not exist before #106 stage 5, which the test-landscape sweep recorded as a
// finding: the admin user CRUD endpoints had no unit coverage.

const adminSubject = "the-admin"

func enabledRequest(t *testing.T, userId string, enabled bool) *http.Request {
	t.Helper()
	body, err := json.Marshal(map[string]bool{"enabled": enabled})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/users/"+userId+"/enabled",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = setChiURLParam(req, "id", userId)
	return setTokenContextWithClaims(req, map[string]interface{}{
		"sub": adminSubject, "auth_time": float64(1),
	})
}

// TestHandleAPIUserEnabledPut_RevocationConditionality is the four-row matrix from #106 findings 4
// and 21. The endpoint serves BOTH directions through one handler, so which requests revoke is a
// real branch rather than a formality.
//
// The rule under test: only a genuine enabled-to-disabled transition sweeps. Enabling never does,
// because no credential changed, and re-disabling an already-disabled account never does either,
// because it would advance the generation and evict sessions a previous disable already handled,
// making a repeated request non-idempotent.
//
// Every row asserts AuditUpdatedUserDetails still fires. That event is pre-existing and decision 7
// requires it to be untouched, so a row where it stopped firing would be a regression this change
// caused rather than a behaviour it intended.
func TestHandleAPIUserEnabledPut_RevocationConditionality(t *testing.T) {
	const userId = int64(42)

	for _, tc := range []struct {
		label string
		// requestedEnabled is the body's enabled field.
		requestedEnabled bool
		// transitioned is what TrySetUserEnabled reports, standing in for the row's starting
		// state: false means the row was already in the requested state.
		transitioned bool
		wantSweep    bool
	}{
		{
			label:            "disabling a live account sweeps and audits",
			requestedEnabled: false, transitioned: true, wantSweep: true,
		},
		{
			// The idempotence row. A second disable must be a no-op beyond the generic event.
			label:            "disabling an already-disabled account does neither",
			requestedEnabled: false, transitioned: false, wantSweep: false,
		},
		{
			label:            "enabling a disabled account does neither",
			requestedEnabled: true, transitioned: true, wantSweep: false,
		},
		{
			label:            "enabling an already-enabled account does neither",
			requestedEnabled: true, transitioned: false, wantSweep: false,
		},
	} {
		t.Run(tc.label, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_audit.NewAuditLogger(t)

			database.On("GetUserById", (*sql.Tx)(nil), userId).
				Return(&models.User{Id: userId}, nil).Once()

			if tc.requestedEnabled {
				// Enabling: the compare-and-set runs outside a transaction, since there is no
				// sweep to be atomic with. Both directions go through it, so neither stays on
				// the full-row UpdateUser that decision 14 rules out.
				database.On("TrySetUserEnabled", (*sql.Tx)(nil), userId, false, true).
					Return(tc.transitioned, nil).Once()
			} else {
				database.On("BeginTransaction").Return(apiRevokeTx, nil).Once()
				database.On("TrySetUserEnabled", apiRevokeTx, userId, true, false).
					Return(tc.transitioned, nil).Once()
				database.On("RollbackTransaction", apiRevokeTx).Return(nil).Once()
				if tc.transitioned {
					database.On("IncrementUserAuthStateGeneration", apiRevokeTx, userId).
						Return(int64(4), nil).Once()
					database.On("GetRefreshTokensByUserId", apiRevokeTx, userId).
						Return([]*models.RefreshToken{}, nil).Once()
					database.On("PromoteRefreshTokenGenerations", apiRevokeTx, []int64{}, int64(4)).
						Return(nil).Once()
					database.On("GetUserSessionsByUserId", apiRevokeTx, userId).
						Return([]models.UserSession{}, nil).Once()
					database.On("CommitTransaction", apiRevokeTx).Return(nil).Once()
				}
			}

			// The pre-existing event, on every row.
			auditLogger.On("Log", constants.AuditUpdatedUserDetails, mock.Anything).Return().Once()
			var revocationPayload map[string]interface{}
			if tc.wantSweep {
				auditLogger.On("Log", constants.AuditRevokedUserAuthState, mock.Anything).
					Run(func(args mock.Arguments) {
						revocationPayload = args.Get(1).(map[string]interface{})
					}).Return().Once()
			}

			// The response re-reads the user.
			database.On("GetUserById", (*sql.Tx)(nil), userId).
				Return(&models.User{Id: userId, Enabled: tc.requestedEnabled}, nil).Once()

			rr := httptest.NewRecorder()
			handler := HandleAPIUserEnabledPut(database, auditLogger)
			handler.ServeHTTP(rr, enabledRequest(t, "42", tc.requestedEnabled))

			assert.Equal(t, http.StatusOK, rr.Code)
			database.AssertExpectations(t)
			auditLogger.AssertExpectations(t)

			if tc.wantSweep {
				require.NotNil(t, revocationPayload)
				assert.Equal(t, "account_disabled", revocationPayload["reason"])
				assert.Equal(t, adminSubject, revocationPayload["loggedInUser"])
				// Nothing preserved on this site, reported as "" rather than omitted.
				value, present := revocationPayload["preservedSessionIdentifier"]
				assert.True(t, present)
				assert.Equal(t, "", value)
			} else {
				// No generation advance and no revocation event. Both matter: the first is the
				// state change, the second is the claim about it.
				database.AssertNotCalled(t, "IncrementUserAuthStateGeneration",
					mock.Anything, mock.Anything)
				auditLogger.AssertNotCalled(t, "Log", constants.AuditRevokedUserAuthState,
					mock.Anything)
			}

			// Never the full-row write, in either direction (decision 14).
			database.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything)
		})
	}
}

// TestHandleAPIUserEnabledPut_SweepFailureRollsBack: the disable transition succeeded and the
// sweep then failed. The compare-and-set must not survive, so the user stays enabled and no event
// claims otherwise.
func TestHandleAPIUserEnabledPut_SweepFailureRollsBack(t *testing.T) {
	const userId = int64(42)
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	database.On("GetUserById", (*sql.Tx)(nil), userId).Return(&models.User{Id: userId}, nil).Once()
	database.On("BeginTransaction").Return(apiRevokeTx, nil).Once()
	database.On("TrySetUserEnabled", apiRevokeTx, userId, true, false).Return(true, nil).Once()
	database.On("IncrementUserAuthStateGeneration", apiRevokeTx, userId).
		Return(int64(0), assert.AnError).Once()
	database.On("RollbackTransaction", apiRevokeTx).Return(nil).Once()

	rr := httptest.NewRecorder()
	handler := HandleAPIUserEnabledPut(database, auditLogger)
	handler.ServeHTTP(rr, enabledRequest(t, "42", false))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	database.AssertExpectations(t)
	database.AssertNotCalled(t, "CommitTransaction", mock.Anything)
	// Not even the pre-existing event: the disable did not happen, so recording it as a user
	// detail update would be false.
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything)
}

// TestHandleAPIUserPasswordPut_RevokesEverything covers the fourth site, the one the issue never
// mentioned (#106 decision 2). An admin setting another user's password revokes all of that
// user's state with no exceptSid: the admin's own session belongs to a different user and is
// unaffected.
func TestHandleAPIUserPasswordPut_RevokesEverything(t *testing.T) {
	const userId = int64(42)
	const newPassword = "N3wP4ss!word"

	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	passwordValidator := validators.NewPasswordValidator()

	database.On("GetUserById", (*sql.Tx)(nil), userId).Return(&models.User{Id: userId}, nil).Once()

	var savedHash string
	database.On("SetUserPasswordHash", apiRevokeTx, userId, mock.Anything).
		Run(func(args mock.Arguments) {
			savedHash = args.Get(2).(string)
		}).Return(nil).Once()
	stubSweep(database, userId, 4)

	auditLogger.On("Log", constants.AuditUpdatedUserAuthentication, mock.Anything).Return().Once()
	var payload map[string]interface{}
	auditLogger.On("Log", constants.AuditRevokedUserAuthState, mock.Anything).
		Run(func(args mock.Arguments) {
			payload = args.Get(1).(map[string]interface{})
		}).Return().Once()

	database.On("GetUserById", (*sql.Tx)(nil), userId).
		Return(&models.User{Id: userId, Enabled: true}, nil).Once()

	body, err := json.Marshal(map[string]string{"newPassword": newPassword})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/users/42/password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = setChiURLParam(req, "id", "42")
	ctx := context.WithValue(req.Context(), constants.ContextKeySettings,
		&models.Settings{PasswordPolicy: enums.PasswordPolicyLow})
	req = setTokenContextWithClaims(req.WithContext(ctx),
		map[string]interface{}{"sub": adminSubject, "auth_time": float64(1)})

	rr := httptest.NewRecorder()
	handler := HandleAPIUserPasswordPut(database, passwordValidator, auditLogger)
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)

	assert.True(t, hashutil.VerifyPasswordHash(savedHash, newPassword))
	database.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything)
	// No exceptSid, so no sid-scoped query and nothing promoted.
	database.AssertNotCalled(t, "GetRefreshTokensBySessionIdentifier", mock.Anything, mock.Anything)

	require.NotNil(t, payload)
	assert.Equal(t, "admin_password_set", payload["reason"])
	assert.Equal(t, adminSubject, payload["loggedInUser"])
	assert.Equal(t, userId, payload["userId"])
	value, present := payload["preservedSessionIdentifier"]
	assert.True(t, present)
	assert.Equal(t, "", value)
}

// TestHandleAPIUserOTPPut_DisableCommitsBothWritesAtomically is the admin half of #111 decision 13.
// Decision 4 names two disable sites and this is the second: they share disableUserOTP, and this case
// is what pins that this handler goes through it rather than keeping two unbound writes of its own.
// Its account sibling, TestHandleAPIAccountOTPPut_Disable_CommitsBothWritesAtomically, carries the
// reasoning about why the two writes have to commit together.
func TestHandleAPIUserOTPPut_DisableCommitsBothWritesAtomically(t *testing.T) {
	const userId = int64(42)

	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	user := &models.User{Id: userId, Enabled: true, OTPEnabled: true}
	database.On("GetUserById", (*sql.Tx)(nil), userId).Return(user, nil).Once()

	var calls []string
	database.On("BeginTransaction").Return(otpDisableTx, nil).
		Run(func(mock.Arguments) { calls = append(calls, "begin") }).Once()
	database.On("UpdateUser", otpDisableTx, user).Return(nil).
		Run(func(mock.Arguments) { calls = append(calls, "update") }).Once()
	database.On("ResetUserOTPStep", otpDisableTx, userId).Return(nil).
		Run(func(mock.Arguments) { calls = append(calls, "reset") }).Once()
	database.On("CommitTransaction", otpDisableTx).Return(nil).
		Run(func(mock.Arguments) { calls = append(calls, "commit") }).Once()
	database.On("RollbackTransaction", otpDisableTx).Return(nil).Once()

	auditLogger.On("Log", constants.AuditDisabledOTP, mock.Anything).Return().Once()
	database.On("GetUserById", (*sql.Tx)(nil), userId).
		Return(&models.User{Id: userId, Enabled: true}, nil).Once()

	body, err := json.Marshal(map[string]bool{"enabled": false})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/users/42/otp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = setChiURLParam(req, "id", "42")
	req = setTokenContextWithClaims(req, map[string]interface{}{
		"sub": adminSubject, "auth_time": float64(1),
	})

	rr := httptest.NewRecorder()
	HandleAPIUserOTPPut(database, auditLogger).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, []string{"begin", "update", "reset", "commit"}, calls,
		"both writes belong inside one transaction, otp_enabled first per decision 10, commit last")
	assert.False(t, user.OTPEnabled)
}

// TestHandleAPIUserCreatePost_StoresResetCodeHash covers the admin user-create path, which
// is one of the three places Goiabada issues a password-reset link and the only one with
// no unit coverage of the email branch before this.
//
// The property: the hash stored beside the encrypted code is the hash of the code that
// actually went into the link. It is the only thing that will find this row when the link
// comes back, since the link carries the code and no email address (#112), so a hash of
// anything else leaves the new user unable to set a password at all.
func TestHandleAPIUserCreatePost_StoresResetCodeHash(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)
	userCreator := mocks_users.NewUserCreator(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	emailSender := mocks_communication.NewEmailSender(t)

	handler := HandleAPIUserCreatePost(httpHelper, database, userCreator,
		validators.NewEmailValidator(database),
		validators.NewProfileValidator(database),
		validators.NewPasswordValidator(),
		auditLogger, emailSender)

	body, err := json.Marshal(map[string]interface{}{
		"email":           "newuser@example.com",
		"setPasswordType": "email",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = setTokenContextWithClaims(req, map[string]interface{}{"sub": adminSubject})
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings,
		&models.Settings{AppName: "TestApp", SMTPEnabled: true}))

	// The handler mutates this model in place before writing it, so it is what the
	// assertions below read.
	createdUser := &models.User{Id: 7, Email: "newuser@example.com"}

	database.On("GetUserByEmail", mock.Anything, "newuser@example.com").Return(nil, nil)
	userCreator.On("CreateUser", mock.Anything).Return(createdUser, nil)
	database.On("UpdateUser", mock.Anything, createdUser).Return(nil)
	auditLogger.On("Log", constants.AuditCreatedUser, mock.Anything).Return()
	var emailedLink string
	httpHelper.On("RenderTemplateToBuffer", mock.Anything, "/layouts/email_layout.html",
		"/emails/email_newuser_set_password.html", mock.Anything).
		Run(func(args mock.Arguments) {
			emailedLink, _ = args.Get(3).(map[string]interface{})["link"].(string)
		}).Return(&bytes.Buffer{}, nil)
	emailSender.On("SendEmail", mock.Anything, mock.Anything).Return(nil)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())

	// Derived from the code the handler issued, decrypted out of the column it wrote,
	// rather than from a value this test chose.
	issuedCode, err := encryption.DecryptData(createdUser.ForgotPasswordCodeEncrypted)
	require.NoError(t, err)
	expectedHash, err := hashutil.HashString(issuedCode)
	require.NoError(t, err)
	assert.Equal(t, expectedHash, createdUser.ForgotPasswordCodeHash,
		"the stored hash must be the hash of the code that was issued")

	// This site's only job is to hand the issued code to the shared builder; the link's shape
	// and the absence of an address in it belong to ResetPasswordLink's own tests (#112
	// decision 5).
	assert.Equal(t, handlers.ResetPasswordLink(issuedCode), emailedLink,
		"the emailed link must be the shared builder's output for the code that was issued")

	httpHelper.AssertExpectations(t)
	database.AssertExpectations(t)
	emailSender.AssertExpectations(t)
}
