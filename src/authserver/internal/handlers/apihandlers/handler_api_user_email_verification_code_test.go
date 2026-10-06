package apihandlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The administrator's email verification code generation stores the code, unverifies the address
// and reports the address in its response and its audit record, so it stores only while the
// account still holds the address the request read (#471 decision 1). It used to write back the
// whole row it read through UpdateUser, which undid a disable, a password change or an OTP change
// made in between, and could answer with an address the code was never stored for.

const (
	codeGenUserId  = int64(73)
	codeGenAddress = "read@example.com"
)

func codeGenRequest() *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/73/email/verification-code", nil)
	req = setChiURLParam(req, "id", "73")
	return setTokenContextWithClaims(req, map[string]interface{}{"scope": "authserver:manage", "sub": adminSubject})
}

func expectCodeGenRead(database *datamocks.Database) {
	database.On("GetUserById", mock.Anything, mock.Anything, codeGenUserId).
		Return(&record.User{Id: codeGenUserId, Subject: "sub-73", Email: codeGenAddress, EmailVerified: true, Enabled: true}, nil).Once()
}

func TestHandleUserEmailVerificationCodePost_StoresTheCodeForTheAddressItRead(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	expectCodeGenRead(database)

	var storedCode []byte
	var storedAt time.Time
	database.On("TryIssueEmailVerificationCode", mock.Anything, mock.Anything, codeGenUserId, codeGenAddress,
		mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			storedCode = args.Get(4).([]byte)
			storedAt = args.Get(5).(time.Time)
		}).
		Return(true, nil).Once()
	var details map[string]interface{}
	auditLogger.On("Log", mock.Anything, audit.EventGeneratedEmailVerificationCode, mock.Anything).
		Run(func(args mock.Arguments) { details = args.Get(2).(map[string]interface{}) }).
		Return().Once()

	rr := httptest.NewRecorder()
	HandleUserEmailVerificationCodePost(database, auditLogger, testDataCipher).ServeHTTP(rr, codeGenRequest())

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	database.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything, mock.Anything)

	var resp api.GenerateUserEmailVerificationCodeResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, codeGenUserId, resp.UserId)
	assert.Equal(t, codeGenAddress, resp.Email)

	// The code answered is the code stored, encrypted, and it expires five minutes after the
	// instant stored with it.
	decrypted, err := testDataCipher.Decrypt(storedCode)
	require.NoError(t, err)
	assert.Equal(t, resp.VerificationCode, decrypted)
	require.NotNil(t, resp.VerificationCodeExpiresAt)
	assert.True(t, resp.VerificationCodeExpiresAt.Equal(storedAt.Add(5*time.Minute)),
		"expires at %v, want five minutes after %v", resp.VerificationCodeExpiresAt, storedAt)

	assert.Equal(t, codeGenAddress, details["email"])
	assert.Equal(t, codeGenUserId, details["userId"])
}

// When the account no longer holds the address the request read, nothing is stored and the
// request answers 409 CONCURRENT_UPDATE in the self-service send's wording, with no code in the
// response and nothing audited as generated.
func TestHandleUserEmailVerificationCodePost_TheAddressMovedUnderTheRequestAnswers409(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	expectCodeGenRead(database)
	database.On("TryIssueEmailVerificationCode", mock.Anything, mock.Anything, codeGenUserId, codeGenAddress,
		mock.Anything, mock.Anything).Return(false, nil).Once()

	rr := httptest.NewRecorder()
	HandleUserEmailVerificationCodePost(database, auditLogger, testDataCipher).ServeHTTP(rr, codeGenRequest())

	require.Equal(t, http.StatusConflict, rr.Code, rr.Body.String())
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, "CONCURRENT_UPDATE", body["error_code"])
	assert.Equal(t, "The account was changed by another request while the code was being sent. Nothing was sent: try again.",
		body["error_description"])
	assert.NotContains(t, rr.Body.String(), "verificationCode")

	database.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything, mock.Anything)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

func TestHandleUserEmailVerificationCodePost_AWriteFailureAnswers500(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	expectCodeGenRead(database)
	database.On("TryIssueEmailVerificationCode", mock.Anything, mock.Anything, codeGenUserId, codeGenAddress,
		mock.Anything, mock.Anything).Return(false, errs.New("the connection was reset")).Once()

	rr := httptest.NewRecorder()
	HandleUserEmailVerificationCodePost(database, auditLogger, testDataCipher).ServeHTTP(rr, codeGenRequest())

	require.Equal(t, http.StatusInternalServerError, rr.Code)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}
