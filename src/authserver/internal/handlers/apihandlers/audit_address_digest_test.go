package apihandlers

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// No audit entry records an email address: an entry about one records email_digest, the SHA-256
// hex digest of the address lowercased and trimmed, and the entries about an account name it by
// user_id too (#779 decision 1). Each test pins the whole details map its event is handed, so a
// left-over email, email_destination or to fails.

// lowercaseAddressDigest is the SHA-256 hex digest of an address the test writes already
// lowercased and trimmed, computed here rather than by the production hash helper.
func lowercaseAddressDigest(lowercaseAddress string) string {
	sum := sha256.Sum256([]byte(lowercaseAddress))
	return hex.EncodeToString(sum[:])
}

// captureAuditDetails expects one entry of event and returns where its details map lands.
func captureAuditDetails(auditLogger *handlersmocks.AuditLogger, event string) *map[string]interface{} {
	var details map[string]interface{}
	auditLogger.On("Log", mock.Anything, event, mock.Anything).
		Run(func(args mock.Arguments) { details = args.Get(2).(map[string]interface{}) }).
		Return().Once()
	return &details
}

func TestHandleUserCreatePost_AuditsTheCreatedUsersIdAndAddressDigest(t *testing.T) {
	database := datamocks.NewDatabase(t)
	userCreator := accounthandlersmocks.NewUserCreator(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleUserCreatePost(handlersmocks.NewPageRenderer(t), database, userCreator,
		accountvalidation.NewEmailValidator(database),
		accountvalidation.NewProfileValidator(database),
		accountvalidation.NewPasswordValidator(),
		auditLogger, accounthandlersmocks.NewEmailSender(t), testDataCipher, testBaseURL)

	body, err := json.Marshal(map[string]interface{}{
		"email":           "newuser@example.com",
		"setPasswordType": "now",
		"password":        "a-long-enough-password-1",
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = setTokenContextWithClaims(req, map[string]interface{}{"sub": adminSubject})
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{AppName: "TestApp"}))

	database.On("GetUserByEmail", mock.Anything, mock.Anything, "newuser@example.com").Return(nil, nil).Once()
	userCreator.On("CreateUser", mock.Anything, mock.Anything).
		Return(&record.User{Id: 41, Email: "newuser@example.com"}, nil).Once()
	details := captureAuditDetails(auditLogger, audit.EventCreatedUser)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	assert.Equal(t, map[string]interface{}{
		"user_id":        int64(41),
		"email_digest":   lowercaseAddressDigest("newuser@example.com"),
		"logged_in_user": adminSubject,
	}, *details)
}

func TestHandleUserEmailVerificationCodePost_AuditsTheAddressDigest(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	expectCodeGenRead(database)
	database.On("TryIssueEmailVerificationCode", mock.Anything, mock.Anything, codeGenUserId, codeGenAddress,
		mock.Anything, mock.Anything).Return(true, nil).Once()
	details := captureAuditDetails(auditLogger, audit.EventGeneratedEmailVerificationCode)

	rr := httptest.NewRecorder()
	HandleUserEmailVerificationCodePost(database, auditLogger, testDataCipher).ServeHTTP(rr, codeGenRequest())

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, map[string]interface{}{
		"user_id":        codeGenUserId,
		"email_digest":   lowercaseAddressDigest("read@example.com"),
		"logged_in_user": adminSubject,
	}, *details)
}

func TestHandleAccountEmailVerificationSendPost_AuditsTheAddressDigest(t *testing.T) {
	pageRenderer := handlersmocks.NewPageRenderer(t)
	database := datamocks.NewDatabase(t)
	emailSender := accounthandlersmocks.NewEmailSender(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	user := &record.User{Id: 7, Subject: verificationSubject, Email: "someone@example.com"}
	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), verificationSubject).Return(user, nil).Once()
	database.On("TryStoreEmailVerificationCode", mock.Anything, (*sql.Tx)(nil), int64(7), "someone@example.com",
		mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Once()
	pageRenderer.On("RenderTemplateToBuffer", mock.Anything, "/layouts/email_layout.html",
		"/emails/email_verification.html", mock.Anything).Return(&bytes.Buffer{}, nil).Once()
	emailSender.On("SendEmail", mock.Anything, mock.Anything, mock.Anything).Return(emaildelivery.SendResult{}, nil).Once()
	details := captureAuditDetails(auditLogger, audit.EventSentEmailVerificationMessage)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/account/email/verification/send", nil)
	req = setTokenContextWithClaims(req, map[string]interface{}{"sub": verificationSubject})
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{SMTPEnabled: true, SMTPHost: "smtp.example.com"}))
	rr := httptest.NewRecorder()

	HandleAccountEmailVerificationSendPost(pageRenderer, database, emailSender, auditLogger,
		testDataCipher, testAdminConsoleBaseURL).ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, map[string]interface{}{
		"user_id":        int64(7),
		"email_digest":   lowercaseAddressDigest("someone@example.com"),
		"logged_in_user": verificationSubject,
	}, *details)
}

// The test email's recipient is typed, so it is normalized as stored addresses are before it is
// digested: a test email sent to a person's address is found by the same digest as their entries.
func TestHandleSettingsEmailSendTestPost_AuditsTheLowercasedRecipientsDigest(t *testing.T) {
	emailSender := accounthandlersmocks.NewEmailSender(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	emailSender.On("SendEmail", mock.Anything, mock.Anything, mock.MatchedBy(func(input *emaildelivery.SendEmailInput) bool {
		return input.To == "Ana.Lima@Example.COM"
	})).Return(emaildelivery.SendResult{}, nil).Once()
	details := captureAuditDetails(auditLogger, audit.EventSentTestEmail)

	body, err := json.Marshal(map[string]string{"to": "Ana.Lima@Example.COM"})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/settings/email/send-test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = setTokenContextWithClaims(req, map[string]interface{}{"sub": adminSubject})
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{SMTPEnabled: true}))
	rr := httptest.NewRecorder()

	HandleSettingsEmailSendTestPost(accountvalidation.NewEmailValidator(nil), emailSender, auditLogger).ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, map[string]interface{}{
		"email_digest":   lowercaseAddressDigest("ana.lima@example.com"),
		"logged_in_user": adminSubject,
	}, *details)
}
