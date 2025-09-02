package accounthandlers

import (
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	"github.com/leodip/goiabada/core/communication"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_communication "github.com/leodip/goiabada/core/communication/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
)

func TestHandleAccountEmailVerificationGet_SMTPNotEnabled(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(uuid.New().String())
	mockDB.On("GetUserBySubject", mock.Anything, mock.Anything).Return(&models.User{}, nil)
	mockHttpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Once()

	handler := HandleAccountEmailVerificationGet(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB)

	req, _ := http.NewRequest("GET", "/account/email-verification", nil)
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, oauth.JwtInfo{
		IdToken: &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"sub": uuid.New(),
			},
		},
	}))
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{SMTPEnabled: false}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAccountEmailVerificationGet_HappyPath(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	user := &models.User{
		Id:      1,
		Subject: uuid.New(),
		Email:   "test@example.com",
	}
	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
	mockDB.On("GetUserBySubject", mock.Anything, user.Subject.String()).Return(user, nil)

	mockSession := &sessions.Session{Values: map[interface{}]interface{}{}}
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/account_email_verification.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["email"] == user.Email && data["smtpEnabled"] == true
	})).Return(nil)

	handler := HandleAccountEmailVerificationGet(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB)

	req, _ := http.NewRequest("GET", "/account/email-verification", nil)
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, oauth.JwtInfo{
		IdToken: &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"sub": user.Subject,
			},
		},
	}))
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{SMTPEnabled: true}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAccountEmailVerificationGet_NotAuthorized(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("")

	handler := HandleAccountEmailVerificationGet(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB)

	req, _ := http.NewRequest("GET", "/account/email-verification", nil)
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, oauth.JwtInfo{
		IdToken: &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"sub": uuid.New(),
			},
		},
	}))
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{SMTPEnabled: true}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, config.GetAdminConsole().BaseURL+"/unauthorized", rr.Header().Get("Location"))

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAccountEmailSendVerificationPost_SMTPNotEnabled(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockEmailSender := mocks_communication.NewEmailSender(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(uuid.New().String())
	mockDB.On("GetUserBySubject", mock.Anything, mock.Anything).Return(&models.User{}, nil)
	mockHttpHelper.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		return err.Error() == "SMTP is not enabled"
	})).Once()

	handler := HandleAccountEmailSendVerificationPost(mockHttpHelper, mockAuthHelper, mockDB, mockEmailSender, mockAuditLogger)

	req, _ := http.NewRequest("POST", "/account/email-send-verification", nil)
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, oauth.JwtInfo{
		IdToken: &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"sub": uuid.New().String(),
			},
		},
	}))
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{SMTPEnabled: false}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockEmailSender.AssertExpectations(t)
	mockAuditLogger.AssertExpectations(t)
}

func TestHandleAccountEmailSendVerificationPost_TooManyRequests(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockEmailSender := mocks_communication.NewEmailSender(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(uuid.New().String())
	mockDB.On("GetUserBySubject", mock.Anything, mock.Anything).Return(&models.User{
		EmailVerificationCodeIssuedAt:  sql.NullTime{Time: time.Now().Add(-30 * time.Second), Valid: true},
		EmailVerificationCodeEncrypted: []byte("encrypted_code"),
	}, nil)

	var capturedResult EmailSendVerificationResult
	mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.AnythingOfType("accounthandlers.EmailSendVerificationResult")).
		Run(func(args mock.Arguments) {
			capturedResult = args.Get(2).(EmailSendVerificationResult)
		}).
		Once()

	handler := HandleAccountEmailSendVerificationPost(mockHttpHelper, mockAuthHelper, mockDB, mockEmailSender, mockAuditLogger)

	req, _ := http.NewRequest("POST", "/account/email-send-verification", nil)
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, oauth.JwtInfo{
		IdToken: &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"sub": uuid.New().String(),
			},
		},
	}))
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{SMTPEnabled: true}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	// Assert on the captured result
	assert.True(t, capturedResult.TooManyRequests, "TooManyRequests should be true")
	assert.Greater(t, capturedResult.WaitInSeconds, 0, "WaitInSeconds should be greater than 0")
	assert.False(t, capturedResult.EmailVerified, "EmailVerified should be false")
	assert.False(t, capturedResult.EmailVerificationSent, "EmailVerificationSent should be false")
	assert.Empty(t, capturedResult.EmailDestination, "EmailDestination should be empty")

	mockHttpHelper.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockEmailSender.AssertExpectations(t)
	mockAuditLogger.AssertExpectations(t)
}

func TestHandleAccountEmailSendVerificationPost_EmailAlreadyVerified(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockEmailSender := mocks_communication.NewEmailSender(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	user := &models.User{
		Id:            1,
		Subject:       uuid.New(),
		Email:         "test@example.com",
		EmailVerified: true,
	}

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
	mockDB.On("GetUserBySubject", mock.Anything, user.Subject.String()).Return(user, nil)

	var capturedResult EmailSendVerificationResult
	mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.AnythingOfType("accounthandlers.EmailSendVerificationResult")).
		Run(func(args mock.Arguments) {
			capturedResult = args.Get(2).(EmailSendVerificationResult)
		}).
		Once()

	handler := HandleAccountEmailSendVerificationPost(mockHttpHelper, mockAuthHelper, mockDB, mockEmailSender, mockAuditLogger)

	req, _ := http.NewRequest("POST", "/account/email-send-verification", nil)
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, oauth.JwtInfo{
		IdToken: &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"sub": user.Subject.String(),
			},
		},
	}))
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{SMTPEnabled: true}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	assert.True(t, capturedResult.EmailVerified, "EmailVerified should be true")
	assert.False(t, capturedResult.EmailVerificationSent, "EmailVerificationSent should be false")
	assert.Empty(t, capturedResult.EmailDestination, "EmailDestination should be empty")
	assert.False(t, capturedResult.TooManyRequests, "TooManyRequests should be false")
	assert.Equal(t, 0, capturedResult.WaitInSeconds, "WaitInSeconds should be 0")

	mockHttpHelper.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockEmailSender.AssertNotCalled(t, "SendEmail")
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAccountEmailSendVerificationPost_NotAuthorized(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockEmailSender := mocks_communication.NewEmailSender(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("")

	handler := HandleAccountEmailSendVerificationPost(mockHttpHelper, mockAuthHelper, mockDB, mockEmailSender, mockAuditLogger)

	req, _ := http.NewRequest("POST", "/account/email-send-verification", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, config.GetAdminConsole().BaseURL+"/unauthorized", rr.Header().Get("Location"))

	mockAuthHelper.AssertExpectations(t)
	mockHttpHelper.AssertNotCalled(t, "EncodeJson")
	mockDB.AssertNotCalled(t, "GetUserBySubject")
	mockEmailSender.AssertNotCalled(t, "SendEmail")
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAccountEmailSendVerificationPost_HappyPath(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockEmailSender := mocks_communication.NewEmailSender(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	user := &models.User{
		Id:            1,
		Subject:       uuid.New(),
		Email:         "test@example.com",
		EmailVerified: false,
	}

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
	mockDB.On("GetUserBySubject", mock.Anything, user.Subject.String()).Return(user, nil)
	mockDB.On("UpdateUser", mock.Anything, mock.MatchedBy(func(u *models.User) bool {
		return u.Id == user.Id &&
			u.EmailVerificationCodeEncrypted != nil &&
			u.EmailVerificationCodeIssuedAt.Valid
	})).Return(nil)

	mockHttpHelper.On("RenderTemplateToBuffer", mock.Anything, "/layouts/email_layout.html", "/emails/email_verification.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		link, ok := data["link"].(string)
		return ok && strings.HasPrefix(link, config.GetAdminConsole().BaseURL+"/account/email-verification")
	})).Return(&bytes.Buffer{}, nil)

	mockEmailSender.On("SendEmail", mock.Anything, mock.MatchedBy(func(input *communication.SendEmailInput) bool {
		return input.To == user.Email &&
			strings.Contains(input.Subject, "Email verification - code")
	})).Return(nil)

	mockAuditLogger.On("Log", constants.AuditSentEmailVerificationMessage, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["userId"] == user.Id &&
			details["emailDestination"] == user.Email &&
			details["loggedInUser"] == user.Subject.String()
	})).Return(nil)

	var capturedResult EmailSendVerificationResult
	mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.AnythingOfType("accounthandlers.EmailSendVerificationResult")).
		Run(func(args mock.Arguments) {
			capturedResult = args.Get(2).(EmailSendVerificationResult)
		}).
		Once()

	handler := HandleAccountEmailSendVerificationPost(mockHttpHelper, mockAuthHelper, mockDB, mockEmailSender, mockAuditLogger)

	req, _ := http.NewRequest("POST", "/account/email-send-verification", nil)
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, oauth.JwtInfo{
		IdToken: &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"sub": user.Subject.String(),
			},
		},
	}))
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{
		SMTPEnabled:      true,
		AESEncryptionKey: []byte("encryption_key-00000000000000000"),
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	assert.False(t, capturedResult.EmailVerified, "EmailVerified should be false")
	assert.True(t, capturedResult.EmailVerificationSent, "EmailVerificationSent should be true")
	assert.Equal(t, user.Email, capturedResult.EmailDestination, "EmailDestination should match user's email")
	assert.False(t, capturedResult.TooManyRequests, "TooManyRequests should be false")
	assert.Equal(t, 0, capturedResult.WaitInSeconds, "WaitInSeconds should be 0")

	mockHttpHelper.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockEmailSender.AssertExpectations(t)
	mockAuditLogger.AssertExpectations(t)
}

func TestHandleAccountEmailVerificationPost_EmailAlreadyVerified(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	user := &models.User{
		Id:            1,
		Subject:       uuid.New(),
		Email:         "test@example.com",
		EmailVerified: true,
	}

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
	mockDB.On("GetUserBySubject", mock.Anything, user.Subject.String()).Return(user, nil)

	handler := HandleAccountEmailVerificationPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

	form := strings.NewReader("verificationCode=123456")
	req, _ := http.NewRequest("POST", "/account/email-verification", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, oauth.JwtInfo{
		IdToken: &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"sub": user.Subject.String(),
			},
		},
	}))
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{SMTPEnabled: true}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, config.GetAdminConsole().BaseURL+"/account/email-verification", rr.Header().Get("Location"))

	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockHttpHelper.AssertNotCalled(t, "RenderTemplate")
	mockSessionStore.AssertNotCalled(t, "Get")
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAccountEmailVerificationPost_NotAuthorized(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("")

	handler := HandleAccountEmailVerificationPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

	form := strings.NewReader("verificationCode=123456")
	req, _ := http.NewRequest("POST", "/account/email-verification", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, config.GetAdminConsole().BaseURL+"/unauthorized", rr.Header().Get("Location"))

	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertNotCalled(t, "GetUserBySubject")
	mockHttpHelper.AssertNotCalled(t, "RenderTemplate")
	mockSessionStore.AssertNotCalled(t, "Get")
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAccountEmailVerificationPost_SMTPNotEnabled(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	user := &models.User{
		Id:            1,
		Subject:       uuid.New(),
		Email:         "test@example.com",
		EmailVerified: false,
	}

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
	mockDB.On("GetUserBySubject", mock.Anything, user.Subject.String()).Return(user, nil)

	mockHttpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.AnythingOfType("*errors.withStack")).Once()

	handler := HandleAccountEmailVerificationPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

	form := strings.NewReader("verificationCode=123456")
	req, _ := http.NewRequest("POST", "/account/email-verification", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, oauth.JwtInfo{
		IdToken: &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"sub": user.Subject.String(),
			},
		},
	}))
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{SMTPEnabled: false}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertNotCalled(t, "Get")
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAccountEmailVerificationPost_InvalidVerificationCode(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	user := &models.User{
		Id:                             1,
		Subject:                        uuid.New(),
		Email:                          "test@example.com",
		EmailVerified:                  false,
		EmailVerificationCodeEncrypted: []byte("encrypted_code"),
		EmailVerificationCodeIssuedAt:  sql.NullTime{Time: time.Now(), Valid: true},
	}

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
	mockDB.On("GetUserBySubject", mock.Anything, user.Subject.String()).Return(user, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/account_email_verification.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "Invalid or expired verification code"
	})).Return(nil)

	mockAuditLogger.On("Log", constants.AuditFailedEmailVerificationCode, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["userId"] == user.Id && details["loggedInUser"] == user.Subject.String()
	})).Return(nil)

	handler := HandleAccountEmailVerificationPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

	form := strings.NewReader("verificationCode=invalid_code")
	req, _ := http.NewRequest("POST", "/account/email-verification", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, oauth.JwtInfo{
		IdToken: &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"sub": user.Subject.String(),
			},
		},
	}))
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{
		SMTPEnabled:      true,
		AESEncryptionKey: []byte("encryption_key-00000000000000000"),
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockHttpHelper.AssertExpectations(t)
	mockAuditLogger.AssertExpectations(t)
}

func TestHandleAccountEmailVerificationPost_ValidVerificationCode(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	encryptionKey := []byte("encryption_key-00000000000000000")
	emailVerificationCodeEncrypted, err := encryption.EncryptText("VALID", encryptionKey)
	assert.Nil(t, err)

	user := &models.User{
		Id:                             1,
		Subject:                        uuid.New(),
		Email:                          "test@example.com",
		EmailVerified:                  false,
		EmailVerificationCodeEncrypted: emailVerificationCodeEncrypted,
		EmailVerificationCodeIssuedAt:  sql.NullTime{Time: time.Now(), Valid: true},
	}

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
	mockDB.On("GetUserBySubject", mock.Anything, user.Subject.String()).Return(user, nil)
	mockDB.On("UpdateUser", mock.Anything, mock.MatchedBy(func(u *models.User) bool {
		return u.Id == user.Id && u.EmailVerified && u.EmailVerificationCodeEncrypted == nil && !u.EmailVerificationCodeIssuedAt.Valid
	})).Return(nil)

	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(&sessions.Session{
		Values: make(map[interface{}]interface{}),
	}, nil)
	mockSessionStore.On("Save", mock.Anything, mock.Anything, mock.AnythingOfType("*sessions.Session")).Return(nil)

	mockAuditLogger.On("Log", constants.AuditVerifiedEmail, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["userId"] == user.Id && details["loggedInUser"] == user.Subject.String()
	})).Return(nil)

	handler := HandleAccountEmailVerificationPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockAuditLogger)

	form := strings.NewReader("verificationCode=VALID")
	req, _ := http.NewRequest("POST", "/account/email-verification", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, oauth.JwtInfo{
		IdToken: &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"sub": user.Subject.String(),
			},
		},
	}))
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{
		SMTPEnabled:      true,
		AESEncryptionKey: encryptionKey,
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, config.GetAdminConsole().BaseURL+"/account/email-verification", rr.Header().Get("Location"))

	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockAuditLogger.AssertExpectations(t)
}
