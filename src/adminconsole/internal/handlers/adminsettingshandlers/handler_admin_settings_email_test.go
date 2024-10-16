package adminsettingshandlers

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/communication"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_tcputils "github.com/leodip/goiabada/adminconsole/internal/tcputils/mocks"
	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_communication "github.com/leodip/goiabada/core/communication/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_inputsanitizer "github.com/leodip/goiabada/core/inputsanitizer/mocks"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
	mocks_valitadors "github.com/leodip/goiabada/core/validators/mocks"
)

func TestHandleAdminSettingsEmailGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)

	settings := &models.Settings{
		SMTPEnabled:    true,
		SMTPHost:       "smtp.example.com",
		SMTPPort:       587,
		SMTPUsername:   "user@example.com",
		SMTPEncryption: enums.SMTPEncryptionSTARTTLS.String(),
		SMTPFromName:   "Test Sender",
		SMTPFromEmail:  "sender@example.com",
	}

	aesEncryptionKey := []byte("testtesttesttest-000000000000000")
	encryptedPassword, err := encryption.EncryptText("testpassword", []byte(aesEncryptionKey))
	assert.NoError(t, err)
	settings.SMTPPasswordEncrypted = encryptedPassword
	settings.AESEncryptionKey = []byte(aesEncryptionKey)

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_settings_email.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		settingsInfo, ok := data["settings"].(SettingsEmailGet)
		return ok &&
			settingsInfo.SMTPEnabled == settings.SMTPEnabled &&
			settingsInfo.SMTPHost == settings.SMTPHost &&
			settingsInfo.SMTPPort == settings.SMTPPort &&
			settingsInfo.SMTPUsername == settings.SMTPUsername &&
			settingsInfo.SMTPEncryption == settings.SMTPEncryption &&
			settingsInfo.SMTPFromName == settings.SMTPFromName &&
			settingsInfo.SMTPFromEmail == settings.SMTPFromEmail &&
			settingsInfo.SMTPPassword == "testpassword"
	})).Return(nil)

	handler := HandleAdminSettingsEmailGet(mockHttpHelper, mockSessionStore)

	req, _ := http.NewRequest("GET", "/admin/settings/email", nil)
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, settings))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
}

func TestHandleAdminSettingsEmailPost(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockEmailValidator := mocks_valitadors.NewEmailValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockTcpConnectionTester := mocks_tcputils.NewTCPConnectionTester(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAdminSettingsEmailPost(
		mockHttpHelper,
		mockSessionStore,
		mockAuthHelper,
		mockDB,
		mockEmailValidator,
		mockInputSanitizer,
		mockTcpConnectionTester,
		mockAuditLogger,
	)

	settings := &models.Settings{
		SMTPEnabled:      true,
		SMTPHost:         "smtp.example.com",
		SMTPPort:         587,
		AESEncryptionKey: []byte("testtesttesttest-000000000000000"),
	}

	form := url.Values{}
	form.Add("smtpEnabled", "on")
	form.Add("hostOrIP", "smtp.example.com")
	form.Add("port", "587")
	form.Add("username", "user@example.com")
	form.Add("password", "password123")
	form.Add("smtpEncryption", enums.SMTPEncryptionSTARTTLS.String())
	form.Add("fromName", "Test Sender")
	form.Add("fromEmail", "sender@example.com")

	req, _ := http.NewRequest("POST", "/admin/settings/email", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
	mockSessionStore.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

	mockTcpConnectionTester.On("TestTCPConnection", "smtp.example.com", 587).Return(nil)

	mockEmailValidator.On("ValidateEmailAddress", "sender@example.com").Return(nil)
	mockInputSanitizer.On("Sanitize", "Test Sender").Return("Test Sender")

	mockDB.On("UpdateSettings", mock.Anything, mock.MatchedBy(func(s *models.Settings) bool {
		return s.SMTPEnabled == true &&
			s.SMTPHost == "smtp.example.com" &&
			s.SMTPPort == 587 &&
			s.SMTPEncryption == enums.SMTPEncryptionSTARTTLS.String() &&
			s.SMTPUsername == "user@example.com" &&
			s.SMTPFromName == "Test Sender" &&
			s.SMTPFromEmail == "sender@example.com"
	})).Return(nil)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin-user")
	mockAuditLogger.On("Log", constants.AuditUpdatedSMTPSettings, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["loggedInUser"] == "admin-user"
	})).Return(nil)

	// Add settings to the request context
	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, config.Get().BaseURL+"/admin/settings/email", rr.Header().Get("Location"))

	mockSessionStore.AssertExpectations(t)
	mockEmailValidator.AssertExpectations(t)
	mockInputSanitizer.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockAuditLogger.AssertExpectations(t)
}

func TestHandleAdminSettingsEmailPost_DisablingSMTP(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockEmailValidator := mocks_valitadors.NewEmailValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockTcpConnectionTester := mocks_tcputils.NewTCPConnectionTester(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAdminSettingsEmailPost(
		mockHttpHelper,
		mockSessionStore,
		mockAuthHelper,
		mockDB,
		mockEmailValidator,
		mockInputSanitizer,
		mockTcpConnectionTester,
		mockAuditLogger,
	)

	settings := &models.Settings{
		SMTPEnabled:      true, // Initially enabled
		AESEncryptionKey: []byte("testtesttesttest-000000000000000"),
	}

	form := url.Values{
		// SMTP is being disabled, so we don't include the "smtpEnabled" field
	}

	req, _ := http.NewRequest("POST", "/admin/settings/email", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
	mockSessionStore.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

	mockDB.On("UpdateSettings", mock.Anything, mock.MatchedBy(func(s *models.Settings) bool {
		return s.SMTPEnabled == false &&
			s.SMTPHost == "" &&
			s.SMTPPort == 0 &&
			s.SMTPEncryption == enums.SMTPEncryptionNone.String() &&
			s.SMTPUsername == "" &&
			s.SMTPPasswordEncrypted == nil &&
			s.SMTPFromName == "" &&
			s.SMTPFromEmail == ""
	})).Return(nil)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin-user")
	mockAuditLogger.On("Log", constants.AuditUpdatedSMTPSettings, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["loggedInUser"] == "admin-user"
	})).Return(nil)

	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, config.Get().BaseURL+"/admin/settings/email", rr.Header().Get("Location"))

	mockSessionStore.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockAuditLogger.AssertExpectations(t)
}

func TestHandleAdminSettingsEmailPost_MissingSmtpHost(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockEmailValidator := mocks_valitadors.NewEmailValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockTcpConnectionTester := mocks_tcputils.NewTCPConnectionTester(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAdminSettingsEmailPost(
		mockHttpHelper,
		mockSessionStore,
		mockAuthHelper,
		mockDB,
		mockEmailValidator,
		mockInputSanitizer,
		mockTcpConnectionTester,
		mockAuditLogger,
	)

	settings := &models.Settings{
		SMTPEnabled:      true,
		SMTPPort:         587,
		AESEncryptionKey: []byte("testtesttesttest-000000000000000"),
	}

	form := url.Values{
		"smtpEnabled": {"on"},
		"port":        {"587"},
	}

	req, _ := http.NewRequest("POST", "/admin/settings/email", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_settings_email.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "SMTP host is required."
	})).Return(nil)

	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockHttpHelper.AssertExpectations(t)
}

func TestHandleAdminSettingsEmailPost_MissingSmtpPort(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockEmailValidator := mocks_valitadors.NewEmailValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockTcpConnectionTester := mocks_tcputils.NewTCPConnectionTester(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAdminSettingsEmailPost(
		mockHttpHelper,
		mockSessionStore,
		mockAuthHelper,
		mockDB,
		mockEmailValidator,
		mockInputSanitizer,
		mockTcpConnectionTester,
		mockAuditLogger,
	)

	settings := &models.Settings{
		SMTPEnabled:      true,
		SMTPHost:         "smtp.example.com",
		AESEncryptionKey: []byte("testtesttesttest-000000000000000"),
	}

	form := url.Values{
		"smtpEnabled": {"on"},
		"hostOrIP":    {"smtp.example.com"},
	}

	req, _ := http.NewRequest("POST", "/admin/settings/email", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_settings_email.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "SMTP port is required."
	})).Return(nil)

	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockHttpHelper.AssertExpectations(t)
}

func TestHandleAdminSettingsEmailPost_SmtpFromEmailIsRequired(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockEmailValidator := mocks_valitadors.NewEmailValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockTcpConnectionTester := mocks_tcputils.NewTCPConnectionTester(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAdminSettingsEmailPost(
		mockHttpHelper,
		mockSessionStore,
		mockAuthHelper,
		mockDB,
		mockEmailValidator,
		mockInputSanitizer,
		mockTcpConnectionTester,
		mockAuditLogger,
	)

	settings := &models.Settings{
		SMTPEnabled:      true,
		AESEncryptionKey: []byte("testtesttesttest-000000000000000"),
	}

	form := url.Values{
		"smtpEnabled": {"on"},
		"hostOrIP":    {"smtp.example.com"},
		"port":        {"587"},
	}

	req, _ := http.NewRequest("POST", "/admin/settings/email", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_settings_email.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "SMTP from email is required."
	})).Return(nil)

	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockHttpHelper.AssertExpectations(t)
}

func TestHandleAdminSettingsEmailPost_SmtpHostLength(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockEmailValidator := mocks_valitadors.NewEmailValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockTcpConnectionTester := mocks_tcputils.NewTCPConnectionTester(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAdminSettingsEmailPost(
		mockHttpHelper,
		mockSessionStore,
		mockAuthHelper,
		mockDB,
		mockEmailValidator,
		mockInputSanitizer,
		mockTcpConnectionTester,
		mockAuditLogger,
	)

	settings := &models.Settings{
		SMTPEnabled:      true,
		AESEncryptionKey: []byte("testtesttesttest-000000000000000"),
	}

	form := url.Values{
		"smtpEnabled": {"on"},
		"hostOrIP":    {"smtp.example" + strings.Repeat("a", 256) + ".com"},
		"port":        {"587"},
		"fromEmail":   {"a@b.c"},
	}

	req, _ := http.NewRequest("POST", "/admin/settings/email", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_settings_email.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "SMTP host must be less than 120 characters."
	})).Return(nil)

	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockHttpHelper.AssertExpectations(t)
}

func TestHandleAdminSettingsEmailPost_SmtpPortInvalid(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockEmailValidator := mocks_valitadors.NewEmailValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockTcpConnectionTester := mocks_tcputils.NewTCPConnectionTester(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAdminSettingsEmailPost(
		mockHttpHelper,
		mockSessionStore,
		mockAuthHelper,
		mockDB,
		mockEmailValidator,
		mockInputSanitizer,
		mockTcpConnectionTester,
		mockAuditLogger,
	)

	settings := &models.Settings{
		SMTPEnabled:      true,
		AESEncryptionKey: []byte("testtesttesttest-000000000000000"),
	}

	form := url.Values{
		"smtpEnabled": {"on"},
		"hostOrIP":    {"smtp.example.com"},
		"port":        {"aaa"},
		"fromEmail":   {"a@b.c"},
	}

	req, _ := http.NewRequest("POST", "/admin/settings/email", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_settings_email.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "SMTP port must be an integer number."
	})).Return(nil)

	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockHttpHelper.AssertExpectations(t)
}

func TestHandleAdminSettingsEmailPost_SmtpPortOutOfRange(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockEmailValidator := mocks_valitadors.NewEmailValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockTcpConnectionTester := mocks_tcputils.NewTCPConnectionTester(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAdminSettingsEmailPost(
		mockHttpHelper,
		mockSessionStore,
		mockAuthHelper,
		mockDB,
		mockEmailValidator,
		mockInputSanitizer,
		mockTcpConnectionTester,
		mockAuditLogger,
	)

	settings := &models.Settings{
		SMTPEnabled:      true,
		AESEncryptionKey: []byte("testtesttesttest-000000000000000"),
	}

	form := url.Values{
		"smtpEnabled": {"on"},
		"hostOrIP":    {"smtp.example.com"},
		"port":        {"70000"}, // Port out of range
		"fromEmail":   {"a@b.c"},
	}

	req, _ := http.NewRequest("POST", "/admin/settings/email", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_settings_email.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "SMTP port must be between 1 and 65535."
	})).Return(nil)

	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockHttpHelper.AssertExpectations(t)
}

func TestHandleAdminSettingsEmailPost_TestTCPConnectionFails(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockEmailValidator := mocks_valitadors.NewEmailValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockTcpConnectionTester := mocks_tcputils.NewTCPConnectionTester(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAdminSettingsEmailPost(
		mockHttpHelper,
		mockSessionStore,
		mockAuthHelper,
		mockDB,
		mockEmailValidator,
		mockInputSanitizer,
		mockTcpConnectionTester,
		mockAuditLogger,
	)

	settings := &models.Settings{
		SMTPEnabled:      true,
		AESEncryptionKey: []byte("testtesttesttest-000000000000000"),
	}

	form := url.Values{
		"smtpEnabled": {"on"},
		"hostOrIP":    {"smtp.example.com"},
		"port":        {"587"},
		"fromEmail":   {"a@b.c"},
	}

	req, _ := http.NewRequest("POST", "/admin/settings/email", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	mockTcpConnectionTester.On("TestTCPConnection", "smtp.example.com", 587).Return(errors.New("connection failed"))

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_settings_email.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return strings.HasPrefix(data["error"].(string), "Unable to connect to the SMTP server:")
	})).Return(nil)

	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockHttpHelper.AssertExpectations(t)
	mockTcpConnectionTester.AssertExpectations(t)
}

func TestHandleAdminSettingsEmailPost_InvalidSmtpEncryption(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockEmailValidator := mocks_valitadors.NewEmailValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockTcpConnectionTester := mocks_tcputils.NewTCPConnectionTester(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAdminSettingsEmailPost(
		mockHttpHelper,
		mockSessionStore,
		mockAuthHelper,
		mockDB,
		mockEmailValidator,
		mockInputSanitizer,
		mockTcpConnectionTester,
		mockAuditLogger,
	)

	settings := &models.Settings{
		SMTPEnabled:      true,
		AESEncryptionKey: []byte("testtesttesttest-000000000000000"),
	}

	form := url.Values{
		"smtpEnabled":    {"on"},
		"hostOrIP":       {"smtp.example.com"},
		"port":           {"587"},
		"fromEmail":      {"a@b.c"},
		"smtpEncryption": {"invalid_encryption"},
	}

	req, _ := http.NewRequest("POST", "/admin/settings/email", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	mockTcpConnectionTester.On("TestTCPConnection", "smtp.example.com", 587).Return(nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_settings_email.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "Invalid SMTP encryption."
	})).Return(nil)

	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockHttpHelper.AssertExpectations(t)
	mockTcpConnectionTester.AssertExpectations(t)
}

func TestHandleAdminSettingsEmailPost_SmtpUsernameTooLong(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockEmailValidator := mocks_valitadors.NewEmailValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockTcpConnectionTester := mocks_tcputils.NewTCPConnectionTester(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAdminSettingsEmailPost(
		mockHttpHelper,
		mockSessionStore,
		mockAuthHelper,
		mockDB,
		mockEmailValidator,
		mockInputSanitizer,
		mockTcpConnectionTester,
		mockAuditLogger,
	)

	settings := &models.Settings{
		SMTPEnabled:      true,
		AESEncryptionKey: []byte("testtesttesttest-000000000000000"),
	}

	form := url.Values{
		"smtpEnabled":    {"on"},
		"hostOrIP":       {"smtp.example.com"},
		"port":           {"587"},
		"username":       {strings.Repeat("a", 61)}, // 61 characters long
		"fromEmail":      {"a@b.c"},
		"smtpEncryption": {enums.SMTPEncryptionSTARTTLS.String()},
	}

	req, _ := http.NewRequest("POST", "/admin/settings/email", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	mockTcpConnectionTester.On("TestTCPConnection", "smtp.example.com", 587).Return(nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_settings_email.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "SMTP username must be less than 60 characters."
	})).Return(nil)

	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockHttpHelper.AssertExpectations(t)
	mockTcpConnectionTester.AssertExpectations(t)
}

func TestHandleAdminSettingsEmailPost_SmtpFromNameTooLong(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockEmailValidator := mocks_valitadors.NewEmailValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockTcpConnectionTester := mocks_tcputils.NewTCPConnectionTester(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAdminSettingsEmailPost(
		mockHttpHelper,
		mockSessionStore,
		mockAuthHelper,
		mockDB,
		mockEmailValidator,
		mockInputSanitizer,
		mockTcpConnectionTester,
		mockAuditLogger,
	)

	settings := &models.Settings{
		SMTPEnabled:      true,
		AESEncryptionKey: []byte("testtesttesttest-000000000000000"),
	}

	form := url.Values{
		"smtpEnabled":    {"on"},
		"hostOrIP":       {"smtp.example.com"},
		"port":           {"587"},
		"fromName":       {strings.Repeat("a", 61)}, // 61 characters long
		"fromEmail":      {"a@b.c"},
		"smtpEncryption": {enums.SMTPEncryptionSTARTTLS.String()},
	}

	req, _ := http.NewRequest("POST", "/admin/settings/email", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	mockTcpConnectionTester.On("TestTCPConnection", "smtp.example.com", 587).Return(nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_settings_email.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "SMTP from name must be less than 60 characters."
	})).Return(nil)

	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockHttpHelper.AssertExpectations(t)
	mockTcpConnectionTester.AssertExpectations(t)
}

func TestHandleAdminSettingsEmailPost_SmtpFromEmailTooLong(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockEmailValidator := mocks_valitadors.NewEmailValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockTcpConnectionTester := mocks_tcputils.NewTCPConnectionTester(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAdminSettingsEmailPost(
		mockHttpHelper,
		mockSessionStore,
		mockAuthHelper,
		mockDB,
		mockEmailValidator,
		mockInputSanitizer,
		mockTcpConnectionTester,
		mockAuditLogger,
	)

	settings := &models.Settings{
		SMTPEnabled:      true,
		AESEncryptionKey: []byte("testtesttesttest-000000000000000"),
	}

	form := url.Values{
		"smtpEnabled":    {"on"},
		"hostOrIP":       {"smtp.example.com"},
		"port":           {"587"},
		"fromName":       {"Test Sender"},
		"fromEmail":      {strings.Repeat("a", 51) + "@example.com"}, // 61 characters long,
		"smtpEncryption": {enums.SMTPEncryptionSTARTTLS.String()},
	}

	req, _ := http.NewRequest("POST", "/admin/settings/email", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	mockTcpConnectionTester.On("TestTCPConnection", "smtp.example.com", 587).Return(nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_settings_email.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "SMTP from email must be less than 60 characters."
	})).Return(nil)

	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockHttpHelper.AssertExpectations(t)
	mockTcpConnectionTester.AssertExpectations(t)
}

func TestHandleAdminSettingsEmailPost_InvalidFromEmailAddress(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockEmailValidator := mocks_valitadors.NewEmailValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockTcpConnectionTester := mocks_tcputils.NewTCPConnectionTester(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAdminSettingsEmailPost(
		mockHttpHelper,
		mockSessionStore,
		mockAuthHelper,
		mockDB,
		mockEmailValidator,
		mockInputSanitizer,
		mockTcpConnectionTester,
		mockAuditLogger,
	)

	settings := &models.Settings{
		SMTPEnabled:      true,
		AESEncryptionKey: []byte("testtesttesttest-000000000000000"),
	}

	form := url.Values{
		"smtpEnabled":    {"on"},
		"hostOrIP":       {"smtp.example.com"},
		"port":           {"587"},
		"fromName":       {"Test Sender"},
		"fromEmail":      {"invalid-email-address"}, // Invalid email address
		"smtpEncryption": {enums.SMTPEncryptionSTARTTLS.String()},
	}

	req, _ := http.NewRequest("POST", "/admin/settings/email", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	mockTcpConnectionTester.On("TestTCPConnection", "smtp.example.com", 587).Return(nil)

	mockEmailValidator.On("ValidateEmailAddress", "invalid-email-address").Return(errors.New("invalid email address"))

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_settings_email.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "Invalid SMTP from email address."
	})).Return(nil)

	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockHttpHelper.AssertExpectations(t)
	mockTcpConnectionTester.AssertExpectations(t)
	mockEmailValidator.AssertExpectations(t)
}

func TestHandleAdminSettingsEmailSendTestGet(t *testing.T) {

	t.Run("Successful render", func(t *testing.T) {

		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)

		handler := HandleAdminSettingsEmailSendTestGet(mockHttpHelper, mockSessionStore)

		req, err := http.NewRequest("GET", "/admin/settings/email/send-test-email", nil)
		assert.NoError(t, err)

		settings := &models.Settings{
			SMTPEnabled: true,
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_settings_email_sendtest.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["smtpEnabled"] == true &&
				data["savedSuccessfully"] == false &&
				data["csrfField"] != nil
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		mockHttpHelper.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
	})

	t.Run("Render with savedSuccessfully flash", func(t *testing.T) {

		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)

		handler := HandleAdminSettingsEmailSendTestGet(mockHttpHelper, mockSessionStore)

		req, err := http.NewRequest("GET", "/admin/settings/email/send-test-email", nil)
		assert.NoError(t, err)

		settings := &models.Settings{
			SMTPEnabled: true,
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSession.AddFlash("true", "savedSuccessfully")
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
		mockSessionStore.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

		mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_settings_email_sendtest.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["smtpEnabled"] == true &&
				data["savedSuccessfully"] == true &&
				data["csrfField"] != nil
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		mockHttpHelper.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
	})

	t.Run("Internal server error on session get", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)

		handler := HandleAdminSettingsEmailSendTestGet(mockHttpHelper, mockSessionStore)

		req, err := http.NewRequest("GET", "/admin/settings/email/send-test-email", nil)
		assert.NoError(t, err)

		settings := &models.Settings{
			SMTPEnabled: true,
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(nil, assert.AnError)

		mockHttpHelper.On("InternalServerError", mock.Anything, mock.Anything, assert.AnError).Once()

		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
	})

	t.Run("Internal server error on render template", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)

		handler := HandleAdminSettingsEmailSendTestGet(mockHttpHelper, mockSessionStore)

		req, err := http.NewRequest("GET", "/admin/settings/email/send-test-email", nil)
		assert.NoError(t, err)

		settings := &models.Settings{
			SMTPEnabled: true,
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_settings_email_sendtest.html", mock.Anything).Return(assert.AnError)
		mockHttpHelper.On("InternalServerError", mock.Anything, mock.Anything, assert.AnError).Once()

		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
	})
}

func TestHandleAdminSettingsEmailSendTestPost_SMTPDisabled(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockEmailValidator := mocks_valitadors.NewEmailValidator(t)
	mockEmailSender := mocks_communication.NewEmailSender(t)

	handler := HandleAdminSettingsEmailSendTestPost(
		mockHttpHelper,
		mockSessionStore,
		mockEmailValidator,
		mockEmailSender,
	)

	settings := &models.Settings{
		SMTPEnabled: false,
	}

	req, _ := http.NewRequest("POST", "/admin/settings/email/send-test", nil)
	rr := httptest.NewRecorder()

	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	mockHttpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
		return err.Error() == "SMTP is not enabled"
	})).Once()

	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockEmailValidator.AssertExpectations(t)
	mockEmailSender.AssertExpectations(t)
}

func TestHandleAdminSettingsEmailSendTestPost_MissingDestinationEmail(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockEmailValidator := mocks_valitadors.NewEmailValidator(t)
	mockEmailSender := mocks_communication.NewEmailSender(t)

	handler := HandleAdminSettingsEmailSendTestPost(
		mockHttpHelper,
		mockSessionStore,
		mockEmailValidator,
		mockEmailSender,
	)

	settings := &models.Settings{
		SMTPEnabled: true,
	}

	form := url.Values{}
	req, _ := http.NewRequest("POST", "/admin/settings/email/send-test", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/menu_layout.html", "/admin_settings_email_sendtest.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "Destination email is required."
	})).Return(nil).Once()

	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockEmailValidator.AssertExpectations(t)
	mockEmailSender.AssertExpectations(t)
}

func TestHandleAdminSettingsEmailSendTestPost_InvalidEmail(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockEmailValidator := mocks_valitadors.NewEmailValidator(t)
	mockEmailSender := mocks_communication.NewEmailSender(t)

	handler := HandleAdminSettingsEmailSendTestPost(
		mockHttpHelper,
		mockSessionStore,
		mockEmailValidator,
		mockEmailSender,
	)

	settings := &models.Settings{
		SMTPEnabled: true,
	}

	form := url.Values{}
	form.Add("destinationEmail", "invalid-email")

	req, _ := http.NewRequest("POST", "/admin/settings/email/send-test", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	mockEmailValidator.On("ValidateEmailAddress", "invalid-email").Return(customerrors.NewErrorDetail("invalid_email", "Invalid email format")).Once()

	mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/menu_layout.html", "/admin_settings_email_sendtest.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "Invalid email format"
	})).Return(nil).Once()

	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockEmailValidator.AssertExpectations(t)
	mockEmailSender.AssertExpectations(t)
}

func TestHandleAdminSettingsEmailSendTestPost_EmailSendingFailure(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockEmailValidator := mocks_valitadors.NewEmailValidator(t)
	mockEmailSender := mocks_communication.NewEmailSender(t)

	handler := HandleAdminSettingsEmailSendTestPost(
		mockHttpHelper,
		mockSessionStore,
		mockEmailValidator,
		mockEmailSender,
	)

	settings := &models.Settings{
		SMTPEnabled: true,
	}

	form := url.Values{}
	form.Add("destinationEmail", "valid@example.com")

	req, _ := http.NewRequest("POST", "/admin/settings/email/send-test", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	mockEmailValidator.On("ValidateEmailAddress", "valid@example.com").Return(nil).Once()
	mockHttpHelper.On("RenderTemplateToBuffer", req, "/layouts/email_layout.html", "/emails/email_test.html", mock.Anything).Return(&bytes.Buffer{}, nil).Once()
	mockEmailSender.On("SendEmail", mock.Anything, mock.MatchedBy(func(input *communication.SendEmailInput) bool {
		return input.To == "valid@example.com" && input.Subject == "Test email"
	})).Return(errors.New("SMTP server error")).Once()

	mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/menu_layout.html", "/admin_settings_email_sendtest.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "Unable to send email: SMTP server error"
	})).Return(nil).Once()

	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockEmailValidator.AssertExpectations(t)
	mockEmailSender.AssertExpectations(t)
}

func TestHandleAdminSettingsEmailSendTestPost_SuccessfulEmailSend(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockEmailValidator := mocks_valitadors.NewEmailValidator(t)
	mockEmailSender := mocks_communication.NewEmailSender(t)

	handler := HandleAdminSettingsEmailSendTestPost(
		mockHttpHelper,
		mockSessionStore,
		mockEmailValidator,
		mockEmailSender,
	)

	settings := &models.Settings{
		SMTPEnabled: true,
	}

	form := url.Values{}
	form.Add("destinationEmail", "valid@example.com")

	req, _ := http.NewRequest("POST", "/admin/settings/email/send-test", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	mockEmailValidator.On("ValidateEmailAddress", "valid@example.com").Return(nil).Once()
	mockHttpHelper.On("RenderTemplateToBuffer", req, "/layouts/email_layout.html", "/emails/email_test.html", mock.Anything).Return(&bytes.Buffer{}, nil).Once()
	mockEmailSender.On("SendEmail", mock.Anything, mock.MatchedBy(func(input *communication.SendEmailInput) bool {
		return input.To == "valid@example.com" && input.Subject == "Test email"
	})).Return(nil).Once()

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", req, constants.SessionName).Return(mockSession, nil).Once()
	mockSessionStore.On("Save", req, rr, mockSession).Return(nil).Once()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, config.Get().BaseURL+"/admin/settings/email/send-test-email", rr.Header().Get("Location"))

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockEmailValidator.AssertExpectations(t)
	mockEmailSender.AssertExpectations(t)
}
