package datatests

import (
	"testing"
	"time"

	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
)

func TestCreateSettings(t *testing.T) {
	settings := &models.Settings{
		AppName:                 "TestApp",
		Issuer:                  "https://test.com",
		UITheme:                 "default",
		PasswordPolicy:          enums.PasswordPolicyMedium,
		SelfRegistrationEnabled: true,
		SelfRegistrationRequiresEmailVerification: true,
		TokenExpirationInSeconds:                  3600,
		RefreshTokenOfflineIdleTimeoutInSeconds:   86400,
		RefreshTokenOfflineMaxLifetimeInSeconds:   604800,
		UserSessionIdleTimeoutInSeconds:           1800,
		UserSessionMaxLifetimeInSeconds:           43200,
		IncludeOpenIDConnectClaimsInAccessToken:   true,
		SessionAuthenticationKey:                  []byte("testauth"),
		SessionEncryptionKey:                      []byte("testencryption"),
		AESEncryptionKey:                          []byte("testaes"),
		SMTPHost:                                  "smtp.test.com",
		SMTPPort:                                  587,
		SMTPUsername:                              "testuser",
		SMTPPasswordEncrypted:                     []byte("testpassword"),
		SMTPFromName:                              "Test Sender",
		SMTPFromEmail:                             "sender@test.com",
		SMTPEncryption:                            "starttls",
		SMTPEnabled:                               true,
		SMSProvider:                               "testsms",
		SMSConfigEncrypted:                        []byte("testconfig"),
	}

	err := database.CreateSettings(nil, settings)
	if err != nil {
		t.Fatalf("Failed to create settings: %v", err)
	}

	if settings.Id == 0 {
		t.Error("Expected non-zero ID after creation")
	}
	if !settings.CreatedAt.Valid || settings.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if !settings.UpdatedAt.Valid || settings.UpdatedAt.Time.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}

	retrievedSettings, err := database.GetSettingsById(nil, settings.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve created settings: %v", err)
	}

	compareSettings(t, settings, retrievedSettings)
}

func TestUpdateSettings(t *testing.T) {
	settings := createTestSettings(t)

	settings.AppName = "UpdatedApp"
	settings.Issuer = "https://updated.com"
	settings.UITheme = "dark"
	settings.PasswordPolicy = enums.PasswordPolicyHigh
	settings.SelfRegistrationEnabled = false
	settings.SelfRegistrationRequiresEmailVerification = false
	settings.TokenExpirationInSeconds = 7200
	settings.RefreshTokenOfflineIdleTimeoutInSeconds = 172800
	settings.RefreshTokenOfflineMaxLifetimeInSeconds = 1209600
	settings.UserSessionIdleTimeoutInSeconds = 3600
	settings.UserSessionMaxLifetimeInSeconds = 86400
	settings.IncludeOpenIDConnectClaimsInAccessToken = false
	settings.SessionAuthenticationKey = []byte("updatedauth")
	settings.SessionEncryptionKey = []byte("updatedencryption")
	settings.AESEncryptionKey = []byte("updatedaes")
	settings.SMTPHost = "smtp.updated.com"
	settings.SMTPPort = 465
	settings.SMTPUsername = "updateduser"
	settings.SMTPPasswordEncrypted = []byte("updatedpassword")
	settings.SMTPFromName = "Updated Sender"
	settings.SMTPFromEmail = "updated@test.com"
	settings.SMTPEncryption = "ssltls"
	settings.SMTPEnabled = false
	settings.SMSProvider = "updatedsms"
	settings.SMSConfigEncrypted = []byte("updatedconfig")

	time.Sleep(time.Millisecond * 100)

	err := database.UpdateSettings(nil, settings)
	if err != nil {
		t.Fatalf("Failed to update settings: %v", err)
	}

	updatedSettings, err := database.GetSettingsById(nil, settings.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve updated settings: %v", err)
	}

	compareSettings(t, settings, updatedSettings)

	if !updatedSettings.UpdatedAt.Time.After(updatedSettings.CreatedAt.Time) {
		t.Error("Expected UpdatedAt to be after CreatedAt")
	}
}

func TestGetSettingsById(t *testing.T) {
	settings := createTestSettings(t)

	retrievedSettings, err := database.GetSettingsById(nil, settings.Id)
	if err != nil {
		t.Fatalf("Failed to get settings by ID: %v", err)
	}

	compareSettings(t, settings, retrievedSettings)

	nonExistentSettings, err := database.GetSettingsById(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent settings, got: %v", err)
	}
	if nonExistentSettings != nil {
		t.Errorf("Expected nil for non-existent settings, got settings with ID: %d", nonExistentSettings.Id)
	}
}

func createTestSettings(t *testing.T) *models.Settings {
	settings := &models.Settings{
		AppName:                 "TestApp",
		Issuer:                  "https://test.com",
		UITheme:                 "default",
		PasswordPolicy:          enums.PasswordPolicyMedium,
		SelfRegistrationEnabled: true,
		SelfRegistrationRequiresEmailVerification: true,
		TokenExpirationInSeconds:                  3600,
		RefreshTokenOfflineIdleTimeoutInSeconds:   86400,
		RefreshTokenOfflineMaxLifetimeInSeconds:   604800,
		UserSessionIdleTimeoutInSeconds:           1800,
		UserSessionMaxLifetimeInSeconds:           43200,
		IncludeOpenIDConnectClaimsInAccessToken:   true,
		SessionAuthenticationKey:                  []byte("testauth"),
		SessionEncryptionKey:                      []byte("testencryption"),
		AESEncryptionKey:                          []byte("testaes"),
		SMTPHost:                                  "smtp.test.com",
		SMTPPort:                                  587,
		SMTPUsername:                              "testuser",
		SMTPPasswordEncrypted:                     []byte("testpassword"),
		SMTPFromName:                              "Test Sender",
		SMTPFromEmail:                             "sender@test.com",
		SMTPEncryption:                            "starttls",
		SMTPEnabled:                               true,
		SMSProvider:                               "testsms",
		SMSConfigEncrypted:                        []byte("testconfig"),
	}
	err := database.CreateSettings(nil, settings)
	if err != nil {
		t.Fatalf("Failed to create test settings: %v", err)
	}
	return settings
}

func compareSettings(t *testing.T, expected, actual *models.Settings) {
	if actual.AppName != expected.AppName {
		t.Errorf("Expected AppName %s, got %s", expected.AppName, actual.AppName)
	}
	if actual.Issuer != expected.Issuer {
		t.Errorf("Expected Issuer %s, got %s", expected.Issuer, actual.Issuer)
	}
	if actual.UITheme != expected.UITheme {
		t.Errorf("Expected UITheme %s, got %s", expected.UITheme, actual.UITheme)
	}
	if actual.PasswordPolicy != expected.PasswordPolicy {
		t.Errorf("Expected PasswordPolicy %v, got %v", expected.PasswordPolicy, actual.PasswordPolicy)
	}
	if actual.SelfRegistrationEnabled != expected.SelfRegistrationEnabled {
		t.Errorf("Expected SelfRegistrationEnabled %v, got %v", expected.SelfRegistrationEnabled, actual.SelfRegistrationEnabled)
	}
	if actual.SelfRegistrationRequiresEmailVerification != expected.SelfRegistrationRequiresEmailVerification {
		t.Errorf("Expected SelfRegistrationRequiresEmailVerification %v, got %v", expected.SelfRegistrationRequiresEmailVerification, actual.SelfRegistrationRequiresEmailVerification)
	}
	if actual.TokenExpirationInSeconds != expected.TokenExpirationInSeconds {
		t.Errorf("Expected TokenExpirationInSeconds %d, got %d", expected.TokenExpirationInSeconds, actual.TokenExpirationInSeconds)
	}
	if actual.RefreshTokenOfflineIdleTimeoutInSeconds != expected.RefreshTokenOfflineIdleTimeoutInSeconds {
		t.Errorf("Expected RefreshTokenOfflineIdleTimeoutInSeconds %d, got %d", expected.RefreshTokenOfflineIdleTimeoutInSeconds, actual.RefreshTokenOfflineIdleTimeoutInSeconds)
	}
	if actual.RefreshTokenOfflineMaxLifetimeInSeconds != expected.RefreshTokenOfflineMaxLifetimeInSeconds {
		t.Errorf("Expected RefreshTokenOfflineMaxLifetimeInSeconds %d, got %d", expected.RefreshTokenOfflineMaxLifetimeInSeconds, actual.RefreshTokenOfflineMaxLifetimeInSeconds)
	}
	if actual.UserSessionIdleTimeoutInSeconds != expected.UserSessionIdleTimeoutInSeconds {
		t.Errorf("Expected UserSessionIdleTimeoutInSeconds %d, got %d", expected.UserSessionIdleTimeoutInSeconds, actual.UserSessionIdleTimeoutInSeconds)
	}
	if actual.UserSessionMaxLifetimeInSeconds != expected.UserSessionMaxLifetimeInSeconds {
		t.Errorf("Expected UserSessionMaxLifetimeInSeconds %d, got %d", expected.UserSessionMaxLifetimeInSeconds, actual.UserSessionMaxLifetimeInSeconds)
	}
	if actual.IncludeOpenIDConnectClaimsInAccessToken != expected.IncludeOpenIDConnectClaimsInAccessToken {
		t.Errorf("Expected IncludeOpenIDConnectClaimsInAccessToken %v, got %v", expected.IncludeOpenIDConnectClaimsInAccessToken, actual.IncludeOpenIDConnectClaimsInAccessToken)
	}
	if string(actual.SessionAuthenticationKey) != string(expected.SessionAuthenticationKey) {
		t.Errorf("Expected SessionAuthenticationKey %s, got %s", string(expected.SessionAuthenticationKey), string(actual.SessionAuthenticationKey))
	}
	if string(actual.SessionEncryptionKey) != string(expected.SessionEncryptionKey) {
		t.Errorf("Expected SessionEncryptionKey %s, got %s", string(expected.SessionEncryptionKey), string(actual.SessionEncryptionKey))
	}
	if string(actual.AESEncryptionKey) != string(expected.AESEncryptionKey) {
		t.Errorf("Expected AESEncryptionKey %s, got %s", string(expected.AESEncryptionKey), string(actual.AESEncryptionKey))
	}
	if actual.SMTPHost != expected.SMTPHost {
		t.Errorf("Expected SMTPHost %s, got %s", expected.SMTPHost, actual.SMTPHost)
	}
	if actual.SMTPPort != expected.SMTPPort {
		t.Errorf("Expected SMTPPort %d, got %d", expected.SMTPPort, actual.SMTPPort)
	}
	if actual.SMTPUsername != expected.SMTPUsername {
		t.Errorf("Expected SMTPUsername %s, got %s", expected.SMTPUsername, actual.SMTPUsername)
	}
	if string(actual.SMTPPasswordEncrypted) != string(expected.SMTPPasswordEncrypted) {
		t.Errorf("Expected SMTPPasswordEncrypted %s, got %s", string(expected.SMTPPasswordEncrypted), string(actual.SMTPPasswordEncrypted))
	}
	if actual.SMTPFromName != expected.SMTPFromName {
		t.Errorf("Expected SMTPFromName %s, got %s", expected.SMTPFromName, actual.SMTPFromName)
	}
	if actual.SMTPFromEmail != expected.SMTPFromEmail {
		t.Errorf("Expected SMTPFromEmail %s, got %s", expected.SMTPFromEmail, actual.SMTPFromEmail)
	}
	if actual.SMTPEncryption != expected.SMTPEncryption {
		t.Errorf("Expected SMTPEncryption %s, got %s", expected.SMTPEncryption, actual.SMTPEncryption)
	}
	if actual.SMTPEnabled != expected.SMTPEnabled {
		t.Errorf("Expected SMTPEnabled %v, got %v", expected.SMTPEnabled, actual.SMTPEnabled)
	}
	if actual.SMSProvider != expected.SMSProvider {
		t.Errorf("Expected SMSProvider %s, got %s", expected.SMSProvider, actual.SMSProvider)
	}
	if string(actual.SMSConfigEncrypted) != string(expected.SMSConfigEncrypted) {
		t.Errorf("Expected SMSConfigEncrypted %s, got %s", string(expected.SMSConfigEncrypted), string(actual.SMSConfigEncrypted))
	}
}
