package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/pkg/errors"
)

func SetSettingsInsertColsAndValues(insertBuilder *sqlbuilder.InsertBuilder, settings *entitiesv2.Settings) *sqlbuilder.InsertBuilder {
	insertBuilder.InsertInto("settings")
	insertBuilder.Cols(
		"created_at",
		"updated_at",
		"app_name",
		"issuer",
		"ui_theme",
		"password_policy",
		"self_registration_enabled",
		"self_registration_requires_email_verification",
		"token_expiration_in_seconds",
		"refresh_token_offline_idle_timeout_in_seconds",
		"refresh_token_offline_max_lifetime_in_seconds",
		"user_session_idle_timeout_in_seconds",
		"user_session_max_lifetime_in_seconds",
		"include_open_id_connect_claims_in_access_token",
		"session_authentication_key",
		"session_encryption_key",
		"aes_encryption_key",
		"smtp_host",
		"smtp_port",
		"smtp_username",
		"smtp_password_encrypted",
		"smtp_from_name",
		"smtp_from_email",
		"smtp_encryption",
		"smtp_enabled",
		"sms_provider",
		"sms_config_encrypted",
	)

	now := time.Now().UTC()
	insertBuilder.Values(
		now,
		now,
		settings.AppName,
		settings.Issuer,
		settings.UITheme,
		settings.PasswordPolicy,
		settings.SelfRegistrationEnabled,
		settings.SelfRegistrationRequiresEmailVerification,
		settings.TokenExpirationInSeconds,
		settings.RefreshTokenOfflineIdleTimeoutInSeconds,
		settings.RefreshTokenOfflineMaxLifetimeInSeconds,
		settings.UserSessionIdleTimeoutInSeconds,
		settings.UserSessionMaxLifetimeInSeconds,
		settings.IncludeOpenIDConnectClaimsInAccessToken,
		settings.SessionAuthenticationKey,
		settings.SessionEncryptionKey,
		settings.AESEncryptionKey,
		settings.SMTPHost,
		settings.SMTPPort,
		settings.SMTPUsername,
		settings.SMTPPasswordEncrypted,
		settings.SMTPFromName,
		settings.SMTPFromEmail,
		settings.SMTPEncryption,
		settings.SMTPEnabled,
		settings.SMSProvider,
		settings.SMSConfigEncrypted,
	)

	return insertBuilder
}

func ScanSettings(rows *sql.Rows) (*entitiesv2.Settings, error) {
	var (
		id                                             int64
		created_at                                     time.Time
		updated_at                                     time.Time
		app_name                                       string
		issuer                                         string
		ui_theme                                       string
		password_policy                                int
		self_registration_enabled                      bool
		self_registration_requires_email_verification  bool
		token_expiration_in_seconds                    int
		refresh_token_offline_idle_timeout_in_seconds  int
		refresh_token_offline_max_lifetime_in_seconds  int
		user_session_idle_timeout_in_seconds           int
		user_session_max_lifetime_in_seconds           int
		include_open_id_connect_claims_in_access_token bool
		session_authentication_key                     []byte
		session_encryption_key                         []byte
		aes_encryption_key                             []byte
		smtp_host                                      string
		smtp_port                                      int
		smtp_username                                  string
		smtp_password_encrypted                        []byte
		smtp_from_name                                 string
		smtp_from_email                                string
		smtp_encryption                                string
		smtp_enabled                                   bool
		sms_provider                                   string
		sms_config_encrypted                           []byte
	)

	err := rows.Scan(
		&id,
		&created_at,
		&updated_at,
		&app_name,
		&issuer,
		&ui_theme,
		&password_policy,
		&self_registration_enabled,
		&self_registration_requires_email_verification,
		&token_expiration_in_seconds,
		&refresh_token_offline_idle_timeout_in_seconds,
		&refresh_token_offline_max_lifetime_in_seconds,
		&user_session_idle_timeout_in_seconds,
		&user_session_max_lifetime_in_seconds,
		&include_open_id_connect_claims_in_access_token,
		&session_authentication_key,
		&session_encryption_key,
		&aes_encryption_key,
		&smtp_host,
		&smtp_port,
		&smtp_username,
		&smtp_password_encrypted,
		&smtp_from_name,
		&smtp_from_email,
		&smtp_encryption,
		&smtp_enabled,
		&sms_provider,
		&sms_config_encrypted,
	)
	if err != nil {
		return nil, errors.Wrap(err, "unable to scan row")
	}

	settings := &entitiesv2.Settings{
		Id:                      id,
		CreatedAt:               created_at,
		UpdatedAt:               updated_at,
		AppName:                 app_name,
		Issuer:                  issuer,
		UITheme:                 ui_theme,
		PasswordPolicy:          enums.PasswordPolicy(password_policy),
		SelfRegistrationEnabled: self_registration_enabled,
		SelfRegistrationRequiresEmailVerification: self_registration_requires_email_verification,
		TokenExpirationInSeconds:                  token_expiration_in_seconds,
		RefreshTokenOfflineIdleTimeoutInSeconds:   refresh_token_offline_idle_timeout_in_seconds,
		RefreshTokenOfflineMaxLifetimeInSeconds:   refresh_token_offline_max_lifetime_in_seconds,
		UserSessionIdleTimeoutInSeconds:           user_session_idle_timeout_in_seconds,
		UserSessionMaxLifetimeInSeconds:           user_session_max_lifetime_in_seconds,
		IncludeOpenIDConnectClaimsInAccessToken:   include_open_id_connect_claims_in_access_token,
		SessionAuthenticationKey:                  session_authentication_key,
		SessionEncryptionKey:                      session_encryption_key,
		AESEncryptionKey:                          aes_encryption_key,
		SMTPHost:                                  smtp_host,
		SMTPPort:                                  smtp_port,
		SMTPUsername:                              smtp_username,
		SMTPPasswordEncrypted:                     smtp_password_encrypted,
		SMTPFromName:                              smtp_from_name,
		SMTPFromEmail:                             smtp_from_email,
		SMTPEncryption:                            smtp_encryption,
		SMTPEnabled:                               smtp_enabled,
		SMSProvider:                               sms_provider,
		SMSConfigEncrypted:                        sms_config_encrypted,
	}

	return settings, nil
}
