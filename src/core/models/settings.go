package models

import (
	"database/sql"

	"github.com/leodip/goiabada/core/enums"
)

type Settings struct {
	Id                                        int64                `db:"id" fieldtag:"pk"`
	CreatedAt                                 sql.NullTime         `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt                                 sql.NullTime         `db:"updated_at"`
	AppName                                   string               `db:"app_name"`
	Issuer                                    string               `db:"issuer"`
	UITheme                                   string               `db:"ui_theme"`
	PasswordPolicy                            enums.PasswordPolicy `db:"password_policy"`
	SelfRegistrationEnabled                   bool                 `db:"self_registration_enabled"`
	SelfRegistrationRequiresEmailVerification bool                 `db:"self_registration_requires_email_verification"`
	TokenExpirationInSeconds                  int                  `db:"token_expiration_in_seconds"`
	RefreshTokenOfflineIdleTimeoutInSeconds   int                  `db:"refresh_token_offline_idle_timeout_in_seconds"`
	RefreshTokenOfflineMaxLifetimeInSeconds   int                  `db:"refresh_token_offline_max_lifetime_in_seconds"`
	UserSessionIdleTimeoutInSeconds           int                  `db:"user_session_idle_timeout_in_seconds"`
	UserSessionMaxLifetimeInSeconds           int                  `db:"user_session_max_lifetime_in_seconds"`
	IncludeOpenIDConnectClaimsInAccessToken   bool                 `db:"include_open_id_connect_claims_in_access_token"`
	SessionAuthenticationKey                  []byte               `db:"session_authentication_key"`
	SessionEncryptionKey                      []byte               `db:"session_encryption_key"`
	AESEncryptionKey                          []byte               `db:"aes_encryption_key"`
	SMTPHost                                  string               `db:"smtp_host"`
	SMTPPort                                  int                  `db:"smtp_port"`
	SMTPUsername                              string               `db:"smtp_username"`
	SMTPPasswordEncrypted                     []byte               `db:"smtp_password_encrypted"`
	SMTPFromName                              string               `db:"smtp_from_name"`
	SMTPFromEmail                             string               `db:"smtp_from_email"`
	SMTPEncryption                            string               `db:"smtp_encryption"`
	SMTPEnabled                               bool                 `db:"smtp_enabled"`
}
