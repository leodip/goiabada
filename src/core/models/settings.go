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
	IncludeOpenIDConnectClaimsInIdToken       bool                 `db:"include_open_id_connect_claims_in_id_token"`
	// AESEncryptionKeyLegacy is the data key as historically stored in the DB.
	// The key now comes from the environment (config.GetAESEncryptionKey, issue
	// #83); this column is retained only so the startup re-encryption migration
	// can read the old key. It is blanked once data has been re-encrypted under
	// the env key. Do NOT use it for encrypt/decrypt at runtime.
	//
	// It is tagged dont-update so UpdateSettings never writes it: the column is
	// NOT NULL, and some drivers read a blanked (empty) value back as nil, which
	// would otherwise make a normal settings update write NULL and fail. Only the
	// seeder (insert) and the migration (direct SQL) ever write this column.
	AESEncryptionKeyLegacy []byte `db:"aes_encryption_key" fieldtag:"dont-update"`
	SMTPHost               string `db:"smtp_host"`
	SMTPPort               int    `db:"smtp_port"`
	SMTPUsername           string `db:"smtp_username"`
	SMTPPasswordEncrypted  []byte `db:"smtp_password_encrypted"`
	SMTPFromName           string `db:"smtp_from_name"`
	SMTPFromEmail          string `db:"smtp_from_email"`
	SMTPEncryption         string `db:"smtp_encryption"`
	SMTPEnabled            bool   `db:"smtp_enabled"`

	// Dynamic Client Registration (RFC 7591)
	DynamicClientRegistrationEnabled bool `db:"dynamic_client_registration_enabled"`

	// PKCE (Proof Key for Code Exchange) Configuration
	// When true, PKCE is required for all authorization code flows (OAuth 2.1 recommendation)
	// Individual clients can override this setting
	PKCERequired bool `db:"pkce_required"`

	// Implicit Flow Configuration
	// SECURITY NOTE: Implicit flow is deprecated in OAuth 2.1.
	// Access tokens in URI fragments can leak via browser history and Referer headers.
	// Authorization Code with PKCE should be used for all new applications.
	// When true, implicit flow (response_type=token, id_token, id_token token) is allowed server-wide
	// Individual clients can override this setting
	ImplicitFlowEnabled bool `db:"implicit_flow_enabled"`

	// Resource Owner Password Credentials (ROPC) Flow Configuration
	// RFC 6749 Section 4.3
	// SECURITY NOTE: ROPC is deprecated in OAuth 2.1 due to credential exposure risks.
	// When true, grant_type=password is allowed at the token endpoint server-wide
	// Individual clients can override this setting
	ResourceOwnerPasswordCredentialsEnabled bool `db:"resource_owner_password_credentials_enabled"`

	// Audit Log Console Output
	// When true, audit events are written to the console via slog
	AuditLogsInConsoleEnabled bool `db:"audit_logs_in_console_enabled"`

	// Audit Log Database Persistence
	// When true, audit events are persisted to the audit_logs table
	AuditLogsInDatabaseEnabled bool `db:"audit_logs_in_database_enabled"`

	// Number of days to retain audit logs in the database (0 = infinite retention)
	AuditLogRetentionDays int `db:"audit_log_retention_days"`
}
