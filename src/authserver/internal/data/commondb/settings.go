package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// settingsColumns is the settings table as scanSettings reads it.
var settingsColumns = columnList{
	sqlite: "id, created_at, updated_at, app_name, issuer, ui_theme, password_policy, " +
		"self_registration_enabled, self_registration_requires_email_verification, " +
		"token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds, " +
		"refresh_token_offline_max_lifetime_in_seconds, user_session_idle_timeout_in_seconds, " +
		"user_session_max_lifetime_in_seconds, include_open_id_connect_claims_in_access_token, " +
		"include_open_id_connect_claims_in_id_token, max_user_sessions_per_user, aes_encryption_key, " +
		"smtp_host, smtp_port, smtp_username, smtp_password_encrypted, smtp_from_name, smtp_from_email, " +
		"smtp_encryption, smtp_enabled, dynamic_client_registration_enabled, pkce_required, " +
		"implicit_flow_enabled, resource_owner_password_credentials_enabled, " +
		"audit_logs_in_console_enabled, audit_logs_in_database_enabled, audit_log_retention_days, last_cleanup_at",
	mysql: "id, created_at, updated_at, app_name, issuer, ui_theme, password_policy, " +
		"self_registration_enabled, self_registration_requires_email_verification, " +
		"token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds, " +
		"refresh_token_offline_max_lifetime_in_seconds, user_session_idle_timeout_in_seconds, " +
		"user_session_max_lifetime_in_seconds, include_open_id_connect_claims_in_access_token, " +
		"include_open_id_connect_claims_in_id_token, max_user_sessions_per_user, aes_encryption_key, " +
		"smtp_host, smtp_port, smtp_username, smtp_password_encrypted, smtp_from_name, smtp_from_email, " +
		"smtp_encryption, smtp_enabled, dynamic_client_registration_enabled, pkce_required, " +
		"implicit_flow_enabled, resource_owner_password_credentials_enabled, " +
		"audit_logs_in_console_enabled, audit_logs_in_database_enabled, audit_log_retention_days, last_cleanup_at",
	postgres: "id, created_at, updated_at, app_name, issuer, ui_theme, password_policy, " +
		"self_registration_enabled, self_registration_requires_email_verification, " +
		"token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds, " +
		"refresh_token_offline_max_lifetime_in_seconds, user_session_idle_timeout_in_seconds, " +
		"user_session_max_lifetime_in_seconds, include_open_id_connect_claims_in_access_token, " +
		"include_open_id_connect_claims_in_id_token, max_user_sessions_per_user, aes_encryption_key, " +
		"smtp_host, smtp_port, smtp_username, smtp_password_encrypted, smtp_from_name, smtp_from_email, " +
		"smtp_encryption, smtp_enabled, dynamic_client_registration_enabled, pkce_required, " +
		"implicit_flow_enabled, resource_owner_password_credentials_enabled, " +
		"audit_logs_in_console_enabled, audit_logs_in_database_enabled, audit_log_retention_days, last_cleanup_at",
	mssql: "id, created_at, updated_at, app_name, issuer, ui_theme, password_policy, " +
		"self_registration_enabled, self_registration_requires_email_verification, " +
		"token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds, " +
		"refresh_token_offline_max_lifetime_in_seconds, user_session_idle_timeout_in_seconds, " +
		"user_session_max_lifetime_in_seconds, include_open_id_connect_claims_in_access_token, " +
		"include_open_id_connect_claims_in_id_token, max_user_sessions_per_user, aes_encryption_key, " +
		"smtp_host, smtp_port, smtp_username, smtp_password_encrypted, smtp_from_name, smtp_from_email, " +
		"smtp_encryption, smtp_enabled, dynamic_client_registration_enabled, pkce_required, " +
		"implicit_flow_enabled, resource_owner_password_credentials_enabled, " +
		"audit_logs_in_console_enabled, audit_logs_in_database_enabled, audit_log_retention_days, last_cleanup_at",
}

// scanSettings reads one row selected with settingsColumns.
func scanSettings(row rowScanner, settings *record.Settings) error {
	return row.Scan(
		&settings.Id,
		&settings.CreatedAt,
		&settings.UpdatedAt,
		&settings.AppName,
		&settings.Issuer,
		&settings.UITheme,
		&settings.PasswordPolicy,
		&settings.SelfRegistrationEnabled,
		&settings.SelfRegistrationRequiresEmailVerification,
		&settings.TokenExpirationInSeconds,
		&settings.RefreshTokenOfflineIdleTimeoutInSeconds,
		&settings.RefreshTokenOfflineMaxLifetimeInSeconds,
		&settings.UserSessionIdleTimeoutInSeconds,
		&settings.UserSessionMaxLifetimeInSeconds,
		&settings.IncludeOpenIDConnectClaimsInAccessToken,
		&settings.IncludeOpenIDConnectClaimsInIdToken,
		&settings.MaxUserSessionsPerUser,
		&settings.AESEncryptionKeyLegacy,
		&settings.SMTPHost,
		&settings.SMTPPort,
		&settings.SMTPUsername,
		&settings.SMTPPasswordEncrypted,
		&settings.SMTPFromName,
		&settings.SMTPFromEmail,
		&settings.SMTPEncryption,
		&settings.SMTPEnabled,
		&settings.DynamicClientRegistrationEnabled,
		&settings.PKCERequired,
		&settings.ImplicitFlowEnabled,
		&settings.ResourceOwnerPasswordCredentialsEnabled,
		&settings.AuditLogsInConsoleEnabled,
		&settings.AuditLogsInDatabaseEnabled,
		&settings.AuditLogRetentionDays,
		&settings.LastCleanupAt,
	)
}

var insertSettings = statement{
	sqlite: "INSERT INTO settings (created_at, updated_at, app_name, issuer, ui_theme, password_policy, " +
		"self_registration_enabled, self_registration_requires_email_verification, " +
		"token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds, " +
		"refresh_token_offline_max_lifetime_in_seconds, user_session_idle_timeout_in_seconds, " +
		"user_session_max_lifetime_in_seconds, include_open_id_connect_claims_in_access_token, " +
		"include_open_id_connect_claims_in_id_token, max_user_sessions_per_user, aes_encryption_key, " +
		"smtp_host, smtp_port, smtp_username, smtp_password_encrypted, smtp_from_name, smtp_from_email, " +
		"smtp_encryption, smtp_enabled, dynamic_client_registration_enabled, pkce_required, " +
		"implicit_flow_enabled, resource_owner_password_credentials_enabled, " +
		"audit_logs_in_console_enabled, audit_logs_in_database_enabled, audit_log_retention_days, " +
		"last_cleanup_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, " +
		"?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
	mysql: "INSERT INTO settings (created_at, updated_at, app_name, issuer, ui_theme, password_policy, " +
		"self_registration_enabled, self_registration_requires_email_verification, " +
		"token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds, " +
		"refresh_token_offline_max_lifetime_in_seconds, user_session_idle_timeout_in_seconds, " +
		"user_session_max_lifetime_in_seconds, include_open_id_connect_claims_in_access_token, " +
		"include_open_id_connect_claims_in_id_token, max_user_sessions_per_user, aes_encryption_key, " +
		"smtp_host, smtp_port, smtp_username, smtp_password_encrypted, smtp_from_name, smtp_from_email, " +
		"smtp_encryption, smtp_enabled, dynamic_client_registration_enabled, pkce_required, " +
		"implicit_flow_enabled, resource_owner_password_credentials_enabled, " +
		"audit_logs_in_console_enabled, audit_logs_in_database_enabled, audit_log_retention_days, " +
		"last_cleanup_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, " +
		"?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
	postgres: "INSERT INTO settings (created_at, updated_at, app_name, issuer, ui_theme, password_policy, " +
		"self_registration_enabled, self_registration_requires_email_verification, " +
		"token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds, " +
		"refresh_token_offline_max_lifetime_in_seconds, user_session_idle_timeout_in_seconds, " +
		"user_session_max_lifetime_in_seconds, include_open_id_connect_claims_in_access_token, " +
		"include_open_id_connect_claims_in_id_token, max_user_sessions_per_user, aes_encryption_key, " +
		"smtp_host, smtp_port, smtp_username, smtp_password_encrypted, smtp_from_name, smtp_from_email, " +
		"smtp_encryption, smtp_enabled, dynamic_client_registration_enabled, pkce_required, " +
		"implicit_flow_enabled, resource_owner_password_credentials_enabled, " +
		"audit_logs_in_console_enabled, audit_logs_in_database_enabled, audit_log_retention_days, " +
		"last_cleanup_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, " +
		"$17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, " +
		"$33) RETURNING id",
	mssql: "INSERT INTO settings (created_at, updated_at, app_name, issuer, ui_theme, password_policy, " +
		"self_registration_enabled, self_registration_requires_email_verification, " +
		"token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds, " +
		"refresh_token_offline_max_lifetime_in_seconds, user_session_idle_timeout_in_seconds, " +
		"user_session_max_lifetime_in_seconds, include_open_id_connect_claims_in_access_token, " +
		"include_open_id_connect_claims_in_id_token, max_user_sessions_per_user, aes_encryption_key, " +
		"smtp_host, smtp_port, smtp_username, smtp_password_encrypted, smtp_from_name, smtp_from_email, " +
		"smtp_encryption, smtp_enabled, dynamic_client_registration_enabled, pkce_required, " +
		"implicit_flow_enabled, resource_owner_password_credentials_enabled, " +
		"audit_logs_in_console_enabled, audit_logs_in_database_enabled, audit_log_retention_days, " +
		"last_cleanup_at) OUTPUT INSERTED.id VALUES (@p1, @p2, @p3, @p4, @p5, @p6, @p7, @p8, @p9, @p10, " +
		"@p11, @p12, @p13, @p14, @p15, @p16, @p17, @p18, @p19, @p20, @p21, @p22, @p23, @p24, @p25, @p26, " +
		"@p27, @p28, @p29, @p30, @p31, @p32, @p33)",
}

// insertInitialSettings is the settings row with its id named, written once, by
// CreateInitialSettings. It answers no id on any engine, since the caller names it.
var insertInitialSettings = statement{
	sqlite: "INSERT INTO settings (id, created_at, updated_at, app_name, issuer, ui_theme, password_policy, " +
		"self_registration_enabled, self_registration_requires_email_verification, " +
		"token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds, " +
		"refresh_token_offline_max_lifetime_in_seconds, user_session_idle_timeout_in_seconds, " +
		"user_session_max_lifetime_in_seconds, include_open_id_connect_claims_in_access_token, " +
		"include_open_id_connect_claims_in_id_token, max_user_sessions_per_user, aes_encryption_key, " +
		"smtp_host, smtp_port, smtp_username, smtp_password_encrypted, smtp_from_name, smtp_from_email, " +
		"smtp_encryption, smtp_enabled, dynamic_client_registration_enabled, pkce_required, " +
		"implicit_flow_enabled, resource_owner_password_credentials_enabled, " +
		"audit_logs_in_console_enabled, audit_logs_in_database_enabled, audit_log_retention_days, " +
		"last_cleanup_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, " +
		"?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
	mysql: "INSERT INTO settings (id, created_at, updated_at, app_name, issuer, ui_theme, password_policy, " +
		"self_registration_enabled, self_registration_requires_email_verification, " +
		"token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds, " +
		"refresh_token_offline_max_lifetime_in_seconds, user_session_idle_timeout_in_seconds, " +
		"user_session_max_lifetime_in_seconds, include_open_id_connect_claims_in_access_token, " +
		"include_open_id_connect_claims_in_id_token, max_user_sessions_per_user, aes_encryption_key, " +
		"smtp_host, smtp_port, smtp_username, smtp_password_encrypted, smtp_from_name, smtp_from_email, " +
		"smtp_encryption, smtp_enabled, dynamic_client_registration_enabled, pkce_required, " +
		"implicit_flow_enabled, resource_owner_password_credentials_enabled, " +
		"audit_logs_in_console_enabled, audit_logs_in_database_enabled, audit_log_retention_days, " +
		"last_cleanup_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, " +
		"?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
	postgres: "INSERT INTO settings (id, created_at, updated_at, app_name, issuer, ui_theme, password_policy, " +
		"self_registration_enabled, self_registration_requires_email_verification, " +
		"token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds, " +
		"refresh_token_offline_max_lifetime_in_seconds, user_session_idle_timeout_in_seconds, " +
		"user_session_max_lifetime_in_seconds, include_open_id_connect_claims_in_access_token, " +
		"include_open_id_connect_claims_in_id_token, max_user_sessions_per_user, aes_encryption_key, " +
		"smtp_host, smtp_port, smtp_username, smtp_password_encrypted, smtp_from_name, smtp_from_email, " +
		"smtp_encryption, smtp_enabled, dynamic_client_registration_enabled, pkce_required, " +
		"implicit_flow_enabled, resource_owner_password_credentials_enabled, " +
		"audit_logs_in_console_enabled, audit_logs_in_database_enabled, audit_log_retention_days, " +
		"last_cleanup_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, " +
		"$17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34)",
	mssql: "INSERT INTO settings (id, created_at, updated_at, app_name, issuer, ui_theme, password_policy, " +
		"self_registration_enabled, self_registration_requires_email_verification, " +
		"token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds, " +
		"refresh_token_offline_max_lifetime_in_seconds, user_session_idle_timeout_in_seconds, " +
		"user_session_max_lifetime_in_seconds, include_open_id_connect_claims_in_access_token, " +
		"include_open_id_connect_claims_in_id_token, max_user_sessions_per_user, aes_encryption_key, " +
		"smtp_host, smtp_port, smtp_username, smtp_password_encrypted, smtp_from_name, smtp_from_email, " +
		"smtp_encryption, smtp_enabled, dynamic_client_registration_enabled, pkce_required, " +
		"implicit_flow_enabled, resource_owner_password_credentials_enabled, " +
		"audit_logs_in_console_enabled, audit_logs_in_database_enabled, audit_log_retention_days, " +
		"last_cleanup_at) VALUES (@p1, @p2, @p3, @p4, @p5, @p6, @p7, @p8, @p9, @p10, @p11, @p12, @p13, " +
		"@p14, @p15, @p16, @p17, @p18, @p19, @p20, @p21, @p22, @p23, @p24, @p25, @p26, @p27, @p28, @p29, " +
		"@p30, @p31, @p32, @p33, @p34)",
}

// updateSettings writes the whole row but created_at, aes_encryption_key and last_cleanup_at, which
// are dont-update: see the record for why each is left alone.
var updateSettings = statement{
	sqlite: "UPDATE settings SET updated_at = ?, app_name = ?, issuer = ?, ui_theme = ?, " +
		"password_policy = ?, self_registration_enabled = ?, " +
		"self_registration_requires_email_verification = ?, token_expiration_in_seconds = ?, " +
		"refresh_token_offline_idle_timeout_in_seconds = ?, " +
		"refresh_token_offline_max_lifetime_in_seconds = ?, user_session_idle_timeout_in_seconds = ?, " +
		"user_session_max_lifetime_in_seconds = ?, include_open_id_connect_claims_in_access_token = ?, " +
		"include_open_id_connect_claims_in_id_token = ?, max_user_sessions_per_user = ?, smtp_host = ?, " +
		"smtp_port = ?, smtp_username = ?, smtp_password_encrypted = ?, smtp_from_name = ?, " +
		"smtp_from_email = ?, smtp_encryption = ?, smtp_enabled = ?, " +
		"dynamic_client_registration_enabled = ?, pkce_required = ?, implicit_flow_enabled = ?, " +
		"resource_owner_password_credentials_enabled = ?, audit_logs_in_console_enabled = ?, " +
		"audit_logs_in_database_enabled = ?, audit_log_retention_days = ? WHERE id = ?",
	mysql: "UPDATE settings SET updated_at = ?, app_name = ?, issuer = ?, ui_theme = ?, " +
		"password_policy = ?, self_registration_enabled = ?, " +
		"self_registration_requires_email_verification = ?, token_expiration_in_seconds = ?, " +
		"refresh_token_offline_idle_timeout_in_seconds = ?, " +
		"refresh_token_offline_max_lifetime_in_seconds = ?, user_session_idle_timeout_in_seconds = ?, " +
		"user_session_max_lifetime_in_seconds = ?, include_open_id_connect_claims_in_access_token = ?, " +
		"include_open_id_connect_claims_in_id_token = ?, max_user_sessions_per_user = ?, smtp_host = ?, " +
		"smtp_port = ?, smtp_username = ?, smtp_password_encrypted = ?, smtp_from_name = ?, " +
		"smtp_from_email = ?, smtp_encryption = ?, smtp_enabled = ?, " +
		"dynamic_client_registration_enabled = ?, pkce_required = ?, implicit_flow_enabled = ?, " +
		"resource_owner_password_credentials_enabled = ?, audit_logs_in_console_enabled = ?, " +
		"audit_logs_in_database_enabled = ?, audit_log_retention_days = ? WHERE id = ?",
	postgres: "UPDATE settings SET updated_at = $1, app_name = $2, issuer = $3, ui_theme = $4, " +
		"password_policy = $5, self_registration_enabled = $6, " +
		"self_registration_requires_email_verification = $7, token_expiration_in_seconds = $8, " +
		"refresh_token_offline_idle_timeout_in_seconds = $9, " +
		"refresh_token_offline_max_lifetime_in_seconds = $10, " +
		"user_session_idle_timeout_in_seconds = $11, user_session_max_lifetime_in_seconds = $12, " +
		"include_open_id_connect_claims_in_access_token = $13, " +
		"include_open_id_connect_claims_in_id_token = $14, max_user_sessions_per_user = $15, " +
		"smtp_host = $16, smtp_port = $17, smtp_username = $18, smtp_password_encrypted = $19, " +
		"smtp_from_name = $20, smtp_from_email = $21, smtp_encryption = $22, smtp_enabled = $23, " +
		"dynamic_client_registration_enabled = $24, pkce_required = $25, implicit_flow_enabled = $26, " +
		"resource_owner_password_credentials_enabled = $27, audit_logs_in_console_enabled = $28, " +
		"audit_logs_in_database_enabled = $29, audit_log_retention_days = $30 WHERE id = $31",
	mssql: "UPDATE settings SET updated_at = @p1, app_name = @p2, issuer = @p3, ui_theme = @p4, " +
		"password_policy = @p5, self_registration_enabled = @p6, " +
		"self_registration_requires_email_verification = @p7, token_expiration_in_seconds = @p8, " +
		"refresh_token_offline_idle_timeout_in_seconds = @p9, " +
		"refresh_token_offline_max_lifetime_in_seconds = @p10, " +
		"user_session_idle_timeout_in_seconds = @p11, user_session_max_lifetime_in_seconds = @p12, " +
		"include_open_id_connect_claims_in_access_token = @p13, " +
		"include_open_id_connect_claims_in_id_token = @p14, max_user_sessions_per_user = @p15, " +
		"smtp_host = @p16, smtp_port = @p17, smtp_username = @p18, smtp_password_encrypted = @p19, " +
		"smtp_from_name = @p20, smtp_from_email = @p21, smtp_encryption = @p22, smtp_enabled = @p23, " +
		"dynamic_client_registration_enabled = @p24, pkce_required = @p25, implicit_flow_enabled = @p26, " +
		"resource_owner_password_credentials_enabled = @p27, audit_logs_in_console_enabled = @p28, " +
		"audit_logs_in_database_enabled = @p29, audit_log_retention_days = @p30 WHERE id = @p31",
}

var selectSettingsById = statement{
	sqlite:   "SELECT " + settingsColumns.sqlite + " FROM settings WHERE id = ?",
	mysql:    "SELECT " + settingsColumns.mysql + " FROM settings WHERE id = ?",
	postgres: "SELECT " + settingsColumns.postgres + " FROM settings WHERE id = $1",
	mssql:    "SELECT " + settingsColumns.mssql + " FROM settings WHERE id = @p1",
}

var acquireSettingsRow = statement{
	sqlite:   "UPDATE settings SET updated_at = ? WHERE id = ?",
	mysql:    "UPDATE settings SET updated_at = ? WHERE id = ?",
	postgres: "UPDATE settings SET updated_at = $1 WHERE id = $2",
	mssql:    "UPDATE settings SET updated_at = @p1 WHERE id = @p2",
}

// claimCleanupRun binds the run's time twice, as last_cleanup_at and as updated_at, then the
// settings row's id, then the cutoff.
var claimCleanupRun = statement{
	sqlite: "UPDATE settings SET last_cleanup_at = ?, updated_at = ? " +
		"WHERE id = ? AND (last_cleanup_at IS NULL OR last_cleanup_at < ?)",
	mysql: "UPDATE settings SET last_cleanup_at = ?, updated_at = ? " +
		"WHERE id = ? AND (last_cleanup_at IS NULL OR last_cleanup_at < ?)",
	postgres: "UPDATE settings SET last_cleanup_at = $1, updated_at = $2 " +
		"WHERE id = $3 AND (last_cleanup_at IS NULL OR last_cleanup_at < $4)",
	mssql: "UPDATE settings SET last_cleanup_at = @p1, updated_at = @p2 " +
		"WHERE id = @p3 AND (last_cleanup_at IS NULL OR last_cleanup_at < @p4)",
}

func (d *Database) CreateSettings(ctx context.Context, tx *sql.Tx, settings *record.Settings) error {

	now := time.Now().UTC()

	originalCreatedAt := settings.CreatedAt
	originalUpdatedAt := settings.UpdatedAt
	settings.CreatedAt = sql.NullTime{Time: now, Valid: true}
	settings.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	id, err := d.insert(ctx, tx, insertSettings, "settings",
		settings.CreatedAt, settings.UpdatedAt, settings.AppName, settings.Issuer, settings.UITheme,
		settings.PasswordPolicy, settings.SelfRegistrationEnabled,
		settings.SelfRegistrationRequiresEmailVerification, settings.TokenExpirationInSeconds,
		settings.RefreshTokenOfflineIdleTimeoutInSeconds, settings.RefreshTokenOfflineMaxLifetimeInSeconds,
		settings.UserSessionIdleTimeoutInSeconds, settings.UserSessionMaxLifetimeInSeconds,
		settings.IncludeOpenIDConnectClaimsInAccessToken, settings.IncludeOpenIDConnectClaimsInIdToken,
		settings.MaxUserSessionsPerUser, settings.AESEncryptionKeyLegacy, settings.SMTPHost,
		settings.SMTPPort, settings.SMTPUsername, settings.SMTPPasswordEncrypted, settings.SMTPFromName,
		settings.SMTPFromEmail, settings.SMTPEncryption, settings.SMTPEnabled,
		settings.DynamicClientRegistrationEnabled, settings.PKCERequired, settings.ImplicitFlowEnabled,
		settings.ResourceOwnerPasswordCredentialsEnabled, settings.AuditLogsInConsoleEnabled,
		settings.AuditLogsInDatabaseEnabled, settings.AuditLogRetentionDays, settings.LastCleanupAt)
	if err != nil {
		settings.CreatedAt = originalCreatedAt
		settings.UpdatedAt = originalUpdatedAt
		return err
	}

	settings.Id = id
	return nil
}

// initialSettingsId is the settings row's id: IsEmpty and every reader of the settings ask for this
// id and no other, so the one row a deployment carries has to be written at it.
const initialSettingsId = 1

// CreateInitialSettings writes a deployment's settings row at initialSettingsId rather than at the
// id the engine's counter hands out. PostgreSQL, MySQL and SQL Server do not give back an id drawn
// inside a transaction that rolled back, so a first seed that failed after its settings insert left
// the next seed's row at 2, which no reader finds: the database stayed unusable and every later
// start failed on the rows it re-inserted (#424 decision 14). Naming the id makes a rolled-back
// seed leave nothing behind, whatever the engine's counter did.
//
// It refuses a nil transaction because SQL Server's IDENTITY_INSERT, which ExplicitIdInsertSQL
// brackets the insert with there, is a setting of the connection, and only a transaction pins the
// three statements to one.
func (d *Database) CreateInitialSettings(ctx context.Context, tx *sql.Tx, settings *record.Settings) error {
	if tx == nil {
		return errs.New("the initial settings are written inside a transaction, and none was given")
	}

	now := time.Now().UTC()

	originalId := settings.Id
	originalCreatedAt := settings.CreatedAt
	originalUpdatedAt := settings.UpdatedAt
	restore := func() {
		settings.Id = originalId
		settings.CreatedAt = originalCreatedAt
		settings.UpdatedAt = originalUpdatedAt
	}
	settings.Id = initialSettingsId
	settings.CreatedAt = sql.NullTime{Time: now, Valid: true}
	settings.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	var before, after []string
	if d.ExplicitIdInsertSQL != nil {
		before, after = d.ExplicitIdInsertSQL("settings")
	}

	for _, statement := range before {
		if _, err := d.ExecSQL(ctx, tx, statement); err != nil {
			restore()
			return errs.Wrap(err, "unable to prepare the initial settings insert")
		}
	}

	if _, err := d.ExecSQL(ctx, tx, insertInitialSettings.text(d.Dialect),
		settings.Id, settings.CreatedAt, settings.UpdatedAt, settings.AppName, settings.Issuer,
		settings.UITheme, settings.PasswordPolicy, settings.SelfRegistrationEnabled,
		settings.SelfRegistrationRequiresEmailVerification, settings.TokenExpirationInSeconds,
		settings.RefreshTokenOfflineIdleTimeoutInSeconds, settings.RefreshTokenOfflineMaxLifetimeInSeconds,
		settings.UserSessionIdleTimeoutInSeconds, settings.UserSessionMaxLifetimeInSeconds,
		settings.IncludeOpenIDConnectClaimsInAccessToken, settings.IncludeOpenIDConnectClaimsInIdToken,
		settings.MaxUserSessionsPerUser, settings.AESEncryptionKeyLegacy, settings.SMTPHost,
		settings.SMTPPort, settings.SMTPUsername, settings.SMTPPasswordEncrypted, settings.SMTPFromName,
		settings.SMTPFromEmail, settings.SMTPEncryption, settings.SMTPEnabled,
		settings.DynamicClientRegistrationEnabled, settings.PKCERequired, settings.ImplicitFlowEnabled,
		settings.ResourceOwnerPasswordCredentialsEnabled, settings.AuditLogsInConsoleEnabled,
		settings.AuditLogsInDatabaseEnabled, settings.AuditLogRetentionDays, settings.LastCleanupAt); err != nil {
		restore()
		return d.wrapSQLError(err, "unable to insert the initial settings")
	}

	for _, statement := range after {
		if _, err := d.ExecSQL(ctx, tx, statement); err != nil {
			restore()
			return errs.Wrap(err, "unable to finish the initial settings insert")
		}
	}

	return nil
}

func (d *Database) UpdateSettings(ctx context.Context, tx *sql.Tx, settings *record.Settings) error {

	if settings.Id == 0 {
		return errs.New("can't update settings with id 0")
	}

	originalUpdatedAt := settings.UpdatedAt
	settings.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	_, err := d.ExecSQL(ctx, tx, updateSettings.text(d.Dialect),
		settings.UpdatedAt, settings.AppName, settings.Issuer, settings.UITheme, settings.PasswordPolicy,
		settings.SelfRegistrationEnabled, settings.SelfRegistrationRequiresEmailVerification,
		settings.TokenExpirationInSeconds, settings.RefreshTokenOfflineIdleTimeoutInSeconds,
		settings.RefreshTokenOfflineMaxLifetimeInSeconds, settings.UserSessionIdleTimeoutInSeconds,
		settings.UserSessionMaxLifetimeInSeconds, settings.IncludeOpenIDConnectClaimsInAccessToken,
		settings.IncludeOpenIDConnectClaimsInIdToken, settings.MaxUserSessionsPerUser, settings.SMTPHost,
		settings.SMTPPort, settings.SMTPUsername, settings.SMTPPasswordEncrypted, settings.SMTPFromName,
		settings.SMTPFromEmail, settings.SMTPEncryption, settings.SMTPEnabled,
		settings.DynamicClientRegistrationEnabled, settings.PKCERequired, settings.ImplicitFlowEnabled,
		settings.ResourceOwnerPasswordCredentialsEnabled, settings.AuditLogsInConsoleEnabled,
		settings.AuditLogsInDatabaseEnabled, settings.AuditLogRetentionDays, settings.Id)
	if err != nil {
		settings.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update settings")
	}

	return nil
}

// AcquireSettingsRow takes the settings row and holds it for the rest of the caller's transaction,
// the way AcquireClientRow holds a client's: one unconditional UPDATE of the row's updated_at, which
// the caller's UpdateSettings overwrites moments later with its own (#407).
//
// WHAT IT BUYS. UpdateSettings writes every mutable column, and each settings section's save
// changes only its own. A save that writes the row its request started with carries every other
// section's columns from that copy, so a save of another section committed meanwhile is written
// back over, and one section's change is lost without an error. A save of the email or audit-log
// settings, reserved to authserver:manage, can be undone that way by a manage-settings save that
// loaded the row before it (#402). The section saves therefore take this row first, read it again
// on the transaction, apply their own section to what they read and write that: the read happens
// under this transaction's lock, so no other save can commit between it and the write. A bare
// re-read does not hold, for the reason AcquireClientRow gives: under MVCC it returns the last
// committed version without waiting for a writer in flight.
//
// The transaction holding it touches no table but settings, so it holds one row and cannot be part
// of a deadlock cycle. TryClaimCleanupRun writes the same row, autocommitted, and waits at most for
// one save.
//
// A row that is not there affects no rows and is not reported here, as AcquireClientRow does not
// report a missing client: the read that follows decides whether it exists.
//
// The transaction is required. Without one the statement autocommits and releases the row before
// the caller's read runs, which is the whole of what this buys.
func (d *Database) AcquireSettingsRow(ctx context.Context, tx *sql.Tx, settingsId int64) error {

	if tx == nil {
		return errs.New("acquiring the settings row requires a transaction: an autocommitted statement releases the row before the caller can read it")
	}

	if settingsId == 0 {
		return errs.New("can't acquire a settings row with an id of 0")
	}

	if _, err := d.ExecSQL(ctx, tx, acquireSettingsRow.text(d.Dialect), time.Now().UTC(), settingsId); err != nil {
		return errs.Wrap(err, "unable to acquire the settings row")
	}

	return nil
}

func (d *Database) GetSettingsById(ctx context.Context, tx *sql.Tx, settingsId int64) (*record.Settings, error) {
	return queryOne(ctx, d, tx, selectSettingsById.text(d.Dialect), []any{settingsId}, scanSettings, "settings")
}

// TryClaimCleanupRun atomically claims the next background cleanup run, and
// reports whether this caller won the claim.
//
// The claim is a conditional UPDATE on settings.last_cleanup_at, which makes this
// column serve two purposes at once:
//
//   - Single flight across instances. Every replica polls, but only the one whose
//     UPDATE affects a row proceeds, so the cleanup does not run concurrently on
//     the same tables from several replicas.
//   - A wall-clock schedule. The decision is "has it been long enough since the
//     last run", not "how long has this process been up", so restarts no longer
//     reset the interval.
//
// claimableBefore is the cutoff: the run is claimable when last_cleanup_at is
// null (never run) or older than it. Pass now.Add(-interval).
//
// The claim is taken BEFORE the work runs, so a crash mid-cleanup delays the next
// attempt by one interval rather than letting every instance retry immediately.
func (d *Database) TryClaimCleanupRun(ctx context.Context, tx *sql.Tx, now time.Time, claimableBefore time.Time) (bool, error) {

	result, err := d.ExecSQL(ctx, tx, claimCleanupRun.text(d.Dialect), now, now, initialSettingsId, claimableBefore)
	if err != nil {
		return false, errs.Wrap(err, "unable to claim the cleanup run")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errs.Wrap(err, "unable to get rows affected when claiming the cleanup run")
	}

	return rowsAffected == 1, nil
}
