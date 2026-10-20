package adminsettingshandlers

import (
	"time"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
)

// generalErrorFields maps the general settings' refusals to the field each is about.
var generalErrorFields = map[string]string{
	i18n.ErrCodeSettingsGeneralAppNameTooLong:   "appName",
	i18n.ErrCodeSettingsAppNameAngleBrackets:    "appName",
	i18n.ErrCodeSettingsGeneralIssuerURIInvalid: "issuer",
	i18n.ErrCodeSettingsGeneralIssuerTooLong:    "issuer",
	i18n.ErrCodeSettingsIssuerAngleBrackets:     "issuer",
}

// sessionsErrorFields maps the session settings' refusals to the field each is about.
var sessionsErrorFields = map[string]string{
	i18n.ErrCodeSettingsSessionsIdleTimeoutNotPositive:       "userSessionIdleTimeoutInSeconds",
	i18n.ErrCodeSettingsSessionsIdleTimeoutTooLarge:          "userSessionIdleTimeoutInSeconds",
	i18n.ErrCodeSettingsSessionsIdleTimeoutAboveMaxLifetime:  "userSessionIdleTimeoutInSeconds",
	i18n.ErrCodeSettingsSessionsMaxLifetimeNotPositive:       "userSessionMaxLifetimeInSeconds",
	i18n.ErrCodeSettingsSessionsMaxLifetimeTooLarge:          "userSessionMaxLifetimeInSeconds",
	i18n.ErrCodeSettingsSessionsMaxSessionsPerUserRequired:   "maxUserSessionsPerUser",
	i18n.ErrCodeSettingsSessionsMaxSessionsPerUserOutOfRange: "maxUserSessionsPerUser",
}

// auditLogsErrorFields maps the audit logging settings' refusals to the retention, the one field
// they can be about.
var auditLogsErrorFields = map[string]string{
	i18n.ErrCodeSettingsAuditLogsRetentionDaysNegative: "auditLogRetentionDays",
	i18n.ErrCodeSettingsAuditLogsRetentionDaysTooLarge: "auditLogRetentionDays",
}

// tokensErrorFields maps the token settings' refusals to the duration each is about. The idle
// timeout above the maximum lifetime shares the client tokens' key.
var tokensErrorFields = map[string]string{
	i18n.ErrCodeSettingsTokensTokenExpirationNotPositive:       "tokenExpirationInSeconds",
	i18n.ErrCodeSettingsTokensTokenExpirationTooLarge:          "tokenExpirationInSeconds",
	i18n.ErrCodeSettingsTokensOfflineIdleTimeoutNotPositive:    "refreshTokenOfflineIdleTimeoutInSeconds",
	i18n.ErrCodeSettingsTokensOfflineIdleTimeoutTooLarge:       "refreshTokenOfflineIdleTimeoutInSeconds",
	i18n.ErrCodeClientTokensOfflineIdleTimeoutAboveMaxLifetime: "refreshTokenOfflineIdleTimeoutInSeconds",
	i18n.ErrCodeSettingsTokensOfflineMaxLifetimeNotPositive:    "refreshTokenOfflineMaxLifetimeInSeconds",
	i18n.ErrCodeSettingsTokensOfflineMaxLifetimeTooLarge:       "refreshTokenOfflineMaxLifetimeInSeconds",
}

// SettingsEmailGet is the email settings page as loaded. SMTPPassword is always empty: the API never
// returns the stored password, only HasSMTPPassword, which draws the Saved or Not set badge and
// offers the removal. SavedSMTPHost is the host that password was saved for, which the page's
// host-change warning compares the host box against (#410).
type SettingsEmailGet struct {
	SMTPEnabled       bool
	SMTPHost          string
	SMTPPort          int
	SMTPUsername      string
	SMTPPassword      string
	SMTPEncryption    string
	SMTPFromName      string
	SMTPFromEmail     string
	HasSMTPPassword   bool
	SavedSMTPHost     string
	ClearSMTPPassword bool
}

// SettingsEmailPost is the email settings form as submitted, which a refused save is redrawn from:
// the typed password goes back in its box, and HasSMTPPassword and SavedSMTPHost come back from the
// hidden fields the page was loaded with, so the badge, the removal checkbox and the host-change
// warning stay as they were (#410).
type SettingsEmailPost struct {
	SMTPEnabled       bool
	SMTPHost          string
	SMTPPort          string
	SMTPUsername      string
	SMTPPassword      string
	SMTPEncryption    string
	SMTPFromName      string
	SMTPFromEmail     string
	HasSMTPPassword   bool
	SavedSMTPHost     string
	ClearSMTPPassword bool
}

type SettingsGeneral struct {
	AppName                                   string
	Issuer                                    string
	SelfRegistrationEnabled                   bool
	SelfRegistrationRequiresEmailVerification bool
	DynamicClientRegistrationEnabled          bool
	PasswordPolicy                            string
	PKCERequired                              bool
	ImplicitFlowEnabled                       bool
	// ResourceOwnerPasswordCredentialsEnabled enables ROPC grant type (RFC 6749 §4.3)
	// SECURITY NOTE: ROPC is deprecated in OAuth 2.1 due to credential exposure risks
	ResourceOwnerPasswordCredentialsEnabled bool
}

type SettingsKey struct {
	Id int64
	// CreatedAt is the instant rather than pre-rendered text: the page formats it with the
	// DateTime template function, which reads the layout from the viewer's catalog. Formatting
	// it here produced "02 Jan 2006 15:04:05 MST" under every locale, month name included,
	// because Go's time.Format has no locale of its own (#373).
	CreatedAt        *time.Time
	State            string
	KeyIdentifier    string
	Type             string
	Algorithm        string
	PublicKeyASN1DER string
	PublicKeyPEM     string
	PublicKeyJWK     string
}

type SettingsSessionGet struct {
	UserSessionIdleTimeoutInSeconds int
	UserSessionMaxLifetimeInSeconds int
	MaxUserSessionsPerUser          int
}

type SettingsSessionPost struct {
	UserSessionIdleTimeoutInSeconds string
	UserSessionMaxLifetimeInSeconds string
	MaxUserSessionsPerUser          string
}

type SettingsTokenGet struct {
	TokenExpirationInSeconds                int
	RefreshTokenOfflineIdleTimeoutInSeconds int
	RefreshTokenOfflineMaxLifetimeInSeconds int
	IncludeOpenIDConnectClaimsInAccessToken bool
	IncludeOpenIDConnectClaimsInIdToken     bool
}

type SettingsTokenPost struct {
	TokenExpirationInSeconds                string
	RefreshTokenOfflineIdleTimeoutInSeconds string
	RefreshTokenOfflineMaxLifetimeInSeconds string
	IncludeOpenIDConnectClaimsInAccessToken bool
	IncludeOpenIDConnectClaimsInIdToken     bool
}

type SettingsUITheme struct {
	UITheme string
}

type SettingsAuditLogsGet struct {
	AuditLogsInConsoleEnabled  bool
	AuditLogsInDatabaseEnabled bool
	AuditLogRetentionDays      int
}

type SettingsAuditLogsPost struct {
	AuditLogsInConsoleEnabled  bool
	AuditLogsInDatabaseEnabled bool
	AuditLogRetentionDays      string
}

type AuditLogsPageResult struct {
	AuditLogs  []api.AuditLogResponse
	Total      int
	Page       int
	PageSize   int
	AuditEvent string
	RequestId  string
}
