package adminsettingshandlers

import (
	"strings"
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

// emailErrorFields maps the email settings' refusals to the field each is about. A host changed
// with a password saved for the old one is the password's to answer, and a connection that fails
// the host's, which names where it went.
var emailErrorFields = map[string]string{
	i18n.ErrCodeSettingsEmailSMTPHostRequired:          "hostOrIP",
	i18n.ErrCodeSettingsEmailSMTPHostTooLong:           "hostOrIP",
	i18n.ErrCodeSettingsEmailConnectFailedHostNotFound: "hostOrIP",
	i18n.ErrCodeSettingsEmailConnectFailedTimedOut:     "hostOrIP",
	i18n.ErrCodeSettingsEmailConnectFailedRefused:      "hostOrIP",
	i18n.ErrCodeSettingsEmailConnectFailed:             "hostOrIP",
	i18n.ErrCodeSettingsEmailSMTPPortRequired:          "port",
	i18n.ErrCodeSettingsEmailSMTPPortOutOfRange:        "port",
	i18n.ErrCodeSettingsEmailSMTPEncryptionInvalid:     "smtpEncryption",
	i18n.ErrCodeSettingsEmailSMTPUsernameTooLong:       "username",
	i18n.ErrCodeSettingsEmailSMTPPasswordTooLong:       "password",
	i18n.ErrCodeSettingsEmailSMTPPasswordAndClear:      "password",
	i18n.ErrCodeSettingsEmailSMTPHostChanged:           "password",
	i18n.ErrCodeSettingsEmailSMTPFromNameTooLong:       "fromName",
	i18n.ErrCodeSettingsSmtpFromNameAngleBrackets:      "fromName",
	i18n.ErrCodeSettingsEmailSMTPFromEmailRequired:     "fromEmail",
	i18n.ErrCodeSettingsEmailSMTPFromEmailTooLong:      "fromEmail",
	i18n.ErrCodeEmailRequired:                          "fromEmail",
	i18n.ErrCodeEmailInvalidFormat:                     "fromEmail",
	i18n.ErrCodeEmailTooLong:                           "fromEmail",
}

// sendTestErrorFields maps the test email's refusals about its address to that field. A send that
// fails is the server's, and names no field.
var sendTestErrorFields = map[string]string{
	i18n.ErrCodeSettingsEmailDestinationRequired: "destinationEmail",
	i18n.ErrCodeEmailRequired:                    "destinationEmail",
	i18n.ErrCodeEmailInvalidFormat:               "destinationEmail",
	i18n.ErrCodeEmailTooLong:                     "destinationEmail",
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

// AuditLogRow is one audit log entry as the viewer draws it: its details read as keys and values
// when they parse as a JSON object, DetailsParsed, and shown as written otherwise.
type AuditLogRow struct {
	api.AuditLogResponse
	DetailPairs   []AuditLogDetail
	DetailsParsed bool
}

// EventSegments is the event's name cut after each underscore, so a phone breaks it between its
// words rather than inside one.
func (r AuditLogRow) EventSegments() []string {
	return strings.SplitAfter(r.AuditEvent, "_")
}

// AuditLogDetail is one key of an audit log entry's details and its value as text.
type AuditLogDetail struct {
	Key   string
	Value string
}

type AuditLogsPageResult struct {
	AuditLogs  []api.AuditLogResponse
	Rows       []AuditLogRow
	Total      int
	Page       int
	PageSize   int
	AuditEvent string
	RequestId  string
}
