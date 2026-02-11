package adminsettingshandlers

import (
	"github.com/leodip/goiabada/core/api"
)

type SettingsEmailGet struct {
	SMTPEnabled    bool
	SMTPHost       string
	SMTPPort       int
	SMTPUsername   string
	SMTPPassword   string
	SMTPEncryption string
	SMTPFromName   string
	SMTPFromEmail  string
}

type SettingsEmailPost struct {
	SMTPEnabled    bool
	SMTPHost       string
	SMTPPort       string
	SMTPUsername   string
	SMTPPassword   string
	SMTPEncryption string
	SMTPFromName   string
	SMTPFromEmail  string
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
	Id               int64
	CreatedAt        string
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
}

type SettingsSessionPost struct {
	UserSessionIdleTimeoutInSeconds string
	UserSessionMaxLifetimeInSeconds string
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
}
