package api

import (
	"time"
)

// PublicSettingsResponse is what /api/public/settings answers. That endpoint needs no
// authentication, so this type is the entire boundary between an anonymous caller and the 32
// fields of models.Settings, among them the legacy AES encryption key and the encrypted SMTP
// password. The auth server's handler_public_settings_test.go holds that boundary in two
// directions: an allowlist of the fields below, and a case filling the model with recognizable
// secrets and asserting none of them reach the body.
//
// Issuer is here because the admin console needs the value the auth server stamps into the iss
// claim, and OIDC Core 1.0 section 3.1.3.7 requires a relying party to match it exactly. It
// discloses nothing new: OIDC Discovery 1.0 section 3 already requires the same value to be served
// to anonymous callers at /.well-known/openid-configuration (#285).
//
// It was declared twice until #350, once per module, field for field, with nothing in the build
// checking that the two agreed: a field added on one side and forgotten on the other decoded to its
// zero value in the console, silently. One declaration in the package both modules already share is
// what ends that.
type PublicSettingsResponse struct {
	AppName     string `json:"appName"`
	UITheme     string `json:"uiTheme"`
	SMTPEnabled bool   `json:"smtpEnabled"`
	Issuer      string `json:"issuer"`
}

// SettingsGeneralResponse represents the general settings returned by the API
type SettingsGeneralResponse struct {
	AppName                                   string `json:"appName"`
	Issuer                                    string `json:"issuer"`
	SelfRegistrationEnabled                   bool   `json:"selfRegistrationEnabled"`
	SelfRegistrationRequiresEmailVerification bool   `json:"selfRegistrationRequiresEmailVerification"`
	DynamicClientRegistrationEnabled          bool   `json:"dynamicClientRegistrationEnabled"`
	PasswordPolicy                            string `json:"passwordPolicy"`
	PKCERequired                              bool   `json:"pkceRequired"`
	// ImplicitFlowEnabled indicates whether implicit flow is enabled server-wide
	// SECURITY NOTE: Implicit flow is deprecated in OAuth 2.1
	ImplicitFlowEnabled bool `json:"implicitFlowEnabled"`
	// ResourceOwnerPasswordCredentialsEnabled indicates whether ROPC is enabled server-wide
	// RFC 6749 Section 4.3
	// SECURITY NOTE: ROPC is deprecated in OAuth 2.1 due to credential exposure risks
	ResourceOwnerPasswordCredentialsEnabled bool `json:"resourceOwnerPasswordCredentialsEnabled"`
}

// UpdateSettingsGeneralRequest contains the general settings fields
// that can be updated via the admin API.
type UpdateSettingsGeneralRequest struct {
	AppName                                   string `json:"appName"`
	Issuer                                    string `json:"issuer"`
	SelfRegistrationEnabled                   bool   `json:"selfRegistrationEnabled"`
	SelfRegistrationRequiresEmailVerification bool   `json:"selfRegistrationRequiresEmailVerification"`
	DynamicClientRegistrationEnabled          bool   `json:"dynamicClientRegistrationEnabled"`
	PasswordPolicy                            string `json:"passwordPolicy"`
	PKCERequired                              bool   `json:"pkceRequired"`
	// ImplicitFlowEnabled: when true, allows implicit flow (response_type=token, id_token, id_token token)
	// SECURITY NOTE: Implicit flow is deprecated in OAuth 2.1
	ImplicitFlowEnabled bool `json:"implicitFlowEnabled"`
	// ResourceOwnerPasswordCredentialsEnabled: when true, allows grant_type=password at token endpoint
	// RFC 6749 Section 4.3
	// SECURITY NOTE: ROPC is deprecated in OAuth 2.1 due to credential exposure risks
	ResourceOwnerPasswordCredentialsEnabled bool `json:"resourceOwnerPasswordCredentialsEnabled"`
}

// SettingsEmailResponse represents the email/SMTP settings returned by the API
type SettingsEmailResponse struct {
	SMTPEnabled     bool   `json:"smtpEnabled"`
	SMTPHost        string `json:"smtpHost"`
	SMTPPort        int    `json:"smtpPort"`
	SMTPUsername    string `json:"smtpUsername"`
	SMTPEncryption  string `json:"smtpEncryption"`
	SMTPFromName    string `json:"smtpFromName"`
	SMTPFromEmail   string `json:"smtpFromEmail"`
	HasSMTPPassword bool   `json:"hasSmtpPassword"`
}

// UpdateSettingsEmailRequest contains SMTP/email settings fields for update
type UpdateSettingsEmailRequest struct {
	SMTPEnabled    bool   `json:"smtpEnabled"`
	SMTPHost       string `json:"smtpHost"`
	SMTPPort       int    `json:"smtpPort"`
	SMTPUsername   string `json:"smtpUsername"`
	SMTPPassword   string `json:"smtpPassword"`
	SMTPEncryption string `json:"smtpEncryption"`
	SMTPFromName   string `json:"smtpFromName"`
	SMTPFromEmail  string `json:"smtpFromEmail"`
}

// SendTestEmailRequest is used by the admin API to trigger a test email
type SendTestEmailRequest struct {
	To string `json:"to"`
}

// SettingsSessionsResponse represents the session settings returned by the API
type SettingsSessionsResponse struct {
	UserSessionIdleTimeoutInSeconds int `json:"userSessionIdleTimeoutInSeconds"`
	UserSessionMaxLifetimeInSeconds int `json:"userSessionMaxLifetimeInSeconds"`
}

// UpdateSettingsSessionsRequest contains session-related settings fields for update
type UpdateSettingsSessionsRequest struct {
	UserSessionIdleTimeoutInSeconds int `json:"userSessionIdleTimeoutInSeconds"`
	UserSessionMaxLifetimeInSeconds int `json:"userSessionMaxLifetimeInSeconds"`
}

// SettingsTokensResponse represents the token settings returned by the API
type SettingsTokensResponse struct {
	TokenExpirationInSeconds                int  `json:"tokenExpirationInSeconds"`
	RefreshTokenOfflineIdleTimeoutInSeconds int  `json:"refreshTokenOfflineIdleTimeoutInSeconds"`
	RefreshTokenOfflineMaxLifetimeInSeconds int  `json:"refreshTokenOfflineMaxLifetimeInSeconds"`
	IncludeOpenIDConnectClaimsInAccessToken bool `json:"includeOpenIDConnectClaimsInAccessToken"`
	IncludeOpenIDConnectClaimsInIdToken     bool `json:"includeOpenIDConnectClaimsInIdToken"`
}

// UpdateSettingsTokensRequest contains token-related global settings fields for update
type UpdateSettingsTokensRequest struct {
	TokenExpirationInSeconds                int  `json:"tokenExpirationInSeconds"`
	RefreshTokenOfflineIdleTimeoutInSeconds int  `json:"refreshTokenOfflineIdleTimeoutInSeconds"`
	RefreshTokenOfflineMaxLifetimeInSeconds int  `json:"refreshTokenOfflineMaxLifetimeInSeconds"`
	IncludeOpenIDConnectClaimsInAccessToken bool `json:"includeOpenIDConnectClaimsInAccessToken"`
	IncludeOpenIDConnectClaimsInIdToken     bool `json:"includeOpenIDConnectClaimsInIdToken"`
}

// SettingsUIThemeResponse represents the UI theme settings returned by the API
type SettingsUIThemeResponse struct {
	UITheme         string   `json:"uiTheme"`
	AvailableThemes []string `json:"availableThemes"`
}

// UpdateSettingsUIThemeRequest contains the UI theme setting field for update
// Empty string means default theme.
type UpdateSettingsUIThemeRequest struct {
	UITheme string `json:"uiTheme"`
}

// SettingsAuditLogsResponse represents the audit log settings returned by the API
type SettingsAuditLogsResponse struct {
	AuditLogsInConsoleEnabled  bool `json:"auditLogsInConsoleEnabled"`
	AuditLogsInDatabaseEnabled bool `json:"auditLogsInDatabaseEnabled"`
	AuditLogRetentionDays      int  `json:"auditLogRetentionDays"`
}

// UpdateSettingsAuditLogsRequest contains audit log settings fields for update
type UpdateSettingsAuditLogsRequest struct {
	AuditLogsInConsoleEnabled  bool `json:"auditLogsInConsoleEnabled"`
	AuditLogsInDatabaseEnabled bool `json:"auditLogsInDatabaseEnabled"`
	AuditLogRetentionDays      int  `json:"auditLogRetentionDays"`
}

// SettingsSigningKeyResponse represents a public view of a signing key
// exposed by the admin API. Private key material is never exposed.
type SettingsSigningKeyResponse struct {
	Id               int64      `json:"id"`
	CreatedAt        *time.Time `json:"createdAt"`
	State            string     `json:"state"`
	KeyIdentifier    string     `json:"keyIdentifier"`
	Type             string     `json:"type"`
	Algorithm        string     `json:"algorithm"`
	PublicKeyASN1DER string     `json:"publicKeyASN1DER"`
	PublicKeyPEM     string     `json:"publicKeyPEM"`
	PublicKeyJWK     string     `json:"publicKeyJWK"`
}

// GetSettingsKeysResponse wraps the list of signing keys
// for the admin settings keys endpoint.
type GetSettingsKeysResponse struct {
	Keys []SettingsSigningKeyResponse `json:"keys"`
}
