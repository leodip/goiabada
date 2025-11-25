package api

type UpdateUserEnabledRequest struct {
    Enabled bool `json:"enabled"`
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
}

type CreateUserAdminRequest struct {
	Email           string `json:"email"`
	EmailVerified   bool   `json:"emailVerified"`
	GivenName       string `json:"givenName"`
	MiddleName      string `json:"middleName"`
	FamilyName      string `json:"familyName"`
	SetPasswordType string `json:"setPasswordType"`    // "now" or "email"
	Password        string `json:"password,omitempty"` // if "now"
}

type UpdateUserProfileRequest struct {
	Username            string `json:"username"`
	GivenName           string `json:"givenName"`
	MiddleName          string `json:"middleName"`
	FamilyName          string `json:"familyName"`
	Nickname            string `json:"nickname"`
	Website             string `json:"website"`
	Gender              string `json:"gender"`
	DateOfBirth         string `json:"dateOfBirth"`
	ZoneInfoCountryName string `json:"zoneInfoCountryName"`
	ZoneInfo            string `json:"zoneInfo"`
	Locale              string `json:"locale"`
}

type UpdateUserAddressRequest struct {
	AddressLine1      string `json:"addressLine1"`
	AddressLine2      string `json:"addressLine2"`
	AddressLocality   string `json:"addressLocality"`
	AddressRegion     string `json:"addressRegion"`
	AddressPostalCode string `json:"addressPostalCode"`
	AddressCountry    string `json:"addressCountry"`
}

type CreateUserAttributeRequest struct {
	Key                  string `json:"key"`
	Value                string `json:"value"`
	IncludeInIdToken     bool   `json:"includeInIdToken"`
	IncludeInAccessToken bool   `json:"includeInAccessToken"`
	UserId               int64  `json:"userId"`
}

type UpdateUserAttributeRequest struct {
	Key                  string `json:"key"`
	Value                string `json:"value"`
	IncludeInIdToken     bool   `json:"includeInIdToken"`
	IncludeInAccessToken bool   `json:"includeInAccessToken"`
}

type UpdateUserPasswordRequest struct {
    NewPassword string `json:"newPassword"`
}

// UpdateAccountPasswordRequest is used by the account (self-service) API to
// change the currently authenticated user's password. The auth server validates
// the current password and the new password against the configured policy.
type UpdateAccountPasswordRequest struct {
    CurrentPassword string `json:"currentPassword"`
    NewPassword     string `json:"newPassword"`
}

type UpdateUserOTPRequest struct {
    Enabled bool `json:"enabled"`
}

// UpdateAccountOTPRequest is used by the account (self-service) API to
// enable or disable OTP for the currently authenticated user. The server
// validates the current password and, when enabling, validates the OTP code
// generated from the provided secret.
type UpdateAccountOTPRequest struct {
    Enabled   bool   `json:"enabled"`
    Password  string `json:"password"`
    OtpCode   string `json:"otpCode,omitempty"`
    SecretKey string `json:"secretKey,omitempty"`
}

type UpdateUserEmailRequest struct {
    Email         string `json:"email"`
    EmailVerified bool   `json:"emailVerified"`
}

// UpdateAccountEmailRequest is used by the account (self-service) API to
// update the currently authenticated user's email address.
// Confirmation is handled by the client UI, so only the email is sent.
type UpdateAccountEmailRequest struct {
    Email string `json:"email"`
}

// VerifyAccountEmailRequest is used by the account (self-service) API to
// verify the currently authenticated user's email address using a code
// sent via email.
type VerifyAccountEmailRequest struct {
    VerificationCode string `json:"verificationCode"`
}

type UpdateUserSessionRequest struct {
	Level2AuthConfigHasChanged *bool `json:"level2AuthConfigHasChanged,omitempty"`
}

type UpdateUserGroupsRequest struct {
	GroupIds []int64 `json:"groupIds"`
}

type UpdateUserPermissionsRequest struct {
	PermissionIds []int64 `json:"permissionIds"`
}

type UpdateGroupPermissionsRequest struct {
    PermissionIds []int64 `json:"permissionIds"`
}

// AccountLogoutRequest is used by clients to request a prepared logout operation.
// The auth server will validate the inputs, mint a short-lived id_token_hint and
// return either a form_post instruction set or a redirect URL.
type AccountLogoutRequest struct {
    PostLogoutRedirectUri string `json:"postLogoutRedirectUri"`
    State                 string `json:"state,omitempty"`
    ClientIdentifier      string `json:"clientIdentifier,omitempty"`
    // ResponseMode can be "form_post" (default) or "redirect"
    ResponseMode          string `json:"responseMode,omitempty"`
}

// UpdateResourcePermissionsRequest replaces the set of permission definitions
// for a resource. The auth server validates, sanitizes, applies create/update/delete,
// and audits.
type UpdateResourcePermissionsRequest struct {
    Permissions []ResourcePermissionUpsert `json:"permissions"`
}

// ResourcePermissionUpsert represents a permission to create or update.
// If Id <= 0 or omitted, a new permission is created.
type ResourcePermissionUpsert struct {
    Id                   int64  `json:"id,omitempty"`
    PermissionIdentifier string `json:"permissionIdentifier"`
    Description          string `json:"description"`
}

// UpdateClientPermissionsRequest is used to replace the full set of
// permissions assigned to a client. The auth server validates existence
// of permissions, enforces client constraints, applies add/remove ops,
// and performs auditing.
type UpdateClientPermissionsRequest struct {
    PermissionIds []int64 `json:"permissionIds"`
}

type UpdateUserPhoneRequest struct {
    PhoneCountryUniqueId string `json:"phoneCountryUniqueId"`
    PhoneNumber          string `json:"phoneNumber"`
    PhoneNumberVerified  bool   `json:"phoneNumberVerified"`
}

// UpdateAccountPhoneRequest is used by the account (self-service) API to
// update the currently authenticated user's phone number. The server will
// always set PhoneNumberVerified to false upon change.
type UpdateAccountPhoneRequest struct {
    PhoneCountryUniqueId string `json:"phoneCountryUniqueId"`
    PhoneNumber          string `json:"phoneNumber"`
}

type CreateGroupRequest struct {
    GroupIdentifier      string `json:"groupIdentifier"`
    Description          string `json:"description"`
    IncludeInIdToken     bool   `json:"includeInIdToken"`
    IncludeInAccessToken bool   `json:"includeInAccessToken"`
}

// CreateResourceRequest is used to create a new resource via the admin API.
// Validation (required fields, identifier format, uniqueness, description length)
// is performed by the authserver.
type CreateResourceRequest struct {
    ResourceIdentifier string `json:"resourceIdentifier"`
    Description        string `json:"description"`
}

// UpdateResourceRequest is used to update an existing resource via the admin API.
// Validation (required fields, identifier format, uniqueness, description length)
// is performed by the authserver.
type UpdateResourceRequest struct {
    ResourceIdentifier string `json:"resourceIdentifier"`
    Description        string `json:"description"`
}

type UpdateGroupRequest struct {
	GroupIdentifier      string `json:"groupIdentifier"`
	Description          string `json:"description"`
	IncludeInIdToken     bool   `json:"includeInIdToken"`
	IncludeInAccessToken bool   `json:"includeInAccessToken"`
}

type AddGroupMemberRequest struct {
	UserId int64 `json:"userId"`
}

type CreateGroupAttributeRequest struct {
    Key                  string `json:"key"`
    Value                string `json:"value"`
    IncludeInIdToken     bool   `json:"includeInIdToken"`
    IncludeInAccessToken bool   `json:"includeInAccessToken"`
    GroupId              int64  `json:"groupId"`
}

type UpdateGroupAttributeRequest struct {
    Key                  string `json:"key"`
    Value                string `json:"value"`
    IncludeInIdToken     bool   `json:"includeInIdToken"`
    IncludeInAccessToken bool   `json:"includeInAccessToken"`
}

// ValidateResourcePermissionRequest checks if a permission identifier and
// description are valid according to server rules.
type ValidateResourcePermissionRequest struct {
    PermissionIdentifier string `json:"permissionIdentifier"`
    Description          string `json:"description"`
}

type CreateClientRequest struct {
    ClientIdentifier         string `json:"clientIdentifier"`
    Description              string `json:"description"`
    AuthorizationCodeEnabled bool   `json:"authorizationCodeEnabled"`
    ClientCredentialsEnabled bool   `json:"clientCredentialsEnabled"`
}

type UpdateClientSettingsRequest struct {
    ClientIdentifier string `json:"clientIdentifier"`
    Description      string `json:"description"`
    Enabled          bool   `json:"enabled"`
    ConsentRequired  bool   `json:"consentRequired"`
    DefaultAcrLevel  string `json:"defaultAcrLevel,omitempty"`
}

// UpdateClientAuthenticationRequest is used to change a client's
// public/confidential mode and (for confidential) its client secret.
// Validation and encryption are handled by the auth server.
type UpdateClientAuthenticationRequest struct {
    IsPublic     bool   `json:"isPublic"`
    ClientSecret string `json:"clientSecret,omitempty"`
}

// UpdateClientOAuth2FlowsRequest is used to change which OAuth2 flows
// are enabled for a client. Validation and security are handled by the auth server.
type UpdateClientOAuth2FlowsRequest struct {
    AuthorizationCodeEnabled bool  `json:"authorizationCodeEnabled"`
    ClientCredentialsEnabled bool  `json:"clientCredentialsEnabled"`
    // PKCERequired: nil = use global setting, true = required, false = optional
    PKCERequired *bool `json:"pkceRequired"`
}

// UpdateClientRedirectURIsRequest is used to replace the full set of
// redirect URIs for a client. The auth server validates and applies
// add/remove operations accordingly.
type UpdateClientRedirectURIsRequest struct {
    RedirectURIs []string `json:"redirectURIs"`
}

// UpdateClientWebOriginsRequest is used to replace the full set of
// web origins for a client. The auth server validates and applies
// add/remove operations accordingly.
type UpdateClientWebOriginsRequest struct {
    WebOrigins []string `json:"webOrigins"`
}

// UpdateClientTokensRequest is used to change token-related settings for a client.
// The auth server validates bounds and business rules, persists the changes,
// and performs auditing.
type UpdateClientTokensRequest struct {
    TokenExpirationInSeconds                int    `json:"tokenExpirationInSeconds"`
    RefreshTokenOfflineIdleTimeoutInSeconds int    `json:"refreshTokenOfflineIdleTimeoutInSeconds"`
    RefreshTokenOfflineMaxLifetimeInSeconds int    `json:"refreshTokenOfflineMaxLifetimeInSeconds"`
    IncludeOpenIDConnectClaimsInAccessToken string `json:"includeOpenIDConnectClaimsInAccessToken"`
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

// UpdateSettingsSessionsRequest contains session-related settings fields for update
type UpdateSettingsSessionsRequest struct {
    UserSessionIdleTimeoutInSeconds int `json:"userSessionIdleTimeoutInSeconds"`
    UserSessionMaxLifetimeInSeconds int `json:"userSessionMaxLifetimeInSeconds"`
}

// UpdateSettingsTokensRequest contains token-related global settings fields for update
type UpdateSettingsTokensRequest struct {
    TokenExpirationInSeconds                int  `json:"tokenExpirationInSeconds"`
    RefreshTokenOfflineIdleTimeoutInSeconds int  `json:"refreshTokenOfflineIdleTimeoutInSeconds"`
    RefreshTokenOfflineMaxLifetimeInSeconds int  `json:"refreshTokenOfflineMaxLifetimeInSeconds"`
    IncludeOpenIDConnectClaimsInAccessToken bool `json:"includeOpenIDConnectClaimsInAccessToken"`
}

// UpdateSettingsUIThemeRequest contains the UI theme setting field for update
// Empty string means default theme.
type UpdateSettingsUIThemeRequest struct {
    UITheme string `json:"uiTheme"`
}

// DynamicClientRegistrationRequest represents RFC 7591 §3.1 client registration request
type DynamicClientRegistrationRequest struct {
	// OAuth 2.0 core metadata (RFC 7591 §2)
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"` // "none", "client_secret_basic", "client_secret_post"
	GrantTypes              []string `json:"grant_types,omitempty"`                // ["authorization_code", "client_credentials", "refresh_token"]

	// Human-readable metadata (RFC 7591 §2)
	ClientName string `json:"client_name,omitempty"`

	// All other fields ignored per RFC 7591 §2:
	// "The authorization server MUST ignore any client metadata
	//  sent by the client that it does not understand"
}
