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
	// ImplicitFlowEnabled: when true, allows implicit flow (response_type=token, id_token, id_token token)
	// SECURITY NOTE: Implicit flow is deprecated in OAuth 2.1
	ImplicitFlowEnabled bool `json:"implicitFlowEnabled"`
	// ResourceOwnerPasswordCredentialsEnabled: when true, allows grant_type=password at token endpoint
	// RFC 6749 Section 4.3
	// SECURITY NOTE: ROPC is deprecated in OAuth 2.1 due to credential exposure risks
	ResourceOwnerPasswordCredentialsEnabled bool `json:"resourceOwnerPasswordCredentialsEnabled"`
}

type CreateUserAdminRequest struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"emailVerified"`
	GivenName     string `json:"givenName"`
	MiddleName    string `json:"middleName"`
	FamilyName    string `json:"familyName"`
	// SetPasswordType selects how the new account gets a password.
	// SetPasswordTypeEmail sends a setup link; SetPasswordTypeNow requires Password on this
	// request. The property is published as a closed enum and is not required, which in OpenAPI
	// means absent is allowed and a present value must be one of the two: the endpoint refuses
	// any other with 400, and treats absent as SetPasswordTypeNow.
	SetPasswordType string `json:"setPasswordType,omitempty"`
	// Password is required unless a setup email will be sent, which means whenever
	// SetPasswordType is not SetPasswordTypeEmail, and on a deployment with no SMTP configured
	// whatever SetPasswordType says.
	Password string `json:"password,omitempty"`
}

// The two values CreateUserAdminRequest.SetPasswordType may take. Declared here, in the package
// both modules share, for the reason AccountLogoutResponseModeFormPost is: the auth server compares
// against them and the admin console sends them, and two literals in two modules is a disagreement
// nothing in the build can see.
//
// Unlike that one this is a genuinely closed set. Before #350 the handler compared against these
// two and refused nothing else, so a third value took neither branch and created an enabled account
// with no password, no setup code and no setup email — nobody was ever told it existed. The schema
// already promised the refusal; only the handler had to be taught to make it.
const (
	SetPasswordTypeNow   = "now"
	SetPasswordTypeEmail = "email"
)

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
// against the enrollment it issued at GET /api/v1/account/otp/enrollment.
//
// There is deliberately no SecretKey field. The server records the enrollment
// it issued and enrolls that seed and no other, so a caller cannot choose which
// authenticator is installed on its own account. A request that still carries
// secretKey is refused with 400 SECRET_KEY_NOT_ACCEPTED rather than having the
// field ignored, which is a breaking change and was chosen as one: nothing sets
// DisallowUnknownFields, so removing the field alone would have changed which
// secret was enrolled without telling anybody (#247).
type UpdateAccountOTPRequest struct {
	Enabled  bool   `json:"enabled"`
	Password string `json:"password"`
	OtpCode  string `json:"otpCode,omitempty"`
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
	// ResponseMode selects which of the two response shapes the endpoint answers.
	// AccountLogoutResponseModeFormPost asks for AccountLogoutFormPostResponse; every other
	// value, absent and empty included, answers AccountLogoutRedirectResponse.
	ResponseMode string `json:"responseMode,omitempty"`
}

// AccountLogoutResponseModeFormPost is the one value of AccountLogoutRequest.ResponseMode that
// changes what /api/v1/account/logout-request answers. It is declared here, in the package both
// modules share, because the auth server compares against it and the admin console sends it: two
// literals in two modules is a disagreement nothing in the build can see, and a console that
// misspelt it would silently go back to putting the id_token_hint in a top-level URL (#350).
const AccountLogoutResponseModeFormPost = "form_post"

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

type CreateClientRequest struct {
	ClientIdentifier         string `json:"clientIdentifier"`
	Description              string `json:"description"`
	DisplayName              string `json:"displayName"`
	AuthorizationCodeEnabled bool   `json:"authorizationCodeEnabled"`
	ClientCredentialsEnabled bool   `json:"clientCredentialsEnabled"`
}

type UpdateClientSettingsRequest struct {
	ClientIdentifier string `json:"clientIdentifier"`
	Description      string `json:"description"`
	WebsiteURL       string `json:"websiteUrl"`
	DisplayName      string `json:"displayName"`
	Enabled          bool   `json:"enabled"`
	ConsentRequired  bool   `json:"consentRequired"`
	ShowLogo         bool   `json:"showLogo"`
	ShowDisplayName  bool   `json:"showDisplayName"`
	ShowDescription  bool   `json:"showDescription"`
	ShowWebsiteURL   bool   `json:"showWebsiteUrl"`
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
	AuthorizationCodeEnabled bool `json:"authorizationCodeEnabled"`
	ClientCredentialsEnabled bool `json:"clientCredentialsEnabled"`
	// PKCERequired: nil = use global setting, true = required, false = optional
	PKCERequired *bool `json:"pkceRequired"`
	// ImplicitGrantEnabled: nil = use global setting, true = enabled, false = disabled
	// SECURITY NOTE: Implicit flow is deprecated in OAuth 2.1
	ImplicitGrantEnabled *bool `json:"implicitGrantEnabled"`
	// ResourceOwnerPasswordCredentialsEnabled: nil = use global setting, true = enabled, false = disabled
	// RFC 6749 Section 4.3
	// SECURITY NOTE: ROPC is deprecated in OAuth 2.1 due to credential exposure risks
	ResourceOwnerPasswordCredentialsEnabled *bool `json:"resourceOwnerPasswordCredentialsEnabled"`
}

// UpdateClientRedirectURIsRequest is used to replace the full set of
// redirect URIs for a client. The auth server validates and applies
// add/remove operations accordingly.
//
// ExpectedRedirectURIs is the list as the caller last read it, and is required: absent or null
// is refused, [] means the caller read an empty list. The save answers 409 CONCURRENT_UPDATE when
// the stored list differs from it, so a save from an outdated page cannot undo another's change.
// No omitempty, so an empty list still puts the key on the wire (#428).
type UpdateClientRedirectURIsRequest struct {
	RedirectURIs         []string `json:"redirectURIs"`
	ExpectedRedirectURIs []string `json:"expectedRedirectURIs"`
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
	IncludeOpenIDConnectClaimsInIdToken     string `json:"includeOpenIDConnectClaimsInIdToken"`
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
	IncludeOpenIDConnectClaimsInIdToken     bool `json:"includeOpenIDConnectClaimsInIdToken"`
}

// UpdateSettingsUIThemeRequest contains the UI theme setting field for update
// Empty string means default theme.
type UpdateSettingsUIThemeRequest struct {
	UITheme string `json:"uiTheme"`
}

// UpdateSettingsAuditLogsRequest contains audit log settings fields for update
type UpdateSettingsAuditLogsRequest struct {
	AuditLogsInConsoleEnabled  bool `json:"auditLogsInConsoleEnabled"`
	AuditLogsInDatabaseEnabled bool `json:"auditLogsInDatabaseEnabled"`
	AuditLogRetentionDays      int  `json:"auditLogRetentionDays"`
}

// The browser session endpoint's request bodies (#266).
//
// The admin console keeps no database connection, so it reaches its own browser sessions
// through the auth server. These are the wire form of sessionstore.Backend, method for
// method, and there is deliberately no `owner` field anywhere: the handler names the
// owner itself, so no request can reach an auth server session.
//
// The identifier travels in the body and never in the request line. A handle in a path
// lands in the auth server's access log, in every proxy in front of it, and in anything
// that reports slow requests, which is one of the reasons a capability-style endpoint was
// rejected in the first place.
//
// `data` is a string because it is a string in the column: it is the session store's
// sealed envelope, which is base64 text, and it is ciphertext the auth server holds no
// key for.

// SessionLoadRequest names the session to read or remove.
type SessionLoadRequest struct {
	Id string `json:"id"`
}

// SessionWriteRequest carries a session's contents.
//
// `authenticated` is a fact about the container and not about its contents: it says
// whether the calling module considers this session signed in, which is what decides
// which of the two lifetimes applies to it. Only the caller can answer it, because only
// the caller can see inside the blob, and only the auth server can turn it into a
// timestamp, because only the auth server can read the deployment's session settings.
type SessionWriteRequest struct {
	Id            string `json:"id"`
	Data          string `json:"data"`
	Authenticated bool   `json:"authenticated"`
}

// SessionTouchRequest records that a live session was used.
type SessionTouchRequest struct {
	Id            string `json:"id"`
	Authenticated bool   `json:"authenticated"`
}
