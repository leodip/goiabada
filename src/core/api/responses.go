package api

import (
	"time"
)

type UserResponse struct {
	Id                            int64      `json:"id"`
	CreatedAt                     *time.Time `json:"createdAt"`
	UpdatedAt                     *time.Time `json:"updatedAt"`
	Enabled                       bool       `json:"enabled"`
	Subject                       string     `json:"subject"`
	Username                      string     `json:"username"`
	GivenName                     string     `json:"givenName"`
	MiddleName                    string     `json:"middleName"`
	FamilyName                    string     `json:"familyName"`
	Nickname                      string     `json:"nickname"`
	Website                       string     `json:"website"`
	Gender                        string     `json:"gender"`
	Email                         string     `json:"email"`
	EmailVerified                 bool       `json:"emailVerified"`
	ZoneInfoCountryName           string     `json:"zoneInfoCountryName"`
	ZoneInfo                      string     `json:"zoneInfo"`
	Locale                        string     `json:"locale"`
	BirthDate                     *time.Time `json:"birthDate"`
	PhoneNumberCountryUniqueId    string     `json:"phoneNumberCountryUniqueId"`
	PhoneNumberCountryCallingCode string     `json:"phoneNumberCountryCallingCode"`
	PhoneNumber                   string     `json:"phoneNumber"`
	PhoneNumberVerified           bool       `json:"phoneNumberVerified"`
	AddressLine1                  string     `json:"addressLine1"`
	AddressLine2                  string     `json:"addressLine2"`
	AddressLocality               string     `json:"addressLocality"`
	AddressRegion                 string     `json:"addressRegion"`
	AddressPostalCode             string     `json:"addressPostalCode"`
	AddressCountry                string     `json:"addressCountry"`
	OTPEnabled                    bool       `json:"otpEnabled"`
}

type UserAttributeResponse struct {
	Id                   int64      `json:"id"`
	CreatedAt            *time.Time `json:"createdAt"`
	UpdatedAt            *time.Time `json:"updatedAt"`
	Key                  string     `json:"key"`
	Value                string     `json:"value"`
	IncludeInIdToken     bool       `json:"includeInIdToken"`
	IncludeInAccessToken bool       `json:"includeInAccessToken"`
	UserId               int64      `json:"userId"`
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

// SettingsSessionsResponse represents the session settings returned by the API
type SettingsSessionsResponse struct {
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

// SettingsUIThemeResponse represents the UI theme settings returned by the API
type SettingsUIThemeResponse struct {
	UITheme         string   `json:"uiTheme"`
	AvailableThemes []string `json:"availableThemes"`
}

// SettingsAuditLogsResponse represents the audit log settings returned by the API
type SettingsAuditLogsResponse struct {
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

type SearchUsersResponse struct {
	Users []UserResponse `json:"users"`
	Total int            `json:"total"`
	Page  int            `json:"page"`
	Size  int            `json:"size"`
	Query string         `json:"query"`
}

type GetUserResponse struct {
	User UserResponse `json:"user"`
}

type CreateUserResponse struct {
	User UserResponse `json:"user"`
}

type UpdateUserResponse struct {
	User UserResponse `json:"user"`
}

// GenerateUserEmailVerificationCodeResponse is returned by the admin API when
// generating a new email verification code for a user.
type GenerateUserEmailVerificationCodeResponse struct {
	VerificationCode          string     `json:"verificationCode"`
	VerificationCodeExpiresAt *time.Time `json:"verificationCodeExpiresAt"`
	UserId                    int64      `json:"userId"`
	Email                     string     `json:"email"`
}

// AccountEmailVerificationSendResponse is returned by the account API when
// requesting that a verification email be sent.
type AccountEmailVerificationSendResponse struct {
	EmailVerificationSent bool   `json:"emailVerificationSent"`
	EmailDestination      string `json:"emailDestination"`
	TooManyRequests       bool   `json:"tooManyRequests"`
	WaitInSeconds         int    `json:"waitInSeconds"`
	EmailVerified         bool   `json:"emailVerified"`
}

type GetUserAttributesResponse struct {
	Attributes []UserAttributeResponse `json:"attributes"`
}

type GetUserAttributeResponse struct {
	Attribute UserAttributeResponse `json:"attribute"`
}

type CreateUserAttributeResponse struct {
	Attribute UserAttributeResponse `json:"attribute"`
}

type UpdateUserAttributeResponse struct {
	Attribute UserAttributeResponse `json:"attribute"`
}

type SuccessResponse struct {
	Success bool `json:"success"`
}

// ErrorResponse is the admin/account API error envelope:
//
//	{
//	  "error_code":        "VALIDATION_ERROR",
//	  "error_args":        {"max": 60},
//	  "error_description": "Please ensure the locality is no longer than 60 characters."
//	}
//
// Field semantics:
//   - error_code: specific stable identifier for the failure (UPPER_SNAKE
//     for legacy codes, dotted lowercase for catalog-keyed localized codes).
//   - error_args: parameters to substitute into the localized message
//     when the consumer renders error_code via the i18n catalog.
//   - error_description: rendered English message — for non-localizing
//     consumers (logs, curl, scripts) and as a debugging aid.
//
// Consumers route by HTTP status code (4xx vs 5xx), not by an in-body
// category string.
//
// Protocol endpoints (/auth/token, /auth/authorize, /connect/register, /userinfo)
// keep their RFC-defined error envelopes and do NOT use this struct.
type ErrorResponse struct {
	ErrorCode        string         `json:"error_code,omitempty"`
	ErrorArgs        map[string]any `json:"error_args,omitempty"`
	ErrorDescription string         `json:"error_description"`
}

// AccountOTPEnrollmentResponse contains the enrollment QR code image (base64)
// and the secret key to set up TOTP in an authenticator app.
type AccountOTPEnrollmentResponse struct {
	Base64Image string `json:"base64Image"`
	SecretKey   string `json:"secretKey"`
}

type UserSessionResponse struct {
	Id                int64      `json:"id"`
	CreatedAt         *time.Time `json:"createdAt"`
	UpdatedAt         *time.Time `json:"updatedAt"`
	SessionIdentifier string     `json:"sessionIdentifier"`
	Started           *time.Time `json:"started"`
	LastAccessed      *time.Time `json:"lastAccessed"`
	AuthMethods       string     `json:"authMethods"`
	AcrLevel          string     `json:"acrLevel"`
	AuthTime          *time.Time `json:"authTime"`
	IpAddress         string     `json:"ipAddress"`
	DeviceName        string     `json:"deviceName"`
	DeviceType        string     `json:"deviceType"`
	DeviceOS          string     `json:"deviceOS"`
	// UserAgent is the request's User-Agent header as the browser sent it, repaired and
	// bounded at the writer. No omitempty: a session created before the column existed
	// carries an empty string, and that is an answer rather than an absence (#281).
	UserAgent string `json:"userAgent"`
	UserId    int64  `json:"userId"`
}

type GetUserSessionResponse struct {
	Session UserSessionResponse `json:"session"`
}

type UserConsentResponse struct {
	Id                int64      `json:"id"`
	CreatedAt         *time.Time `json:"createdAt"`
	UpdatedAt         *time.Time `json:"updatedAt"`
	ClientId          int64      `json:"clientId"`
	UserId            int64      `json:"userId"`
	Scope             string     `json:"scope"`
	GrantedAt         *time.Time `json:"grantedAt"`
	ClientIdentifier  string     `json:"clientIdentifier"`
	ClientDescription string     `json:"clientDescription"`
}

type GetUserConsentsResponse struct {
	Consents []UserConsentResponse `json:"consents"`
}

type GroupResponse struct {
	Id                   int64      `json:"id"`
	CreatedAt            *time.Time `json:"createdAt"`
	UpdatedAt            *time.Time `json:"updatedAt"`
	GroupIdentifier      string     `json:"groupIdentifier"`
	Description          string     `json:"description"`
	IncludeInIdToken     bool       `json:"includeInIdToken"`
	IncludeInAccessToken bool       `json:"includeInAccessToken"`
	MemberCount          int        `json:"memberCount"`
}

type GetGroupsResponse struct {
	Groups []GroupResponse `json:"groups"`
}

type GetUserGroupsResponse struct {
	User   UserResponse    `json:"user"`
	Groups []GroupResponse `json:"groups"`
}

// GroupWithPermissionResponse embeds group info and indicates whether
// the group has a specific permission (used for annotated group search).
type GroupWithPermissionResponse struct {
	GroupResponse
	HasPermission bool `json:"hasPermission"`
}

// SearchGroupsWithPermissionAnnotationResponse returns paginated groups
// annotated with whether they have a specific permission assigned.
type SearchGroupsWithPermissionAnnotationResponse struct {
	Groups []GroupWithPermissionResponse `json:"groups"`
	Total  int                           `json:"total"`
	Page   int                           `json:"page"`
	Size   int                           `json:"size"`
}

// UserWithPermissionResponse embeds user info and indicates whether
// the user has a specific permission (used for annotated user search).
type UserWithPermissionResponse struct {
	UserResponse
	HasPermission bool `json:"hasPermission"`
}

// SearchUsersWithPermissionAnnotationResponse returns paginated users
// annotated with whether they have a specific permission assigned.
type SearchUsersWithPermissionAnnotationResponse struct {
	Users []UserWithPermissionResponse `json:"users"`
	Total int                          `json:"total"`
	Page  int                          `json:"page"`
	Size  int                          `json:"size"`
	Query string                       `json:"query"`
}

type PermissionResponse struct {
	Id                   int64            `json:"id"`
	PermissionIdentifier string           `json:"permissionIdentifier"`
	Description          string           `json:"description"`
	ResourceId           int64            `json:"resourceId"`
	Resource             ResourceResponse `json:"resource"`
}

type ResourceResponse struct {
	Id                 int64  `json:"id"`
	ResourceIdentifier string `json:"resourceIdentifier"`
	Description        string `json:"description"`
	// IsSystemLevelResource travels because the API enforces it and a consumer has to mirror it:
	// the resource handlers refuse a rename and a delete on a system-level resource, and the admin
	// console disables those controls to match. It is on the wire rather than recomputed by each
	// consumer, the way IsSystemLevelClient already is, because a local copy of the rule can
	// disagree with the server's and offer a control the API then answers 403 to (#350).
	IsSystemLevelResource bool `json:"isSystemLevelResource"`
}

type GetUserPermissionsResponse struct {
	User        UserResponse         `json:"user"`
	Permissions []PermissionResponse `json:"permissions"`
}

type GetGroupPermissionsResponse struct {
	Group       GroupResponse        `json:"group"`
	Permissions []PermissionResponse `json:"permissions"`
}

type GetResourcesResponse struct {
	Resources []ResourceResponse `json:"resources"`
}

type CreateResourceResponse struct {
	Resource ResourceResponse `json:"resource"`
}

// GetResourceResponse returns the details of a single resource
type GetResourceResponse struct {
	Resource ResourceResponse `json:"resource"`
}

// UpdateResourceResponse returns the updated resource
type UpdateResourceResponse struct {
	Resource ResourceResponse `json:"resource"`
}

type GetPermissionsByResourceResponse struct {
	Permissions []PermissionResponse `json:"permissions"`
}

// GetUsersByPermissionResponse returns users that have a given permission
// with pagination metadata.
type GetUsersByPermissionResponse struct {
	Users []UserResponse `json:"users"`
	Total int            `json:"total"`
	Page  int            `json:"page"`
	Size  int            `json:"size"`
}

type PhoneCountryResponse struct {
	UniqueId    string `json:"uniqueId"`
	Alpha2      string `json:"alpha2"`
	Emoji       string `json:"emoji"`
	CallingCode string `json:"callingCode"`
	Name        string `json:"name"`
}

type GetPhoneCountriesResponse struct {
	PhoneCountries []PhoneCountryResponse `json:"phoneCountries"`
}

// UserSessionDetailResponse is a session plus the two things a caller cannot work out for
// itself: the clients it authorized, which is a join, and whether it is the caller's own,
// which needs a claim from a token an API caller may not be able to read (RFC 6749 1.4).
// Everything else a page shows about a session is derived from the embedded timestamps by
// whoever is rendering it.
//
// It carried four pre-rendered strings and a constant true isValid until #373. The strings
// were an English RFC1123 date and a Go duration, computed at the server from instants that
// were already in the same payload, so they were stale before the page drew them and no
// locale could reach them; isValid was a field every producer set to true after skipping
// every session for which it would have been false.
type UserSessionDetailResponse struct {
	UserSessionResponse
	IsCurrent         bool     `json:"isCurrent"`
	ClientIdentifiers []string `json:"clientIdentifiers"`
}

type GetUserSessionsResponse struct {
	Sessions []UserSessionDetailResponse `json:"sessions"`
}

type CreateGroupResponse struct {
	Group GroupResponse `json:"group"`
}

type GetGroupResponse struct {
	Group GroupResponse `json:"group"`
}

type UpdateGroupResponse struct {
	Group GroupResponse `json:"group"`
}

type GetGroupMembersResponse struct {
	Members []UserResponse `json:"members"`
	Total   int            `json:"total"`
	Page    int            `json:"page"`
	Size    int            `json:"size"`
}

type SearchUsersWithGroupAnnotationResponse struct {
	Users []UserWithGroupMembershipResponse `json:"users"`
	Total int                               `json:"total"`
	Page  int                               `json:"page"`
	Size  int                               `json:"size"`
	Query string                            `json:"query"`
}

type UserWithGroupMembershipResponse struct {
	UserResponse
	InGroup bool `json:"inGroup"`
}

type GroupAttributeResponse struct {
	Id                   int64      `json:"id"`
	CreatedAt            *time.Time `json:"createdAt"`
	UpdatedAt            *time.Time `json:"updatedAt"`
	Key                  string     `json:"key"`
	Value                string     `json:"value"`
	IncludeInIdToken     bool       `json:"includeInIdToken"`
	IncludeInAccessToken bool       `json:"includeInAccessToken"`
	GroupId              int64      `json:"groupId"`
}

type GetGroupAttributesResponse struct {
	Attributes []GroupAttributeResponse `json:"attributes"`
}

type GetGroupAttributeResponse struct {
	Attribute GroupAttributeResponse `json:"attribute"`
}

type CreateGroupAttributeResponse struct {
	Attribute GroupAttributeResponse `json:"attribute"`
}

type UpdateGroupAttributeResponse struct {
	Attribute GroupAttributeResponse `json:"attribute"`
}

// RedirectURIResponse is a client's redirect URI as this API publishes it.
//
// It exists because ClientResponse used to carry models.RedirectURI directly. That is a
// persistence row: it declares no json tags, so its keys reached the wire in Go's own spelling
// ("Id", "URI", "ClientId") inside a body whose every other key is lowerCamelCase, and its
// sql.NullTime CreatedAt arrived as {"Time":"0001-01-01T00:00:00Z","Valid":false} where a NULL
// column should read null. No released openapi.yaml has ever described that shape; every published
// contract declares the lowerCamelCase keys below, so a client generated from one was broken on
// exactly this position until it moved here. Adding a field to the persistence row must no longer
// change the wire (#350).
type RedirectURIResponse struct {
	Id        int64      `json:"id"`
	CreatedAt *time.Time `json:"createdAt"`
	URI       string     `json:"uri"`
	ClientId  int64      `json:"clientId"`
}

// WebOriginResponse is a client's allowed web origin as this API publishes it, and is here for the
// same reason as RedirectURIResponse above (#350).
type WebOriginResponse struct {
	Id        int64      `json:"id"`
	CreatedAt *time.Time `json:"createdAt"`
	Origin    string     `json:"origin"`
	ClientId  int64      `json:"clientId"`
}

type ClientResponse struct {
	Id               int64      `json:"id"`
	CreatedAt        *time.Time `json:"createdAt"`
	UpdatedAt        *time.Time `json:"updatedAt"`
	ClientIdentifier string     `json:"clientIdentifier"`
	ClientSecret     string     `json:"clientSecret,omitempty"` // Only in detail API
	Description      string     `json:"description"`
	WebsiteURL       string     `json:"websiteUrl"`
	DisplayName      string     `json:"displayName"`
	Enabled          bool       `json:"enabled"`
	ConsentRequired  bool       `json:"consentRequired"`
	// CreatedViaDCR is read-only on purpose. It records that the client registered itself through
	// /connect/register, which is a fact about where the client came from rather than a setting, so
	// ClientUpdateRequest deliberately does not carry it and neither an administrator nor the client
	// itself can clear the marking. The setting an administrator does get is ConsentRequired (#108).
	CreatedViaDCR            bool  `json:"createdViaDcr"`
	ShowLogo                 bool  `json:"showLogo"`
	ShowDisplayName          bool  `json:"showDisplayName"`
	ShowDescription          bool  `json:"showDescription"`
	ShowWebsiteURL           bool  `json:"showWebsiteUrl"`
	IsPublic                 bool  `json:"isPublic"`
	IsSystemLevelClient      bool  `json:"isSystemLevelClient"`
	AuthorizationCodeEnabled bool  `json:"authorizationCodeEnabled"`
	ClientCredentialsEnabled bool  `json:"clientCredentialsEnabled"`
	PKCERequired             *bool `json:"pkceRequired"`
	// ImplicitGrantEnabled: nil = use global setting, true = enabled, false = disabled
	// SECURITY NOTE: Implicit flow is deprecated in OAuth 2.1
	ImplicitGrantEnabled *bool `json:"implicitGrantEnabled"`
	// ResourceOwnerPasswordCredentialsEnabled: nil = use global setting, true = enabled, false = disabled
	// RFC 6749 Section 4.3
	// SECURITY NOTE: ROPC is deprecated in OAuth 2.1 due to credential exposure risks
	ResourceOwnerPasswordCredentialsEnabled *bool                 `json:"resourceOwnerPasswordCredentialsEnabled"`
	TokenExpirationInSeconds                int                   `json:"tokenExpirationInSeconds"`
	RefreshTokenOfflineIdleTimeoutInSeconds int                   `json:"refreshTokenOfflineIdleTimeoutInSeconds"`
	RefreshTokenOfflineMaxLifetimeInSeconds int                   `json:"refreshTokenOfflineMaxLifetimeInSeconds"`
	IncludeOpenIDConnectClaimsInAccessToken string                `json:"includeOpenIDConnectClaimsInAccessToken"`
	IncludeOpenIDConnectClaimsInIdToken     string                `json:"includeOpenIDConnectClaimsInIdToken"`
	DefaultAcrLevel                         string                `json:"defaultAcrLevel"`
	RedirectURIs                            []RedirectURIResponse `json:"redirectURIs"`
	WebOrigins                              []WebOriginResponse   `json:"webOrigins"`
}

// AccountLogoutFormPostResponse instructs the client to POST to the OP's
// end-session endpoint with the given parameters. This avoids placing
// id_token_hint into the URL where it could leak via logs or referrer.
type AccountLogoutFormPostResponse struct {
	Method   string            `json:"method"`   // always "POST"
	Endpoint string            `json:"endpoint"` // e.g., {authserver}/auth/logout
	Params   map[string]string `json:"params"`   // id_token_hint, post_logout_redirect_uri, state
}

// AccountLogoutRedirectResponse provides a ready-to-follow URL for logout.
// This is simpler but exposes the token in the URL.
type AccountLogoutRedirectResponse struct {
	LogoutUrl string `json:"logoutUrl"`
}

type GetClientsResponse struct {
	Clients []ClientResponse `json:"clients"`
}

type GetClientResponse struct {
	Client ClientResponse `json:"client"`
}

type CreateClientResponse struct {
	Client ClientResponse `json:"client"`
}

type UpdateClientResponse struct {
	Client ClientResponse `json:"client"`
}

type GetClientPermissionsResponse struct {
	Client      ClientResponse       `json:"client"`
	Permissions []PermissionResponse `json:"permissions"`
}

// DynamicClientRegistrationResponse represents RFC 7591 §3.2.1 successful registration
type DynamicClientRegistrationResponse struct {
	// REQUIRED (RFC 7591 §3.2.1)
	ClientID string `json:"client_id"`

	// OPTIONAL - only present for confidential clients (RFC 7591 §3.2.1)
	ClientSecret string `json:"client_secret,omitempty"`

	// Timestamps (RFC 7591 §3.2.1)
	ClientIDIssuedAt      int64 `json:"client_id_issued_at"`
	ClientSecretExpiresAt int64 `json:"client_secret_expires_at"` // 0 = never expires

	// Echo back registered metadata (RFC 7591 §3.2.1)
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ClientName              string   `json:"client_name,omitempty"`
}

// DynamicClientRegistrationError represents RFC 7591 §3.2.2 error response
type DynamicClientRegistrationError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// RFC 7591 §3.2.2 error codes
const (
	DCRErrorInvalidRedirectURI    = "invalid_redirect_uri"
	DCRErrorInvalidClientMetadata = "invalid_client_metadata"
)

type AuditLogResponse struct {
	Id         int64  `json:"id"`
	CreatedAt  string `json:"createdAt"`
	AuditEvent string `json:"auditEvent"`
	Details    string `json:"details"`
	// RequestId is the request's id as the application log carries it, empty when the entry
	// was not written on a request (#328).
	RequestId string `json:"requestId"`
}

type GetAuditLogsResponse struct {
	AuditLogs []AuditLogResponse `json:"auditLogs"`
	Total     int                `json:"total"`
	Page      int                `json:"page"`
	Size      int                `json:"size"`
}

// The browser session endpoint's response bodies (#266). See the request types for why
// there is no owner anywhere in this contract.

// SessionLoadResponse is one stored session.
//
// lastAccessed is here because the caller decides whether to touch, and it makes that
// decision against a threshold rather than on every read: without the timestamp the hop
// would have to happen twice or the laziness would have to move to the server, and it
// belongs with the store that owns the threshold.
type SessionLoadResponse struct {
	Data         string    `json:"data"`
	LastAccessed time.Time `json:"lastAccessed"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

// SessionWriteResponse is the deadline the auth server chose for a session it just
// wrote. The caller sets its cookie's own expiry from it, so the browser never holds a
// handle that outlives what it names.
type SessionWriteResponse struct {
	ExpiresAt time.Time `json:"expiresAt"`
}

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
