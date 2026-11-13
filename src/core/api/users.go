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
	PageLanguage                  string     `json:"pageLanguage"`
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
	// OTPAuthenticatorDisabled is true while the user's authenticator is disabled after
	// 100 wrong codes in a row: OTPEnabled still reads true, every code is refused, and
	// turning OTP off is the way back, after which the user sets up a new one (#489).
	OTPAuthenticatorDisabled bool `json:"otpAuthenticatorDisabled"`
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

type CreateUserResponse struct {
	User UserResponse `json:"user"`
	// SetupEmailSent is present exactly when the server set out to send a setup email, which is
	// when email is enabled and the request's setPasswordType is "email": true when it was sent,
	// false when the send failed. It is absent otherwise, so false never means "not asked" (#725).
	SetupEmailSent *bool `json:"setupEmailSent,omitempty"`
}

type UpdateUserEnabledRequest struct {
	Enabled bool `json:"enabled"`
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
	// PageLanguage is optional, unlike every other field here: nil leaves the stored page language
	// as it is, so a client written before the field existed does not reset its users to
	// Automatic; "" sets Automatic; any other value must be the tag of one of the auth server's
	// loaded catalogs (#631 decision 8).
	PageLanguage *string `json:"pageLanguage,omitempty"`
}

type UpdateUserAddressRequest struct {
	AddressLine1      string `json:"addressLine1"`
	AddressLine2      string `json:"addressLine2"`
	AddressLocality   string `json:"addressLocality"`
	AddressRegion     string `json:"addressRegion"`
	AddressPostalCode string `json:"addressPostalCode"`
	AddressCountry    string `json:"addressCountry"`
}

type UpdateUserPhoneRequest struct {
	PhoneCountryUniqueId string `json:"phoneCountryUniqueId"`
	PhoneNumber          string `json:"phoneNumber"`
	PhoneNumberVerified  bool   `json:"phoneNumberVerified"`
}

type UpdateUserEmailRequest struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"emailVerified"`
}

type UpdateUserPasswordRequest struct {
	NewPassword string `json:"newPassword"`
}

type UpdateUserOTPRequest struct {
	Enabled bool `json:"enabled"`
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

type GetUserAttributesResponse struct {
	Attributes []UserAttributeResponse `json:"attributes"`
}

type GetUserAttributeResponse struct {
	Attribute UserAttributeResponse `json:"attribute"`
}

type CreateUserAttributeRequest struct {
	Key                  string `json:"key"`
	Value                string `json:"value"`
	IncludeInIdToken     bool   `json:"includeInIdToken"`
	IncludeInAccessToken bool   `json:"includeInAccessToken"`
	UserId               int64  `json:"userId"`
}

type CreateUserAttributeResponse struct {
	Attribute UserAttributeResponse `json:"attribute"`
}

type UpdateUserAttributeRequest struct {
	Key                  string `json:"key"`
	Value                string `json:"value"`
	IncludeInIdToken     bool   `json:"includeInIdToken"`
	IncludeInAccessToken bool   `json:"includeInAccessToken"`
}

type UpdateUserAttributeResponse struct {
	Attribute UserAttributeResponse `json:"attribute"`
}

// UpdateUserGroupsRequest replaces the whole set of groups a user belongs to.
// ExpectedGroupIds is the set as the caller last read it, as ExpectedPermissionIds is on
// UpdateUserPermissionsRequest (#428).
type UpdateUserGroupsRequest struct {
	GroupIds         []int64 `json:"groupIds"`
	ExpectedGroupIds []int64 `json:"expectedGroupIds"`
}

type GetUserGroupsResponse struct {
	User   UserResponse    `json:"user"`
	Groups []GroupResponse `json:"groups"`
}

// UpdateUserPermissionsRequest replaces the whole set of permissions granted to a user.
//
// ExpectedPermissionIds is the set as the caller last read it, required and compared as
// ExpectedRedirectURIs is: absent or null is refused, [] means the caller read no grants, and a
// stored set that differs answers 409 CONCURRENT_UPDATE (#428).
type UpdateUserPermissionsRequest struct {
	PermissionIds         []int64 `json:"permissionIds"`
	ExpectedPermissionIds []int64 `json:"expectedPermissionIds"`
}

type GetUserPermissionsResponse struct {
	User        UserResponse         `json:"user"`
	Permissions []PermissionResponse `json:"permissions"`
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

// UserConsentResponse is a consent and the client it was given to. ClientName and
// ClientNameUnverified are the name the user was shown for that client on the consent screen and
// whether it is the client's own claim about itself, so a page listing a user's consents names
// each client as the user saw it. ClientDescription is the stored description on the admin
// endpoint; the account endpoint, which answers the user, carries it only as the consent screen
// shows it: when an administrator chose to show it, and never beside an unverified name, which is
// then the description already.
type UserConsentResponse struct {
	Id                   int64      `json:"id"`
	CreatedAt            *time.Time `json:"createdAt"`
	UpdatedAt            *time.Time `json:"updatedAt"`
	ClientId             int64      `json:"clientId"`
	UserId               int64      `json:"userId"`
	Scope                string     `json:"scope"`
	GrantedAt            *time.Time `json:"grantedAt"`
	ClientIdentifier     string     `json:"clientIdentifier"`
	ClientName           string     `json:"clientName"`
	ClientNameUnverified bool       `json:"clientNameUnverified"`
	ClientDescription    string     `json:"clientDescription"`
}

type GetUserConsentsResponse struct {
	Consents []UserConsentResponse `json:"consents"`
}

// UserExportResponse is what the auth server holds about one user, in one document, as GET
// /api/v1/admin/users/{id}/export answers it: what an operator hands a person who asked for their
// data (#781). It leaves out every attribute, the user's own or a group's, that no app receives,
// with both include-in-token flags off (#782 decision 8). Each part is the entry the matching admin API read answers, inside this versioned
// wrapper, and every list is in id order, oldest first, so two exports of one person compare line
// by line (decision 3). FormatVersion goes up only for a change that breaks a reader; a field added
// to a reused entry appears here too, and is additive.
type UserExportResponse struct {
	FormatVersion int       `json:"formatVersion"`
	ExportedAt    time.Time `json:"exportedAt"`
	// Issuer is the auth server's issuer, since a subject is a stable identifier only together
	// with its issuer (OpenID Connect Core 1.0 section 5.7).
	Issuer                   string                            `json:"issuer"`
	Identifiers              UserExportIdentifiersResponse     `json:"identifiers"`
	User                     UserResponse                      `json:"user"`
	Attributes               []UserAttributeResponse           `json:"attributes"`
	Groups                   []UserExportGroupResponse         `json:"groups"`
	Permissions              []PermissionResponse              `json:"permissions"`
	Consents                 []UserConsentResponse             `json:"consents"`
	Sessions                 []UserSessionDetailResponse       `json:"sessions"`
	RefreshTokens            []UserExportRefreshTokenResponse  `json:"refreshTokens"`
	LegalDocumentAcceptances []LegalDocumentAcceptanceResponse `json:"legalDocumentAcceptances"`
	ProfilePicture           *UserExportProfilePictureResponse `json:"profilePicture"`
	AuditEvents              []UserExportAuditEventResponse    `json:"auditEvents"`
}

// UserExportAuditEventResponse is one audit event about the user or made by them in the user
// export: the audit log's entry, as GET /api/v1/admin/audit-logs answers it, plus
// ActedByAdministrator (#781 decision 2). An event another user's token made about the user, an
// administrator's on the admin API, does not name them: ActedByAdministrator is true, LoggedInUserId
// is nil and the details carry no logged_in_user. The other user a sign-in on a shared browser
// ended is not named either: cross_user_session_replaced carries no previous_user_id. An event the
// user made keeps whom it acted on, and a client or the recover command named as the actor stays,
// since neither is a person.
type UserExportAuditEventResponse struct {
	AuditLogResponse
	ActedByAdministrator bool `json:"actedByAdministrator"`
}

// UserExportIdentifiersResponse is what the user is known by, to search older audit rows and the
// logs with: the row id, the subject, the email address, and EmailDigest, the SHA-256 hex digest
// of that address, which is how an audit entry about an address records it.
type UserExportIdentifiersResponse struct {
	Id          int64  `json:"id"`
	Subject     string `json:"subject"`
	Email       string `json:"email"`
	EmailDigest string `json:"emailDigest"`
}

// UserExportGroupResponse is one group the user is a member of, as GET /api/v1/admin/users/{id}/groups
// answers it, with the attributes and permissions the user gets through it, as the group's own
// attribute and permission reads answer them, each list in id order.
type UserExportGroupResponse struct {
	GroupResponse
	Attributes  []GroupAttributeResponse `json:"attributes"`
	Permissions []PermissionResponse     `json:"permissions"`
}

// UserExportProfilePictureResponse is the user's profile picture: its content type and the image
// itself, which JSON carries as standard base64.
type UserExportProfilePictureResponse struct {
	ContentType string `json:"contentType"`
	Data        []byte `json:"data"`
}

// UserExportRefreshTokenResponse is one refresh token the auth server holds for the user in the
// user export, rotated-out and revoked ones included (#781 decision 4). ClientName and
// ClientNameUnverified are the client's name as a consent shows it. MaxLifetime is set on an
// Offline token, SessionIdentifier on a session-bound (Refresh) one. Jti is the id the audit events
// name as refresh_token_jti; the token itself is never stored. Revoked is true when the token's own
// row, its authorization code or its rotation family is marked revoked.
//
// IpAddress, UserAgent and AuthenticatedAt are the sign-in the token came from. A code-flow token
// takes all three from its authorization code. A password-grant token has no code, so its address
// and browser are empty, and its AuthenticatedAt is when the password was checked, which its row
// keeps through every rotation and so can differ from IssuedAt; it is nil only where nothing is
// stored.
type UserExportRefreshTokenResponse struct {
	ClientIdentifier     string     `json:"clientIdentifier"`
	ClientName           string     `json:"clientName"`
	ClientNameUnverified bool       `json:"clientNameUnverified"`
	Scope                string     `json:"scope"`
	Type                 string     `json:"type"`
	IssuedAt             *time.Time `json:"issuedAt"`
	ExpiresAt            *time.Time `json:"expiresAt"`
	MaxLifetime          *time.Time `json:"maxLifetime"`
	SessionIdentifier    string     `json:"sessionIdentifier"`
	Jti                  string     `json:"jti"`
	Revoked              bool       `json:"revoked"`
	IpAddress            string     `json:"ipAddress"`
	UserAgent            string     `json:"userAgent"`
	AuthenticatedAt      *time.Time `json:"authenticatedAt"`
}
