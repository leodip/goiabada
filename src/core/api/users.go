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
