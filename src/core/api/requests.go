package api

type UpdateUserEnabledRequest struct {
	Enabled bool `json:"enabled"`
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

type UpdateUserOTPRequest struct {
	Enabled bool `json:"enabled"`
}

type UpdateUserEmailRequest struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"emailVerified"`
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
    AuthorizationCodeEnabled bool `json:"authorizationCodeEnabled"`
    ClientCredentialsEnabled bool `json:"clientCredentialsEnabled"`
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
