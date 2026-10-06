package api

import (
	"time"
)

// RedirectURIResponse is a client's redirect URI as this API publishes it.
//
// It exists because ClientResponse used to carry record.RedirectURI directly. That is a
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
	Description      string     `json:"description"`
	WebsiteURL       string     `json:"websiteUrl"`
	DisplayName      string     `json:"displayName"`
	Enabled          bool       `json:"enabled"`
	ConsentRequired  bool       `json:"consentRequired"`
	// CreatedViaDCR is read-only on purpose. It records that the client registered itself through
	// /connect/register, which is a fact about where the client came from rather than a setting, so
	// UpdateClientSettingsRequest deliberately does not carry it and neither an administrator nor the
	// client itself can clear the marking. The setting an administrator does get is ConsentRequired
	// (#108).
	CreatedViaDCR bool `json:"createdViaDcr"`
	// AdministrativeScopesAllowed is read-only here too: whether the client may request the
	// administrative authserver scopes on a user's behalf, true for the admin console's client
	// whatever its row holds. Only UpdateClientAdministrativeScopesRequest, on its own route
	// reserved to authserver:manage, changes it; the create request and the settings save carry no
	// such field, so no caller sets or clears it by accident (#499 decisions 4 and 5).
	AdministrativeScopesAllowed bool  `json:"administrativeScopesAllowed"`
	ShowLogo                    bool  `json:"showLogo"`
	ShowDisplayName             bool  `json:"showDisplayName"`
	ShowDescription             bool  `json:"showDescription"`
	ShowWebsiteURL              bool  `json:"showWebsiteUrl"`
	IsPublic                    bool  `json:"isPublic"`
	IsSystemLevelClient         bool  `json:"isSystemLevelClient"`
	AuthorizationCodeEnabled    bool  `json:"authorizationCodeEnabled"`
	ClientCredentialsEnabled    bool  `json:"clientCredentialsEnabled"`
	PKCERequired                *bool `json:"pkceRequired"`
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

type GetClientsResponse struct {
	Clients []ClientResponse `json:"clients"`
}

type GetClientResponse struct {
	Client ClientResponse `json:"client"`
}

// GetClientSecretResponse is GET /clients/{id}/secret's answer, the client's secret decrypted, or
// empty for a client that holds none. It is the one response that carries a client secret:
// ClientResponse carried it on the detail until #402 moved it here, so that admin-read, which
// reaches the detail and not this route, receives no credential (#403).
type GetClientSecretResponse struct {
	ClientSecret string `json:"clientSecret"`
}

type CreateClientRequest struct {
	ClientIdentifier         string `json:"clientIdentifier"`
	Description              string `json:"description"`
	DisplayName              string `json:"displayName"`
	AuthorizationCodeEnabled bool   `json:"authorizationCodeEnabled"`
	ClientCredentialsEnabled bool   `json:"clientCredentialsEnabled"`
}

type CreateClientResponse struct {
	Client ClientResponse `json:"client"`
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
//
// ExpectedWebOrigins is the list as the caller last read it, required as ExpectedRedirectURIs is
// and compared the same way, each value in its canonical form (#428).
type UpdateClientWebOriginsRequest struct {
	WebOrigins         []string `json:"webOrigins"`
	ExpectedWebOrigins []string `json:"expectedWebOrigins"`
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

// UpdateClientAdministrativeScopesRequest switches whether a client may request the administrative
// authserver scopes, on PUT /clients/{id}/administrative-scopes. Allowed is a pointer so that a body
// without it, or with null, is refused rather than read as switching the allowance off (#499
// decision 5).
type UpdateClientAdministrativeScopesRequest struct {
	Allowed *bool `json:"allowed"`
}

type UpdateClientResponse struct {
	Client ClientResponse `json:"client"`
}

// UpdateClientPermissionsRequest is used to replace the full set of
// permissions assigned to a client. The auth server validates existence
// of permissions, enforces client constraints, applies add/remove ops,
// and performs auditing. ExpectedPermissionIds is as on UpdateUserPermissionsRequest (#428).
type UpdateClientPermissionsRequest struct {
	PermissionIds         []int64 `json:"permissionIds"`
	ExpectedPermissionIds []int64 `json:"expectedPermissionIds"`
}

type GetClientPermissionsResponse struct {
	Client      ClientResponse       `json:"client"`
	Permissions []PermissionResponse `json:"permissions"`
}
