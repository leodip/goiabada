package models

import (
	"database/sql"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/enums"
)

type Client struct {
	Id                    int64        `db:"id" fieldtag:"pk"`
	CreatedAt             sql.NullTime `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt             sql.NullTime `db:"updated_at"`
	ClientIdentifier      string       `db:"client_identifier"`
	ClientSecretEncrypted []byte       `db:"client_secret_encrypted"`
	Description           string       `db:"description"`
	WebsiteURL            string       `db:"website_url"`
	DisplayName           string       `db:"display_name"`
	Enabled               bool         `db:"enabled"`
	ConsentRequired       bool         `db:"consent_required"`
	// CreatedViaDCR records that this client registered itself through /connect/register rather
	// than being created by an administrator. It is the enforced form of what the dcr_ identifier
	// prefix only suggests, and it is what the consent screen's unverified marking reads (#108).
	CreatedViaDCR            bool `db:"created_via_dcr"`
	ShowLogo                 bool `db:"show_logo"`
	ShowDisplayName          bool `db:"show_display_name"`
	ShowDescription          bool `db:"show_description"`
	ShowWebsiteURL           bool `db:"show_website_url"`
	IsPublic                 bool `db:"is_public"`
	AuthorizationCodeEnabled bool `db:"authorization_code_enabled"`
	ClientCredentialsEnabled bool `db:"client_credentials_enabled"`
	// PKCERequired overrides global setting if set.
	// nil = use global setting, true = PKCE required, false = PKCE optional
	PKCERequired *bool `db:"pkce_required"`
	// ImplicitGrantEnabled overrides global implicit flow setting if set.
	// SECURITY NOTE: Implicit flow is deprecated in OAuth 2.1.
	// nil = use global setting, true = implicit grant enabled, false = implicit grant disabled
	ImplicitGrantEnabled *bool `db:"implicit_grant_enabled"`
	// ResourceOwnerPasswordCredentialsEnabled overrides global ROPC setting if set.
	// RFC 6749 Section 4.3
	// SECURITY NOTE: ROPC is deprecated in OAuth 2.1 due to credential exposure risks.
	// nil = use global setting, true = enabled, false = disabled
	ResourceOwnerPasswordCredentialsEnabled *bool          `db:"resource_owner_password_credentials_enabled"`
	TokenExpirationInSeconds                int            `db:"token_expiration_in_seconds"`
	RefreshTokenOfflineIdleTimeoutInSeconds int            `db:"refresh_token_offline_idle_timeout_in_seconds"`
	RefreshTokenOfflineMaxLifetimeInSeconds int            `db:"refresh_token_offline_max_lifetime_in_seconds"`
	IncludeOpenIDConnectClaimsInAccessToken string         `db:"include_open_id_connect_claims_in_access_token"`
	IncludeOpenIDConnectClaimsInIdToken     string         `db:"include_open_id_connect_claims_in_id_token"`
	DefaultAcrLevel                         enums.AcrLevel `db:"default_acr_level"`
	Permissions                             []Permission   `db:"-"`
	RedirectURIs                            []RedirectURI  `db:"-"`
	WebOrigins                              []WebOrigin    `db:"-"`
}

func (c *Client) IsSystemLevelClient() bool {
	systemLevelClients := []string{
		constants.AdminConsoleClientIdentifier,
	}
	for _, systemLevelClient := range systemLevelClients {
		if c.ClientIdentifier == systemLevelClient {
			return true
		}
	}
	return false
}

// IsPKCERequired returns whether PKCE is required for this client.
// A public client always requires PKCE, whatever the client-level override and the global
// setting say. Otherwise the client-level override, when set, takes precedence over the
// global setting.
//
// The public arm comes first because a public client presents no credential at the token
// endpoint, so the code's binding to a verifier is the only thing tying the redemption back
// to the ceremony that produced it. Without it an attacker who strips code_challenge from the
// authorization request gets a code bound to nothing and can spend it against a client that
// authenticates with nothing (RFC 9700 section 4.8.1). Removing this line reopens that, and it
// reopens it silently: the two ways in are an explicit false override on a public client and a
// nil column while the global setting is off, which is what /connect/register creates (#245).
func (c *Client) IsPKCERequired(globalPKCERequired bool) bool {
	if c.IsPublic {
		return true
	}
	if c.PKCERequired != nil {
		return *c.PKCERequired
	}
	return globalPKCERequired
}

// IsImplicitGrantEnabled returns whether implicit grant is enabled for this client,
// taking into account both the client-level override and global settings.
// If the client has an explicit setting, it takes precedence over the global setting.
// SECURITY NOTE: Implicit flow is deprecated in OAuth 2.1.
func (c *Client) IsImplicitGrantEnabled(globalImplicitFlowEnabled bool) bool {
	if c.ImplicitGrantEnabled != nil {
		return *c.ImplicitGrantEnabled
	}
	return globalImplicitFlowEnabled
}

// IsResourceOwnerPasswordCredentialsEnabled returns whether ROPC grant is enabled for this client,
// taking into account both the client-level override and global settings.
// If the client has an explicit setting, it takes precedence over the global setting.
// RFC 6749 Section 4.3
// SECURITY NOTE: ROPC is deprecated in OAuth 2.1 due to credential exposure risks.
func (c *Client) IsResourceOwnerPasswordCredentialsEnabled(globalROPCEnabled bool) bool {
	if c.ResourceOwnerPasswordCredentialsEnabled != nil {
		return *c.ResourceOwnerPasswordCredentialsEnabled
	}
	return globalROPCEnabled
}
