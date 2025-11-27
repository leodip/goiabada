package models

import (
	"database/sql"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/enums"
)

type Client struct {
	Id                                      int64          `db:"id" fieldtag:"pk"`
	CreatedAt                               sql.NullTime   `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt                               sql.NullTime   `db:"updated_at"`
	ClientIdentifier                        string         `db:"client_identifier"`
	ClientSecretEncrypted                   []byte         `db:"client_secret_encrypted"`
	Description                             string         `db:"description"`
	Enabled                                 bool           `db:"enabled"`
	ConsentRequired                         bool           `db:"consent_required"`
	IsPublic                                bool           `db:"is_public"`
	AuthorizationCodeEnabled bool `db:"authorization_code_enabled"`
	ClientCredentialsEnabled bool `db:"client_credentials_enabled"`
	// PKCERequired overrides global setting if set.
	// nil = use global setting, true = PKCE required, false = PKCE optional
	PKCERequired *bool `db:"pkce_required"`
	// ImplicitGrantEnabled overrides global implicit flow setting if set.
	// SECURITY NOTE: Implicit flow is deprecated in OAuth 2.1.
	// nil = use global setting, true = implicit grant enabled, false = implicit grant disabled
	ImplicitGrantEnabled *bool `db:"implicit_grant_enabled"`
	TokenExpirationInSeconds                int            `db:"token_expiration_in_seconds"`
	RefreshTokenOfflineIdleTimeoutInSeconds int            `db:"refresh_token_offline_idle_timeout_in_seconds"`
	RefreshTokenOfflineMaxLifetimeInSeconds int            `db:"refresh_token_offline_max_lifetime_in_seconds"`
	IncludeOpenIDConnectClaimsInAccessToken string         `db:"include_open_id_connect_claims_in_access_token"`
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

// IsPKCERequired returns whether PKCE is required for this client,
// taking into account both the client-level override and global settings.
// If the client has an explicit setting, it takes precedence over the global setting.
func (c *Client) IsPKCERequired(globalPKCERequired bool) bool {
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
