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
	AuthorizationCodeEnabled                bool           `db:"authorization_code_enabled"`
	ClientCredentialsEnabled                bool           `db:"client_credentials_enabled"`
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
