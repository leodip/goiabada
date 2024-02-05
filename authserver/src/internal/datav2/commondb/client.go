package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/pkg/errors"
)

func ClientSetColsAndValues(insertBuilder *sqlbuilder.InsertBuilder, client *entitiesv2.Client) *sqlbuilder.InsertBuilder {
	insertBuilder.InsertInto("clients")
	insertBuilder.Cols(
		"created_at",
		"updated_at",
		"client_identifier",
		"client_secret_encrypted",
		"description",
		"enabled",
		"consent_required",
		"is_public",
		"authorization_code_enabled",
		"client_credentials_enabled",
		"token_expiration_in_seconds",
		"refresh_token_offline_idle_timeout_in_seconds",
		"refresh_token_offline_max_lifetime_in_seconds",
		"include_open_id_connect_claims_in_access_token",
		"default_acr_level",
	)

	now := time.Now().UTC()
	insertBuilder.Values(
		now,
		now,
		client.ClientIdentifier,
		client.ClientSecretEncrypted,
		client.Description,
		client.Enabled,
		client.ConsentRequired,
		client.IsPublic,
		client.AuthorizationCodeEnabled,
		client.ClientCredentialsEnabled,
		client.TokenExpirationInSeconds,
		client.RefreshTokenOfflineIdleTimeoutInSeconds,
		client.RefreshTokenOfflineMaxLifetimeInSeconds,
		client.IncludeOpenIDConnectClaimsInAccessToken,
		client.DefaultAcrLevel,
	)

	return insertBuilder
}

func ClientScan(rows *sql.Rows) (*entitiesv2.Client, error) {
	var (
		id                                             int64
		created_at                                     time.Time
		updated_at                                     time.Time
		client_identifier                              string
		client_secret_encrypted                        []byte
		description                                    string
		enabled                                        bool
		consent_required                               bool
		is_public                                      bool
		authorization_code_enabled                     bool
		client_credentials_enabled                     bool
		token_expiration_in_seconds                    int
		refresh_token_offline_idle_timeout_in_seconds  int
		refresh_token_offline_max_lifetime_in_seconds  int
		include_open_id_connect_claims_in_access_token string
		default_acr_level                              enums.AcrLevel
	)

	err := rows.Scan(
		&id,
		&created_at,
		&updated_at,
		&client_identifier,
		&client_secret_encrypted,
		&description,
		&enabled,
		&consent_required,
		&is_public,
		&authorization_code_enabled,
		&client_credentials_enabled,
		&token_expiration_in_seconds,
		&refresh_token_offline_idle_timeout_in_seconds,
		&refresh_token_offline_max_lifetime_in_seconds,
		&include_open_id_connect_claims_in_access_token,
		&default_acr_level,
	)
	if err != nil {
		return nil, errors.Wrap(err, "unable to scan client")
	}

	client := &entitiesv2.Client{
		Id:                                      id,
		CreatedAt:                               created_at,
		UpdatedAt:                               updated_at,
		ClientIdentifier:                        client_identifier,
		ClientSecretEncrypted:                   client_secret_encrypted,
		Description:                             description,
		Enabled:                                 enabled,
		ConsentRequired:                         consent_required,
		IsPublic:                                is_public,
		AuthorizationCodeEnabled:                authorization_code_enabled,
		ClientCredentialsEnabled:                client_credentials_enabled,
		TokenExpirationInSeconds:                token_expiration_in_seconds,
		RefreshTokenOfflineIdleTimeoutInSeconds: refresh_token_offline_idle_timeout_in_seconds,
		RefreshTokenOfflineMaxLifetimeInSeconds: refresh_token_offline_max_lifetime_in_seconds,
		IncludeOpenIDConnectClaimsInAccessToken: include_open_id_connect_claims_in_access_token,
		DefaultAcrLevel:                         default_acr_level,
	}

	return client, nil
}
