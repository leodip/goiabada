package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// clientColumns is the clients table as scanClient reads it.
var clientColumns = columnList{
	sqlite: "id, created_at, updated_at, client_identifier, client_secret_encrypted, description, " +
		"website_url, privacy_policy_url, terms_of_service_url, display_name, enabled, " +
		"consent_required, remember_consent, backchannel_logout_uri, " +
		"backchannel_logout_session_required, dpop_bound_access_tokens, created_via_dcr, " +
		"administrative_scopes_allowed, show_logo, show_display_name, show_description, " +
		"show_website_url, is_public, authorization_code_enabled, client_credentials_enabled, " +
		"pkce_required, implicit_grant_enabled, resource_owner_password_credentials_enabled, " +
		"token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds, " +
		"refresh_token_offline_max_lifetime_in_seconds, " +
		"include_open_id_connect_claims_in_access_token, " +
		"include_open_id_connect_claims_in_id_token, default_acr_level, brand_id, token_endpoint_auth_method",
	mysql: "id, created_at, updated_at, client_identifier, client_secret_encrypted, description, " +
		"website_url, privacy_policy_url, terms_of_service_url, display_name, enabled, " +
		"consent_required, remember_consent, backchannel_logout_uri, " +
		"backchannel_logout_session_required, dpop_bound_access_tokens, created_via_dcr, " +
		"administrative_scopes_allowed, show_logo, show_display_name, show_description, " +
		"show_website_url, is_public, authorization_code_enabled, client_credentials_enabled, " +
		"pkce_required, implicit_grant_enabled, resource_owner_password_credentials_enabled, " +
		"token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds, " +
		"refresh_token_offline_max_lifetime_in_seconds, " +
		"include_open_id_connect_claims_in_access_token, " +
		"include_open_id_connect_claims_in_id_token, default_acr_level, brand_id, token_endpoint_auth_method",
	postgres: "id, created_at, updated_at, client_identifier, client_secret_encrypted, description, " +
		"website_url, privacy_policy_url, terms_of_service_url, display_name, enabled, " +
		"consent_required, remember_consent, backchannel_logout_uri, " +
		"backchannel_logout_session_required, dpop_bound_access_tokens, created_via_dcr, " +
		"administrative_scopes_allowed, show_logo, show_display_name, show_description, " +
		"show_website_url, is_public, authorization_code_enabled, client_credentials_enabled, " +
		"pkce_required, implicit_grant_enabled, resource_owner_password_credentials_enabled, " +
		"token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds, " +
		"refresh_token_offline_max_lifetime_in_seconds, " +
		"include_open_id_connect_claims_in_access_token, " +
		"include_open_id_connect_claims_in_id_token, default_acr_level, brand_id, token_endpoint_auth_method",
	mssql: "id, created_at, updated_at, client_identifier, client_secret_encrypted, description, " +
		"website_url, privacy_policy_url, terms_of_service_url, display_name, enabled, " +
		"consent_required, remember_consent, backchannel_logout_uri, " +
		"backchannel_logout_session_required, dpop_bound_access_tokens, created_via_dcr, " +
		"administrative_scopes_allowed, show_logo, show_display_name, show_description, " +
		"show_website_url, is_public, authorization_code_enabled, client_credentials_enabled, " +
		"pkce_required, implicit_grant_enabled, resource_owner_password_credentials_enabled, " +
		"token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds, " +
		"refresh_token_offline_max_lifetime_in_seconds, " +
		"include_open_id_connect_claims_in_access_token, " +
		"include_open_id_connect_claims_in_id_token, default_acr_level, brand_id, token_endpoint_auth_method",
}

// scanClient reads one row selected with clientColumns.
func scanClient(row rowScanner, client *record.Client) error {
	return row.Scan(
		&client.ID,
		&client.CreatedAt,
		&client.UpdatedAt,
		&client.ClientIdentifier,
		&client.ClientSecretEncrypted,
		&client.Description,
		&client.WebsiteURL,
		&client.PrivacyPolicyURL,
		&client.TermsOfServiceURL,
		&client.DisplayName,
		&client.Enabled,
		&client.ConsentRequired,
		&client.RememberConsent,
		&client.BackchannelLogoutURI,
		&client.BackchannelLogoutSessionRequired,
		&client.DPoPBoundAccessTokens,
		&client.CreatedViaDCR,
		&client.AdministrativeScopesAllowed,
		&client.ShowLogo,
		&client.ShowDisplayName,
		&client.ShowDescription,
		&client.ShowWebsiteURL,
		&client.IsPublic,
		&client.AuthorizationCodeEnabled,
		&client.ClientCredentialsEnabled,
		&client.PKCERequired,
		&client.ImplicitGrantEnabled,
		&client.ResourceOwnerPasswordCredentialsEnabled,
		&client.TokenExpirationInSeconds,
		&client.RefreshTokenOfflineIdleTimeoutInSeconds,
		&client.RefreshTokenOfflineMaxLifetimeInSeconds,
		&client.IncludeOpenIDConnectClaimsInAccessToken,
		&client.IncludeOpenIDConnectClaimsInIDToken,
		&client.DefaultACRLevel,
		&client.BrandID,
		&client.TokenEndpointAuthMethod,
	)
}

var insertClient = statement{
	sqlite: "INSERT INTO clients (created_at, updated_at, client_identifier, " +
		"client_secret_encrypted, description, website_url, privacy_policy_url, " +
		"terms_of_service_url, display_name, enabled, " +
		"consent_required, remember_consent, backchannel_logout_uri, " +
		"backchannel_logout_session_required, dpop_bound_access_tokens, created_via_dcr, " +
		"administrative_scopes_allowed, show_logo, " +
		"show_display_name, show_description, show_website_url, is_public, " +
		"authorization_code_enabled, client_credentials_enabled, pkce_required, " +
		"implicit_grant_enabled, resource_owner_password_credentials_enabled, " +
		"token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds, " +
		"refresh_token_offline_max_lifetime_in_seconds, " +
		"include_open_id_connect_claims_in_access_token, " +
		"include_open_id_connect_claims_in_id_token, default_acr_level, brand_id, token_endpoint_auth_method) " +
		"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
	mysql: "INSERT INTO clients (created_at, updated_at, client_identifier, " +
		"client_secret_encrypted, description, website_url, privacy_policy_url, " +
		"terms_of_service_url, display_name, enabled, " +
		"consent_required, remember_consent, backchannel_logout_uri, " +
		"backchannel_logout_session_required, dpop_bound_access_tokens, created_via_dcr, " +
		"administrative_scopes_allowed, show_logo, " +
		"show_display_name, show_description, show_website_url, is_public, " +
		"authorization_code_enabled, client_credentials_enabled, pkce_required, " +
		"implicit_grant_enabled, resource_owner_password_credentials_enabled, " +
		"token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds, " +
		"refresh_token_offline_max_lifetime_in_seconds, " +
		"include_open_id_connect_claims_in_access_token, " +
		"include_open_id_connect_claims_in_id_token, default_acr_level, brand_id, token_endpoint_auth_method) " +
		"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
	postgres: "INSERT INTO clients (created_at, updated_at, client_identifier, " +
		"client_secret_encrypted, description, website_url, privacy_policy_url, " +
		"terms_of_service_url, display_name, enabled, " +
		"consent_required, remember_consent, backchannel_logout_uri, " +
		"backchannel_logout_session_required, dpop_bound_access_tokens, created_via_dcr, " +
		"administrative_scopes_allowed, show_logo, " +
		"show_display_name, show_description, show_website_url, is_public, " +
		"authorization_code_enabled, client_credentials_enabled, pkce_required, " +
		"implicit_grant_enabled, resource_owner_password_credentials_enabled, " +
		"token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds, " +
		"refresh_token_offline_max_lifetime_in_seconds, " +
		"include_open_id_connect_claims_in_access_token, " +
		"include_open_id_connect_claims_in_id_token, default_acr_level, brand_id, token_endpoint_auth_method) " +
		"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, " +
		"$21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35) RETURNING id",
	mssql: "INSERT INTO clients (created_at, updated_at, client_identifier, " +
		"client_secret_encrypted, description, website_url, privacy_policy_url, " +
		"terms_of_service_url, display_name, enabled, " +
		"consent_required, remember_consent, backchannel_logout_uri, " +
		"backchannel_logout_session_required, dpop_bound_access_tokens, created_via_dcr, " +
		"administrative_scopes_allowed, show_logo, " +
		"show_display_name, show_description, show_website_url, is_public, " +
		"authorization_code_enabled, client_credentials_enabled, pkce_required, " +
		"implicit_grant_enabled, resource_owner_password_credentials_enabled, " +
		"token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds, " +
		"refresh_token_offline_max_lifetime_in_seconds, " +
		"include_open_id_connect_claims_in_access_token, " +
		"include_open_id_connect_claims_in_id_token, " +
		"default_acr_level, brand_id, token_endpoint_auth_method) OUTPUT INSERTED.id VALUES (@p1, @p2, @p3, " +
		"@p4, @p5, @p6, @p7, @p8, @p9, @p10, @p11, @p12, @p13, @p14, @p15, @p16, @p17, @p18, @p19, @p20, " +
		"@p21, @p22, @p23, @p24, @p25, @p26, @p27, @p28, @p29, @p30, @p31, @p32, @p33, @p34, @p35)",
}

// updateClient writes the whole row but created_at, client_identifier,
// administrative_scopes_allowed, remember_consent, the two back-channel logout columns,
// dpop_bound_access_tokens, brand_id and token_endpoint_auth_method, which are dont-update: the
// identifier is written after creation only by SetClientIdentifier, the allowance has one writer,
// SetClientAdministrativeScopesAllowed, Remember consent is written only by CreateClient,
// SetClientRememberConsent and SetClientPublic's transition, the back-channel logout columns only
// by CreateClient and SetClientBackchannelLogout, "Require DPoP for token requests" only by
// CreateClient and SetClientDPoPBoundAccessTokens, a client's brand only by CreateClient,
// SetClientBrand and a brand's deletion, and the registered method only by CreateClient and
// SetClientPublic's transition (#710, #499, #711, #784, #42, #812, #708).
var updateClient = statement{
	sqlite: "UPDATE clients SET updated_at = ?, client_secret_encrypted = ?, " +
		"description = ?, website_url = ?, privacy_policy_url = ?, terms_of_service_url = ?, " +
		"display_name = ?, enabled = ?, consent_required = ?, " +
		"created_via_dcr = ?, show_logo = ?, show_display_name = ?, show_description = ?, " +
		"show_website_url = ?, is_public = ?, authorization_code_enabled = ?, " +
		"client_credentials_enabled = ?, pkce_required = ?, implicit_grant_enabled = ?, " +
		"resource_owner_password_credentials_enabled = ?, token_expiration_in_seconds = ?, " +
		"refresh_token_offline_idle_timeout_in_seconds = ?, " +
		"refresh_token_offline_max_lifetime_in_seconds = ?, " +
		"include_open_id_connect_claims_in_access_token = ?, " +
		"include_open_id_connect_claims_in_id_token = ?, default_acr_level = ? WHERE id = ?",
	mysql: "UPDATE clients SET updated_at = ?, client_secret_encrypted = ?, " +
		"description = ?, website_url = ?, privacy_policy_url = ?, terms_of_service_url = ?, " +
		"display_name = ?, enabled = ?, consent_required = ?, " +
		"created_via_dcr = ?, show_logo = ?, show_display_name = ?, show_description = ?, " +
		"show_website_url = ?, is_public = ?, authorization_code_enabled = ?, " +
		"client_credentials_enabled = ?, pkce_required = ?, implicit_grant_enabled = ?, " +
		"resource_owner_password_credentials_enabled = ?, token_expiration_in_seconds = ?, " +
		"refresh_token_offline_idle_timeout_in_seconds = ?, " +
		"refresh_token_offline_max_lifetime_in_seconds = ?, " +
		"include_open_id_connect_claims_in_access_token = ?, " +
		"include_open_id_connect_claims_in_id_token = ?, default_acr_level = ? WHERE id = ?",
	postgres: "UPDATE clients SET updated_at = $1, " +
		"client_secret_encrypted = $2, description = $3, website_url = $4, " +
		"privacy_policy_url = $5, terms_of_service_url = $6, display_name = $7, " +
		"enabled = $8, consent_required = $9, created_via_dcr = $10, show_logo = $11, " +
		"show_display_name = $12, show_description = $13, show_website_url = $14, " +
		"is_public = $15, authorization_code_enabled = $16, client_credentials_enabled = $17, " +
		"pkce_required = $18, implicit_grant_enabled = $19, " +
		"resource_owner_password_credentials_enabled = $20, token_expiration_in_seconds = $21, " +
		"refresh_token_offline_idle_timeout_in_seconds = $22, " +
		"refresh_token_offline_max_lifetime_in_seconds = $23, " +
		"include_open_id_connect_claims_in_access_token = $24, " +
		"include_open_id_connect_claims_in_id_token = $25, default_acr_level = $26 WHERE id = $27",
	mssql: "UPDATE clients SET updated_at = @p1, " +
		"client_secret_encrypted = @p2, description = @p3, website_url = @p4, " +
		"privacy_policy_url = @p5, terms_of_service_url = @p6, " +
		"display_name = @p7, enabled = @p8, consent_required = @p9, created_via_dcr = @p10, " +
		"show_logo = @p11, show_display_name = @p12, show_description = @p13, " +
		"show_website_url = @p14, is_public = @p15, authorization_code_enabled = @p16, " +
		"client_credentials_enabled = @p17, pkce_required = @p18, implicit_grant_enabled = @p19, " +
		"resource_owner_password_credentials_enabled = @p20, token_expiration_in_seconds = @p21, " +
		"refresh_token_offline_idle_timeout_in_seconds = @p22, " +
		"refresh_token_offline_max_lifetime_in_seconds = @p23, " +
		"include_open_id_connect_claims_in_access_token = @p24, " +
		"include_open_id_connect_claims_in_id_token = @p25, " +
		"default_acr_level = @p26 WHERE id = @p27",
}

// setClientIdentifier writes a client's identifier; see SetClientIdentifier.
var setClientIdentifier = statement{
	sqlite:   "UPDATE clients SET client_identifier = ?, updated_at = ? WHERE id = ?",
	mysql:    "UPDATE clients SET client_identifier = ?, updated_at = ? WHERE id = ?",
	postgres: "UPDATE clients SET client_identifier = $1, updated_at = $2 WHERE id = $3",
	mssql:    "UPDATE clients SET client_identifier = @p1, updated_at = @p2 WHERE id = @p3",
}

var setClientRememberConsent = statement{
	sqlite:   "UPDATE clients SET remember_consent = ?, updated_at = ? WHERE id = ?",
	mysql:    "UPDATE clients SET remember_consent = ?, updated_at = ? WHERE id = ?",
	postgres: "UPDATE clients SET remember_consent = $1, updated_at = $2 WHERE id = $3",
	mssql:    "UPDATE clients SET remember_consent = @p1, updated_at = @p2 WHERE id = @p3",
}

// setClientBackchannelLogout writes the two back-channel logout columns; see
// SetClientBackchannelLogout.
var setClientBackchannelLogout = statement{
	sqlite:   "UPDATE clients SET backchannel_logout_uri = ?, backchannel_logout_session_required = ?, updated_at = ? WHERE id = ?",
	mysql:    "UPDATE clients SET backchannel_logout_uri = ?, backchannel_logout_session_required = ?, updated_at = ? WHERE id = ?",
	postgres: "UPDATE clients SET backchannel_logout_uri = $1, backchannel_logout_session_required = $2, updated_at = $3 WHERE id = $4",
	mssql:    "UPDATE clients SET backchannel_logout_uri = @p1, backchannel_logout_session_required = @p2, updated_at = @p3 WHERE id = @p4",
}

// setClientDPoPBoundAccessTokens writes "Require DPoP for token requests"; see
// SetClientDPoPBoundAccessTokens.
var setClientDPoPBoundAccessTokens = statement{
	sqlite:   "UPDATE clients SET dpop_bound_access_tokens = ?, updated_at = ? WHERE id = ?",
	mysql:    "UPDATE clients SET dpop_bound_access_tokens = ?, updated_at = ? WHERE id = ?",
	postgres: "UPDATE clients SET dpop_bound_access_tokens = $1, updated_at = $2 WHERE id = $3",
	mssql:    "UPDATE clients SET dpop_bound_access_tokens = @p1, updated_at = @p2 WHERE id = @p3",
}

var setClientAdministrativeScopesAllowed = statement{
	sqlite:   "UPDATE clients SET administrative_scopes_allowed = ?, updated_at = ? WHERE id = ?",
	mysql:    "UPDATE clients SET administrative_scopes_allowed = ?, updated_at = ? WHERE id = ?",
	postgres: "UPDATE clients SET administrative_scopes_allowed = $1, updated_at = $2 WHERE id = $3",
	mssql:    "UPDATE clients SET administrative_scopes_allowed = @p1, updated_at = @p2 WHERE id = @p3",
}

// acquireClientRow writes updated_at alone; see AcquireClientRow.
var acquireClientRow = statement{
	sqlite:   "UPDATE clients SET updated_at = ? WHERE id = ?",
	mysql:    "UPDATE clients SET updated_at = ? WHERE id = ?",
	postgres: "UPDATE clients SET updated_at = $1 WHERE id = $2",
	mssql:    "UPDATE clients SET updated_at = @p1 WHERE id = @p2",
}

// makeClientPublic changes a row only where it is still confidential, and turns Remember consent
// off and clears the registered token_endpoint_auth_method in the same write; see SetClientPublic.
var makeClientPublic = statement{
	sqlite:   "UPDATE clients SET is_public = ?, remember_consent = ?, token_endpoint_auth_method = ?, updated_at = ? WHERE id = ? AND is_public = ?",
	mysql:    "UPDATE clients SET is_public = ?, remember_consent = ?, token_endpoint_auth_method = ?, updated_at = ? WHERE id = ? AND is_public = ?",
	postgres: "UPDATE clients SET is_public = $1, remember_consent = $2, token_endpoint_auth_method = $3, updated_at = $4 WHERE id = $5 AND is_public = $6",
	mssql:    "UPDATE clients SET is_public = @p1, remember_consent = @p2, token_endpoint_auth_method = @p3, updated_at = @p4 WHERE id = @p5 AND is_public = @p6",
}

var selectClientByID = statement{
	sqlite:   "SELECT " + clientColumns.sqlite + " FROM clients WHERE id = ?",
	mysql:    "SELECT " + clientColumns.mysql + " FROM clients WHERE id = ?",
	postgres: "SELECT " + clientColumns.postgres + " FROM clients WHERE id = $1",
	mssql:    "SELECT " + clientColumns.mssql + " FROM clients WHERE id = @p1",
}

// selectClientByIDForUpdate is the locking read GetClientByIDForUpdate runs, the lock in each
// engine's own grammar, as selectUserByIDForUpdate spells it.
var selectClientByIDForUpdate = statement{
	sqlite:   "SELECT " + clientColumns.sqlite + " FROM clients WHERE id = ?",
	mysql:    "SELECT " + clientColumns.mysql + " FROM clients WHERE id = ? FOR UPDATE",
	postgres: "SELECT " + clientColumns.postgres + " FROM clients WHERE id = $1 FOR UPDATE",
	mssql:    "SELECT " + clientColumns.mssql + " FROM clients WITH (UPDLOCK, ROWLOCK) WHERE id = @p1",
}

// selectClientByIDForShare is the shared locking read GetClientByIDForShare runs. PostgreSQL's is
// FOR KEY SHARE, the lock the codes table's foreign key takes on the row at the insert anyway: a
// rename's and a deletion's FOR UPDATE conflict with it, a save that changes none of the row's
// keys does not. SQL Server's REPEATABLEREAD hint holds the shared lock to the end of the
// transaction, where READ COMMITTED would release it at the end of the statement, and reads by
// locking even with READ_COMMITTED_SNAPSHOT on. SQLite's is a plain read: its pool has one
// connection, so no other transaction runs while the reader's is open.
var selectClientByIDForShare = statement{
	sqlite:   "SELECT " + clientColumns.sqlite + " FROM clients WHERE id = ?",
	mysql:    "SELECT " + clientColumns.mysql + " FROM clients WHERE id = ? FOR SHARE",
	postgres: "SELECT " + clientColumns.postgres + " FROM clients WHERE id = $1 FOR KEY SHARE",
	mssql:    "SELECT " + clientColumns.mssql + " FROM clients WITH (REPEATABLEREAD, ROWLOCK) WHERE id = @p1",
}

var selectClientByClientIdentifier = statement{
	sqlite:   "SELECT " + clientColumns.sqlite + " FROM clients WHERE client_identifier = ?",
	mysql:    "SELECT " + clientColumns.mysql + " FROM clients WHERE client_identifier = ?",
	postgres: "SELECT " + clientColumns.postgres + " FROM clients WHERE client_identifier = $1",
	mssql:    "SELECT " + clientColumns.mssql + " FROM clients WHERE client_identifier = @p1",
}

// selectClientsWhere is completed by an IN list of client ids.
var selectClientsWhere = statement{
	sqlite:   "SELECT " + clientColumns.sqlite + " FROM clients WHERE ",
	mysql:    "SELECT " + clientColumns.mysql + " FROM clients WHERE ",
	postgres: "SELECT " + clientColumns.postgres + " FROM clients WHERE ",
	mssql:    "SELECT " + clientColumns.mssql + " FROM clients WHERE ",
}

var selectAllClients = statement{
	sqlite:   "SELECT " + clientColumns.sqlite + " FROM clients",
	mysql:    "SELECT " + clientColumns.mysql + " FROM clients",
	postgres: "SELECT " + clientColumns.postgres + " FROM clients",
	mssql:    "SELECT " + clientColumns.mssql + " FROM clients",
}

var deleteClient = statement{
	sqlite:   "DELETE FROM clients WHERE id = ?",
	mysql:    "DELETE FROM clients WHERE id = ?",
	postgres: "DELETE FROM clients WHERE id = $1",
	mssql:    "DELETE FROM clients WHERE id = @p1",
}

func (d *Database) CreateClient(ctx context.Context, tx *sql.Tx, client *record.Client) error {

	now := time.Now().UTC()

	originalCreatedAt := client.CreatedAt
	originalUpdatedAt := client.UpdatedAt
	client.CreatedAt = sql.NullTime{Time: now, Valid: true}
	client.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	id, err := d.insert(ctx, tx, insertClient, "client",
		client.CreatedAt, client.UpdatedAt, client.ClientIdentifier, client.ClientSecretEncrypted,
		client.Description, client.WebsiteURL, client.PrivacyPolicyURL, client.TermsOfServiceURL,
		client.DisplayName, client.Enabled, client.ConsentRequired, client.RememberConsent,
		client.BackchannelLogoutURI, client.BackchannelLogoutSessionRequired, client.DPoPBoundAccessTokens,
		client.CreatedViaDCR,
		client.AdministrativeScopesAllowed, client.ShowLogo, client.ShowDisplayName, client.ShowDescription, client.ShowWebsiteURL, client.IsPublic, client.AuthorizationCodeEnabled,
		client.ClientCredentialsEnabled, client.PKCERequired, client.ImplicitGrantEnabled,
		client.ResourceOwnerPasswordCredentialsEnabled, client.TokenExpirationInSeconds,
		client.RefreshTokenOfflineIdleTimeoutInSeconds, client.RefreshTokenOfflineMaxLifetimeInSeconds,
		client.IncludeOpenIDConnectClaimsInAccessToken, client.IncludeOpenIDConnectClaimsInIDToken,
		client.DefaultACRLevel, client.BrandID, client.TokenEndpointAuthMethod)
	if err != nil {
		client.CreatedAt = originalCreatedAt
		client.UpdatedAt = originalUpdatedAt
		return err
	}

	client.ID = id
	return nil
}

func (d *Database) UpdateClient(ctx context.Context, tx *sql.Tx, client *record.Client) error {

	if client.ID == 0 {
		return errs.New("can't update client with id 0")
	}

	originalUpdatedAt := client.UpdatedAt
	client.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	_, err := d.ExecSQL(ctx, tx, updateClient.text(d.Dialect),
		client.UpdatedAt, client.ClientSecretEncrypted, client.Description,
		client.WebsiteURL, client.PrivacyPolicyURL, client.TermsOfServiceURL, client.DisplayName,
		client.Enabled, client.ConsentRequired, client.CreatedViaDCR,
		client.ShowLogo, client.ShowDisplayName, client.ShowDescription, client.ShowWebsiteURL,
		client.IsPublic, client.AuthorizationCodeEnabled, client.ClientCredentialsEnabled,
		client.PKCERequired, client.ImplicitGrantEnabled, client.ResourceOwnerPasswordCredentialsEnabled,
		client.TokenExpirationInSeconds, client.RefreshTokenOfflineIdleTimeoutInSeconds,
		client.RefreshTokenOfflineMaxLifetimeInSeconds, client.IncludeOpenIDConnectClaimsInAccessToken,
		client.IncludeOpenIDConnectClaimsInIDToken, client.DefaultACRLevel,
		client.ID)
	if err != nil {
		client.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update client")
	}

	return nil
}

// SetClientIdentifier gives a client a new identifier and reports whether it did. It is the
// column's one writer after creation, and the settings save its one caller: UpdateClient leaves
// the column out (dont-update), so the OAuth2 flows, tokens and authentication saves, which write
// from a copy loaded earlier in their request, cannot write back an identifier renamed since
// (#710 decision 4).
//
// It takes the client's row with a locking read, GetClientByIDForUpdate, which waits out a
// writer in flight and writes nothing, so an identifier the row already holds leaves the row
// untouched, updated_at included. It writes only when the one given differs, compared byte for
// byte in Go rather than by the engine, whose collation may fold case: RFC 6749 section 1.9 makes
// client_id case sensitive. The answer is
// decided against the row read under that lock, never against a copy read before it, because a
// rename committed in between would make a stale copy report a change the row does not make, or
// miss one it does, and the answer is what decides whether the client's grants are revoked. True
// means this call wrote a different identifier; false means the row already held it, or there is
// no such client, which the caller's own read under the lock answers.
//
// A transaction is required, for the reason GetClientByIDForUpdate gives.
func (d *Database) SetClientIdentifier(ctx context.Context, tx *sql.Tx, clientID int64, clientIdentifier string) (bool, error) {

	if tx == nil {
		return false, errs.New("setting a client's identifier requires a transaction: the row must be held between reading the identifier and writing it")
	}
	if clientID == 0 {
		return false, errs.New("can't set the identifier of a client with an id of 0")
	}
	if clientIdentifier == "" {
		return false, errs.New("can't set a client's identifier to an empty value")
	}

	current, err := d.GetClientByIDForUpdate(ctx, tx, clientID)
	if err != nil {
		return false, err
	}
	if current == nil || current.ClientIdentifier == clientIdentifier {
		return false, nil
	}

	if _, err := d.ExecSQL(ctx, tx, setClientIdentifier.text(d.Dialect),
		clientIdentifier, time.Now().UTC(), clientID); err != nil {
		return false, errs.Wrap(err, "unable to set the client's identifier")
	}
	return true, nil
}

// SetClientAdministrativeScopesAllowed writes a client's allowance to request the administrative
// authserver scopes, and nothing else but updated_at. It is the column's one writer: UpdateClient
// leaves it out (dont-update), so a whole-row save made from a copy read earlier cannot write back
// an allowance an operator has switched since (#499 decisions 4 and 5).
//
// A client that is not there affects no rows and is not reported here, for the reason
// AcquireClientRow gives: its caller reads the row back to answer, and that read is the one place
// that decides whether the client still exists.
func (d *Database) SetClientAdministrativeScopesAllowed(ctx context.Context, tx *sql.Tx, clientID int64, allowed bool) error {

	if clientID == 0 {
		return errs.New("can't set the administrative scopes allowance of a client with an id of 0")
	}

	if _, err := d.ExecSQL(ctx, tx, setClientAdministrativeScopesAllowed.text(d.Dialect),
		allowed, time.Now().UTC(), clientID); err != nil {
		return errs.Wrap(err, "unable to set the client's administrative scopes allowance")
	}
	return nil
}

// SetClientRememberConsent writes whether a user's earlier approval may skip the consent screen for
// this client, and nothing else but updated_at (#711). UpdateClient leaves the column out
// (dont-update), so a whole-row save made from a copy read earlier cannot write back a value that
// changed since; this, CreateClient and SetClientPublic's transition are its writers.
//
// A client that is not there affects no rows and is not reported here, for the reason
// AcquireClientRow gives.
func (d *Database) SetClientRememberConsent(ctx context.Context, tx *sql.Tx, clientID int64, remember bool) error {

	if clientID == 0 {
		return errs.New("can't set Remember consent on a client with an id of 0")
	}

	if _, err := d.ExecSQL(ctx, tx, setClientRememberConsent.text(d.Dialect),
		remember, time.Now().UTC(), clientID); err != nil {
		return errs.Wrap(err, "unable to set the client's Remember consent")
	}
	return nil
}

// SetClientBackchannelLogout writes a client's back-channel logout URI and whether it requires the
// session identifier, and nothing else but updated_at (#784 decisions 14 and 15). UpdateClient
// leaves both columns out (dont-update), so a whole-row save made from a copy read earlier cannot
// write back a URI that changed since; this and CreateClient are their writers.
//
// A client that is not there affects no rows and is not reported here, for the reason
// AcquireClientRow gives.
func (d *Database) SetClientBackchannelLogout(ctx context.Context, tx *sql.Tx, clientID int64, uri string, sessionRequired bool) error {

	if clientID == 0 {
		return errs.New("can't set the back-channel logout of a client with an id of 0")
	}

	if _, err := d.ExecSQL(ctx, tx, setClientBackchannelLogout.text(d.Dialect),
		uri, sessionRequired, time.Now().UTC(), clientID); err != nil {
		return errs.Wrap(err, "unable to set the client's back-channel logout")
	}
	return nil
}

// SetClientDPoPBoundAccessTokens writes whether the client requires DPoP for its token requests
// (RFC 9449 section 5.2's dpop_bound_access_tokens), and nothing else but updated_at (#42 decision
// 12). UpdateClient leaves the column out (dont-update), so a whole-row save made from a copy read
// earlier cannot write back a setting switched since; this and CreateClient are its writers.
//
// A client that is not there affects no rows and is not reported here, for the reason
// AcquireClientRow gives.
func (d *Database) SetClientDPoPBoundAccessTokens(ctx context.Context, tx *sql.Tx, clientID int64, required bool) error {

	if clientID == 0 {
		return errs.New("can't set the DPoP requirement of a client with an id of 0")
	}

	if _, err := d.ExecSQL(ctx, tx, setClientDPoPBoundAccessTokens.text(d.Dialect),
		required, time.Now().UTC(), clientID); err != nil {
		return errs.Wrap(err, "unable to set the client's DPoP requirement")
	}
	return nil
}

// AcquireClientRow takes the client's row and holds it for the rest of the caller's
// transaction. It is one unconditional UPDATE that writes nothing a reader can observe: the row's
// updated_at, which every caller of this overwrites moments later with its own write.
//
// WHAT IT BUYS, AND WHY A READ ALONE DOES NOT. A caller that re-reads a column to decide what to
// preserve, and then writes the whole row back, has two statements with a gap between them.
// Another transaction can commit inside that gap, and the write then carries the value read
// before that commit. `WHERE id = ?` alone matches under every engine's snapshot, so this
// statement waits out any in-flight writer and takes the row; a read after it sees what that
// writer committed, and no later writer can get between the read and the caller's write.
//
// Measured rather than assumed, on all four engines, for #245: under MVCC (mysql,
// postgres) a bare re-read returns the last committed version without waiting at all, so the
// window is the other writer's whole transaction rather than the gap between two statements.
// SQL Server's shared locks narrow it but do not close it. Removing this call therefore reopens
// a window on three engines, and does so silently, because everything still passes when nothing
// else is writing (#245).
//
// SQLite is the one engine where the interleaving cannot be constructed: sqlitedb/db.go's Pool
// is one connection, so a second writer queues behind the open transaction rather than landing
// inside it.
//
// The transaction is required rather than optional. Without one the statement autocommits and
// drops the row before the caller's read runs, which is the whole of what this buys.
func (d *Database) AcquireClientRow(ctx context.Context, tx *sql.Tx, clientID int64) error {

	if tx == nil {
		return errs.New("acquiring a client row requires a transaction: an autocommitted statement releases the row before the caller can read it")
	}

	if clientID == 0 {
		return errs.New("can't acquire a client row with an id of 0")
	}

	if _, err := d.ExecSQL(ctx, tx, acquireClientRow.text(d.Dialect), time.Now().UTC(), clientID); err != nil {
		return errs.Wrap(err, "unable to acquire client row")
	}

	// A client that is not there affects no rows and is not reported here. There is nothing to
	// hold, and every caller reads the row immediately afterwards, which is the one place that
	// decides whether the client still exists. Answering it twice would put the same sentence in
	// two places and let them disagree.
	return nil
}

// SetClientPublic makes one client public and reports whether THIS call performed the
// confidential-to-public transition. That transition is the write that removes the client's
// obligation to authenticate, so it is the one whose caller must revoke the grants issued while
// a secret was still required (#245). A save of a client that was already public takes nothing
// away and reports false, which is what stops an administrator re-saving a form from signing
// every user of the application out.
//
// The transition also turns Remember consent off, in the same conditional statement: nobody has
// vouched for the identity of a client that has just become public, and a save of a client that
// was already public keeps the administrator's choice (#711 decision 5). It clears the
// token_endpoint_auth_method the client registered in the same statement: a public client
// authenticates with no secret, and a switch back to confidential leaves it empty, so the client
// then authenticates with either method (#708 decision 3).
//
// WHY THE ANSWER IS NOT A READ. The obvious shape is to load the row, compare, then write. It
// does not hold: the load and the write are separate statements, and another request can commit
// confidential mode and issue a grant under the secret it created in between. The classification
// then comes from the stale side, reads "already public", and the transaction commits a public
// client still holding grants that only a secret could have redeemed.
//
// WHY IT IS TWO STATEMENTS AND NOT ONE. The conditional UPDATE below is the classification: the
// row it affects is the transition, and affecting none means there was nothing to change. On
// MySQL and SQL Server that statement alone is enough, because both wait for the in-flight
// writer and re-evaluate the predicate against the row it committed. PostgreSQL does not.
// Its READ COMMITTED mode finds target rows from the snapshot as of command start, so a row
// whose committed version still says public is never a target of `AND is_public = <false>`: the
// statement neither waits nor re-evaluates, and reports zero while the unconditional write that
// follows it blocks, unblocks and commits public anyway. Measured on all four engines, for #245.
//
// So the first statement is an acquisition and the second is the classification. The
// acquisition is AcquireClientRow, shared with the three endpoints that re-read these columns
// rather than classifying them (#245 decision 18), so the mechanism has one spelling and one
// explanation: `WHERE id = ?` alone matches under every engine's snapshot, so it waits out any
// in-flight writer and takes the row, and the conditional UPDATE after it evaluates against this
// transaction's own version, which was derived from the committed one.
//
// The transaction is required rather than optional, for the reason revocation.RevokeClientGrants states
// about its own: without one, each statement autocommits and the acquisition drops its lock
// before the classification runs, which is the whole mechanism.
func (d *Database) SetClientPublic(ctx context.Context, tx *sql.Tx, clientID int64) (bool, error) {

	if tx == nil {
		return false, errs.New("making a client public requires a transaction: the row must be held between acquiring it and classifying the write")
	}

	if clientID == 0 {
		return false, errs.New("can't make a client public with an id of 0")
	}

	if err := d.AcquireClientRow(ctx, tx, clientID); err != nil {
		return false, err
	}

	result, err := d.ExecSQL(ctx, tx, makeClientPublic.text(d.Dialect), true, false, "", time.Now().UTC(), clientID, false)
	if err != nil {
		return false, errs.Wrap(err, "unable to make client public")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errs.Wrap(err, "unable to get rows affected when making client public")
	}
	if rowsAffected == 1 {
		return true, nil
	}

	// Zero rows has two causes and only one of them is an error, so they are told apart here
	// rather than reported as the same thing. This read DECIDES NOTHING about the transition:
	// that answer is already in hand above, and the row is held by the acquisition, so all this
	// can observe is whether there is a client to have saved at all.
	client, err := d.GetClientByID(ctx, tx, clientID)
	if err != nil {
		return false, err
	}
	if client == nil {
		return false, errs.New("can't make a client public: no client with that id")
	}
	return false, nil
}

func (d *Database) GetClientByID(ctx context.Context, tx *sql.Tx, clientID int64) (*record.Client, error) {
	return queryOne(ctx, d, tx, selectClientByID.text(d.Dialect), []any{clientID}, scanClient, "client")
}

// GetClientByIDForUpdate reads the client as last committed and takes its row for the rest of the
// caller's transaction, without writing it: a locking read, as GetUserByIDForUpdate is a user's. A
// writer of the row, AcquireClientRow among them, and another locking read, SetClientIdentifier's
// among them, wait for this transaction to end, and this read waits for a writer's transaction to
// end and answers what it committed.
//
// The initial password grant reads its client this way before it writes its first refresh token,
// so a rename of the client is ordered against it: either the grant commits first and the rename's
// sweep finds its token, or the rename commits first and the grant reads the identifier it gave the
// client (#710 decision 5). It writes nothing, so a password grant does not move the client's
// updated_at, which the admin console shows.
//
// tx is required: without one the statement autocommits and the row is released before the caller
// can decide on what it read.
func (d *Database) GetClientByIDForUpdate(ctx context.Context, tx *sql.Tx, clientID int64) (*record.Client, error) {

	if tx == nil {
		return nil, errs.New("a locking read of a client requires a transaction: an autocommitted statement releases the row before the caller can decide on it")
	}

	return queryOne(ctx, d, tx, selectClientByIDForUpdate.text(d.Dialect), []any{clientID}, scanClient, "client")
}

// GetClientByIDForShare reads the client as last committed and holds a shared lock on its row for
// the rest of the caller's transaction, without writing it. A rename (SetClientIdentifier) and a
// deletion (DeleteClient), which take the row exclusively to change it, wait for this transaction
// to end, and this read waits for theirs and answers what they committed. On MySQL, PostgreSQL and
// SQL Server two shared reads of the row do not wait for each other; on SQLite, whose statement is
// a plain read, the pool's one connection runs one transaction at a time.
//
// Code issuance reads its client this way before it inserts the code, so a rename is ordered
// against it: either the code commits first and the rename's sweep revokes it, or the rename
// commits first and issuance reads the identifier it gave the client and issues nothing (#866).
//
// tx is required, for the reason GetClientByIDForUpdate gives.
func (d *Database) GetClientByIDForShare(ctx context.Context, tx *sql.Tx, clientID int64) (*record.Client, error) {

	if tx == nil {
		return nil, errs.New("a shared locking read of a client requires a transaction: an autocommitted statement releases the row before the caller can decide on it")
	}

	return queryOne(ctx, d, tx, selectClientByIDForShare.text(d.Dialect), []any{clientID}, scanClient, "client")
}

func (d *Database) GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*record.Client, error) {

	client, err := queryOne(ctx, d, tx, selectClientByClientIdentifier.text(d.Dialect), []any{clientIdentifier},
		scanClient, "client")
	if err != nil {
		return nil, err
	}
	// The engine may have folded a value this lookup did not ask for; see
	// engineFoldedTheMatch. RFC 6749 section 1.9 makes client_id case sensitive.
	if client != nil && engineFoldedTheMatch(client.ClientIdentifier, clientIdentifier) {
		return nil, nil
	}

	return client, nil
}

func (d *Database) ClientLoadRedirectURIs(ctx context.Context, tx *sql.Tx, client *record.Client) error {

	if client == nil {
		return nil
	}

	var err error
	client.RedirectURIs, err = d.GetRedirectURIsByClientID(ctx, tx, client.ID)
	if err != nil {
		return errs.Wrap(err, "unable to get redirect URIs")
	}

	return nil
}

// ClientLoadPostLogoutRedirectURIs loads the client's sign-out redirect URIs, which nothing at
// sign-in reads (#147).
func (d *Database) ClientLoadPostLogoutRedirectURIs(ctx context.Context, tx *sql.Tx, client *record.Client) error {

	if client == nil {
		return nil
	}

	var err error
	client.PostLogoutRedirectURIs, err = d.GetPostLogoutRedirectURIsByClientID(ctx, tx, client.ID)
	if err != nil {
		return errs.Wrap(err, "unable to get sign-out redirect URIs")
	}

	return nil
}

func (d *Database) ClientLoadWebOrigins(ctx context.Context, tx *sql.Tx, client *record.Client) error {

	if client == nil {
		return nil
	}

	var err error
	client.WebOrigins, err = d.GetWebOriginsByClientID(ctx, tx, client.ID)
	if err != nil {
		return errs.Wrap(err, "unable to get web origins")
	}

	return nil
}

func (d *Database) GetClientsByIDs(ctx context.Context, tx *sql.Tx, clientIDs []int64) ([]record.Client, error) {

	if len(clientIDs) == 0 {
		return []record.Client{}, nil
	}

	clients := make([]record.Client, 0, len(clientIDs))

	err := forEachIDBatch(clientIDs, func(batch []int64) error {
		query := selectClientsWhere.text(d.Dialect) + inList(d.Dialect, "id", 1, len(batch))
		var err error
		clients, err = queryAll(ctx, d, tx, clients, query, int64Args(batch), scanClient, "client")
		return err
	})
	if err != nil {
		return nil, err
	}

	return clients, nil
}

func (d *Database) ClientLoadPermissions(ctx context.Context, tx *sql.Tx, client *record.Client) error {

	if client == nil {
		return nil
	}

	clientPermissions, err := d.GetClientPermissionsByClientID(ctx, tx, client.ID)
	if err != nil {
		return err
	}

	permissionIDs := make([]int64, 0)
	for _, clientPermission := range clientPermissions {
		permissionIDs = append(permissionIDs, clientPermission.PermissionID)
	}

	client.Permissions, err = d.GetPermissionsByIDs(ctx, tx, permissionIDs)
	if err != nil {
		return err
	}

	return nil
}

func (d *Database) GetAllClients(ctx context.Context, tx *sql.Tx) ([]record.Client, error) {
	return queryAll(ctx, d, tx, make([]record.Client, 0), selectAllClients.text(d.Dialect), nil, scanClient, "client")
}

// DeleteClient removes the client and, by ON DELETE CASCADE, every row that references it.
// Refresh tokens are cleared explicitly first because SQL Server cannot cascade them: see
// deleteRefreshTokensByColumn. refresh_tokens.client_id is NO ACTION on all four engines and
// only refresh_tokens.code_id is CASCADE, so that statement really does take a client's
// ROPC-issued tokens before the cascade runs.
//
// No row is acquired ahead of the first sweep. The final DELETE takes the clients row itself,
// and a transaction of this shape racing an authorization ceremony for the same client, or a
// termination of a session that holds this client's tokens, is answered by RunInTransaction
// rerunning whichever of the two the engine aborts (#301).
//
// The sweep runs again once the locking read below holds the clients row, for the initial
// password grant, which writes its first refresh token under that row (#710 decision 5): one
// that wrote it while the first sweep ran has committed by then, and that second sweep takes its
// token, which would otherwise refuse the DELETE by the NO ACTION key.
//
// In the same transaction, last, it records the deleted identifier with the moment of the
// deletion, which the access-token liveness check reads so that a new client taking the
// identifier does not revive the deleted one's access tokens (#676 decision 6). The identifier
// is the one the row holds as it is deleted (#710 decision 11): it is read by a locking read of
// the clients row just before the DELETE, which takes that row at the point the DELETE would
// take it anyway, so the order above is unchanged, and a rename committed meanwhile is waited
// for and read rather than missed by a read that does not wait for a writer, which would record
// the identifier the client had before and leave the one it gave up unrecorded. A client that is
// not there records nothing.
func (d *Database) DeleteClient(ctx context.Context, tx *sql.Tx, clientID int64) error {

	return d.inTransaction(ctx, tx, func(tx *sql.Tx) error {
		err := d.deleteRefreshTokensByColumn(ctx, tx, "client_id", clientID)
		if err != nil {
			return err
		}

		client, err := d.GetClientByIDForUpdate(ctx, tx, clientID)
		if err != nil {
			return err
		}

		// Again, now that the row is held: an initial password grant the read above waited for
		// has committed its first refresh token, which the first sweep could not see.
		err = d.deleteRefreshTokensByColumn(ctx, tx, "client_id", clientID)
		if err != nil {
			return err
		}

		_, err = d.ExecSQL(ctx, tx, deleteClient.text(d.Dialect), clientID)
		if err != nil {
			return errs.Wrap(err, "unable to delete client")
		}

		if client == nil {
			return nil
		}
		return d.recordClientDeleted(ctx, tx, client.ClientIdentifier, time.Now())
	})
}
