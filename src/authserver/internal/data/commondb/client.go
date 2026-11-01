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
		"consent_required, created_via_dcr, " +
		"administrative_scopes_allowed, show_logo, show_display_name, show_description, " +
		"show_website_url, is_public, authorization_code_enabled, client_credentials_enabled, " +
		"pkce_required, implicit_grant_enabled, resource_owner_password_credentials_enabled, " +
		"token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds, " +
		"refresh_token_offline_max_lifetime_in_seconds, " +
		"include_open_id_connect_claims_in_access_token, " +
		"include_open_id_connect_claims_in_id_token, default_acr_level",
	mysql: "id, created_at, updated_at, client_identifier, client_secret_encrypted, description, " +
		"website_url, privacy_policy_url, terms_of_service_url, display_name, enabled, " +
		"consent_required, created_via_dcr, " +
		"administrative_scopes_allowed, show_logo, show_display_name, show_description, " +
		"show_website_url, is_public, authorization_code_enabled, client_credentials_enabled, " +
		"pkce_required, implicit_grant_enabled, resource_owner_password_credentials_enabled, " +
		"token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds, " +
		"refresh_token_offline_max_lifetime_in_seconds, " +
		"include_open_id_connect_claims_in_access_token, " +
		"include_open_id_connect_claims_in_id_token, default_acr_level",
	postgres: "id, created_at, updated_at, client_identifier, client_secret_encrypted, description, " +
		"website_url, privacy_policy_url, terms_of_service_url, display_name, enabled, " +
		"consent_required, created_via_dcr, " +
		"administrative_scopes_allowed, show_logo, show_display_name, show_description, " +
		"show_website_url, is_public, authorization_code_enabled, client_credentials_enabled, " +
		"pkce_required, implicit_grant_enabled, resource_owner_password_credentials_enabled, " +
		"token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds, " +
		"refresh_token_offline_max_lifetime_in_seconds, " +
		"include_open_id_connect_claims_in_access_token, " +
		"include_open_id_connect_claims_in_id_token, default_acr_level",
	mssql: "id, created_at, updated_at, client_identifier, client_secret_encrypted, description, " +
		"website_url, privacy_policy_url, terms_of_service_url, display_name, enabled, " +
		"consent_required, created_via_dcr, " +
		"administrative_scopes_allowed, show_logo, show_display_name, show_description, " +
		"show_website_url, is_public, authorization_code_enabled, client_credentials_enabled, " +
		"pkce_required, implicit_grant_enabled, resource_owner_password_credentials_enabled, " +
		"token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds, " +
		"refresh_token_offline_max_lifetime_in_seconds, " +
		"include_open_id_connect_claims_in_access_token, " +
		"include_open_id_connect_claims_in_id_token, default_acr_level",
}

// scanClient reads one row selected with clientColumns.
func scanClient(row rowScanner, client *record.Client) error {
	return row.Scan(
		&client.Id,
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
		&client.IncludeOpenIDConnectClaimsInIdToken,
		&client.DefaultAcrLevel,
	)
}

var insertClient = statement{
	sqlite: "INSERT INTO clients (created_at, updated_at, client_identifier, " +
		"client_secret_encrypted, description, website_url, privacy_policy_url, " +
		"terms_of_service_url, display_name, enabled, " +
		"consent_required, created_via_dcr, administrative_scopes_allowed, show_logo, " +
		"show_display_name, show_description, show_website_url, is_public, " +
		"authorization_code_enabled, client_credentials_enabled, pkce_required, " +
		"implicit_grant_enabled, resource_owner_password_credentials_enabled, " +
		"token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds, " +
		"refresh_token_offline_max_lifetime_in_seconds, " +
		"include_open_id_connect_claims_in_access_token, " +
		"include_open_id_connect_claims_in_id_token, default_acr_level) VALUES (?, ?, ?, ?, ?, " +
		"?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
	mysql: "INSERT INTO clients (created_at, updated_at, client_identifier, " +
		"client_secret_encrypted, description, website_url, privacy_policy_url, " +
		"terms_of_service_url, display_name, enabled, " +
		"consent_required, created_via_dcr, administrative_scopes_allowed, show_logo, " +
		"show_display_name, show_description, show_website_url, is_public, " +
		"authorization_code_enabled, client_credentials_enabled, pkce_required, " +
		"implicit_grant_enabled, resource_owner_password_credentials_enabled, " +
		"token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds, " +
		"refresh_token_offline_max_lifetime_in_seconds, " +
		"include_open_id_connect_claims_in_access_token, " +
		"include_open_id_connect_claims_in_id_token, default_acr_level) VALUES (?, ?, ?, ?, ?, " +
		"?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
	postgres: "INSERT INTO clients (created_at, updated_at, client_identifier, " +
		"client_secret_encrypted, description, website_url, privacy_policy_url, " +
		"terms_of_service_url, display_name, enabled, " +
		"consent_required, created_via_dcr, administrative_scopes_allowed, show_logo, " +
		"show_display_name, show_description, show_website_url, is_public, " +
		"authorization_code_enabled, client_credentials_enabled, pkce_required, " +
		"implicit_grant_enabled, resource_owner_password_credentials_enabled, " +
		"token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds, " +
		"refresh_token_offline_max_lifetime_in_seconds, " +
		"include_open_id_connect_claims_in_access_token, " +
		"include_open_id_connect_claims_in_id_token, default_acr_level) VALUES ($1, $2, $3, $4, " +
		"$5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, " +
		"$23, $24, $25, $26, $27, $28, $29) RETURNING id",
	mssql: "INSERT INTO clients (created_at, updated_at, client_identifier, " +
		"client_secret_encrypted, description, website_url, privacy_policy_url, " +
		"terms_of_service_url, display_name, enabled, " +
		"consent_required, created_via_dcr, administrative_scopes_allowed, show_logo, " +
		"show_display_name, show_description, show_website_url, is_public, " +
		"authorization_code_enabled, client_credentials_enabled, pkce_required, " +
		"implicit_grant_enabled, resource_owner_password_credentials_enabled, " +
		"token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds, " +
		"refresh_token_offline_max_lifetime_in_seconds, " +
		"include_open_id_connect_claims_in_access_token, " +
		"include_open_id_connect_claims_in_id_token, " +
		"default_acr_level) OUTPUT INSERTED.id VALUES (@p1, @p2, @p3, @p4, @p5, @p6, @p7, @p8, " +
		"@p9, @p10, @p11, @p12, @p13, @p14, @p15, @p16, @p17, @p18, @p19, @p20, @p21, @p22, " +
		"@p23, @p24, @p25, @p26, @p27, @p28, @p29)",
}

// updateClient writes the whole row but created_at and administrative_scopes_allowed, which are
// dont-update: the allowance has one writer, SetClientAdministrativeScopesAllowed.
var updateClient = statement{
	sqlite: "UPDATE clients SET updated_at = ?, client_identifier = ?, client_secret_encrypted = ?, " +
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
	mysql: "UPDATE clients SET updated_at = ?, client_identifier = ?, client_secret_encrypted = ?, " +
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
	postgres: "UPDATE clients SET updated_at = $1, client_identifier = $2, " +
		"client_secret_encrypted = $3, description = $4, website_url = $5, " +
		"privacy_policy_url = $6, terms_of_service_url = $7, display_name = $8, " +
		"enabled = $9, consent_required = $10, created_via_dcr = $11, show_logo = $12, " +
		"show_display_name = $13, show_description = $14, show_website_url = $15, " +
		"is_public = $16, authorization_code_enabled = $17, client_credentials_enabled = $18, " +
		"pkce_required = $19, implicit_grant_enabled = $20, " +
		"resource_owner_password_credentials_enabled = $21, token_expiration_in_seconds = $22, " +
		"refresh_token_offline_idle_timeout_in_seconds = $23, " +
		"refresh_token_offline_max_lifetime_in_seconds = $24, " +
		"include_open_id_connect_claims_in_access_token = $25, " +
		"include_open_id_connect_claims_in_id_token = $26, default_acr_level = $27 WHERE id = $28",
	mssql: "UPDATE clients SET updated_at = @p1, client_identifier = @p2, " +
		"client_secret_encrypted = @p3, description = @p4, website_url = @p5, " +
		"privacy_policy_url = @p6, terms_of_service_url = @p7, " +
		"display_name = @p8, enabled = @p9, consent_required = @p10, created_via_dcr = @p11, " +
		"show_logo = @p12, show_display_name = @p13, show_description = @p14, " +
		"show_website_url = @p15, is_public = @p16, authorization_code_enabled = @p17, " +
		"client_credentials_enabled = @p18, pkce_required = @p19, implicit_grant_enabled = @p20, " +
		"resource_owner_password_credentials_enabled = @p21, token_expiration_in_seconds = @p22, " +
		"refresh_token_offline_idle_timeout_in_seconds = @p23, " +
		"refresh_token_offline_max_lifetime_in_seconds = @p24, " +
		"include_open_id_connect_claims_in_access_token = @p25, " +
		"include_open_id_connect_claims_in_id_token = @p26, " +
		"default_acr_level = @p27 WHERE id = @p28",
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

// makeClientPublic changes a row only where it is still confidential; see SetClientPublic.
var makeClientPublic = statement{
	sqlite:   "UPDATE clients SET is_public = ?, updated_at = ? WHERE id = ? AND is_public = ?",
	mysql:    "UPDATE clients SET is_public = ?, updated_at = ? WHERE id = ? AND is_public = ?",
	postgres: "UPDATE clients SET is_public = $1, updated_at = $2 WHERE id = $3 AND is_public = $4",
	mssql:    "UPDATE clients SET is_public = @p1, updated_at = @p2 WHERE id = @p3 AND is_public = @p4",
}

var selectClientById = statement{
	sqlite:   "SELECT " + clientColumns.sqlite + " FROM clients WHERE id = ?",
	mysql:    "SELECT " + clientColumns.mysql + " FROM clients WHERE id = ?",
	postgres: "SELECT " + clientColumns.postgres + " FROM clients WHERE id = $1",
	mssql:    "SELECT " + clientColumns.mssql + " FROM clients WHERE id = @p1",
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
		client.DisplayName, client.Enabled, client.ConsentRequired, client.CreatedViaDCR,
		client.AdministrativeScopesAllowed, client.ShowLogo, client.ShowDisplayName, client.ShowDescription, client.ShowWebsiteURL, client.IsPublic, client.AuthorizationCodeEnabled,
		client.ClientCredentialsEnabled, client.PKCERequired, client.ImplicitGrantEnabled,
		client.ResourceOwnerPasswordCredentialsEnabled, client.TokenExpirationInSeconds,
		client.RefreshTokenOfflineIdleTimeoutInSeconds, client.RefreshTokenOfflineMaxLifetimeInSeconds,
		client.IncludeOpenIDConnectClaimsInAccessToken, client.IncludeOpenIDConnectClaimsInIdToken,
		client.DefaultAcrLevel)
	if err != nil {
		client.CreatedAt = originalCreatedAt
		client.UpdatedAt = originalUpdatedAt
		return err
	}

	client.Id = id
	return nil
}

func (d *Database) UpdateClient(ctx context.Context, tx *sql.Tx, client *record.Client) error {

	if client.Id == 0 {
		return errs.New("can't update client with id 0")
	}

	originalUpdatedAt := client.UpdatedAt
	client.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	_, err := d.ExecSQL(ctx, tx, updateClient.text(d.Dialect),
		client.UpdatedAt, client.ClientIdentifier, client.ClientSecretEncrypted, client.Description,
		client.WebsiteURL, client.PrivacyPolicyURL, client.TermsOfServiceURL, client.DisplayName,
		client.Enabled, client.ConsentRequired, client.CreatedViaDCR,
		client.ShowLogo, client.ShowDisplayName, client.ShowDescription, client.ShowWebsiteURL,
		client.IsPublic, client.AuthorizationCodeEnabled, client.ClientCredentialsEnabled,
		client.PKCERequired, client.ImplicitGrantEnabled, client.ResourceOwnerPasswordCredentialsEnabled,
		client.TokenExpirationInSeconds, client.RefreshTokenOfflineIdleTimeoutInSeconds,
		client.RefreshTokenOfflineMaxLifetimeInSeconds, client.IncludeOpenIDConnectClaimsInAccessToken,
		client.IncludeOpenIDConnectClaimsInIdToken, client.DefaultAcrLevel,
		client.Id)
	if err != nil {
		client.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update client")
	}

	return nil
}

// SetClientAdministrativeScopesAllowed writes a client's allowance to request the administrative
// authserver scopes, and nothing else but updated_at. It is the column's one writer: UpdateClient
// leaves it out (dont-update), so a whole-row save made from a copy read earlier cannot write back
// an allowance an operator has switched since (#499 decisions 4 and 5).
//
// A client that is not there affects no rows and is not reported here, for the reason
// AcquireClientRow gives: its caller reads the row back to answer, and that read is the one place
// that decides whether the client still exists.
func (d *Database) SetClientAdministrativeScopesAllowed(ctx context.Context, tx *sql.Tx, clientId int64, allowed bool) error {

	if clientId == 0 {
		return errs.New("can't set the administrative scopes allowance of a client with an id of 0")
	}

	if _, err := d.ExecSQL(ctx, tx, setClientAdministrativeScopesAllowed.text(d.Dialect),
		allowed, time.Now().UTC(), clientId); err != nil {
		return errs.Wrap(err, "unable to set the client's administrative scopes allowance")
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
func (d *Database) AcquireClientRow(ctx context.Context, tx *sql.Tx, clientId int64) error {

	if tx == nil {
		return errs.New("acquiring a client row requires a transaction: an autocommitted statement releases the row before the caller can read it")
	}

	if clientId == 0 {
		return errs.New("can't acquire a client row with an id of 0")
	}

	if _, err := d.ExecSQL(ctx, tx, acquireClientRow.text(d.Dialect), time.Now().UTC(), clientId); err != nil {
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
func (d *Database) SetClientPublic(ctx context.Context, tx *sql.Tx, clientId int64) (bool, error) {

	if tx == nil {
		return false, errs.New("making a client public requires a transaction: the row must be held between acquiring it and classifying the write")
	}

	if clientId == 0 {
		return false, errs.New("can't make a client public with an id of 0")
	}

	if err := d.AcquireClientRow(ctx, tx, clientId); err != nil {
		return false, err
	}

	result, err := d.ExecSQL(ctx, tx, makeClientPublic.text(d.Dialect), true, time.Now().UTC(), clientId, false)
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
	client, err := d.GetClientById(ctx, tx, clientId)
	if err != nil {
		return false, err
	}
	if client == nil {
		return false, errs.New("can't make a client public: no client with that id")
	}
	return false, nil
}

func (d *Database) GetClientById(ctx context.Context, tx *sql.Tx, clientId int64) (*record.Client, error) {
	return queryOne(ctx, d, tx, selectClientById.text(d.Dialect), []any{clientId}, scanClient, "client")
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
	client.RedirectURIs, err = d.GetRedirectURIsByClientId(ctx, tx, client.Id)
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
	client.PostLogoutRedirectURIs, err = d.GetPostLogoutRedirectURIsByClientId(ctx, tx, client.Id)
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
	client.WebOrigins, err = d.GetWebOriginsByClientId(ctx, tx, client.Id)
	if err != nil {
		return errs.Wrap(err, "unable to get web origins")
	}

	return nil
}

func (d *Database) GetClientsByIds(ctx context.Context, tx *sql.Tx, clientIds []int64) ([]record.Client, error) {

	if len(clientIds) == 0 {
		return []record.Client{}, nil
	}

	clients := make([]record.Client, 0, len(clientIds))

	err := forEachIdBatch(clientIds, func(batch []int64) error {
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

	clientPermissions, err := d.GetClientPermissionsByClientId(ctx, tx, client.Id)
	if err != nil {
		return err
	}

	permissionIds := make([]int64, 0)
	for _, clientPermission := range clientPermissions {
		permissionIds = append(permissionIds, clientPermission.PermissionId)
	}

	client.Permissions, err = d.GetPermissionsByIds(ctx, tx, permissionIds)
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
// No row is acquired ahead of these two statements. The final DELETE takes the clients row
// itself, and a transaction of this shape racing an authorization ceremony for the same
// client, or a termination of a session that holds this client's tokens, is answered by
// RunInTransaction rerunning whichever of the two the engine aborts (#301).
//
// In the same transaction, last, it records the deleted identifier with the moment of the
// deletion, which the access-token liveness check reads so that a new client taking the
// identifier does not revive the deleted one's access tokens (#676 decision 6). The identifier
// is read first, by the client's id; a client that is not there records nothing.
func (d *Database) DeleteClient(ctx context.Context, tx *sql.Tx, clientId int64) error {

	return d.inTransaction(ctx, tx, func(tx *sql.Tx) error {
		client, err := d.GetClientById(ctx, tx, clientId)
		if err != nil {
			return err
		}

		err = d.deleteRefreshTokensByColumn(ctx, tx, "client_id", clientId)
		if err != nil {
			return err
		}

		_, err = d.ExecSQL(ctx, tx, deleteClient.text(d.Dialect), clientId)
		if err != nil {
			return errs.Wrap(err, "unable to delete client")
		}

		if client == nil {
			return nil
		}
		return d.recordClientDeleted(ctx, tx, client.ClientIdentifier, time.Now())
	})
}
