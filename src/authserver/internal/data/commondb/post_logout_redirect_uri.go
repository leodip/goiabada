package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// postLogoutRedirectURIColumns is the post_logout_redirect_uris table as scanPostLogoutRedirectURI
// reads it.
var postLogoutRedirectURIColumns = columnList{
	sqlite:   "id, created_at, uri, client_id",
	mysql:    "id, created_at, uri, client_id",
	postgres: "id, created_at, uri, client_id",
	mssql:    "id, created_at, uri, client_id",
}

// scanPostLogoutRedirectURI reads one row selected with postLogoutRedirectURIColumns.
func scanPostLogoutRedirectURI(row rowScanner, postLogoutRedirectURI *record.PostLogoutRedirectURI) error {
	return row.Scan(
		&postLogoutRedirectURI.Id,
		&postLogoutRedirectURI.CreatedAt,
		&postLogoutRedirectURI.URI,
		&postLogoutRedirectURI.ClientId,
	)
}

var insertPostLogoutRedirectURI = statement{
	sqlite:   "INSERT INTO post_logout_redirect_uris (created_at, uri, client_id) VALUES (?, ?, ?)",
	mysql:    "INSERT INTO post_logout_redirect_uris (created_at, uri, client_id) VALUES (?, ?, ?)",
	postgres: "INSERT INTO post_logout_redirect_uris (created_at, uri, client_id) VALUES ($1, $2, $3) RETURNING id",
	mssql:    "INSERT INTO post_logout_redirect_uris (created_at, uri, client_id) OUTPUT INSERTED.id VALUES (@p1, @p2, @p3)",
}

var selectPostLogoutRedirectURIsByClientId = statement{
	sqlite:   "SELECT " + postLogoutRedirectURIColumns.sqlite + " FROM post_logout_redirect_uris WHERE client_id = ?",
	mysql:    "SELECT " + postLogoutRedirectURIColumns.mysql + " FROM post_logout_redirect_uris WHERE client_id = ?",
	postgres: "SELECT " + postLogoutRedirectURIColumns.postgres + " FROM post_logout_redirect_uris WHERE client_id = $1",
	mssql:    "SELECT " + postLogoutRedirectURIColumns.mssql + " FROM post_logout_redirect_uris WHERE client_id = @p1",
}

// selectClientsByPostLogoutRedirectURI is every client with a sign-out redirect URI the engine calls
// equal to the one asked for, one row per matching URI, with that URI last so the caller can recheck
// the match. The URIs are selected in a derived table under a name of their own, so the client
// columns, which share none of its names, read unqualified. uri is not indexed, since a 2048-wide
// column cannot be indexed whole on MySQL or SQL Server, so this scans the sign-out table, which
// holds only sign-out targets (#147 decision 10).
var selectClientsByPostLogoutRedirectURI = statement{
	sqlite: "SELECT " + clientColumns.sqlite + ", signout_uri FROM clients INNER JOIN " +
		"(SELECT client_id, uri AS signout_uri FROM post_logout_redirect_uris WHERE uri = ?) AS matches " +
		"ON clients.id = matches.client_id ORDER BY clients.id",
	mysql: "SELECT " + clientColumns.mysql + ", signout_uri FROM clients INNER JOIN " +
		"(SELECT client_id, uri AS signout_uri FROM post_logout_redirect_uris WHERE uri = ?) AS matches " +
		"ON clients.id = matches.client_id ORDER BY clients.id",
	postgres: "SELECT " + clientColumns.postgres + ", signout_uri FROM clients INNER JOIN " +
		"(SELECT client_id, uri AS signout_uri FROM post_logout_redirect_uris WHERE uri = $1) AS matches " +
		"ON clients.id = matches.client_id ORDER BY clients.id",
	mssql: "SELECT " + clientColumns.mssql + ", signout_uri FROM clients INNER JOIN " +
		"(SELECT client_id, uri AS signout_uri FROM post_logout_redirect_uris WHERE uri = @p1) AS matches " +
		"ON clients.id = matches.client_id ORDER BY clients.id",
}

var deletePostLogoutRedirectURI = statement{
	sqlite:   "DELETE FROM post_logout_redirect_uris WHERE id = ?",
	mysql:    "DELETE FROM post_logout_redirect_uris WHERE id = ?",
	postgres: "DELETE FROM post_logout_redirect_uris WHERE id = $1",
	mssql:    "DELETE FROM post_logout_redirect_uris WHERE id = @p1",
}

func (d *Database) CreatePostLogoutRedirectURI(ctx context.Context, tx *sql.Tx, postLogoutRedirectURI *record.PostLogoutRedirectURI) error {

	if postLogoutRedirectURI.ClientId == 0 {
		return errs.New("client id must be greater than 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := postLogoutRedirectURI.CreatedAt
	postLogoutRedirectURI.CreatedAt = sql.NullTime{Time: now, Valid: true}

	id, err := d.insert(ctx, tx, insertPostLogoutRedirectURI, "postLogoutRedirectURI",
		postLogoutRedirectURI.CreatedAt, postLogoutRedirectURI.URI, postLogoutRedirectURI.ClientId)
	if err != nil {
		postLogoutRedirectURI.CreatedAt = originalCreatedAt
		return err
	}

	postLogoutRedirectURI.Id = id
	return nil
}

func (d *Database) GetPostLogoutRedirectURIsByClientId(ctx context.Context, tx *sql.Tx, clientId int64) ([]record.PostLogoutRedirectURI, error) {
	return queryAll(ctx, d, tx, []record.PostLogoutRedirectURI{}, selectPostLogoutRedirectURIsByClientId.text(d.Dialect),
		[]any{clientId}, scanPostLogoutRedirectURI, "postLogoutRedirectURI")
}

// clientHoldingURI is one row of selectClientsByPostLogoutRedirectURI: a client and the sign-out
// redirect URI of its that the engine matched.
type clientHoldingURI struct {
	client record.Client
	uri    string
}

// scanClientHoldingURI reads the client columns with scanClient and the matched URI after them.
func scanClientHoldingURI(row rowScanner, held *clientHoldingURI) error {
	return scanClient(trailingScan{row: row, extra: []any{&held.uri}}, &held.client)
}

// trailingScan hands a scan function's destinations to row with extra ones after them, so a row
// carrying more columns than a record reads through that record's own scan function.
type trailingScan struct {
	row   rowScanner
	extra []any
}

func (s trailingScan) Scan(dest ...any) error {
	return s.row.Scan(append(dest, s.extra...)...)
}

// GetClientsByPostLogoutRedirectURI answers the clients whose sign-out redirect URIs hold uri,
// each once, in id order, and an empty list when none does (#147 decision 10).
//
// The match is exact. The engine's answer is rechecked in Go, because SQL Server pads for `=` and
// SQL Server and MySQL fold a composed accent onto its decomposed spelling under every collation:
// see engineFoldedTheMatch. RP-Initiated Logout 1.0 section 3 requires the value to "exactly match
// one of the previously registered post_logout_redirect_uris values". A client holding the URI more
// than once, which the list save refuses but the table allows, is answered once, so the caller's
// count of matching clients is a count of clients.
func (d *Database) GetClientsByPostLogoutRedirectURI(ctx context.Context, tx *sql.Tx, uri string) ([]record.Client, error) {

	rows, err := queryAll(ctx, d, tx, nil, selectClientsByPostLogoutRedirectURI.text(d.Dialect), []any{uri},
		scanClientHoldingURI, "client")
	if err != nil {
		return nil, err
	}

	clients := []record.Client{}
	seen := map[int64]bool{}
	for _, held := range rows {
		if engineFoldedTheMatch(held.uri, uri) || seen[held.client.Id] {
			continue
		}
		seen[held.client.Id] = true
		clients = append(clients, held.client)
	}

	return clients, nil
}

func (d *Database) DeletePostLogoutRedirectURI(ctx context.Context, tx *sql.Tx, postLogoutRedirectURIId int64) error {

	_, err := d.ExecSQL(ctx, tx, deletePostLogoutRedirectURI.text(d.Dialect), postLogoutRedirectURIId)
	if err != nil {
		return errs.Wrap(err, "unable to delete postLogoutRedirectURI")
	}

	return nil
}
