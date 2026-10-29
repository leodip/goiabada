package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

var deleteDeletedClient = statement{
	sqlite:   "DELETE FROM deleted_clients WHERE client_identifier = ?",
	mysql:    "DELETE FROM deleted_clients WHERE client_identifier = ?",
	postgres: "DELETE FROM deleted_clients WHERE client_identifier = $1",
	mssql:    "DELETE FROM deleted_clients WHERE client_identifier = @p1",
}

// insertDeletedClient writes the whole record, which has no id: the identifier is its key.
var insertDeletedClient = statement{
	sqlite:   "INSERT INTO deleted_clients (client_identifier, deleted_at) VALUES (?, ?)",
	mysql:    "INSERT INTO deleted_clients (client_identifier, deleted_at) VALUES (?, ?)",
	postgres: "INSERT INTO deleted_clients (client_identifier, deleted_at) VALUES ($1, $2)",
	mssql:    "INSERT INTO deleted_clients (client_identifier, deleted_at) VALUES (@p1, @p2)",
}

var selectDeletedClient = statement{
	sqlite:   "SELECT client_identifier, deleted_at FROM deleted_clients WHERE client_identifier = ?",
	mysql:    "SELECT client_identifier, deleted_at FROM deleted_clients WHERE client_identifier = ?",
	postgres: "SELECT client_identifier, deleted_at FROM deleted_clients WHERE client_identifier = $1",
	mssql:    "SELECT client_identifier, deleted_at FROM deleted_clients WHERE client_identifier = @p1",
}

// A deleted client's identifier is recorded with the moment of its deletion (#676 decision 6). An
// access token names its client only by client_id, which a new client may take, and its iat has
// whole seconds, so a token issued in a client's creation second cannot be placed before or after
// the creation by its own claims: the access-token liveness check reads this record for it.
//
// An empty identifier is an error in both methods below: no client has one, so it can only be a
// caller bug.

// recordClientDeleted writes the record of one deletion, on the deleting transaction, replacing the
// record of an earlier deletion of the same identifier: only the latest can precede a client that
// exists now. The delete and the insert run on the transaction DeleteClient holds, after it deleted
// the clients row, so two deletions of one identifier are ordered by that row.
func (d *Database) recordClientDeleted(ctx context.Context, tx *sql.Tx, clientIdentifier string, deletedAt time.Time) error {

	if clientIdentifier == "" {
		return errs.New("can't record the deletion of a client with an empty identifier")
	}

	if _, err := d.ExecSQL(ctx, tx, deleteDeletedClient.text(d.Dialect), clientIdentifier); err != nil {
		return errs.Wrap(err, "unable to replace the record of a deleted client")
	}
	deleted := &record.DeletedClient{ClientIdentifier: clientIdentifier, DeletedAt: deletedAt.UTC()}
	if _, err := d.ExecSQL(ctx, tx, insertDeletedClient.text(d.Dialect), deleted.ClientIdentifier, deleted.DeletedAt); err != nil {
		return errs.Wrap(err, "unable to record the deleted client")
	}
	return nil
}

// GetDeletedClientByClientIdentifier returns the record of the latest deletion of a client with
// this identifier, or nil when none was deleted.
//
// The row that comes back is compared with the identifier it was asked for in Go, for the reason
// GetAuthorizeRequestByHandleHash states: SQL Server pads for `=` under every collation, so an
// identifier with trailing spaces would find the record of the one without (#283).
func (d *Database) GetDeletedClientByClientIdentifier(ctx context.Context, tx *sql.Tx,
	clientIdentifier string) (*record.DeletedClient, error) {

	if clientIdentifier == "" {
		return nil, errs.New("can't look up a deleted client with an empty identifier")
	}

	rows, err := d.QuerySQL(ctx, tx, selectDeletedClient.text(d.Dialect), clientIdentifier)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		var deleted record.DeletedClient
		if err := rows.Scan(&deleted.ClientIdentifier, &deleted.DeletedAt); err != nil {
			return nil, errs.Wrap(err, "unable to scan deleted client")
		}
		if engineFoldedTheMatch(deleted.ClientIdentifier, clientIdentifier) {
			return nil, nil
		}
		return &deleted, nil
	}
	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return nil, nil
}
