package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// The resources whose tokens a confidential client may introspect (#676 decisions 5 and 14). A row
// is created and deleted, never rewritten, so there is no whole-row UPDATE.

// clientIntrospectionResourceColumns is the clients_introspection_resources table as
// scanClientIntrospectionResource reads it.
var clientIntrospectionResourceColumns = columnList{
	sqlite:   "id, created_at, client_id, resource_id",
	mysql:    "id, created_at, client_id, resource_id",
	postgres: "id, created_at, client_id, resource_id",
	mssql:    "id, created_at, client_id, resource_id",
}

// scanClientIntrospectionResource reads one row selected with clientIntrospectionResourceColumns.
func scanClientIntrospectionResource(row rowScanner, link *record.ClientIntrospectionResource) error {
	return row.Scan(
		&link.ID,
		&link.CreatedAt,
		&link.ClientID,
		&link.ResourceID,
	)
}

var insertClientIntrospectionResource = statement{
	sqlite:   "INSERT INTO clients_introspection_resources (created_at, client_id, resource_id) VALUES (?, ?, ?)",
	mysql:    "INSERT INTO clients_introspection_resources (created_at, client_id, resource_id) VALUES (?, ?, ?)",
	postgres: "INSERT INTO clients_introspection_resources (created_at, client_id, resource_id) VALUES ($1, $2, $3) RETURNING id",
	mssql:    "INSERT INTO clients_introspection_resources (created_at, client_id, resource_id) OUTPUT INSERTED.id VALUES (@p1, @p2, @p3)",
}

var selectClientIntrospectionResourcesByClientID = statement{
	sqlite:   "SELECT " + clientIntrospectionResourceColumns.sqlite + " FROM clients_introspection_resources WHERE client_id = ?",
	mysql:    "SELECT " + clientIntrospectionResourceColumns.mysql + " FROM clients_introspection_resources WHERE client_id = ?",
	postgres: "SELECT " + clientIntrospectionResourceColumns.postgres + " FROM clients_introspection_resources WHERE client_id = $1",
	mssql:    "SELECT " + clientIntrospectionResourceColumns.mssql + " FROM clients_introspection_resources WHERE client_id = @p1",
}

var deleteClientIntrospectionResource = statement{
	sqlite:   "DELETE FROM clients_introspection_resources WHERE id = ?",
	mysql:    "DELETE FROM clients_introspection_resources WHERE id = ?",
	postgres: "DELETE FROM clients_introspection_resources WHERE id = $1",
	mssql:    "DELETE FROM clients_introspection_resources WHERE id = @p1",
}

var deleteClientIntrospectionResourcesByClientID = statement{
	sqlite:   "DELETE FROM clients_introspection_resources WHERE client_id = ?",
	mysql:    "DELETE FROM clients_introspection_resources WHERE client_id = ?",
	postgres: "DELETE FROM clients_introspection_resources WHERE client_id = $1",
	mssql:    "DELETE FROM clients_introspection_resources WHERE client_id = @p1",
}

func (d *Database) CreateClientIntrospectionResource(ctx context.Context, tx *sql.Tx, link *record.ClientIntrospectionResource) error {

	if link.ClientID == 0 {
		return errs.New("can't create clientIntrospectionResource with client_id 0")
	}

	if link.ResourceID == 0 {
		return errs.New("can't create clientIntrospectionResource with resource_id 0")
	}

	originalCreatedAt := link.CreatedAt
	link.CreatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	id, err := d.insert(ctx, tx, insertClientIntrospectionResource, "clientIntrospectionResource",
		link.CreatedAt, link.ClientID, link.ResourceID)
	if err != nil {
		link.CreatedAt = originalCreatedAt
		return err
	}

	link.ID = id
	return nil
}

func (d *Database) GetClientIntrospectionResourcesByClientID(ctx context.Context, tx *sql.Tx, clientID int64) ([]record.ClientIntrospectionResource, error) {
	return queryAll(ctx, d, tx, nil, selectClientIntrospectionResourcesByClientID.text(d.Dialect), []any{clientID},
		scanClientIntrospectionResource, "clientIntrospectionResource")
}

func (d *Database) DeleteClientIntrospectionResource(ctx context.Context, tx *sql.Tx, clientIntrospectionResourceID int64) error {

	_, err := d.ExecSQL(ctx, tx, deleteClientIntrospectionResource.text(d.Dialect), clientIntrospectionResourceID)
	if err != nil {
		return errs.Wrap(err, "unable to delete clientIntrospectionResource")
	}

	return nil
}

func (d *Database) DeleteClientIntrospectionResourcesByClientID(ctx context.Context, tx *sql.Tx, clientID int64) error {

	_, err := d.ExecSQL(ctx, tx, deleteClientIntrospectionResourcesByClientID.text(d.Dialect), clientID)
	if err != nil {
		return errs.Wrap(err, "unable to delete the client's introspection resources")
	}

	return nil
}
