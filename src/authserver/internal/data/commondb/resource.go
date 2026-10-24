package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// resourceColumns is the resources table as scanResource reads it.
var resourceColumns = columnList{
	sqlite:   "id, created_at, updated_at, resource_identifier, description",
	mysql:    "id, created_at, updated_at, resource_identifier, description",
	postgres: "id, created_at, updated_at, resource_identifier, description",
	mssql:    "id, created_at, updated_at, resource_identifier, description",
}

// scanResource reads one row selected with resourceColumns.
func scanResource(row rowScanner, resource *record.Resource) error {
	return row.Scan(
		&resource.Id,
		&resource.CreatedAt,
		&resource.UpdatedAt,
		&resource.ResourceIdentifier,
		&resource.Description,
	)
}

var insertResource = statement{
	sqlite:   "INSERT INTO resources (created_at, updated_at, resource_identifier, description) VALUES (?, ?, ?, ?)",
	mysql:    "INSERT INTO resources (created_at, updated_at, resource_identifier, description) VALUES (?, ?, ?, ?)",
	postgres: "INSERT INTO resources (created_at, updated_at, resource_identifier, description) VALUES ($1, $2, $3, $4) RETURNING id",
	mssql:    "INSERT INTO resources (created_at, updated_at, resource_identifier, description) OUTPUT INSERTED.id VALUES (@p1, @p2, @p3, @p4)",
}

// updateResource writes the whole row but created_at, which is dont-update.
var updateResource = statement{
	sqlite:   "UPDATE resources SET updated_at = ?, resource_identifier = ?, description = ? WHERE id = ?",
	mysql:    "UPDATE resources SET updated_at = ?, resource_identifier = ?, description = ? WHERE id = ?",
	postgres: "UPDATE resources SET updated_at = $1, resource_identifier = $2, description = $3 WHERE id = $4",
	mssql:    "UPDATE resources SET updated_at = @p1, resource_identifier = @p2, description = @p3 WHERE id = @p4",
}

var selectResourceById = statement{
	sqlite:   "SELECT " + resourceColumns.sqlite + " FROM resources WHERE id = ?",
	mysql:    "SELECT " + resourceColumns.mysql + " FROM resources WHERE id = ?",
	postgres: "SELECT " + resourceColumns.postgres + " FROM resources WHERE id = $1",
	mssql:    "SELECT " + resourceColumns.mssql + " FROM resources WHERE id = @p1",
}

var selectResourceByResourceIdentifier = statement{
	sqlite:   "SELECT " + resourceColumns.sqlite + " FROM resources WHERE resource_identifier = ?",
	mysql:    "SELECT " + resourceColumns.mysql + " FROM resources WHERE resource_identifier = ?",
	postgres: "SELECT " + resourceColumns.postgres + " FROM resources WHERE resource_identifier = $1",
	mssql:    "SELECT " + resourceColumns.mssql + " FROM resources WHERE resource_identifier = @p1",
}

// selectResourcesWhere is completed by an IN list of resource ids.
var selectResourcesWhere = statement{
	sqlite:   "SELECT " + resourceColumns.sqlite + " FROM resources WHERE ",
	mysql:    "SELECT " + resourceColumns.mysql + " FROM resources WHERE ",
	postgres: "SELECT " + resourceColumns.postgres + " FROM resources WHERE ",
	mssql:    "SELECT " + resourceColumns.mssql + " FROM resources WHERE ",
}

var selectAllResources = statement{
	sqlite:   "SELECT " + resourceColumns.sqlite + " FROM resources",
	mysql:    "SELECT " + resourceColumns.mysql + " FROM resources",
	postgres: "SELECT " + resourceColumns.postgres + " FROM resources",
	mssql:    "SELECT " + resourceColumns.mssql + " FROM resources",
}

var selectIdentifiersSharedByClientsAndResources = statement{
	sqlite: "SELECT clients.client_identifier, resources.resource_identifier FROM clients " +
		"INNER JOIN resources ON clients.client_identifier = resources.resource_identifier ORDER BY clients.client_identifier",
	mysql: "SELECT clients.client_identifier, resources.resource_identifier FROM clients " +
		"INNER JOIN resources ON clients.client_identifier = resources.resource_identifier ORDER BY clients.client_identifier",
	postgres: "SELECT clients.client_identifier, resources.resource_identifier FROM clients " +
		"INNER JOIN resources ON clients.client_identifier = resources.resource_identifier ORDER BY clients.client_identifier",
	mssql: "SELECT clients.client_identifier, resources.resource_identifier FROM clients " +
		"INNER JOIN resources ON clients.client_identifier = resources.resource_identifier ORDER BY clients.client_identifier",
}

var deleteResource = statement{
	sqlite:   "DELETE FROM resources WHERE id = ?",
	mysql:    "DELETE FROM resources WHERE id = ?",
	postgres: "DELETE FROM resources WHERE id = $1",
	mssql:    "DELETE FROM resources WHERE id = @p1",
}

func (d *Database) CreateResource(ctx context.Context, tx *sql.Tx, resource *record.Resource) error {

	now := time.Now().UTC()

	originalCreatedAt := resource.CreatedAt
	originalUpdatedAt := resource.UpdatedAt
	resource.CreatedAt = sql.NullTime{Time: now, Valid: true}
	resource.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	id, err := d.insert(ctx, tx, insertResource, "resource",
		resource.CreatedAt, resource.UpdatedAt, resource.ResourceIdentifier, resource.Description)
	if err != nil {
		resource.CreatedAt = originalCreatedAt
		resource.UpdatedAt = originalUpdatedAt
		return err
	}

	resource.Id = id
	return nil
}

func (d *Database) UpdateResource(ctx context.Context, tx *sql.Tx, resource *record.Resource) error {

	if resource.Id == 0 {
		return errs.New("can't update resource with id 0")
	}

	originalUpdatedAt := resource.UpdatedAt
	resource.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	_, err := d.ExecSQL(ctx, tx, updateResource.text(d.Dialect),
		resource.UpdatedAt, resource.ResourceIdentifier, resource.Description, resource.Id)
	if err != nil {
		resource.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update resource")
	}

	return nil
}

func (d *Database) GetResourceById(ctx context.Context, tx *sql.Tx, resourceId int64) (*record.Resource, error) {
	return queryOne(ctx, d, tx, selectResourceById.text(d.Dialect), []any{resourceId}, scanResource, "resource")
}

func (d *Database) GetResourceByResourceIdentifier(ctx context.Context, tx *sql.Tx, resourceIdentifier string) (*record.Resource, error) {

	resource, err := queryOne(ctx, d, tx, selectResourceByResourceIdentifier.text(d.Dialect),
		[]any{resourceIdentifier}, scanResource, "resource")
	if err != nil {
		return nil, err
	}
	// The engine may have folded a value this lookup did not ask for; see
	// engineFoldedTheMatch. RFC 6749 section 3.3 makes the scope string, whose first half
	// this resolves, case sensitive.
	if resource != nil && engineFoldedTheMatch(resource.ResourceIdentifier, resourceIdentifier) {
		return nil, nil
	}

	return resource, nil
}

func (d *Database) GetResourcesByIds(ctx context.Context, tx *sql.Tx, resourceIds []int64) ([]record.Resource, error) {

	if len(resourceIds) == 0 {
		return nil, nil
	}

	var resources []record.Resource

	err := forEachIdBatch(resourceIds, func(batch []int64) error {
		query := selectResourcesWhere.text(d.Dialect) + inList(d.Dialect, "id", 1, len(batch))
		var err error
		resources, err = queryAll(ctx, d, tx, resources, query, int64Args(batch), scanResource, "resource")
		return err
	})
	if err != nil {
		return nil, err
	}

	return resources, nil
}

func (d *Database) GetAllResources(ctx context.Context, tx *sql.Tx) ([]record.Resource, error) {
	return queryAll(ctx, d, tx, nil, selectAllResources.text(d.Dialect), nil, scanResource, "resource")
}

// GetIdentifiersSharedByClientsAndResources joins the two tables on their identifiers and keeps
// only the rows whose two strings are the same string, because the engine may have folded a pair
// that is not; see engineFoldedTheMatch. A pair the engine does not join is not one either: both
// columns carry the same case- and accent-sensitive collation on every engine.
func (d *Database) GetIdentifiersSharedByClientsAndResources(ctx context.Context, tx *sql.Tx) ([]string, error) {
	rows, err := d.QuerySQL(ctx, tx, selectIdentifiersSharedByClientsAndResources.text(d.Dialect))
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var identifiers []string
	for rows.Next() {
		var clientIdentifier, resourceIdentifier string
		if err := rows.Scan(&clientIdentifier, &resourceIdentifier); err != nil {
			return nil, errs.Wrap(err, "unable to scan shared identifier")
		}
		if engineFoldedTheMatch(resourceIdentifier, clientIdentifier) {
			continue
		}
		identifiers = append(identifiers, clientIdentifier)
	}

	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return identifiers, nil
}

func (d *Database) DeleteResource(ctx context.Context, tx *sql.Tx, resourceId int64) error {

	_, err := d.ExecSQL(ctx, tx, deleteResource.text(d.Dialect), resourceId)
	if err != nil {
		return errs.Wrap(err, "unable to delete resource")
	}

	return nil
}
