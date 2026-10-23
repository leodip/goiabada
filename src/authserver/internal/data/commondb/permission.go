package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/errs"
)

// permissionColumns is the permissions table as scanPermission reads it.
var permissionColumns = columnList{
	sqlite:   "id, created_at, updated_at, permission_identifier, description, resource_id",
	mysql:    "id, created_at, updated_at, permission_identifier, description, resource_id",
	postgres: "id, created_at, updated_at, permission_identifier, description, resource_id",
	mssql:    "id, created_at, updated_at, permission_identifier, description, resource_id",
}

// scanPermission reads one row selected with permissionColumns.
func scanPermission(row rowScanner, permission *record.Permission) error {
	return row.Scan(
		&permission.Id,
		&permission.CreatedAt,
		&permission.UpdatedAt,
		&permission.PermissionIdentifier,
		&permission.Description,
		&permission.ResourceId,
	)
}

var insertPermission = statement{
	sqlite:   "INSERT INTO permissions (created_at, updated_at, permission_identifier, description, resource_id) VALUES (?, ?, ?, ?, ?)",
	mysql:    "INSERT INTO permissions (created_at, updated_at, permission_identifier, description, resource_id) VALUES (?, ?, ?, ?, ?)",
	postgres: "INSERT INTO permissions (created_at, updated_at, permission_identifier, description, resource_id) VALUES ($1, $2, $3, $4, $5) RETURNING id",
	mssql:    "INSERT INTO permissions (created_at, updated_at, permission_identifier, description, resource_id) OUTPUT INSERTED.id VALUES (@p1, @p2, @p3, @p4, @p5)",
}

// updatePermission writes the whole row but created_at, which is dont-update.
var updatePermission = statement{
	sqlite:   "UPDATE permissions SET updated_at = ?, permission_identifier = ?, description = ?, resource_id = ? WHERE id = ?",
	mysql:    "UPDATE permissions SET updated_at = ?, permission_identifier = ?, description = ?, resource_id = ? WHERE id = ?",
	postgres: "UPDATE permissions SET updated_at = $1, permission_identifier = $2, description = $3, resource_id = $4 WHERE id = $5",
	mssql:    "UPDATE permissions SET updated_at = @p1, permission_identifier = @p2, description = @p3, resource_id = @p4 WHERE id = @p5",
}

var selectPermissionById = statement{
	sqlite:   "SELECT " + permissionColumns.sqlite + " FROM permissions WHERE id = ?",
	mysql:    "SELECT " + permissionColumns.mysql + " FROM permissions WHERE id = ?",
	postgres: "SELECT " + permissionColumns.postgres + " FROM permissions WHERE id = $1",
	mssql:    "SELECT " + permissionColumns.mssql + " FROM permissions WHERE id = @p1",
}

var selectPermissionsByResourceId = statement{
	sqlite:   "SELECT " + permissionColumns.sqlite + " FROM permissions WHERE resource_id = ?",
	mysql:    "SELECT " + permissionColumns.mysql + " FROM permissions WHERE resource_id = ?",
	postgres: "SELECT " + permissionColumns.postgres + " FROM permissions WHERE resource_id = $1",
	mssql:    "SELECT " + permissionColumns.mssql + " FROM permissions WHERE resource_id = @p1",
}

// selectPermissionsWhere is completed by an IN list of permission ids.
var selectPermissionsWhere = statement{
	sqlite:   "SELECT " + permissionColumns.sqlite + " FROM permissions WHERE ",
	mysql:    "SELECT " + permissionColumns.mysql + " FROM permissions WHERE ",
	postgres: "SELECT " + permissionColumns.postgres + " FROM permissions WHERE ",
	mssql:    "SELECT " + permissionColumns.mssql + " FROM permissions WHERE ",
}

var deletePermission = statement{
	sqlite:   "DELETE FROM permissions WHERE id = ?",
	mysql:    "DELETE FROM permissions WHERE id = ?",
	postgres: "DELETE FROM permissions WHERE id = $1",
	mssql:    "DELETE FROM permissions WHERE id = @p1",
}

// acquireManagePermission assigns permission_identifier to itself on the authserver resource's
// manage permission, which is a write that takes the row and changes nothing.
var acquireManagePermission = statement{
	sqlite: "UPDATE permissions SET permission_identifier = permission_identifier WHERE permission_identifier = ? " +
		"AND EXISTS (SELECT 1 FROM resources WHERE resources.id = permissions.resource_id AND resources.resource_identifier = ?)",
	mysql: "UPDATE permissions SET permission_identifier = permission_identifier WHERE permission_identifier = ? " +
		"AND EXISTS (SELECT 1 FROM resources WHERE resources.id = permissions.resource_id AND resources.resource_identifier = ?)",
	postgres: "UPDATE permissions SET permission_identifier = permission_identifier WHERE permission_identifier = $1 " +
		"AND EXISTS (SELECT 1 FROM resources WHERE resources.id = permissions.resource_id AND resources.resource_identifier = $2)",
	mssql: "UPDATE permissions SET permission_identifier = permission_identifier WHERE permission_identifier = @p1 " +
		"AND EXISTS (SELECT 1 FROM resources WHERE resources.id = permissions.resource_id AND resources.resource_identifier = @p2)",
}

var selectManagePermission = statement{
	sqlite: "SELECT permissions.id, permissions.permission_identifier, resources.resource_identifier FROM permissions " +
		"INNER JOIN resources ON resources.id = permissions.resource_id " +
		"WHERE permissions.permission_identifier = ? AND resources.resource_identifier = ?",
	mysql: "SELECT permissions.id, permissions.permission_identifier, resources.resource_identifier FROM permissions " +
		"INNER JOIN resources ON resources.id = permissions.resource_id " +
		"WHERE permissions.permission_identifier = ? AND resources.resource_identifier = ?",
	postgres: "SELECT permissions.id, permissions.permission_identifier, resources.resource_identifier FROM permissions " +
		"INNER JOIN resources ON resources.id = permissions.resource_id " +
		"WHERE permissions.permission_identifier = $1 AND resources.resource_identifier = $2",
	mssql: "SELECT permissions.id, permissions.permission_identifier, resources.resource_identifier FROM permissions " +
		"INNER JOIN resources ON resources.id = permissions.resource_id " +
		"WHERE permissions.permission_identifier = @p1 AND resources.resource_identifier = @p2",
}

func (d *Database) CreatePermission(ctx context.Context, tx *sql.Tx, permission *record.Permission) error {

	if permission.ResourceId == 0 {
		return errs.New("can't create permission with resource_id 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := permission.CreatedAt
	originalUpdatedAt := permission.UpdatedAt
	permission.CreatedAt = sql.NullTime{Time: now, Valid: true}
	permission.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	id, err := d.insert(ctx, tx, insertPermission, "permission",
		permission.CreatedAt, permission.UpdatedAt, permission.PermissionIdentifier, permission.Description,
		permission.ResourceId)
	if err != nil {
		permission.CreatedAt = originalCreatedAt
		permission.UpdatedAt = originalUpdatedAt
		return err
	}

	permission.Id = id
	return nil
}

func (d *Database) UpdatePermission(ctx context.Context, tx *sql.Tx, permission *record.Permission) error {

	if permission.Id == 0 {
		return errs.New("can't update permission with id 0")
	}

	originalUpdatedAt := permission.UpdatedAt
	permission.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	_, err := d.ExecSQL(ctx, tx, updatePermission.text(d.Dialect),
		permission.UpdatedAt, permission.PermissionIdentifier, permission.Description, permission.ResourceId,
		permission.Id)
	if err != nil {
		permission.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update permission")
	}

	return nil
}

func (d *Database) GetPermissionById(ctx context.Context, tx *sql.Tx, permissionId int64) (*record.Permission, error) {
	return queryOne(ctx, d, tx, selectPermissionById.text(d.Dialect), []any{permissionId}, scanPermission, "permission")
}

func (d *Database) GetPermissionsByResourceId(ctx context.Context, tx *sql.Tx, resourceId int64) ([]record.Permission, error) {
	return queryAll(ctx, d, tx, nil, selectPermissionsByResourceId.text(d.Dialect), []any{resourceId},
		scanPermission, "permission")
}

func (d *Database) PermissionsLoadResources(ctx context.Context, tx *sql.Tx, permissions []record.Permission) error {

	if permissions == nil {
		return nil
	}

	resourceIds := make([]int64, 0, len(permissions))
	for _, permission := range permissions {
		resourceIds = append(resourceIds, permission.ResourceId)
	}

	resources, err := d.GetResourcesByIds(ctx, tx, resourceIds)
	if err != nil {
		return errs.Wrap(err, "unable to get resources for permissions")
	}

	resourceMap := make(map[int64]record.Resource, len(resources))
	for _, resource := range resources {
		resourceMap[resource.Id] = resource
	}

	for i := range permissions {
		permissions[i].Resource = resourceMap[permissions[i].ResourceId]
	}

	return nil
}

func (d *Database) GetPermissionsByIds(ctx context.Context, tx *sql.Tx, permissionIds []int64) ([]record.Permission, error) {

	if len(permissionIds) == 0 {
		return nil, nil
	}

	var permissions []record.Permission

	err := forEachIdBatch(permissionIds, func(batch []int64) error {
		query := selectPermissionsWhere.text(d.Dialect) + inList(d.Dialect, "id", 1, len(batch))
		var err error
		permissions, err = queryAll(ctx, d, tx, permissions, query, int64Args(batch), scanPermission, "permission")
		return err
	})
	if err != nil {
		return nil, err
	}

	return permissions, nil
}

func (d *Database) DeletePermission(ctx context.Context, tx *sql.Tx, permissionId int64) error {

	_, err := d.ExecSQL(ctx, tx, deletePermission.text(d.Dialect), permissionId)
	if err != nil {
		return errs.Wrap(err, "unable to delete permission")
	}

	return nil
}

// AcquireManagePermissionRow takes the authserver resource's manage permission row and holds it for
// the rest of the caller's transaction, the way AcquireUserRow holds a user's: one UPDATE assigning
// a column to itself, which waits for any transaction holding the row and makes the next one wait
// for this. It answers the permission's id, read on the transaction after the acquisition.
//
// Every write that can remove the last holder of authserver:manage takes this row first, then
// decides under it whether it removes a holder and counts the holders left (#402 decision 11). Two
// removals of the last two administrators touch no common row otherwise: each counts two inside its
// own transaction, neither sees the other's uncommitted change on MySQL, PostgreSQL or SQL Server,
// and both commit. With both taking this row, the second waits, and a read after the wait sees what
// the first committed. A read taken before the acquisition would not, which is why the acquisition
// is the first statement and the id comes from a read after it.
//
// The row is found by its two identifiers, the resource's through a correlated EXISTS, so the
// acquisition needs no read before it. permission_identifier is unique only per resource, and a custom
// resource can declare a manage permission of its own, which is not the administrators'.
//
// No manage permission is an error, not a benign answer: a lock that holds nothing serializes
// nothing, and the guard behind it would count unprotected. RowsAffected cannot tell, since MySQL
// counts a row whose columns did not change as unaffected, so the read after the acquisition is what
// decides it. That read compares the identifiers in Go as well, because SQL Server pads for `=` and
// would match an identifier with trailing spaces (engineFoldedTheMatch).
//
// tx is required: without one the statement autocommits and the row is released before the caller
// can count under it.
func (d *Database) AcquireManagePermissionRow(ctx context.Context, tx *sql.Tx) (int64, error) {

	if tx == nil {
		return 0, errs.New("acquiring the manage permission row requires a transaction: an autocommitted statement releases the row before the caller can count under it")
	}

	_, err := d.ExecSQL(ctx, tx, acquireManagePermission.text(d.Dialect),
		builtin.ManagePermissionIdentifier, builtin.AuthServerResourceIdentifier)
	if err != nil {
		return 0, errs.Wrap(err, "unable to acquire the manage permission row")
	}

	rows, err := d.QuerySQL(ctx, tx, selectManagePermission.text(d.Dialect),
		builtin.ManagePermissionIdentifier, builtin.AuthServerResourceIdentifier)
	if err != nil {
		return 0, errs.Wrap(err, "unable to read the manage permission row")
	}
	defer func() { _ = rows.Close() }()

	var found []int64
	for rows.Next() {
		var id int64
		var permissionIdentifier, resourceIdentifier string
		if err := rows.Scan(&id, &permissionIdentifier, &resourceIdentifier); err != nil {
			return 0, errs.Wrap(err, "unable to scan the manage permission row")
		}
		if engineFoldedTheMatch(permissionIdentifier, builtin.ManagePermissionIdentifier) ||
			engineFoldedTheMatch(resourceIdentifier, builtin.AuthServerResourceIdentifier) {
			continue
		}
		found = append(found, id)
	}
	if err := rows.Err(); err != nil {
		return 0, errs.Wrap(err, "unable to read query results")
	}

	if len(found) != 1 {
		return 0, errs.Errorf("expected one %s:%s permission row to acquire, found %d",
			builtin.AuthServerResourceIdentifier, builtin.ManagePermissionIdentifier, len(found))
	}

	return found[0], nil
}
