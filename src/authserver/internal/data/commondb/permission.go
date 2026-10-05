package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/errs"
)

func (d *Database) CreatePermission(ctx context.Context, tx *sql.Tx, permission *record.Permission) error {

	if permission.ResourceId == 0 {
		return errs.New("can't create permission with resource_id 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := permission.CreatedAt
	originalUpdatedAt := permission.UpdatedAt
	permission.CreatedAt = sql.NullTime{Time: now, Valid: true}
	permission.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	permissionStruct := sqlbuilder.NewStruct(new(record.Permission)).
		For(d.Flavor)

	insertBuilder := permissionStruct.WithoutTag("pk").InsertInto("permissions", permission)

	id, err := d.insertReturningId(ctx, tx, insertBuilder, "permission")
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

	permissionStruct := sqlbuilder.NewStruct(new(record.Permission)).
		For(d.Flavor)

	updateBuilder := permissionStruct.WithoutTag("pk").WithoutTag("dont-update").Update("permissions", permission)
	updateBuilder.Where(updateBuilder.Equal("id", permission.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSQL(ctx, tx, sql, args...)
	if err != nil {
		permission.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update permission")
	}

	return nil
}

func (d *Database) getPermissionCommon(ctx context.Context, tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	permissionStruct *sqlbuilder.Struct) (*record.Permission, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySQL(ctx, tx, sql, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var permission record.Permission
	if rows.Next() {
		addr := permissionStruct.Addr(&permission)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errs.Wrap(err, "unable to scan permission")
		}
		return &permission, nil
	}
	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return nil, nil
}

func (d *Database) GetPermissionById(ctx context.Context, tx *sql.Tx, permissionId int64) (*record.Permission, error) {

	permissionStruct := sqlbuilder.NewStruct(new(record.Permission)).
		For(d.Flavor)

	selectBuilder := permissionStruct.SelectFrom("permissions")
	selectBuilder.Where(selectBuilder.Equal("id", permissionId))

	permission, err := d.getPermissionCommon(ctx, tx, selectBuilder, permissionStruct)
	if err != nil {
		return nil, err
	}

	return permission, nil
}

func (d *Database) GetPermissionsByResourceId(ctx context.Context, tx *sql.Tx, resourceId int64) ([]record.Permission, error) {

	permissionStruct := sqlbuilder.NewStruct(new(record.Permission)).
		For(d.Flavor)

	selectBuilder := permissionStruct.SelectFrom("permissions")
	selectBuilder.Where(selectBuilder.Equal("resource_id", resourceId))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySQL(ctx, tx, sql, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var permissions []record.Permission
	for rows.Next() {
		var permission record.Permission
		addr := permissionStruct.Addr(&permission)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errs.Wrap(err, "unable to scan permission")
		}
		permissions = append(permissions, permission)
	}

	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return permissions, nil
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
		permissionStruct := sqlbuilder.NewStruct(new(record.Permission)).
			For(d.Flavor)

		selectBuilder := permissionStruct.SelectFrom("permissions")
		selectBuilder.Where(selectBuilder.In("id", sqlbuilder.Flatten(batch)...))

		sql, args := selectBuilder.Build()
		rows, err := d.QuerySQL(ctx, tx, sql, args...)
		if err != nil {
			return errs.Wrap(err, "unable to query database")
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var permission record.Permission
			addr := permissionStruct.Addr(&permission)
			err = rows.Scan(addr...)
			if err != nil {
				return errs.Wrap(err, "unable to scan permission")
			}
			permissions = append(permissions, permission)
		}

		if err := rows.Err(); err != nil {
			return errs.Wrap(err, "unable to read query results")
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return permissions, nil
}

func (d *Database) DeletePermission(ctx context.Context, tx *sql.Tx, permissionId int64) error {

	clientStruct := sqlbuilder.NewStruct(new(record.Permission)).
		For(d.Flavor)

	deleteBuilder := clientStruct.DeleteFrom("permissions")
	deleteBuilder.Where(deleteBuilder.Equal("id", permissionId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSQL(ctx, tx, sql, args...)
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

	ofAuthServer := d.Flavor.NewSelectBuilder()
	ofAuthServer.Select("1")
	ofAuthServer.From("resources")
	ofAuthServer.Where(
		"resources.id = permissions.resource_id",
		ofAuthServer.Equal("resources.resource_identifier", builtin.AuthServerResourceIdentifier),
	)

	acquire := d.Flavor.NewUpdateBuilder()
	acquire.Update("permissions")
	acquire.Set("permission_identifier = permission_identifier")
	acquire.Where(
		acquire.Equal("permission_identifier", builtin.ManagePermissionIdentifier),
		acquire.Exists(ofAuthServer),
	)

	query, args := acquire.BuildWithFlavor(d.Flavor)
	if _, err := d.ExecSQL(ctx, tx, query, args...); err != nil {
		return 0, errs.Wrap(err, "unable to acquire the manage permission row")
	}

	read := d.Flavor.NewSelectBuilder()
	read.Select("permissions.id", "permissions.permission_identifier", "resources.resource_identifier")
	read.From("permissions")
	read.JoinWithOption(sqlbuilder.InnerJoin, "resources", "resources.id = permissions.resource_id")
	read.Where(
		read.Equal("permissions.permission_identifier", builtin.ManagePermissionIdentifier),
		read.Equal("resources.resource_identifier", builtin.AuthServerResourceIdentifier),
	)

	query, args = read.BuildWithFlavor(d.Flavor)
	rows, err := d.QuerySQL(ctx, tx, query, args...)
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
