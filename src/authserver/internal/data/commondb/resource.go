package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

func (d *Database) CreateResource(ctx context.Context, tx *sql.Tx, resource *record.Resource) error {

	now := time.Now().UTC()

	originalCreatedAt := resource.CreatedAt
	originalUpdatedAt := resource.UpdatedAt
	resource.CreatedAt = sql.NullTime{Time: now, Valid: true}
	resource.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	resourceStruct := sqlbuilder.NewStruct(new(record.Resource)).
		For(d.Flavor)

	insertBuilder := resourceStruct.WithoutTag("pk").InsertInto("resources", resource)

	id, err := d.insertReturningId(ctx, tx, insertBuilder, "resource")
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

	resourceStruct := sqlbuilder.NewStruct(new(record.Resource)).
		For(d.Flavor)

	updateBuilder := resourceStruct.WithoutTag("pk").WithoutTag("dont-update").Update("resources", resource)
	updateBuilder.Where(updateBuilder.Equal("id", resource.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSQL(ctx, tx, sql, args...)
	if err != nil {
		resource.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update resource")
	}

	return nil
}

func (d *Database) getResourceCommon(ctx context.Context, tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	resourceStruct *sqlbuilder.Struct) (*record.Resource, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySQL(ctx, tx, sql, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var resource record.Resource
	if rows.Next() {
		addr := resourceStruct.Addr(&resource)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errs.Wrap(err, "unable to scan resource")
		}
		return &resource, nil
	}
	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return nil, nil
}

func (d *Database) GetResourceById(ctx context.Context, tx *sql.Tx, resourceId int64) (*record.Resource, error) {

	resourceStruct := sqlbuilder.NewStruct(new(record.Resource)).
		For(d.Flavor)

	selectBuilder := resourceStruct.SelectFrom("resources")
	selectBuilder.Where(selectBuilder.Equal("id", resourceId))

	resource, err := d.getResourceCommon(ctx, tx, selectBuilder, resourceStruct)
	if err != nil {
		return nil, err
	}

	return resource, nil
}

func (d *Database) GetResourceByResourceIdentifier(ctx context.Context, tx *sql.Tx, resourceIdentifier string) (*record.Resource, error) {

	resourceStruct := sqlbuilder.NewStruct(new(record.Resource)).
		For(d.Flavor)

	selectBuilder := resourceStruct.SelectFrom("resources")
	selectBuilder.Where(selectBuilder.Equal("resource_identifier", resourceIdentifier))

	resource, err := d.getResourceCommon(ctx, tx, selectBuilder, resourceStruct)
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
		resourceStruct := sqlbuilder.NewStruct(new(record.Resource)).
			For(d.Flavor)

		selectBuilder := resourceStruct.SelectFrom("resources")
		selectBuilder.Where(selectBuilder.In("id", sqlbuilder.Flatten(batch)...))

		sql, args := selectBuilder.Build()
		rows, err := d.QuerySQL(ctx, tx, sql, args...)
		if err != nil {
			return errs.Wrap(err, "unable to query database")
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var resource record.Resource
			addr := resourceStruct.Addr(&resource)
			err = rows.Scan(addr...)
			if err != nil {
				return errs.Wrap(err, "unable to scan resource")
			}
			resources = append(resources, resource)
		}

		if err := rows.Err(); err != nil {
			return errs.Wrap(err, "unable to read query results")
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return resources, nil
}

func (d *Database) GetAllResources(ctx context.Context, tx *sql.Tx) ([]record.Resource, error) {
	resourceStruct := sqlbuilder.NewStruct(new(record.Resource)).
		For(d.Flavor)

	selectBuilder := resourceStruct.SelectFrom("resources")

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySQL(ctx, tx, sql, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var resources []record.Resource
	for rows.Next() {
		var resource record.Resource
		addr := resourceStruct.Addr(&resource)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errs.Wrap(err, "unable to scan resource")
		}
		resources = append(resources, resource)
	}

	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return resources, nil
}

func (d *Database) DeleteResource(ctx context.Context, tx *sql.Tx, resourceId int64) error {

	clientStruct := sqlbuilder.NewStruct(new(record.Resource)).
		For(d.Flavor)

	deleteBuilder := clientStruct.DeleteFrom("resources")
	deleteBuilder.Where(deleteBuilder.Equal("id", resourceId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSQL(ctx, tx, sql, args...)
	if err != nil {
		return errs.Wrap(err, "unable to delete resource")
	}

	return nil
}
