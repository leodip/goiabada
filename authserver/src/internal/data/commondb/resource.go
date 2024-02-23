package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/pkg/errors"
)

func (d *CommonDatabase) CreateResource(tx *sql.Tx, resource *entities.Resource) error {

	now := time.Now().UTC()

	originalCreatedAt := resource.CreatedAt
	originalUpdatedAt := resource.UpdatedAt
	resource.CreatedAt = sql.NullTime{Time: now, Valid: true}
	resource.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	resourceStruct := sqlbuilder.NewStruct(new(entities.Resource)).
		For(d.Flavor)

	insertBuilder := resourceStruct.WithoutTag("pk").InsertInto("resources", resource)

	sql, args := insertBuilder.Build()
	result, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		resource.CreatedAt = originalCreatedAt
		resource.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert resource")
	}

	id, err := result.LastInsertId()
	if err != nil {
		resource.CreatedAt = originalCreatedAt
		resource.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	resource.Id = id
	return nil
}

func (d *CommonDatabase) UpdateResource(tx *sql.Tx, resource *entities.Resource) error {

	if resource.Id == 0 {
		return errors.WithStack(errors.New("can't update resource with id 0"))
	}

	originalUpdatedAt := resource.UpdatedAt
	resource.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	resourceStruct := sqlbuilder.NewStruct(new(entities.Resource)).
		For(d.Flavor)

	updateBuilder := resourceStruct.WithoutTag("pk").Update("resources", resource)
	updateBuilder.Where(updateBuilder.Equal("id", resource.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		resource.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update resource")
	}

	return nil
}

func (d *CommonDatabase) getResourceCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	resourceStruct *sqlbuilder.Struct) (*entities.Resource, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var resource entities.Resource
	if rows.Next() {
		addr := resourceStruct.Addr(&resource)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan resource")
		}
		return &resource, nil
	}
	return nil, nil
}

func (d *CommonDatabase) GetResourceById(tx *sql.Tx, resourceId int64) (*entities.Resource, error) {

	resourceStruct := sqlbuilder.NewStruct(new(entities.Resource)).
		For(d.Flavor)

	selectBuilder := resourceStruct.SelectFrom("resources")
	selectBuilder.Where(selectBuilder.Equal("id", resourceId))

	resource, err := d.getResourceCommon(tx, selectBuilder, resourceStruct)
	if err != nil {
		return nil, err
	}

	return resource, nil
}

func (d *CommonDatabase) GetResourceByResourceIdentifier(tx *sql.Tx, resourceIdentifier string) (*entities.Resource, error) {

	resourceStruct := sqlbuilder.NewStruct(new(entities.Resource)).
		For(d.Flavor)

	selectBuilder := resourceStruct.SelectFrom("resources")
	selectBuilder.Where(selectBuilder.Equal("resource_identifier", resourceIdentifier))

	resource, err := d.getResourceCommon(tx, selectBuilder, resourceStruct)
	if err != nil {
		return nil, err
	}

	return resource, nil
}

func (d *CommonDatabase) GetResourcesByIds(tx *sql.Tx, resourceIds []int64) ([]entities.Resource, error) {

	if len(resourceIds) == 0 {
		return nil, nil
	}

	resourceStruct := sqlbuilder.NewStruct(new(entities.Resource)).
		For(d.Flavor)

	selectBuilder := resourceStruct.SelectFrom("resources")
	selectBuilder.Where(selectBuilder.In("id", sqlbuilder.Flatten(resourceIds)...))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var resources []entities.Resource
	for rows.Next() {
		var resource entities.Resource
		addr := resourceStruct.Addr(&resource)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan resource")
		}
		resources = append(resources, resource)
	}

	return resources, nil
}

func (d *CommonDatabase) GetAllResources(tx *sql.Tx) ([]entities.Resource, error) {
	resourceStruct := sqlbuilder.NewStruct(new(entities.Resource)).
		For(d.Flavor)

	selectBuilder := resourceStruct.SelectFrom("resources")

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(nil, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var resources []entities.Resource
	for rows.Next() {
		var resource entities.Resource
		addr := resourceStruct.Addr(&resource)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan resource")
		}
		resources = append(resources, resource)
	}

	return resources, nil
}

func (d *CommonDatabase) DeleteResource(tx *sql.Tx, resourceId int64) error {

	clientStruct := sqlbuilder.NewStruct(new(entities.Resource)).
		For(d.Flavor)

	deleteBuilder := clientStruct.DeleteFrom("resources")
	deleteBuilder.Where(deleteBuilder.Equal("id", resourceId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete resource")
	}

	return nil
}
