package mysqldb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateResource(tx *sql.Tx, resource *entitiesv2.Resource) error {

	now := time.Now().UTC()

	originalCreatedAt := resource.CreatedAt
	originalUpdatedAt := resource.UpdatedAt
	resource.CreatedAt = now
	resource.UpdatedAt = now

	resourceStruct := sqlbuilder.NewStruct(new(entitiesv2.Resource)).
		For(sqlbuilder.MySQL)

	insertBuilder := resourceStruct.WithoutTag("pk").InsertInto("resources", resource)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
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

func (d *MySQLDatabase) UpdateResource(tx *sql.Tx, resource *entitiesv2.Resource) error {

	if resource.Id == 0 {
		return errors.New("can't update resource with id 0")
	}

	originalUpdatedAt := resource.UpdatedAt
	resource.UpdatedAt = time.Now().UTC()

	resourceStruct := sqlbuilder.NewStruct(new(entitiesv2.Resource)).
		For(sqlbuilder.MySQL)

	updateBuilder := resourceStruct.WithoutTag("pk").Update("resources", resource)
	updateBuilder.Where(updateBuilder.Equal("id", resource.Id))

	sql, args := updateBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		resource.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update resource")
	}

	return nil
}

func (d *MySQLDatabase) getResourceCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	resourceStruct *sqlbuilder.Struct) (*entitiesv2.Resource, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var resource entitiesv2.Resource
	if rows.Next() {
		addr := resourceStruct.Addr(&resource)
		rows.Scan(addr...)
		return &resource, nil
	}
	return nil, nil
}

func (d *MySQLDatabase) GetResourceById(tx *sql.Tx, resourceId int64) (*entitiesv2.Resource, error) {

	if resourceId <= 0 {
		return nil, errors.New("resource id must be greater than 0")
	}

	resourceStruct := sqlbuilder.NewStruct(new(entitiesv2.Resource)).
		For(sqlbuilder.MySQL)

	selectBuilder := resourceStruct.SelectFrom("resources")
	selectBuilder.Where(selectBuilder.Equal("id", resourceId))

	resource, err := d.getResourceCommon(tx, selectBuilder, resourceStruct)
	if err != nil {
		return nil, err
	}

	return resource, nil
}

func (d *MySQLDatabase) GetResourceByResourceIdentifier(tx *sql.Tx, resourceIdentifier string) (*entitiesv2.Resource, error) {

	if resourceIdentifier == "" {
		return nil, errors.New("resource identifier must be set")
	}

	resourceStruct := sqlbuilder.NewStruct(new(entitiesv2.Resource)).
		For(sqlbuilder.MySQL)

	selectBuilder := resourceStruct.SelectFrom("resources")
	selectBuilder.Where(selectBuilder.Equal("resource_identifier", resourceIdentifier))

	resource, err := d.getResourceCommon(tx, selectBuilder, resourceStruct)
	if err != nil {
		return nil, err
	}

	return resource, nil
}
