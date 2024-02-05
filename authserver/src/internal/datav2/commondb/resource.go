package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func ResourceSetColsAndValues(insertBuilder *sqlbuilder.InsertBuilder, resource *entitiesv2.Resource) *sqlbuilder.InsertBuilder {
	insertBuilder.InsertInto("resources")
	insertBuilder.Cols(
		"created_at",
		"updated_at",
		"resource_identifier",
		"description",
	)

	now := time.Now().UTC()
	insertBuilder.Values(
		now,
		now,
		resource.ResourceIdentifier,
		resource.Description,
	)

	return insertBuilder
}

func ResourceScan(rows *sql.Rows) (*entitiesv2.Resource, error) {
	var (
		id                  int64
		created_at          time.Time
		updated_at          time.Time
		resource_identifier string
		description         string
	)

	err := rows.Scan(
		&id,
		&created_at,
		&updated_at,
		&resource_identifier,
		&description,
	)
	if err != nil {
		return nil, errors.Wrap(err, "unable to scan resource")
	}

	resource := &entitiesv2.Resource{
		Id:                 id,
		CreatedAt:          created_at,
		UpdatedAt:          updated_at,
		ResourceIdentifier: resource_identifier,
		Description:        description,
	}

	return resource, nil
}
