package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func SetPermissionInsertColsAndValues(insertBuilder *sqlbuilder.InsertBuilder, permission *entitiesv2.Permission) *sqlbuilder.InsertBuilder {
	insertBuilder.InsertInto("permissions")
	insertBuilder.Cols(
		"created_at",
		"updated_at",
		"permission_identifier",
		"description",
		"resource_id",
	)

	now := time.Now().UTC()
	insertBuilder.Values(
		now,
		now,
		permission.PermissionIdentifier,
		permission.Description,
		permission.ResourceId,
	)

	return insertBuilder
}

func ScanPermission(rows *sql.Rows) (*entitiesv2.Permission, error) {
	var (
		id                    int64
		created_at            time.Time
		updated_at            time.Time
		permission_identifier string
		description           string
		resource_id           int64
	)

	err := rows.Scan(
		&id,
		&created_at,
		&updated_at,
		&permission_identifier,
		&description,
		&resource_id,
	)
	if err != nil {
		return nil, errors.Wrap(err, "unable to scan permission")
	}

	permission := &entitiesv2.Permission{
		Id:                   id,
		CreatedAt:            created_at,
		UpdatedAt:            updated_at,
		PermissionIdentifier: permission_identifier,
		Description:          description,
		ResourceId:           resource_id,
	}

	return permission, nil
}
