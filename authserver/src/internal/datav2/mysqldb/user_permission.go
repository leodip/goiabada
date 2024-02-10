package mysqldb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateUserPermission(tx *sql.Tx, userPermission *entitiesv2.UserPermission) error {

	if userPermission.UserId == 0 {
		return errors.New("can't create userPermission with user_id 0")
	}

	if userPermission.PermissionId == 0 {
		return errors.New("can't create userPermission with permission_id 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := userPermission.CreatedAt
	originalUpdatedAt := userPermission.UpdatedAt
	userPermission.CreatedAt = now
	userPermission.UpdatedAt = now

	userPermissionStruct := sqlbuilder.NewStruct(new(entitiesv2.UserPermission)).
		For(sqlbuilder.MySQL)

	insertBuilder := userPermissionStruct.WithoutTag("pk").InsertInto("users_permissions", userPermission)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		userPermission.CreatedAt = originalCreatedAt
		userPermission.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert userPermission")
	}

	id, err := result.LastInsertId()
	if err != nil {
		userPermission.CreatedAt = originalCreatedAt
		userPermission.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	userPermission.Id = id
	return nil
}

func (d *MySQLDatabase) UpdateUserPermission(tx *sql.Tx, userPermission *entitiesv2.UserPermission) error {

	if userPermission.Id == 0 {
		return errors.New("can't update userPermission with id 0")
	}

	originalUpdatedAt := userPermission.UpdatedAt
	userPermission.UpdatedAt = time.Now().UTC()

	userPermissionStruct := sqlbuilder.NewStruct(new(entitiesv2.UserPermission)).
		For(sqlbuilder.MySQL)

	updateBuilder := userPermissionStruct.WithoutTag("pk").Update("users_permissions", userPermission)
	updateBuilder.Where(updateBuilder.Equal("id", userPermission.Id))

	sql, args := updateBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		userPermission.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update userPermission")
	}

	return nil
}

func (d *MySQLDatabase) getUserPermissionCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	userPermissionStruct *sqlbuilder.Struct) (*entitiesv2.UserPermission, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var userPermission entitiesv2.UserPermission
	if rows.Next() {
		addr := userPermissionStruct.Addr(&userPermission)
		rows.Scan(addr...)
		return &userPermission, nil
	}
	return nil, nil
}

func (d *MySQLDatabase) GetUserPermissionById(tx *sql.Tx, userPermissionId int64) (*entitiesv2.UserPermission, error) {

	if userPermissionId <= 0 {
		return nil, errors.New("userPermission id must be greater than 0")
	}

	userPermissionStruct := sqlbuilder.NewStruct(new(entitiesv2.UserPermission)).
		For(sqlbuilder.MySQL)

	selectBuilder := userPermissionStruct.SelectFrom("users_permissions")
	selectBuilder.Where(selectBuilder.Equal("id", userPermissionId))

	userPermission, err := d.getUserPermissionCommon(tx, selectBuilder, userPermissionStruct)
	if err != nil {
		return nil, err
	}

	return userPermission, nil
}
