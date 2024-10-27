package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *CommonDatabase) CreateUserPermission(tx *sql.Tx, userPermission *models.UserPermission) error {

	if userPermission.UserId == 0 {
		return errors.WithStack(errors.New("can't create userPermission with user_id 0"))
	}

	if userPermission.PermissionId == 0 {
		return errors.WithStack(errors.New("can't create userPermission with permission_id 0"))
	}

	now := time.Now().UTC()

	originalCreatedAt := userPermission.CreatedAt
	originalUpdatedAt := userPermission.UpdatedAt
	userPermission.CreatedAt = sql.NullTime{Time: now, Valid: true}
	userPermission.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	userPermissionStruct := sqlbuilder.NewStruct(new(models.UserPermission)).
		For(d.Flavor)

	insertBuilder := userPermissionStruct.WithoutTag("pk").InsertInto("users_permissions", userPermission)

	sql, args := insertBuilder.Build()
	result, err := d.ExecSql(tx, sql, args...)
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

func (d *CommonDatabase) UpdateUserPermission(tx *sql.Tx, userPermission *models.UserPermission) error {

	if userPermission.Id == 0 {
		return errors.WithStack(errors.New("can't update userPermission with id 0"))
	}

	originalUpdatedAt := userPermission.UpdatedAt
	userPermission.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	userPermissionStruct := sqlbuilder.NewStruct(new(models.UserPermission)).
		For(d.Flavor)

	updateBuilder := userPermissionStruct.WithoutTag("pk").WithoutTag("dont-update").Update("users_permissions", userPermission)
	updateBuilder.Where(updateBuilder.Equal("id", userPermission.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		userPermission.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update userPermission")
	}

	return nil
}

func (d *CommonDatabase) getUserPermissionCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	userPermissionStruct *sqlbuilder.Struct) (*models.UserPermission, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var userPermission models.UserPermission
	if rows.Next() {
		addr := userPermissionStruct.Addr(&userPermission)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan userPermission")
		}
		return &userPermission, nil
	}
	return nil, nil
}

func (d *CommonDatabase) GetUserPermissionById(tx *sql.Tx, userPermissionId int64) (*models.UserPermission, error) {

	userPermissionStruct := sqlbuilder.NewStruct(new(models.UserPermission)).
		For(d.Flavor)

	selectBuilder := userPermissionStruct.SelectFrom("users_permissions")
	selectBuilder.Where(selectBuilder.Equal("id", userPermissionId))

	userPermission, err := d.getUserPermissionCommon(tx, selectBuilder, userPermissionStruct)
	if err != nil {
		return nil, err
	}

	return userPermission, nil
}

func (d *CommonDatabase) GetUserPermissionsByUserIds(tx *sql.Tx, userIds []int64) ([]models.UserPermission, error) {

	if len(userIds) == 0 {
		return nil, nil
	}

	userPermissionStruct := sqlbuilder.NewStruct(new(models.UserPermission)).
		For(d.Flavor)

	selectBuilder := userPermissionStruct.SelectFrom("users_permissions")
	selectBuilder.Where(selectBuilder.In("user_id", sqlbuilder.Flatten(userIds)...))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var userPermissions []models.UserPermission
	for rows.Next() {
		var userPermission models.UserPermission
		addr := userPermissionStruct.Addr(&userPermission)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan userPermission")
		}
		userPermissions = append(userPermissions, userPermission)
	}

	return userPermissions, nil
}

func (d *CommonDatabase) GetUserPermissionsByUserId(tx *sql.Tx, userId int64) ([]models.UserPermission, error) {

	userPermissionStruct := sqlbuilder.NewStruct(new(models.UserPermission)).
		For(d.Flavor)

	selectBuilder := userPermissionStruct.SelectFrom("users_permissions")
	selectBuilder.Where(selectBuilder.Equal("user_id", userId))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var userPermissions []models.UserPermission
	for rows.Next() {
		var userPermission models.UserPermission
		addr := userPermissionStruct.Addr(&userPermission)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan userPermission")
		}
		userPermissions = append(userPermissions, userPermission)
	}

	return userPermissions, nil
}

func (d *CommonDatabase) GetUserPermissionByUserIdAndPermissionId(tx *sql.Tx, userId, permissionId int64) (*models.UserPermission, error) {

	userPermissionStruct := sqlbuilder.NewStruct(new(models.UserPermission)).
		For(d.Flavor)

	selectBuilder := userPermissionStruct.SelectFrom("users_permissions")
	selectBuilder.Where(selectBuilder.Equal("user_id", userId))
	selectBuilder.Where(selectBuilder.Equal("permission_id", permissionId))

	userPermission, err := d.getUserPermissionCommon(tx, selectBuilder, userPermissionStruct)
	if err != nil {
		return nil, err
	}

	return userPermission, nil
}

func (d *CommonDatabase) GetUsersByPermissionIdPaginated(tx *sql.Tx, permissionId int64, page int, pageSize int) ([]models.User, int, error) {

	if permissionId <= 0 {
		return nil, 0, errors.WithStack(errors.New("permissionId must be greater than 0"))
	}

	if page < 1 {
		page = 1
	}

	if pageSize < 1 {
		pageSize = 10
	}

	userStruct := sqlbuilder.NewStruct(new(models.User)).
		For(d.Flavor)

	selectBuilder := userStruct.SelectFrom("users")
	selectBuilder.JoinWithOption(sqlbuilder.InnerJoin, "users_permissions", "users.id = users_permissions.user_id")
	selectBuilder.Where(selectBuilder.Equal("users_permissions.permission_id", permissionId))
	selectBuilder.OrderBy("users.given_name").Asc()
	selectBuilder.Offset((page - 1) * pageSize)
	selectBuilder.Limit(pageSize)

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var user models.User
		addr := userStruct.Addr(&user)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, 0, errors.Wrap(err, "unable to scan user")
		}
		users = append(users, user)
	}

	selectBuilder = d.Flavor.NewSelectBuilder()
	selectBuilder.Select("count(*)").From("users")
	selectBuilder.JoinWithOption(sqlbuilder.InnerJoin, "users_permissions", "users.id = users_permissions.user_id")
	selectBuilder.Where(selectBuilder.Equal("users_permissions.permission_id", permissionId))

	sql, args = selectBuilder.Build()
	rows2, err := d.QuerySql(nil, sql, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, "unable to query database")
	}
	defer rows2.Close()

	var total int
	if rows2.Next() {
		err = rows2.Scan(&total)
		if err != nil {
			return nil, 0, errors.Wrap(err, "unable to scan total")
		}
	}

	return users, total, nil
}

func (d *CommonDatabase) DeleteUserPermission(tx *sql.Tx, userPermissionId int64) error {

	clientStruct := sqlbuilder.NewStruct(new(models.UserPermission)).
		For(d.Flavor)

	deleteBuilder := clientStruct.DeleteFrom("users_permissions")
	deleteBuilder.Where(deleteBuilder.Equal("id", userPermissionId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete userPermission")
	}

	return nil
}
