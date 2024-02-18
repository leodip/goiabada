package mysqldb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateUser(tx *sql.Tx, user *entitiesv2.User) error {

	now := time.Now().UTC()

	originalCreatedAt := user.CreatedAt
	originalUpdatedAt := user.UpdatedAt
	user.CreatedAt = sql.NullTime{Time: now, Valid: true}
	user.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	userStruct := sqlbuilder.NewStruct(new(entitiesv2.User)).
		For(sqlbuilder.MySQL)

	insertBuilder := userStruct.WithoutTag("pk").InsertInto("users", user)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		user.CreatedAt = originalCreatedAt
		user.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert user")
	}

	id, err := result.LastInsertId()
	if err != nil {
		user.CreatedAt = originalCreatedAt
		user.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	user.Id = id
	return nil
}

func (d *MySQLDatabase) UpdateUser(tx *sql.Tx, user *entitiesv2.User) error {

	if user.Id == 0 {
		return errors.New("can't update user with id 0")
	}

	originalUpdatedAt := user.UpdatedAt
	user.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	userStruct := sqlbuilder.NewStruct(new(entitiesv2.User)).
		For(sqlbuilder.MySQL)

	updateBuilder := userStruct.WithoutTag("pk").Update("users", user)
	updateBuilder.Where(updateBuilder.Equal("id", user.Id))

	sql, args := updateBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		user.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update user")
	}

	return nil
}

func (d *MySQLDatabase) getUserCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	userStruct *sqlbuilder.Struct) (*entitiesv2.User, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var user entitiesv2.User
	if rows.Next() {
		addr := userStruct.Addr(&user)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan user")
		}
		return &user, nil
	}
	return nil, nil
}

func (d *MySQLDatabase) GetUsersByIds(tx *sql.Tx, userIds []int64) (map[int64]entitiesv2.User, error) {

	userStruct := sqlbuilder.NewStruct(new(entitiesv2.User)).
		For(sqlbuilder.MySQL)

	selectBuilder := userStruct.SelectFrom("users")
	selectBuilder.Where(selectBuilder.In("id", sqlbuilder.Flatten(userIds)...))

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	users := make(map[int64]entitiesv2.User)
	for rows.Next() {
		var user entitiesv2.User
		addr := userStruct.Addr(&user)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan user")
		}
		users[user.Id] = user
	}

	return users, nil
}

func (d *MySQLDatabase) GetUserById(tx *sql.Tx, userId int64) (*entitiesv2.User, error) {

	userStruct := sqlbuilder.NewStruct(new(entitiesv2.User)).
		For(sqlbuilder.MySQL)

	selectBuilder := userStruct.SelectFrom("users")
	selectBuilder.Where(selectBuilder.Equal("id", userId))

	user, err := d.getUserCommon(tx, selectBuilder, userStruct)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (d *MySQLDatabase) UsersLoadPermissions(tx *sql.Tx, users []entitiesv2.User) error {

	if users == nil {
		return nil
	}

	userIds := make([]int64, len(users))
	for i, user := range users {
		userIds[i] = user.Id
	}

	userPermissions, err := d.GetUserPermissionsByUserIds(tx, userIds)
	if err != nil {
		return err
	}

	permissionIds := make([]int64, len(userPermissions))
	for i, userPermission := range userPermissions {
		permissionIds[i] = userPermission.PermissionId
	}

	permissions, err := d.GetPermissionsByIds(tx, permissionIds)
	if err != nil {
		return err
	}

	permissionsByUserId := make(map[int64][]entitiesv2.Permission)
	for _, userPermission := range userPermissions {
		permissionsByUserId[userPermission.UserId] = append(permissionsByUserId[userPermission.UserId], permissions[userPermission.PermissionId])
	}

	for i, user := range users {
		users[i].Permissions = permissionsByUserId[user.Id]
	}

	return nil
}

func (d *MySQLDatabase) UserLoadAttributes(tx *sql.Tx, user *entitiesv2.User) error {

	if user == nil {
		return nil
	}

	userAttributes, err := d.GetUserAttributesByUserId(tx, user.Id)
	if err != nil {
		return err
	}

	user.Attributes = userAttributes

	return nil
}

func (d *MySQLDatabase) UserLoadPermissions(tx *sql.Tx, user *entitiesv2.User) error {

	if user == nil {
		return nil
	}

	userPermissions, err := d.GetUserPermissionsByUserId(tx, user.Id)
	if err != nil {
		return err
	}

	permissionIds := make([]int64, len(userPermissions))
	for i, userPermission := range userPermissions {
		permissionIds[i] = userPermission.PermissionId
	}

	permissions, err := d.GetPermissionsByIds(tx, permissionIds)
	if err != nil {
		return err
	}

	user.Permissions = permissions

	return nil

}

func (d *MySQLDatabase) UsersLoadGroups(tx *sql.Tx, users []entitiesv2.User) error {

	if users == nil {
		return nil
	}

	userIds := make([]int64, len(users))
	for i, user := range users {
		userIds[i] = user.Id
	}

	userGroups, err := d.GetUserGroupsByUserIds(tx, userIds)
	if err != nil {
		return err
	}

	groupIds := make([]int64, len(userGroups))
	for i, userGroup := range userGroups {
		groupIds[i] = userGroup.GroupId
	}

	groups, err := d.GetGroupsByIds(tx, groupIds)
	if err != nil {
		return err
	}

	groupsByUserId := make(map[int64][]entitiesv2.Group)
	for _, userGroup := range userGroups {
		groupsByUserId[userGroup.UserId] = append(groupsByUserId[userGroup.UserId], groups[userGroup.GroupId])
	}

	for i, user := range users {
		users[i].Groups = groupsByUserId[user.Id]
	}

	return nil
}

func (d *MySQLDatabase) UserLoadGroups(tx *sql.Tx, user *entitiesv2.User) error {

	if user == nil {
		return nil
	}

	userGroups, err := d.GetUserGroupsByUserId(tx, user.Id)
	if err != nil {
		return err
	}

	groupIds := make([]int64, len(userGroups))
	for i, group := range userGroups {
		groupIds[i] = group.GroupId
	}

	groups, err := d.GetGroupsByIds(tx, groupIds)
	if err != nil {
		return err
	}

	user.Groups = groups

	return nil
}

func (d *MySQLDatabase) GetUserByUsername(tx *sql.Tx, username string) (*entitiesv2.User, error) {

	userStruct := sqlbuilder.NewStruct(new(entitiesv2.User)).
		For(sqlbuilder.MySQL)

	selectBuilder := userStruct.SelectFrom("users")
	selectBuilder.Where(selectBuilder.Equal("username", username))

	user, err := d.getUserCommon(tx, selectBuilder, userStruct)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (d *MySQLDatabase) GetUserBySubject(tx *sql.Tx, subject string) (*entitiesv2.User, error) {

	userStruct := sqlbuilder.NewStruct(new(entitiesv2.User)).
		For(sqlbuilder.MySQL)

	selectBuilder := userStruct.SelectFrom("users")
	selectBuilder.Where(selectBuilder.Equal("subject", subject))

	user, err := d.getUserCommon(tx, selectBuilder, userStruct)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (d *MySQLDatabase) GetUserByEmail(tx *sql.Tx, email string) (*entitiesv2.User, error) {

	userStruct := sqlbuilder.NewStruct(new(entitiesv2.User)).
		For(sqlbuilder.MySQL)

	selectBuilder := userStruct.SelectFrom("users")
	selectBuilder.Where(selectBuilder.Equal("email", email))

	user, err := d.getUserCommon(tx, selectBuilder, userStruct)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (d *MySQLDatabase) GetLastUserWithOTPState(tx *sql.Tx, otpEnabledState bool) (*entitiesv2.User, error) {
	userStruct := sqlbuilder.NewStruct(new(entitiesv2.User)).
		For(sqlbuilder.MySQL)

	selectBuilder := userStruct.SelectFrom("users")
	selectBuilder.Where(selectBuilder.Equal("otp_enabled", otpEnabledState))
	selectBuilder.OrderBy("id").Desc()
	selectBuilder.Limit(1)

	user, err := d.getUserCommon(tx, selectBuilder, userStruct)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (d *MySQLDatabase) SearchUsersPaginated(tx *sql.Tx, query string, page int, pageSize int) ([]entitiesv2.User, int, error) {

	if page < 1 {
		page = 1
	}

	if pageSize < 1 {
		pageSize = 10
	}

	userStruct := sqlbuilder.NewStruct(new(entitiesv2.User)).
		For(sqlbuilder.MySQL)

	selectBuilder := userStruct.SelectFrom("users")

	if query != "" {
		selectBuilder.Where(
			selectBuilder.Or(
				selectBuilder.Like("subject", "%"+query+"%"),
				selectBuilder.Like("username", "%"+query+"%"),
				selectBuilder.Like("given_name", "%"+query+"%"),
				selectBuilder.Like("middle_name", "%"+query+"%"),
				selectBuilder.Like("family_name", "%"+query+"%"),
				selectBuilder.Like("email", "%"+query+"%"),
			),
		)
	}
	selectBuilder.OrderBy("users.given_name").Asc()
	selectBuilder.Offset((page - 1) * pageSize)
	selectBuilder.Limit(pageSize)

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(nil, sql, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var users []entitiesv2.User
	for rows.Next() {
		var user entitiesv2.User
		addr := userStruct.Addr(&user)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, 0, errors.Wrap(err, "unable to scan user")
		}
		users = append(users, user)
	}

	var count int
	selectBuilder = sqlbuilder.MySQL.NewSelectBuilder()
	selectBuilder.Select("count(*)").From("users")

	if query != "" {
		selectBuilder.Where(
			selectBuilder.Or(
				selectBuilder.Like("subject", "%"+query+"%"),
				selectBuilder.Like("username", "%"+query+"%"),
				selectBuilder.Like("given_name", "%"+query+"%"),
				selectBuilder.Like("middle_name", "%"+query+"%"),
				selectBuilder.Like("family_name", "%"+query+"%"),
				selectBuilder.Like("email", "%"+query+"%"),
			),
		)
	}

	sql, args = selectBuilder.Build()
	rows, err = d.querySql(nil, sql, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	if rows.Next() {
		rows.Scan(&count)
	}

	return users, count, nil
}

func (d *MySQLDatabase) DeleteUser(tx *sql.Tx, userId int64) error {

	userStruct := sqlbuilder.NewStruct(new(entitiesv2.UserSession)).
		For(sqlbuilder.MySQL)

	deleteBuilder := userStruct.DeleteFrom("users")
	deleteBuilder.Where(deleteBuilder.Equal("id", userId))

	sql, args := deleteBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete user")
	}

	return nil
}
