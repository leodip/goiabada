package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/models"
	"github.com/pkg/errors"
)

func (d *CommonDatabase) CreateUser(tx *sql.Tx, user *models.User) error {

	now := time.Now().UTC()

	originalCreatedAt := user.CreatedAt
	originalUpdatedAt := user.UpdatedAt
	user.CreatedAt = sql.NullTime{Time: now, Valid: true}
	user.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	userStruct := sqlbuilder.NewStruct(new(models.User)).
		For(d.Flavor)

	insertBuilder := userStruct.WithoutTag("pk").InsertInto("users", user)

	sql, args := insertBuilder.Build()
	result, err := d.ExecSql(tx, sql, args...)
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

func (d *CommonDatabase) UpdateUser(tx *sql.Tx, user *models.User) error {

	if user.Id == 0 {
		return errors.WithStack(errors.New("can't update user with id 0"))
	}

	originalUpdatedAt := user.UpdatedAt
	user.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	userStruct := sqlbuilder.NewStruct(new(models.User)).
		For(d.Flavor)

	updateBuilder := userStruct.WithoutTag("pk").Update("users", user)
	updateBuilder.Where(updateBuilder.Equal("id", user.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		user.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update user")
	}

	return nil
}

func (d *CommonDatabase) getUserCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	userStruct *sqlbuilder.Struct) (*models.User, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var user models.User
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

func (d *CommonDatabase) GetUsersByIds(tx *sql.Tx, userIds []int64) (map[int64]models.User, error) {

	userStruct := sqlbuilder.NewStruct(new(models.User)).
		For(d.Flavor)

	selectBuilder := userStruct.SelectFrom("users")
	selectBuilder.Where(selectBuilder.In("id", sqlbuilder.Flatten(userIds)...))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	users := make(map[int64]models.User)
	for rows.Next() {
		var user models.User
		addr := userStruct.Addr(&user)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan user")
		}
		users[user.Id] = user
	}

	return users, nil
}

func (d *CommonDatabase) GetUserById(tx *sql.Tx, userId int64) (*models.User, error) {

	userStruct := sqlbuilder.NewStruct(new(models.User)).
		For(d.Flavor)

	selectBuilder := userStruct.SelectFrom("users")
	selectBuilder.Where(selectBuilder.Equal("id", userId))

	user, err := d.getUserCommon(tx, selectBuilder, userStruct)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (d *CommonDatabase) UsersLoadPermissions(tx *sql.Tx, users []models.User) error {

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

	permissionsByUserId := make(map[int64][]models.Permission)
	for _, userPermission := range userPermissions {
		permissionsByUserId[userPermission.UserId] = append(permissionsByUserId[userPermission.UserId], permissions[userPermission.PermissionId])
	}

	for i, user := range users {
		users[i].Permissions = permissionsByUserId[user.Id]
	}

	return nil
}

func (d *CommonDatabase) UserLoadAttributes(tx *sql.Tx, user *models.User) error {

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

func (d *CommonDatabase) UserLoadPermissions(tx *sql.Tx, user *models.User) error {

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

func (d *CommonDatabase) UsersLoadGroups(tx *sql.Tx, users []models.User) error {

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

	groupsByUserId := make(map[int64][]models.Group)
	for _, userGroup := range userGroups {
		var group models.Group
		for _, g := range groups {
			if g.Id == userGroup.GroupId {
				group = g
				break
			}
		}
		groupsByUserId[userGroup.UserId] = append(groupsByUserId[userGroup.UserId], group)
	}

	for i, user := range users {
		users[i].Groups = groupsByUserId[user.Id]
	}

	return nil
}

func (d *CommonDatabase) UserLoadGroups(tx *sql.Tx, user *models.User) error {

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

func (d *CommonDatabase) GetUserByUsername(tx *sql.Tx, username string) (*models.User, error) {

	userStruct := sqlbuilder.NewStruct(new(models.User)).
		For(d.Flavor)

	selectBuilder := userStruct.SelectFrom("users")
	selectBuilder.Where(selectBuilder.Equal("username", username))

	user, err := d.getUserCommon(tx, selectBuilder, userStruct)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (d *CommonDatabase) GetUserBySubject(tx *sql.Tx, subject string) (*models.User, error) {

	userStruct := sqlbuilder.NewStruct(new(models.User)).
		For(d.Flavor)

	selectBuilder := userStruct.SelectFrom("users")
	selectBuilder.Where(selectBuilder.Equal("subject", subject))

	user, err := d.getUserCommon(tx, selectBuilder, userStruct)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (d *CommonDatabase) GetUserByEmail(tx *sql.Tx, email string) (*models.User, error) {

	userStruct := sqlbuilder.NewStruct(new(models.User)).
		For(d.Flavor)

	selectBuilder := userStruct.SelectFrom("users")
	selectBuilder.Where(selectBuilder.Equal("email", email))

	user, err := d.getUserCommon(tx, selectBuilder, userStruct)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (d *CommonDatabase) GetLastUserWithOTPState(tx *sql.Tx, otpEnabledState bool) (*models.User, error) {
	userStruct := sqlbuilder.NewStruct(new(models.User)).
		For(d.Flavor)

	selectBuilder := userStruct.SelectFrom("users")
	selectBuilder.Where(
		selectBuilder.And(
			selectBuilder.Equal("otp_enabled", otpEnabledState),
			selectBuilder.Equal("enabled", true),
		),
	)
	selectBuilder.OrderBy("id").Desc()
	selectBuilder.Limit(1)

	user, err := d.getUserCommon(tx, selectBuilder, userStruct)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (d *CommonDatabase) SearchUsersPaginated(tx *sql.Tx, query string, page int, pageSize int) ([]models.User, int, error) {

	if page < 1 {
		page = 1
	}

	if pageSize < 1 {
		pageSize = 10
	}

	userStruct := sqlbuilder.NewStruct(new(models.User)).
		For(d.Flavor)

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
	rows, err := d.QuerySql(nil, sql, args...)
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

	var count int
	selectBuilder = d.Flavor.NewSelectBuilder()
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
	rows2, err := d.QuerySql(nil, sql, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, "unable to query database")
	}
	defer rows2.Close()

	if rows2.Next() {
		rows2.Scan(&count)
	}

	return users, count, nil
}

func (d *CommonDatabase) DeleteUser(tx *sql.Tx, userId int64) error {

	userStruct := sqlbuilder.NewStruct(new(models.UserSession)).
		For(d.Flavor)

	deleteBuilder := userStruct.DeleteFrom("users")
	deleteBuilder.Where(deleteBuilder.Equal("id", userId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete user")
	}

	return nil
}
