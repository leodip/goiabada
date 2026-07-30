package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
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

	updateBuilder := userStruct.WithoutTag("pk").WithoutTag("dont-update").Update("users", user)
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
	defer func() { _ = rows.Close() }()

	var user models.User
	if rows.Next() {
		addr := userStruct.Addr(&user)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan user")
		}
		return &user, nil
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "unable to read query results")
	}

	return nil, nil
}

func (d *CommonDatabase) GetUsersByIds(tx *sql.Tx, userIds []int64) (map[int64]models.User, error) {

	if len(userIds) == 0 {
		return nil, nil
	}

	userStruct := sqlbuilder.NewStruct(new(models.User)).
		For(d.Flavor)

	selectBuilder := userStruct.SelectFrom("users")
	selectBuilder.Where(selectBuilder.In("id", sqlbuilder.Flatten(userIds)...))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

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

	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "unable to read query results")
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

	// Create a map for faster permission lookups
	permissionMap := make(map[int64]models.Permission)
	for _, permission := range permissions {
		permissionMap[permission.Id] = permission
	}

	permissionsByUserId := make(map[int64][]models.Permission)
	for _, userPermission := range userPermissions {
		if permission, ok := permissionMap[userPermission.PermissionId]; ok {
			permissionsByUserId[userPermission.UserId] = append(permissionsByUserId[userPermission.UserId], permission)
		}
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
	selectBuilder.OrderByDesc("id")
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
	selectBuilder.OrderByAsc("users.given_name")
	selectBuilder.Offset((page - 1) * pageSize)
	selectBuilder.Limit(pageSize)

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

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
	defer func() { _ = rows2.Close() }()

	if rows2.Next() {
		err = rows2.Scan(&count)
		if err != nil {
			return nil, 0, errors.Wrap(err, "unable to scan count")
		}
	}

	if err := rows.Err(); err != nil {
		return nil, 0, errors.Wrap(err, "unable to read query results")
	}
	if err := rows2.Err(); err != nil {
		return nil, 0, errors.Wrap(err, "unable to read count results")
	}

	return users, count, nil
}

// DeleteUser removes the user and, by ON DELETE CASCADE, every row that
// references it. Refresh tokens are cleared explicitly first because SQL Server
// cannot cascade them: see deleteRefreshTokensByColumn.
func (d *CommonDatabase) DeleteUser(tx *sql.Tx, userId int64) error {

	return d.inTransaction(tx, func(tx *sql.Tx) error {
		if err := d.deleteRefreshTokensByColumn(tx, "user_id", userId); err != nil {
			return err
		}

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
	})
}

// IncrementUserAuthStateGeneration advances the user's authentication generation and
// returns the new value.
//
// This is the security boundary for #106: credentials authenticated under generation N
// cannot create or use authentication state once the user reaches N+1.
//
// **tx is required.** The increment and the read-back are two statements, because no
// single syntax for both increments-and-returns is portable across all four supported
// engines. Outside a transaction another increment can land between them, and this
// caller would then return the OTHER caller's generation and stamp it on the session and
// tokens it is preserving, which would leave them valid past the boundary the other
// credential change just established. A nil tx is refused rather than documented against,
// since every caller already owns a transaction: the credential write, the increment and
// the revocation sweep are one atomic unit by design.
//
// Deliberately not part of UpdateUser. auth_state_generation is tagged dont-update
// because every credential handler loads the whole user and writes it back, so leaving
// it in the ordinary update set would let a request holding a stale model silently
// regress the boundary.
func (d *CommonDatabase) IncrementUserAuthStateGeneration(tx *sql.Tx, userId int64) (int64, error) {

	if userId == 0 {
		return 0, errors.WithStack(errors.New("can't increment the auth state generation of user with id 0"))
	}
	if tx == nil {
		return 0, errors.WithStack(errors.New("incrementing the auth state generation requires a transaction: the increment and the read-back must not be separable"))
	}

	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("users")
	ub.Set(
		"auth_state_generation = auth_state_generation + 1",
		ub.Assign("updated_at", time.Now().UTC()),
	)
	ub.Where(ub.Equal("id", userId))

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSql(tx, query, args...)
	if err != nil {
		return 0, errors.Wrap(err, "unable to increment user auth state generation")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "unable to get rows affected when incrementing user auth state generation")
	}
	if rowsAffected != 1 {
		return 0, errors.WithStack(errors.New("user not found when incrementing auth state generation"))
	}

	// Read back rather than computing the successor in Go: the increment happened in the
	// database, so this is the value that actually landed.
	sb := d.Flavor.NewSelectBuilder()
	sb.Select("auth_state_generation").From("users")
	sb.Where(sb.Equal("id", userId))
	query, args = sb.BuildWithFlavor(d.Flavor)

	var generation int64
	rows, err := d.QuerySql(tx, query, args...)
	if err != nil {
		return 0, errors.Wrap(err, "unable to read back user auth state generation")
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return 0, errors.WithStack(errors.New("user vanished while incrementing auth state generation"))
	}
	if err := rows.Scan(&generation); err != nil {
		return 0, errors.Wrap(err, "unable to scan user auth state generation")
	}

	return generation, nil
}

// SetUserPasswordHash writes a new password hash and clears any outstanding
// forgot-password code in the same statement, so a reset cannot leave a usable code
// behind.
//
// Narrow rather than going through UpdateUser, which writes every non-tagged column:
// a credential handler that loaded the user before a concurrent admin disable would
// otherwise write Enabled back as it was and silently re-enable the account. (#106)
func (d *CommonDatabase) SetUserPasswordHash(tx *sql.Tx, userId int64, passwordHash string) error {

	if userId == 0 {
		return errors.WithStack(errors.New("can't set the password hash of user with id 0"))
	}

	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("users")
	// The two clears are raw SQL rather than Assign(..., nil). sqlbuilder sends an
	// untyped Go nil as a parameter, and the SQL Server driver types it as nvarchar,
	// which it then refuses to convert implicitly to varbinary(max):
	// "Implicit conversion from data type nvarchar to varbinary(max) is not allowed".
	// A literal NULL has no parameter type to get wrong and is portable across all four
	// engines.
	ub.Set(
		ub.Assign("password_hash", passwordHash),
		"forgot_password_code_encrypted = NULL",
		"forgot_password_code_issued_at = NULL",
		ub.Assign("updated_at", time.Now().UTC()),
	)
	ub.Where(ub.Equal("id", userId))

	query, args := ub.BuildWithFlavor(d.Flavor)
	_, err := d.ExecSql(tx, query, args...)
	if err != nil {
		return errors.Wrap(err, "unable to set user password hash")
	}

	return nil
}

// TrySetUserEnabled flips enabled from expected to desired, reporting whether this
// call is the one that made the transition. A false return means the row was already
// in the desired state (or the user does not exist), which callers treat as "nothing
// to do" rather than an error.
//
// Compare-and-set for the same reason MarkCodeAsUsed is: a read-then-unconditional-write
// lets two concurrent requests both believe they performed the transition. The disable
// direction's return is what gates the revocation sweep, so a second disable of an
// already-disabled account does not sweep or audit again.
//
// Covers both directions on purpose. The endpoint behind it serves enable as well as
// disable, and leaving enable on the full-row UpdateUser would keep the clobbering
// problem alive in half of it. (#106)
func (d *CommonDatabase) TrySetUserEnabled(tx *sql.Tx, userId int64, expected bool, desired bool) (bool, error) {

	if userId == 0 {
		return false, errors.WithStack(errors.New("can't set enabled on user with id 0"))
	}

	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("users")
	ub.Set(
		ub.Assign("enabled", desired),
		ub.Assign("updated_at", time.Now().UTC()),
	)
	ub.Where(
		ub.Equal("id", userId),
		ub.Equal("enabled", expected),
	)

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSql(tx, query, args...)
	if err != nil {
		return false, errors.Wrap(err, "unable to set user enabled")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errors.Wrap(err, "unable to get rows affected when setting user enabled")
	}

	return rowsAffected == 1, nil
}
