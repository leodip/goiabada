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

// GetUserByForgotPasswordCodeHash finds the user holding an outstanding reset code, by
// an unsalted SHA-256 of that code. It is what lets the reset link carry the code and
// nothing else, so no email address travels in it and no part of the link ever needs
// percent-encoding (#112). Follows GetCodeByCodeHash, which looks a row up by the same
// kind of hash.
//
// Locating the row is not authenticating it. The caller still compares the submitted
// code against the encrypted column in constant time and checks the code's expiry; this
// only says which row to compare against.
func (d *CommonDatabase) GetUserByForgotPasswordCodeHash(tx *sql.Tx, codeHash string) (*models.User, error) {

	// The dormant value is '' on every user with no code outstanding, so an empty
	// codeHash reaching the query would match one of them and hand the caller somebody
	// else's account. Refused here rather than trusted to callers, which is a second
	// line behind the fact that SHA-256 hex is always 64 characters and so no supplied
	// code can produce ''.
	if codeHash == "" {
		return nil, nil
	}

	userStruct := sqlbuilder.NewStruct(new(models.User)).
		For(d.Flavor)

	selectBuilder := userStruct.SelectFrom("users")
	selectBuilder.Where(selectBuilder.Equal("forgot_password_code_hash", codeHash))

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
	// given_name is not unique, so it does not order the rows totally, and a page is a slice
	// of an order. Where tied rows straddle a page boundary the database is free to arrange
	// them differently for the page-1 query than for the page-2 query, which shows one user on
	// both pages and omits another entirely. The ties are the common case rather than the
	// exception: every self-registered user has an empty given name, as does the seeded admin.
	// Ordering by the primary key as well makes the order total, which is what makes paging
	// through it correct. Same reason audit_log.go pages by created_at DESC, id DESC (#112).
	selectBuilder.OrderByAsc("users.given_name").OrderByAsc("users.id")
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

// IncrementUserOtpConfigGeneration advances the user's OTP configuration generation and
// returns the value that landed.
//
// Called at every site that establishes or removes an authenticator, inside the same
// transaction as the write that changed it. That is the whole point of decision 2 in
// #242: a separate write whose error is merely surfaced leaves exactly the state the
// re-prompt exists to prevent, the authenticator on with the counter unmoved and every
// existing session's snapshot still matching, and the caller cannot recover from it
// because a retry is refused with OTP_ALREADY_ENABLED.
//
// Narrow rather than going through UpdateUser, which writes every non-tagged column:
// otp_config_generation is tagged dont-update precisely so a handler that loaded the
// user before a concurrent change cannot write the old counter back and discharge every
// session's obligation at once (#106, #242).
func (d *CommonDatabase) IncrementUserOtpConfigGeneration(tx *sql.Tx, userId int64) (int64, error) {

	if userId == 0 {
		return 0, errors.WithStack(errors.New("can't increment the otp config generation of user with id 0"))
	}
	if tx == nil {
		return 0, errors.WithStack(errors.New("incrementing the otp config generation requires a transaction: it must commit with the write that changed the authenticator"))
	}

	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("users")
	ub.Set(
		"otp_config_generation = otp_config_generation + 1",
		ub.Assign("updated_at", time.Now().UTC()),
	)
	ub.Where(ub.Equal("id", userId))

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSql(tx, query, args...)
	if err != nil {
		return 0, errors.Wrap(err, "unable to increment user otp config generation")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "unable to get rows affected when incrementing user otp config generation")
	}
	if rowsAffected != 1 {
		return 0, errors.WithStack(errors.New("user not found when incrementing otp config generation"))
	}

	// Read back rather than computing the successor in Go: the increment happened in the
	// database, so this is the value that actually landed. The browser enrollment caller
	// promotes this value onto the session it is about to create, and computing N+1 here
	// would promote a number a concurrent change may already have passed.
	sb := d.Flavor.NewSelectBuilder()
	sb.Select("otp_config_generation").From("users")
	sb.Where(sb.Equal("id", userId))
	query, args = sb.BuildWithFlavor(d.Flavor)

	var generation int64
	rows, err := d.QuerySql(tx, query, args...)
	if err != nil {
		return 0, errors.Wrap(err, "unable to read back user otp config generation")
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return 0, errors.WithStack(errors.New("user vanished while incrementing otp config generation"))
	}
	if err := rows.Scan(&generation); err != nil {
		return 0, errors.Wrap(err, "unable to scan user otp config generation")
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
	// The clears are raw SQL rather than Assign(..., nil). sqlbuilder sends an
	// untyped Go nil as a parameter, and the SQL Server driver types it as nvarchar,
	// which it then refuses to convert implicitly to varbinary(max):
	// "Implicit conversion from data type nvarchar to varbinary(max) is not allowed".
	// A literal NULL has no parameter type to get wrong and is portable across all four
	// engines.
	//
	// The hash clears to '' rather than NULL because its column is NOT NULL, '' being
	// the dormant value meaning no code outstanding. Clearing it matters for the same
	// reason clearing the encrypted code does: the expiry check would still refuse a
	// used code, but the row should not be findable by that hash at all (#112).
	ub.Set(
		ub.Assign("password_hash", passwordHash),
		"forgot_password_code_encrypted = NULL",
		"forgot_password_code_issued_at = NULL",
		"forgot_password_code_hash = ''",
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

// TryConsumeForgotPasswordCode writes a new password hash and claims the outstanding
// reset code in one conditional UPDATE, reporting whether this call is the one that made
// the transition. The claim is codeHash matching what the row still carries, so a second
// call with the same hash matches no row, returns false, and leaves the first call's
// password in place.
//
// Compare-and-set for the same reason MarkCodeAsUsed, TrySetUserEnabled and
// TryConsumeUserOTPStep are: a read-then-unconditional-write lets two concurrent
// requests both believe they performed the transition. Here that would mean two
// submissions of one reset link both setting a password, with the later one winning.
//
// **Why the predicate is the code hash and not just the user id.** The reset flow keeps
// its "this code was validated" marker in the session, which is a client-side encrypted
// cookie: clearing it in a response replaces the browser's copy and cannot invalidate a
// copy an attacker kept. A marker naming only the durable user id would therefore
// outlive the password write, a newly issued code, and any other password change. Naming
// the hash and claiming it here is what keeps a replayed marker from setting a password
// a second time, which is the property the encrypted column's NULLing already gives the
// pre-#112 flow.
//
// **A false return is not proof of replay**, the same imprecision MarkCodeAsUsed
// documents: the code may have been consumed already, cleared by an unrelated password
// change, superseded by a newly issued one, or the user row may be gone. The caller
// responds identically in all of them.
//
// Separate from SetUserPasswordHash rather than a fourth parameter on it: its other two
// callers, the admin user-create path and the account password-change API, hold no
// outstanding code and would have to pass a meaningless predicate.
func (d *CommonDatabase) TryConsumeForgotPasswordCode(tx *sql.Tx, userId int64, codeHash string,
	passwordHash string) (bool, error) {

	if userId == 0 {
		return false, errors.WithStack(errors.New("can't consume a forgot password code for user with id 0"))
	}
	// An error rather than a benign false, and it is not defensive: '' is the dormant
	// value on every user with no code outstanding, so an empty predicate would claim
	// one of them and set a password on an account nobody asked to reset.
	if codeHash == "" {
		return false, errors.WithStack(errors.New("can't consume an empty forgot password code hash"))
	}

	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("users")
	// The same narrow write SetUserPasswordHash performs, plus the hash clear. Narrow
	// rather than a full-row UpdateUser so a concurrent admin disable cannot be undone
	// by it (#106). See SetUserPasswordHash for why the clears are raw SQL.
	ub.Set(
		ub.Assign("password_hash", passwordHash),
		"forgot_password_code_encrypted = NULL",
		"forgot_password_code_issued_at = NULL",
		"forgot_password_code_hash = ''",
		ub.Assign("updated_at", time.Now().UTC()),
	)
	ub.Where(
		ub.Equal("id", userId),
		ub.Equal("forgot_password_code_hash", codeHash),
	)

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSql(tx, query, args...)
	if err != nil {
		return false, errors.Wrap(err, "unable to consume forgot password code")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errors.Wrap(err, "unable to get rows affected when consuming forgot password code")
	}

	// rowsAffected == 1 means this call transitioned the row on all four engines: the
	// predicate requires a non-empty hash and the SET clears it to '', so the row always
	// changes and MySQL's changed-rows accounting agrees with matched rows. That is the
	// trap RevokeCodesBySessionIdentifier documents, and it does not bite here.
	return rowsAffected == 1, nil
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

// TryConsumeUserOTPStep records step as the user's most recently consumed TOTP time
// step, but only if it is strictly newer than what is stored, and reports whether
// this call is the one that made the transition. Compare-and-set for the same reason
// MarkCodeAsUsed is: accepting a code and recording it as used must not be separable,
// or two concurrent submissions of one code both pass. The single conditional UPDATE
// is the claim and the replay check at once (#111).
//
// requireOTPEnabled adds `otp_enabled = true` to the predicate. Verification sites
// pass true, because a verification claim asserts a factor and that assertion is only
// true of an enrolled authenticator: without the term, a request that loaded the user
// before a concurrent disable could still claim a step and be issued a token naming
// amr "otp" for an authenticator that had just been removed. Enrollment sites pass
// false, because they claim before the enable write and otp_enabled is still off
// there (#111 decision 10).
//
// **A false return is not proof of replay.** It means no row transitioned, and the
// causes are not distinguishable here: the step is at or below the stored one, the
// user row is gone, or, at a verification site, the authenticator was removed under
// this request. The caller loaded the user moments earlier, so replay is
// overwhelmingly the cause, and the response is identical either way. This is the
// same imprecision MarkCodeAsUsed documents about its own three-way false.
//
// **A query error is not benign.** It returns (false, err) and the caller responds
// 500. Collapsing a database fault into "not consumed" would refuse valid codes;
// collapsing it into "consumed" would accept replays for the duration of the fault.
//
// tx is optional, as on MarkCodeAsUsed: this is one statement and nothing is read
// back, so the transaction requirement IncrementUserAuthStateGeneration documents
// does not apply.
//
// Deliberately not part of UpdateUser. last_otp_step is tagged dont-update because
// the OTP enrollment handler claims a step and then writes the whole user back, so an
// ordinary update would write the pre-claim value over the claim.
func (d *CommonDatabase) TryConsumeUserOTPStep(tx *sql.Tx, userId int64, step int64,
	requireOTPEnabled bool) (bool, error) {

	if userId == 0 {
		return false, errors.WithStack(errors.New("can't consume an OTP step for user with id 0"))
	}

	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("users")
	ub.Set(
		ub.Assign("last_otp_step", step),
		ub.Assign("updated_at", time.Now().UTC()),
	)
	// The strict inequality is what refuses a replay: the second submission of one code
	// carries the step already stored, so it matches no row. rowsAffected == 1 means
	// this call transitioned the row on all four engines, because matching the WHERE
	// implies the assigned step differs from the stored one, so MySQL's changed-rows
	// accounting agrees with matched rows. That is the trap
	// RevokeCodesBySessionIdentifier documents, and it does not bite here.
	predicates := []string{
		ub.Equal("id", userId),
		ub.LessThan("last_otp_step", step),
	}
	if requireOTPEnabled {
		// A bound Go bool, as TrySetUserEnabled does against users.enabled. The two
		// columns carry the same type on every engine, so nothing here is dialect
		// specific.
		predicates = append(predicates, ub.Equal("otp_enabled", true))
	}
	ub.Where(predicates...)

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSql(tx, query, args...)
	if err != nil {
		return false, errors.Wrap(err, "unable to consume user OTP step")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errors.Wrap(err, "unable to get rows affected when consuming user OTP step")
	}

	return rowsAffected == 1, nil
}

// ResetUserOTPStep returns the user's consumed-step marker to 0, meaning no code has
// been consumed. Called when OTP is disabled: the marker belongs to the enrolled
// authenticator, and it is the only remedy if a clock jump strands the marker in the
// future, where every code would be refused until wall time caught up (#111
// decision 4).
//
// **Callers must reset AFTER the write that clears otp_enabled, not before.** Neither
// order needs a transaction, but reversed there is a window in which the marker reads
// 0 while the authenticator still reads enabled, and a verification request that
// loaded the old state claims an already-consumed step through it, which is precisely
// the hole TryConsumeUserOTPStep's requireOTPEnabled term closes.
//
// Not a bypass: self-service disable verifies the password first, admin disable
// requires authserver:manage, and re-enrolling requires possession of a fresh secret.
//
// Resetting an already-reset user is not a failure, so this reports only an error
// rather than whether anything changed. Nothing gates on the transition, unlike
// TrySetUserEnabled's disable direction.
func (d *CommonDatabase) ResetUserOTPStep(tx *sql.Tx, userId int64) error {

	if userId == 0 {
		return errors.WithStack(errors.New("can't reset the OTP step of user with id 0"))
	}

	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("users")
	ub.Set(
		ub.Assign("last_otp_step", 0),
		ub.Assign("updated_at", time.Now().UTC()),
	)
	ub.Where(ub.Equal("id", userId))

	query, args := ub.BuildWithFlavor(d.Flavor)
	_, err := d.ExecSql(tx, query, args...)
	if err != nil {
		return errors.Wrap(err, "unable to reset user OTP step")
	}

	return nil
}
