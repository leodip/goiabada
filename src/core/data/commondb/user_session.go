package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *CommonDatabase) CreateUserSession(tx *sql.Tx, userSession *models.UserSession) error {

	if userSession.UserId == 0 {
		return errors.WithStack(errors.New("user id must be greater than 0"))
	}

	now := time.Now().UTC()

	originalCreatedAt := userSession.CreatedAt
	originalUpdatedAt := userSession.UpdatedAt
	userSession.CreatedAt = sql.NullTime{Time: now, Valid: true}
	userSession.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	userSessionStruct := sqlbuilder.NewStruct(new(models.UserSession)).
		For(d.Flavor)

	insertBuilder := userSessionStruct.WithoutTag("pk").InsertInto("user_sessions", userSession)

	sql, args := insertBuilder.Build()
	result, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		userSession.CreatedAt = originalCreatedAt
		userSession.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert userSession")
	}

	id, err := result.LastInsertId()
	if err != nil {
		userSession.CreatedAt = originalCreatedAt
		userSession.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	userSession.Id = id
	return nil
}

func (d *CommonDatabase) UpdateUserSession(tx *sql.Tx, userSession *models.UserSession) error {

	if userSession.Id == 0 {
		return errors.WithStack(errors.New("can't update userSession with id 0"))
	}

	originalUpdatedAt := userSession.UpdatedAt
	userSession.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	userSessionStruct := sqlbuilder.NewStruct(new(models.UserSession)).
		For(d.Flavor)

	updateBuilder := userSessionStruct.WithoutTag("pk").WithoutTag("dont-update").Update("user_sessions", userSession)
	updateBuilder.Where(updateBuilder.Equal("id", userSession.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		userSession.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update userSession")
	}

	return nil
}

func (d *CommonDatabase) getUserSessionCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	userSessionStruct *sqlbuilder.Struct) (*models.UserSession, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var userSession models.UserSession
	if rows.Next() {
		addr := userSessionStruct.Addr(&userSession)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan userSession")
		}
		return &userSession, nil
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "unable to read query results")
	}

	return nil, nil
}

func (d *CommonDatabase) GetUserSessionById(tx *sql.Tx, userSessionId int64) (*models.UserSession, error) {

	userSessionStruct := sqlbuilder.NewStruct(new(models.UserSession)).
		For(d.Flavor)

	selectBuilder := userSessionStruct.SelectFrom("user_sessions")
	selectBuilder.Where(selectBuilder.Equal("id", userSessionId))

	userSession, err := d.getUserSessionCommon(tx, selectBuilder, userSessionStruct)
	if err != nil {
		return nil, err
	}

	return userSession, nil
}

func (d *CommonDatabase) GetUserSessionBySessionIdentifier(tx *sql.Tx, sessionIdentifier string) (*models.UserSession, error) {

	if sessionIdentifier == "" {
		return nil, nil
	}

	userSessionStruct := sqlbuilder.NewStruct(new(models.UserSession)).
		For(d.Flavor)

	selectBuilder := userSessionStruct.SelectFrom("user_sessions")
	selectBuilder.Where(selectBuilder.Equal("session_identifier", sessionIdentifier))

	userSession, err := d.getUserSessionCommon(tx, selectBuilder, userSessionStruct)
	if err != nil {
		return nil, err
	}

	return userSession, nil
}

func (d *CommonDatabase) GetUserSessionsByClientIdPaginated(tx *sql.Tx, clientId int64, page int, pageSize int) ([]models.UserSession, int, error) {
	if clientId <= 0 {
		return nil, 0, errors.WithStack(errors.New("client id must be greater than 0"))
	}

	if page < 1 {
		page = 1
	}

	if pageSize < 1 {
		pageSize = 10
	}

	userSessionStruct := sqlbuilder.NewStruct(new(models.UserSession)).
		For(d.Flavor)

	selectBuilder := userSessionStruct.SelectFrom("user_sessions")
	selectBuilder.JoinWithOption(sqlbuilder.InnerJoin, "user_session_clients", "user_sessions.id = user_session_clients.user_session_id")
	selectBuilder.Where(selectBuilder.Equal("user_session_clients.client_id", clientId))
	// last_accessed does not order the rows totally: two sessions touched in the same instant tie,
	// and paging over a non-total order can repeat one session on the next page and skip another.
	// See SearchUsersPaginated in user.go for the full reason (#112).
	selectBuilder.OrderByDesc("user_sessions.last_accessed").OrderByDesc("user_sessions.id")
	selectBuilder.Offset((page - 1) * pageSize)
	selectBuilder.Limit(pageSize)

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var userSessions []models.UserSession
	for rows.Next() {
		var userSession models.UserSession
		addr := userSessionStruct.Addr(&userSession)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, 0, errors.Wrap(err, "unable to scan userSession")
		}
		userSessions = append(userSessions, userSession)
	}

	selectBuilder = d.Flavor.NewSelectBuilder()
	selectBuilder.Select("count(*)").From("user_sessions")
	selectBuilder.JoinWithOption(sqlbuilder.InnerJoin, "user_session_clients", "user_sessions.id = user_session_clients.user_session_id")
	selectBuilder.Where(selectBuilder.Equal("user_session_clients.client_id", clientId))

	sql, args = selectBuilder.Build()
	rows2, err := d.QuerySql(nil, sql, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows2.Close() }()

	var total int
	if rows2.Next() {
		err = rows2.Scan(&total)
		if err != nil {
			return nil, 0, errors.Wrap(err, "unable to scan total")
		}
	}

	if err := rows.Err(); err != nil {
		return nil, 0, errors.Wrap(err, "unable to read query results")
	}
	if err := rows2.Err(); err != nil {
		return nil, 0, errors.Wrap(err, "unable to read count results")
	}

	return userSessions, total, nil
}

func (d *CommonDatabase) UserSessionsLoadUsers(tx *sql.Tx, userSessions []models.UserSession) error {

	if userSessions == nil {
		return nil
	}

	userIds := make([]int64, 0, len(userSessions))
	for _, userSession := range userSessions {
		userIds = append(userIds, userSession.UserId)
	}

	users, err := d.GetUsersByIds(tx, userIds)
	if err != nil {
		return errors.Wrap(err, "unable to load users")
	}

	usersById := make(map[int64]models.User)
	for _, user := range users {
		usersById[user.Id] = user
	}

	for i, userSession := range userSessions {
		user, ok := usersById[userSession.UserId]
		if !ok {
			return errors.Errorf("unable to find user with id %v", userSession.Id)
		}
		userSessions[i].User = user
	}

	return nil
}

func (d *CommonDatabase) UserSessionsLoadClients(tx *sql.Tx, userSessions []models.UserSession) error {
	if userSessions == nil {
		return nil
	}

	userSessionIds := make([]int64, 0, len(userSessions))
	for _, userSession := range userSessions {
		userSessionIds = append(userSessionIds, userSession.Id)
	}

	userSessionClients, err := d.GetUserSessionClientsByUserSessionIds(tx, userSessionIds)
	if err != nil {
		return errors.Wrap(err, "unable to load userSessionClients")
	}

	userSessionClientsByUserSessionId := make(map[int64][]models.UserSessionClient)
	for _, userSessionClient := range userSessionClients {
		userSessionClientsByUserSessionId[userSessionClient.UserSessionId] = append(userSessionClientsByUserSessionId[userSessionClient.UserSessionId], userSessionClient)
	}

	for i, userSession := range userSessions {
		userSessions[i].Clients = userSessionClientsByUserSessionId[userSession.Id]
	}

	return nil
}

func (d *CommonDatabase) UserSessionLoadClients(tx *sql.Tx, userSession *models.UserSession) error {

	if userSession == nil {
		return nil
	}

	userSessionClients, err := d.GetUserSessionClientsByUserSessionId(tx, userSession.Id)
	if err != nil {
		return errors.Wrap(err, "unable to load userSessionClients")
	}

	userSession.Clients = userSessionClients

	return nil
}

func (d *CommonDatabase) UserSessionLoadUser(tx *sql.Tx, userSession *models.UserSession) error {

	if userSession == nil {
		return nil
	}

	user, err := d.GetUserById(tx, userSession.UserId)
	if err != nil {
		return errors.Wrap(err, "unable to load user")
	}

	if user != nil {
		userSession.User = *user
	}
	return nil
}

func (d *CommonDatabase) GetUserSessionsByUserId(tx *sql.Tx, userId int64) ([]models.UserSession, error) {

	userSessionStruct := sqlbuilder.NewStruct(new(models.UserSession)).
		For(d.Flavor)

	selectBuilder := userSessionStruct.SelectFrom("user_sessions")
	selectBuilder.Where(selectBuilder.Equal("user_id", userId))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var userSessions []models.UserSession
	for rows.Next() {
		var userSession models.UserSession
		addr := userSessionStruct.Addr(&userSession)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan userSession")
		}
		userSessions = append(userSessions, userSession)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "unable to read query results")
	}

	return userSessions, nil
}

func (d *CommonDatabase) DeleteUserSession(tx *sql.Tx, userSessionId int64) error {

	userSessionStruct := sqlbuilder.NewStruct(new(models.UserSession)).
		For(d.Flavor)

	deleteBuilder := userSessionStruct.DeleteFrom("user_sessions")
	deleteBuilder.Where(deleteBuilder.Equal("id", userSessionId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete userSession")
	}

	return nil
}

// AcquireUserSessionRow takes the session's row and holds it for the rest of the caller's
// transaction. It is one unconditional UPDATE that writes only updated_at, a column nothing
// reads: session validity is measured from last_accessed and started, and neither moves.
//
// WHAT IT BUYS. An authorization ceremony inserting a code and an explicit termination sweeping
// that session's grants touch no common row, so nothing makes one wait for the other and a code
// can be inserted after the sweep ran and before it committed. That code escapes the sweep and
// yields a refresh token outliving the session. With both sides writing this row before anything
// else, one of them waits, and the one that waited reads its answer after the wait: either the
// termination sweeps after the insert committed and marks the new code, or the acquisition here
// matches no rows and the ceremony refuses without writing a code at all (#139).
//
// It keys on the session identifier rather than the id because that is what a ceremony holds. The
// column is UNIQUE on all four engines, so the statement is a single-row lock everywhere, which is
// what AcquireClientRow relies on for its own key (#245).
func (d *CommonDatabase) AcquireUserSessionRow(tx *sql.Tx, sessionIdentifier string) (bool, error) {

	// The transaction is required for AcquireClientRow's stated reason: without one the statement
	// autocommits and releases the row before the caller can use it, which is the whole of what
	// this buys.
	if tx == nil {
		return false, errors.WithStack(errors.New("acquiring a user session row requires a transaction: an autocommitted statement releases the row before the caller can use it"))
	}

	// No row carries an empty session identifier, so the statement would match nothing and report
	// the session gone for every session there is.
	if sessionIdentifier == "" {
		return false, errors.WithStack(errors.New("can't acquire a user session row with an empty session identifier"))
	}

	acquire := sqlbuilder.NewUpdateBuilder()
	acquire.Update("user_sessions")
	acquire.Set(acquire.Assign("updated_at", time.Now().UTC()))
	acquire.Where(acquire.Equal("session_identifier", sessionIdentifier))

	query, args := acquire.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSql(tx, query, args...)
	if err != nil {
		return false, errors.Wrap(err, "unable to acquire user session row")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errors.Wrap(err, "unable to get the number of rows affected acquiring a user session row")
	}

	// Existence is reported rather than only errors, because "the row is gone" is the answer the
	// caller acts on and no later read re-asks the question. A failure above returns the error
	// instead of a benign false: a statement that did not run has not established that the session
	// is absent.
	return rowsAffected == 1, nil
}

// Deletes user sessions that have been idle longer than the specified timeout
func (d *CommonDatabase) DeleteIdleSessions(tx *sql.Tx, idleTimeout time.Duration) error {
	deleteBuilder := d.Flavor.NewDeleteBuilder()
	deleteBuilder.DeleteFrom("user_sessions")
	deleteBuilder.Where(
		deleteBuilder.LessThan("last_accessed", time.Now().UTC().Add(-idleTimeout)),
	)

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete idle sessions")
	}

	return nil
}

// Deletes user sessions that have existed longer than the specified maximum lifetime
func (d *CommonDatabase) DeleteExpiredSessions(tx *sql.Tx, maxLifetime time.Duration) error {
	deleteBuilder := d.Flavor.NewDeleteBuilder()
	deleteBuilder.DeleteFrom("user_sessions")
	deleteBuilder.Where(
		deleteBuilder.LessThan("started", time.Now().UTC().Add(-maxLifetime)),
	)

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete expired sessions")
	}

	return nil
}

// PromoteUserSessionGeneration moves one session to a new authentication generation.
//
// Narrow on purpose: auth_state_generation is tagged dont-update, so it is excluded
// from UpdateUserSession and can only be changed here. That matters most for the
// session this promotion exists to serve: BumpUserSession writes the whole row on
// every request, so if the column were in the ordinary update set the first bump after
// a password change would undo the promotion and sign the user out. (#106)
func (d *CommonDatabase) PromoteUserSessionGeneration(tx *sql.Tx, userSessionId int64, generation int64) error {

	if userSessionId == 0 {
		return errors.WithStack(errors.New("can't promote the generation of user session with id 0"))
	}

	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("user_sessions")
	ub.Set(
		ub.Assign("auth_state_generation", generation),
		ub.Assign("updated_at", time.Now().UTC()),
	)
	ub.Where(ub.Equal("id", userSessionId))

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSql(tx, query, args...)
	if err != nil {
		return errors.Wrap(err, "unable to promote user session generation")
	}

	// A promotion that matched nothing is an error, not a no-op. The caller is
	// preserving one session and its refresh tokens together; silently promoting the
	// tokens while the session was never promoted leaves that preservation half
	// applied, so the session is rejected on the next request while its tokens live on.
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return errors.Wrap(err, "unable to get rows affected when promoting user session generation")
	}
	if rowsAffected != 1 {
		return errors.WithStack(errors.New("user session not found when promoting its auth state generation"))
	}

	return nil
}

// PromoteUserSessionOtpConfigGeneration records that this session has satisfied the level
// 2 question against the given OTP configuration generation, so it stops owing a
// re-prompt until the user's counter moves again.
//
// Narrow for the same reason PromoteUserSessionGeneration is: otp_config_generation is
// tagged dont-update, so it is excluded from UpdateUserSession and can only be changed
// here. BumpUserSession writes the whole row on every request, so in the ordinary update
// set the first bump would carry whatever the caller's stale model held.
//
// Called from /auth/completed and nowhere else, with a value captured earlier in the
// ceremony. Reading the counter live here instead would launder an authenticator change
// that landed after the ceremony asked its level 2 question (#242, #106 decision 11).
func (d *CommonDatabase) PromoteUserSessionOtpConfigGeneration(tx *sql.Tx, userSessionId int64, generation int64) error {

	if userSessionId == 0 {
		return errors.WithStack(errors.New("can't promote the otp config generation of user session with id 0"))
	}

	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("user_sessions")
	ub.Set(
		ub.Assign("otp_config_generation", generation),
		ub.Assign("updated_at", time.Now().UTC()),
	)
	ub.Where(ub.Equal("id", userSessionId))

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSql(tx, query, args...)
	if err != nil {
		return errors.Wrap(err, "unable to promote user session otp config generation")
	}

	// A promotion that matched nothing is an error, not a no-op, as above: the caller has
	// just completed a ceremony that answered the level 2 question, and silently failing
	// to record that leaves the session re-prompted on every later request.
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return errors.Wrap(err, "unable to get rows affected when promoting user session otp config generation")
	}
	if rowsAffected != 1 {
		return errors.WithStack(errors.New("user session not found when promoting its otp config generation"))
	}

	return nil
}
