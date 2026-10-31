package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// userSessionColumns is the user_sessions table as scanUserSession reads it, each column qualified
// by its table, because the page of a client's sessions reads it in a join with
// user_session_clients, which has an id, timestamps, started and last_accessed of its own.
var userSessionColumns = columnList{
	sqlite: "user_sessions.id, user_sessions.created_at, user_sessions.updated_at, user_sessions.session_identifier, " +
		"user_sessions.started, user_sessions.last_accessed, user_sessions.auth_methods, user_sessions.acr_level, " +
		"user_sessions.auth_time, user_sessions.password_auth_time, user_sessions.ip_address, " +
		"user_sessions.device_name, user_sessions.device_type, user_sessions.device_os, user_sessions.user_agent, " +
		"user_sessions.device_id, user_sessions.auth_state_generation, user_sessions.otp_config_generation, " +
		"user_sessions.user_id",
	mysql: "user_sessions.id, user_sessions.created_at, user_sessions.updated_at, user_sessions.session_identifier, " +
		"user_sessions.started, user_sessions.last_accessed, user_sessions.auth_methods, user_sessions.acr_level, " +
		"user_sessions.auth_time, user_sessions.password_auth_time, user_sessions.ip_address, " +
		"user_sessions.device_name, user_sessions.device_type, user_sessions.device_os, user_sessions.user_agent, " +
		"user_sessions.device_id, user_sessions.auth_state_generation, user_sessions.otp_config_generation, " +
		"user_sessions.user_id",
	postgres: "user_sessions.id, user_sessions.created_at, user_sessions.updated_at, user_sessions.session_identifier, " +
		"user_sessions.started, user_sessions.last_accessed, user_sessions.auth_methods, user_sessions.acr_level, " +
		"user_sessions.auth_time, user_sessions.password_auth_time, user_sessions.ip_address, " +
		"user_sessions.device_name, user_sessions.device_type, user_sessions.device_os, user_sessions.user_agent, " +
		"user_sessions.device_id, user_sessions.auth_state_generation, user_sessions.otp_config_generation, " +
		"user_sessions.user_id",
	mssql: "user_sessions.id, user_sessions.created_at, user_sessions.updated_at, user_sessions.session_identifier, " +
		"user_sessions.started, user_sessions.last_accessed, user_sessions.auth_methods, user_sessions.acr_level, " +
		"user_sessions.auth_time, user_sessions.password_auth_time, user_sessions.ip_address, " +
		"user_sessions.device_name, user_sessions.device_type, user_sessions.device_os, user_sessions.user_agent, " +
		"user_sessions.device_id, user_sessions.auth_state_generation, user_sessions.otp_config_generation, " +
		"user_sessions.user_id",
}

// scanUserSession reads one row selected with userSessionColumns.
func scanUserSession(row rowScanner, userSession *record.UserSession) error {
	return row.Scan(
		&userSession.Id,
		&userSession.CreatedAt,
		&userSession.UpdatedAt,
		&userSession.SessionIdentifier,
		&userSession.Started,
		&userSession.LastAccessed,
		&userSession.AuthMethods,
		&userSession.AcrLevel,
		&userSession.AuthTime,
		&userSession.PasswordAuthTime,
		&userSession.IpAddress,
		&userSession.DeviceName,
		&userSession.DeviceType,
		&userSession.DeviceOS,
		&userSession.UserAgent,
		&userSession.DeviceId,
		&userSession.AuthStateGeneration,
		&userSession.OtpConfigGeneration,
		&userSession.UserId,
	)
}

// insertUserSession writes every column but id, the dont-update ones included: a new session
// starts at the generations it was created under and belongs to its user for good.
var insertUserSession = statement{
	sqlite: "INSERT INTO user_sessions (created_at, updated_at, session_identifier, started, last_accessed, " +
		"auth_methods, acr_level, auth_time, password_auth_time, ip_address, device_name, device_type, device_os, " +
		"user_agent, device_id, auth_state_generation, otp_config_generation, user_id) " +
		"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
	mysql: "INSERT INTO user_sessions (created_at, updated_at, session_identifier, started, last_accessed, " +
		"auth_methods, acr_level, auth_time, password_auth_time, ip_address, device_name, device_type, device_os, " +
		"user_agent, device_id, auth_state_generation, otp_config_generation, user_id) " +
		"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
	postgres: "INSERT INTO user_sessions (created_at, updated_at, session_identifier, started, last_accessed, " +
		"auth_methods, acr_level, auth_time, password_auth_time, ip_address, device_name, device_type, device_os, " +
		"user_agent, device_id, auth_state_generation, otp_config_generation, user_id) " +
		"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18) RETURNING id",
	mssql: "INSERT INTO user_sessions (created_at, updated_at, session_identifier, started, last_accessed, " +
		"auth_methods, acr_level, auth_time, password_auth_time, ip_address, device_name, device_type, device_os, " +
		"user_agent, device_id, auth_state_generation, otp_config_generation, user_id) " +
		"OUTPUT INSERTED.id VALUES (@p1, @p2, @p3, @p4, @p5, @p6, @p7, @p8, @p9, @p10, @p11, @p12, @p13, @p14, " +
		"@p15, @p16, @p17, @p18)",
}

// updateUserSession writes the whole row but created_at, auth_state_generation,
// otp_config_generation and user_id, which are dont-update: BumpUserSession writes the whole row on
// every request, so a stale record written back cannot regress a generation, and SQL Server does
// not re-check the foreign key to users, which would take the users row in the reverse of the order
// a ceremony takes it (#106, #139, #242).
var updateUserSession = statement{
	sqlite: "UPDATE user_sessions SET updated_at = ?, session_identifier = ?, started = ?, last_accessed = ?, " +
		"auth_methods = ?, acr_level = ?, auth_time = ?, password_auth_time = ?, ip_address = ?, device_name = ?, " +
		"device_type = ?, device_os = ?, user_agent = ?, device_id = ? WHERE id = ?",
	mysql: "UPDATE user_sessions SET updated_at = ?, session_identifier = ?, started = ?, last_accessed = ?, " +
		"auth_methods = ?, acr_level = ?, auth_time = ?, password_auth_time = ?, ip_address = ?, device_name = ?, " +
		"device_type = ?, device_os = ?, user_agent = ?, device_id = ? WHERE id = ?",
	postgres: "UPDATE user_sessions SET updated_at = $1, session_identifier = $2, started = $3, last_accessed = $4, " +
		"auth_methods = $5, acr_level = $6, auth_time = $7, password_auth_time = $8, ip_address = $9, " +
		"device_name = $10, device_type = $11, device_os = $12, user_agent = $13, device_id = $14 WHERE id = $15",
	mssql: "UPDATE user_sessions SET updated_at = @p1, session_identifier = @p2, started = @p3, " +
		"last_accessed = @p4, auth_methods = @p5, acr_level = @p6, auth_time = @p7, password_auth_time = @p8, " +
		"ip_address = @p9, device_name = @p10, device_type = @p11, device_os = @p12, user_agent = @p13, " +
		"device_id = @p14 WHERE id = @p15",
}

var selectUserSessionById = statement{
	sqlite:   "SELECT " + userSessionColumns.sqlite + " FROM user_sessions WHERE id = ?",
	mysql:    "SELECT " + userSessionColumns.mysql + " FROM user_sessions WHERE id = ?",
	postgres: "SELECT " + userSessionColumns.postgres + " FROM user_sessions WHERE id = $1",
	mssql:    "SELECT " + userSessionColumns.mssql + " FROM user_sessions WHERE id = @p1",
}

var selectUserSessionBySessionIdentifier = statement{
	sqlite:   "SELECT " + userSessionColumns.sqlite + " FROM user_sessions WHERE session_identifier = ?",
	mysql:    "SELECT " + userSessionColumns.mysql + " FROM user_sessions WHERE session_identifier = ?",
	postgres: "SELECT " + userSessionColumns.postgres + " FROM user_sessions WHERE session_identifier = $1",
	mssql:    "SELECT " + userSessionColumns.mssql + " FROM user_sessions WHERE session_identifier = @p1",
}

var selectUserSessionsByUserId = statement{
	sqlite:   "SELECT " + userSessionColumns.sqlite + " FROM user_sessions WHERE user_id = ?",
	mysql:    "SELECT " + userSessionColumns.mysql + " FROM user_sessions WHERE user_id = ?",
	postgres: "SELECT " + userSessionColumns.postgres + " FROM user_sessions WHERE user_id = $1",
	mssql:    "SELECT " + userSessionColumns.mssql + " FROM user_sessions WHERE user_id = @p1",
}

// selectUserSessionsByClientIdPage binds the client id, the page size, then the offset; SQL Server
// reads the two in the other order, OFFSET before FETCH NEXT.
//
// last_accessed does not order the rows totally: two sessions touched in the same instant tie, and
// paging over a non-total order can repeat one session on the next page and skip another. The id
// breaks the tie. See SearchUsersPaginated in user.go for the full reason (#112).
var selectUserSessionsByClientIdPage = statement{
	sqlite: "SELECT " + userSessionColumns.sqlite + " FROM user_sessions " +
		"INNER JOIN user_session_clients ON user_sessions.id = user_session_clients.user_session_id " +
		"WHERE user_session_clients.client_id = ? " +
		"ORDER BY user_sessions.last_accessed DESC, user_sessions.id DESC LIMIT ? OFFSET ?",
	mysql: "SELECT " + userSessionColumns.mysql + " FROM user_sessions " +
		"INNER JOIN user_session_clients ON user_sessions.id = user_session_clients.user_session_id " +
		"WHERE user_session_clients.client_id = ? " +
		"ORDER BY user_sessions.last_accessed DESC, user_sessions.id DESC LIMIT ? OFFSET ?",
	postgres: "SELECT " + userSessionColumns.postgres + " FROM user_sessions " +
		"INNER JOIN user_session_clients ON user_sessions.id = user_session_clients.user_session_id " +
		"WHERE user_session_clients.client_id = $1 " +
		"ORDER BY user_sessions.last_accessed DESC, user_sessions.id DESC LIMIT $2 OFFSET $3",
	mssql: "SELECT " + userSessionColumns.mssql + " FROM user_sessions " +
		"INNER JOIN user_session_clients ON user_sessions.id = user_session_clients.user_session_id " +
		"WHERE user_session_clients.client_id = @p1 " +
		"ORDER BY user_sessions.last_accessed DESC, user_sessions.id DESC OFFSET @p3 ROWS FETCH NEXT @p2 ROWS ONLY",
}

// countUserSessionsByClientId counts the rows selectUserSessionsByClientIdPage pages through, over
// the same join.
var countUserSessionsByClientId = statement{
	sqlite: "SELECT count(*) FROM user_sessions " +
		"INNER JOIN user_session_clients ON user_sessions.id = user_session_clients.user_session_id " +
		"WHERE user_session_clients.client_id = ?",
	mysql: "SELECT count(*) FROM user_sessions " +
		"INNER JOIN user_session_clients ON user_sessions.id = user_session_clients.user_session_id " +
		"WHERE user_session_clients.client_id = ?",
	postgres: "SELECT count(*) FROM user_sessions " +
		"INNER JOIN user_session_clients ON user_sessions.id = user_session_clients.user_session_id " +
		"WHERE user_session_clients.client_id = $1",
	mssql: "SELECT count(*) FROM user_sessions " +
		"INNER JOIN user_session_clients ON user_sessions.id = user_session_clients.user_session_id " +
		"WHERE user_session_clients.client_id = @p1",
}

var deleteUserSession = statement{
	sqlite:   "DELETE FROM user_sessions WHERE id = ?",
	mysql:    "DELETE FROM user_sessions WHERE id = ?",
	postgres: "DELETE FROM user_sessions WHERE id = $1",
	mssql:    "DELETE FROM user_sessions WHERE id = @p1",
}

// acquireUserSessionRow binds updated_at, then the session identifier.
var acquireUserSessionRow = statement{
	sqlite:   "UPDATE user_sessions SET updated_at = ? WHERE session_identifier = ?",
	mysql:    "UPDATE user_sessions SET updated_at = ? WHERE session_identifier = ?",
	postgres: "UPDATE user_sessions SET updated_at = $1 WHERE session_identifier = $2",
	mssql:    "UPDATE user_sessions SET updated_at = @p1 WHERE session_identifier = @p2",
}

var deleteIdleSessions = statement{
	sqlite:   "DELETE FROM user_sessions WHERE last_accessed < ?",
	mysql:    "DELETE FROM user_sessions WHERE last_accessed < ?",
	postgres: "DELETE FROM user_sessions WHERE last_accessed < $1",
	mssql:    "DELETE FROM user_sessions WHERE last_accessed < @p1",
}

var deleteExpiredSessions = statement{
	sqlite:   "DELETE FROM user_sessions WHERE started < ?",
	mysql:    "DELETE FROM user_sessions WHERE started < ?",
	postgres: "DELETE FROM user_sessions WHERE started < $1",
	mssql:    "DELETE FROM user_sessions WHERE started < @p1",
}

// promoteUserSessionGeneration binds the generation, updated_at, then the id.
var promoteUserSessionGeneration = statement{
	sqlite:   "UPDATE user_sessions SET auth_state_generation = ?, updated_at = ? WHERE id = ?",
	mysql:    "UPDATE user_sessions SET auth_state_generation = ?, updated_at = ? WHERE id = ?",
	postgres: "UPDATE user_sessions SET auth_state_generation = $1, updated_at = $2 WHERE id = $3",
	mssql:    "UPDATE user_sessions SET auth_state_generation = @p1, updated_at = @p2 WHERE id = @p3",
}

// promoteUserSessionOtpConfigGeneration binds the generation, updated_at, then the id.
var promoteUserSessionOtpConfigGeneration = statement{
	sqlite:   "UPDATE user_sessions SET otp_config_generation = ?, updated_at = ? WHERE id = ?",
	mysql:    "UPDATE user_sessions SET otp_config_generation = ?, updated_at = ? WHERE id = ?",
	postgres: "UPDATE user_sessions SET otp_config_generation = $1, updated_at = $2 WHERE id = $3",
	mssql:    "UPDATE user_sessions SET otp_config_generation = @p1, updated_at = @p2 WHERE id = @p3",
}

// lowerUserSessionsToPassword binds the password's methods, level2_mandatory, level2_optional,
// updated_at, the user id, then the password's methods and level2_mandatory again for the
// condition.
var lowerUserSessionsToPassword = statement{
	sqlite: "UPDATE user_sessions SET auth_methods = ?, " +
		"acr_level = CASE WHEN acr_level = ? THEN ? ELSE acr_level END, " +
		"auth_time = password_auth_time, updated_at = ? " +
		"WHERE user_id = ? AND (auth_methods <> ? OR acr_level = ?)",
	mysql: "UPDATE user_sessions SET auth_methods = ?, " +
		"acr_level = CASE WHEN acr_level = ? THEN ? ELSE acr_level END, " +
		"auth_time = password_auth_time, updated_at = ? " +
		"WHERE user_id = ? AND (auth_methods <> ? OR acr_level = ?)",
	postgres: "UPDATE user_sessions SET auth_methods = $1, " +
		"acr_level = CASE WHEN acr_level = $2 THEN $3 ELSE acr_level END, " +
		"auth_time = password_auth_time, updated_at = $4 " +
		"WHERE user_id = $5 AND (auth_methods <> $6 OR acr_level = $7)",
	mssql: "UPDATE user_sessions SET auth_methods = @p1, " +
		"acr_level = CASE WHEN acr_level = @p2 THEN @p3 ELSE acr_level END, " +
		"auth_time = password_auth_time, updated_at = @p4 " +
		"WHERE user_id = @p5 AND (auth_methods <> @p6 OR acr_level = @p7)",
}

func (d *Database) CreateUserSession(ctx context.Context, tx *sql.Tx, userSession *record.UserSession) error {

	if userSession.UserId == 0 {
		return errs.New("user id must be greater than 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := userSession.CreatedAt
	originalUpdatedAt := userSession.UpdatedAt
	userSession.CreatedAt = sql.NullTime{Time: now, Valid: true}
	userSession.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	id, err := d.insert(ctx, tx, insertUserSession, "userSession",
		userSession.CreatedAt, userSession.UpdatedAt, userSession.SessionIdentifier, userSession.Started,
		userSession.LastAccessed, userSession.AuthMethods, userSession.AcrLevel, userSession.AuthTime,
		userSession.PasswordAuthTime, userSession.IpAddress, userSession.DeviceName, userSession.DeviceType,
		userSession.DeviceOS, userSession.UserAgent, userSession.DeviceId, userSession.AuthStateGeneration,
		userSession.OtpConfigGeneration, userSession.UserId)
	if err != nil {
		userSession.CreatedAt = originalCreatedAt
		userSession.UpdatedAt = originalUpdatedAt
		return err
	}

	userSession.Id = id
	return nil
}

func (d *Database) UpdateUserSession(ctx context.Context, tx *sql.Tx, userSession *record.UserSession) error {

	if userSession.Id == 0 {
		return errs.New("can't update userSession with id 0")
	}

	originalUpdatedAt := userSession.UpdatedAt
	userSession.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	_, err := d.ExecSQL(ctx, tx, updateUserSession.text(d.Dialect),
		userSession.UpdatedAt, userSession.SessionIdentifier, userSession.Started, userSession.LastAccessed,
		userSession.AuthMethods, userSession.AcrLevel, userSession.AuthTime, userSession.PasswordAuthTime,
		userSession.IpAddress, userSession.DeviceName, userSession.DeviceType, userSession.DeviceOS,
		userSession.UserAgent, userSession.DeviceId, userSession.Id)
	if err != nil {
		userSession.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update userSession")
	}

	return nil
}

func (d *Database) GetUserSessionById(ctx context.Context, tx *sql.Tx, userSessionId int64) (*record.UserSession, error) {
	return queryOne(ctx, d, tx, selectUserSessionById.text(d.Dialect), []any{userSessionId},
		scanUserSession, "userSession")
}

func (d *Database) GetUserSessionBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (*record.UserSession, error) {

	if sessionIdentifier == "" {
		return nil, nil
	}

	return queryOne(ctx, d, tx, selectUserSessionBySessionIdentifier.text(d.Dialect), []any{sessionIdentifier},
		scanUserSession, "userSession")
}

func (d *Database) GetUserSessionsByClientIdPaginated(ctx context.Context, tx *sql.Tx, clientId int64, page int, pageSize int) ([]record.UserSession, int, error) {
	if clientId <= 0 {
		return nil, 0, errs.New("client id must be greater than 0")
	}

	if page < 1 {
		page = 1
	}

	if pageSize < 1 {
		pageSize = 10
	}

	userSessions, err := queryAll(ctx, d, tx, nil, selectUserSessionsByClientIdPage.text(d.Dialect),
		[]any{clientId, pageSize, PageOffset(page, pageSize)}, scanUserSession, "userSession")
	if err != nil {
		return nil, 0, err
	}

	rows, err := d.QuerySQL(ctx, tx, countUserSessionsByClientId.text(d.Dialect), clientId)
	if err != nil {
		return nil, 0, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var total int
	if rows.Next() {
		err = rows.Scan(&total)
		if err != nil {
			return nil, 0, errs.Wrap(err, "unable to scan total")
		}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, errs.Wrap(err, "unable to read count results")
	}

	return userSessions, total, nil
}

func (d *Database) UserSessionsLoadUsers(ctx context.Context, tx *sql.Tx, userSessions []record.UserSession) error {

	if userSessions == nil {
		return nil
	}

	userIds := make([]int64, 0, len(userSessions))
	for _, userSession := range userSessions {
		userIds = append(userIds, userSession.UserId)
	}

	users, err := d.GetUsersByIds(ctx, tx, userIds)
	if err != nil {
		return errs.Wrap(err, "unable to load users")
	}

	usersById := make(map[int64]record.User)
	for _, user := range users {
		usersById[user.Id] = user
	}

	for i, userSession := range userSessions {
		user, ok := usersById[userSession.UserId]
		if !ok {
			return errs.Errorf("unable to find user with id %v", userSession.Id)
		}
		userSessions[i].User = user
	}

	return nil
}

func (d *Database) UserSessionsLoadClients(ctx context.Context, tx *sql.Tx, userSessions []record.UserSession) error {
	if userSessions == nil {
		return nil
	}

	userSessionIds := make([]int64, 0, len(userSessions))
	for _, userSession := range userSessions {
		userSessionIds = append(userSessionIds, userSession.Id)
	}

	userSessionClients, err := d.GetUserSessionClientsByUserSessionIds(ctx, tx, userSessionIds)
	if err != nil {
		return errs.Wrap(err, "unable to load userSessionClients")
	}

	userSessionClientsByUserSessionId := make(map[int64][]record.UserSessionClient)
	for _, userSessionClient := range userSessionClients {
		userSessionClientsByUserSessionId[userSessionClient.UserSessionId] = append(userSessionClientsByUserSessionId[userSessionClient.UserSessionId], userSessionClient)
	}

	for i, userSession := range userSessions {
		userSessions[i].Clients = userSessionClientsByUserSessionId[userSession.Id]
	}

	return nil
}

func (d *Database) UserSessionLoadClients(ctx context.Context, tx *sql.Tx, userSession *record.UserSession) error {

	if userSession == nil {
		return nil
	}

	userSessionClients, err := d.GetUserSessionClientsByUserSessionId(ctx, tx, userSession.Id)
	if err != nil {
		return errs.Wrap(err, "unable to load userSessionClients")
	}

	userSession.Clients = userSessionClients

	return nil
}

func (d *Database) UserSessionLoadUser(ctx context.Context, tx *sql.Tx, userSession *record.UserSession) error {

	if userSession == nil {
		return nil
	}

	user, err := d.GetUserById(ctx, tx, userSession.UserId)
	if err != nil {
		return errs.Wrap(err, "unable to load user")
	}

	if user != nil {
		userSession.User = *user
	}
	return nil
}

func (d *Database) GetUserSessionsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]record.UserSession, error) {
	return queryAll(ctx, d, tx, nil, selectUserSessionsByUserId.text(d.Dialect), []any{userId},
		scanUserSession, "userSession")
}

func (d *Database) DeleteUserSession(ctx context.Context, tx *sql.Tx, userSessionId int64) error {

	_, err := d.ExecSQL(ctx, tx, deleteUserSession.text(d.Dialect), userSessionId)
	if err != nil {
		return errs.Wrap(err, "unable to delete userSession")
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
func (d *Database) AcquireUserSessionRow(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (bool, error) {

	// The transaction is required for AcquireClientRow's stated reason: without one the statement
	// autocommits and releases the row before the caller can use it, which is the whole of what
	// this buys.
	if tx == nil {
		return false, errs.New("acquiring a user session row requires a transaction: an autocommitted statement releases the row before the caller can use it")
	}

	// No row carries an empty session identifier, so the statement would match nothing and report
	// the session gone for every session there is.
	if sessionIdentifier == "" {
		return false, errs.New("can't acquire a user session row with an empty session identifier")
	}

	result, err := d.ExecSQL(ctx, tx, acquireUserSessionRow.text(d.Dialect), time.Now().UTC(), sessionIdentifier)
	if err != nil {
		return false, errs.Wrap(err, "unable to acquire user session row")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errs.Wrap(err, "unable to get the number of rows affected acquiring a user session row")
	}

	// Existence is reported rather than only errors, because "the row is gone" is the answer the
	// caller acts on and no later read re-asks the question. A failure above returns the error
	// instead of a benign false: a statement that did not run has not established that the session
	// is absent.
	return rowsAffected == 1, nil
}

// Deletes user sessions that have been idle longer than the specified timeout
func (d *Database) DeleteIdleSessions(ctx context.Context, tx *sql.Tx, idleTimeout time.Duration) error {
	_, err := d.ExecSQL(ctx, tx, deleteIdleSessions.text(d.Dialect), time.Now().UTC().Add(-idleTimeout))
	if err != nil {
		return errs.Wrap(err, "unable to delete idle sessions")
	}

	return nil
}

// Deletes user sessions that have existed longer than the specified maximum lifetime
func (d *Database) DeleteExpiredSessions(ctx context.Context, tx *sql.Tx, maxLifetime time.Duration) error {
	_, err := d.ExecSQL(ctx, tx, deleteExpiredSessions.text(d.Dialect), time.Now().UTC().Add(-maxLifetime))
	if err != nil {
		return errs.Wrap(err, "unable to delete expired sessions")
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
func (d *Database) PromoteUserSessionGeneration(ctx context.Context, tx *sql.Tx, userSessionId int64, generation int64) error {

	if userSessionId == 0 {
		return errs.New("can't promote the generation of user session with id 0")
	}

	result, err := d.ExecSQL(ctx, tx, promoteUserSessionGeneration.text(d.Dialect),
		generation, time.Now().UTC(), userSessionId)
	if err != nil {
		return errs.Wrap(err, "unable to promote user session generation")
	}

	// A promotion that matched nothing is an error, not a no-op. The caller is
	// preserving one session and its refresh tokens together; silently promoting the
	// tokens while the session was never promoted leaves that preservation half
	// applied, so the session is rejected on the next request while its tokens live on.
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return errs.Wrap(err, "unable to get rows affected when promoting user session generation")
	}
	if rowsAffected != 1 {
		return errs.New("user session not found when promoting its auth state generation")
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
func (d *Database) PromoteUserSessionOtpConfigGeneration(ctx context.Context, tx *sql.Tx, userSessionId int64, generation int64) error {

	if userSessionId == 0 {
		return errs.New("can't promote the otp config generation of user session with id 0")
	}

	result, err := d.ExecSQL(ctx, tx, promoteUserSessionOtpConfigGeneration.text(d.Dialect),
		generation, time.Now().UTC(), userSessionId)
	if err != nil {
		return errs.Wrap(err, "unable to promote user session otp config generation")
	}

	// A promotion that matched nothing is an error, not a no-op, as above: the caller has
	// just completed a ceremony that answered the level 2 question, and silently failing
	// to record that leaves the session re-prompted on every later request.
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return errs.Wrap(err, "unable to get rows affected when promoting user session otp config generation")
	}
	if rowsAffected != 1 {
		return errs.New("user session not found when promoting its otp config generation")
	}

	return nil
}

// LowerUserSessionsToPassword lowers every session of userId that claims more than a password to
// what the password alone reached, when the user's authenticator is removed: auth_methods becomes
// passwordMethods, a level2_mandatory session becomes level2_optional, the level a user with no
// authenticator reaches with a password, and auth_time becomes password_auth_time, the time the
// password was entered (#542). A session at level 1 stays at level 1.
//
// passwordMethods is the whole of what is kept, not what is removed: every session was created after
// a password, and every other method there is, otp and recovery_code, is a second factor the
// authenticator backs, so a session that names anything but the password alone names one (#257). The caller passes the password's amr value because this layer
// imports nothing that spells it.
//
// ONE STATEMENT, AND THAT IS THE POINT. The lowering used to read each session and write the whole
// row back, so a sign-in binding to the session between the read and the write was undone, and the
// lowering could restore a level and an auth_time a prompt=login had just replaced. An UPDATE
// evaluates each row as it writes it, and waits for a transaction writing a row it would lower.
//
// It does not wait for one writing a row it would not lower as committed: on PostgreSQL a session
// claiming no code is passed over even while a sign-in is writing a code onto it. That sign-in holds
// the user's row, though, which it takes to check its claim (otpcredential.OTPClaim.Recheck), and
// the removal this runs in took the user's row first, so the two never overlap.
func (d *Database) LowerUserSessionsToPassword(ctx context.Context, tx *sql.Tx, userId int64, passwordMethods string) error {

	if userId == 0 {
		return errs.New("can't lower the user sessions of user id 0")
	}
	if passwordMethods == "" {
		return errs.New("can't lower user sessions to no authentication method")
	}

	mandatory, optional := record.AcrLevel2Mandatory.String(), record.AcrLevel2Optional.String()
	if _, err := d.ExecSQL(ctx, tx, lowerUserSessionsToPassword.text(d.Dialect),
		passwordMethods, mandatory, optional, time.Now().UTC(), userId, passwordMethods, mandatory); err != nil {
		return errs.Wrap(err, "unable to lower user sessions")
	}
	return nil
}
