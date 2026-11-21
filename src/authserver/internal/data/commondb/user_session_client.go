package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// userSessionClientColumns is the user_session_clients table as scanUserSessionClient reads it.
var userSessionClientColumns = columnList{
	sqlite:   "id, created_at, updated_at, user_session_id, client_id, started, last_accessed",
	mysql:    "id, created_at, updated_at, user_session_id, client_id, started, last_accessed",
	postgres: "id, created_at, updated_at, user_session_id, client_id, started, last_accessed",
	mssql:    "id, created_at, updated_at, user_session_id, client_id, started, last_accessed",
}

// scanUserSessionClient reads one row selected with userSessionClientColumns.
func scanUserSessionClient(row rowScanner, userSessionClient *record.UserSessionClient) error {
	return row.Scan(
		&userSessionClient.ID,
		&userSessionClient.CreatedAt,
		&userSessionClient.UpdatedAt,
		&userSessionClient.UserSessionID,
		&userSessionClient.ClientID,
		&userSessionClient.Started,
		&userSessionClient.LastAccessed,
	)
}

var insertUserSessionClient = statement{
	sqlite: "INSERT INTO user_session_clients (created_at, updated_at, user_session_id, client_id, started, " +
		"last_accessed) VALUES (?, ?, ?, ?, ?, ?)",
	mysql: "INSERT INTO user_session_clients (created_at, updated_at, user_session_id, client_id, started, " +
		"last_accessed) VALUES (?, ?, ?, ?, ?, ?)",
	postgres: "INSERT INTO user_session_clients (created_at, updated_at, user_session_id, client_id, started, " +
		"last_accessed) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
	mssql: "INSERT INTO user_session_clients (created_at, updated_at, user_session_id, client_id, started, " +
		"last_accessed) OUTPUT INSERTED.id VALUES (@p1, @p2, @p3, @p4, @p5, @p6)",
}

// updateUserSessionClient writes the whole row but created_at, user_session_id and client_id, which
// are dont-update: nothing reassigns an association's session or its client, and SQL Server
// re-checks a foreign key named in a SET list, taking a shared lock on the parent row, which
// deadlocked BumpUserSession against a client's deletion (#139).
var updateUserSessionClient = statement{
	sqlite:   "UPDATE user_session_clients SET updated_at = ?, started = ?, last_accessed = ? WHERE id = ?",
	mysql:    "UPDATE user_session_clients SET updated_at = ?, started = ?, last_accessed = ? WHERE id = ?",
	postgres: "UPDATE user_session_clients SET updated_at = $1, started = $2, last_accessed = $3 WHERE id = $4",
	mssql:    "UPDATE user_session_clients SET updated_at = @p1, started = @p2, last_accessed = @p3 WHERE id = @p4",
}

var selectUserSessionClientByID = statement{
	sqlite:   "SELECT " + userSessionClientColumns.sqlite + " FROM user_session_clients WHERE id = ?",
	mysql:    "SELECT " + userSessionClientColumns.mysql + " FROM user_session_clients WHERE id = ?",
	postgres: "SELECT " + userSessionClientColumns.postgres + " FROM user_session_clients WHERE id = $1",
	mssql:    "SELECT " + userSessionClientColumns.mssql + " FROM user_session_clients WHERE id = @p1",
}

var selectUserSessionClientsByUserSessionID = statement{
	sqlite:   "SELECT " + userSessionClientColumns.sqlite + " FROM user_session_clients WHERE user_session_id = ?",
	mysql:    "SELECT " + userSessionClientColumns.mysql + " FROM user_session_clients WHERE user_session_id = ?",
	postgres: "SELECT " + userSessionClientColumns.postgres + " FROM user_session_clients WHERE user_session_id = $1",
	mssql:    "SELECT " + userSessionClientColumns.mssql + " FROM user_session_clients WHERE user_session_id = @p1",
}

// selectCommittedUserSessionClientsByUserSessionID and selectCommittedClientByID are the reads
// GetCommittedUserSessionClients runs: the same rows as selectUserSessionClientsByUserSessionID and
// selectClientByID, read as last committed. On MySQL that takes a locking read, FOR SHARE; the
// other three already read what was committed when each statement started (see
// GetCommittedUserSessionClients).
var selectCommittedUserSessionClientsByUserSessionID = statement{
	sqlite:   "SELECT " + userSessionClientColumns.sqlite + " FROM user_session_clients WHERE user_session_id = ?",
	mysql:    "SELECT " + userSessionClientColumns.mysql + " FROM user_session_clients WHERE user_session_id = ? FOR SHARE",
	postgres: "SELECT " + userSessionClientColumns.postgres + " FROM user_session_clients WHERE user_session_id = $1",
	mssql:    "SELECT " + userSessionClientColumns.mssql + " FROM user_session_clients WHERE user_session_id = @p1",
}

var selectCommittedClientByID = statement{
	sqlite:   "SELECT " + clientColumns.sqlite + " FROM clients WHERE id = ?",
	mysql:    "SELECT " + clientColumns.mysql + " FROM clients WHERE id = ? FOR SHARE",
	postgres: "SELECT " + clientColumns.postgres + " FROM clients WHERE id = $1",
	mssql:    "SELECT " + clientColumns.mssql + " FROM clients WHERE id = @p1",
}

// selectUserSessionClientsWhere is completed by an IN list of ids or of user session ids.
var selectUserSessionClientsWhere = statement{
	sqlite:   "SELECT " + userSessionClientColumns.sqlite + " FROM user_session_clients WHERE ",
	mysql:    "SELECT " + userSessionClientColumns.mysql + " FROM user_session_clients WHERE ",
	postgres: "SELECT " + userSessionClientColumns.postgres + " FROM user_session_clients WHERE ",
	mssql:    "SELECT " + userSessionClientColumns.mssql + " FROM user_session_clients WHERE ",
}

var deleteUserSessionClient = statement{
	sqlite:   "DELETE FROM user_session_clients WHERE id = ?",
	mysql:    "DELETE FROM user_session_clients WHERE id = ?",
	postgres: "DELETE FROM user_session_clients WHERE id = $1",
	mssql:    "DELETE FROM user_session_clients WHERE id = @p1",
}

func (d *Database) CreateUserSessionClient(ctx context.Context, tx *sql.Tx, userSessionClient *record.UserSessionClient) error {

	now := time.Now().UTC()

	originalCreatedAt := userSessionClient.CreatedAt
	originalUpdatedAt := userSessionClient.UpdatedAt
	userSessionClient.CreatedAt = sql.NullTime{Time: now, Valid: true}
	userSessionClient.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	id, err := d.insert(ctx, tx, insertUserSessionClient, "userSessionClient",
		userSessionClient.CreatedAt, userSessionClient.UpdatedAt, userSessionClient.UserSessionID,
		userSessionClient.ClientID, userSessionClient.Started, userSessionClient.LastAccessed)
	if err != nil {
		userSessionClient.CreatedAt = originalCreatedAt
		userSessionClient.UpdatedAt = originalUpdatedAt
		return err
	}

	userSessionClient.ID = id
	return nil
}

func (d *Database) UpdateUserSessionClient(ctx context.Context, tx *sql.Tx, userSessionClient *record.UserSessionClient) error {

	if userSessionClient.ID == 0 {
		return errs.New("can't update userSessionClient with id 0")
	}

	originalUpdatedAt := userSessionClient.UpdatedAt
	userSessionClient.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	_, err := d.ExecSQL(ctx, tx, updateUserSessionClient.text(d.Dialect),
		userSessionClient.UpdatedAt, userSessionClient.Started, userSessionClient.LastAccessed, userSessionClient.ID)
	if err != nil {
		userSessionClient.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update userSessionClient")
	}

	return nil
}

func (d *Database) UserSessionClientsLoadClients(ctx context.Context, tx *sql.Tx, userSessionClients []record.UserSessionClient) error {

	if userSessionClients == nil {
		return nil
	}

	clientIDs := make([]int64, 0)
	for _, userSessionClient := range userSessionClients {
		clientIDs = append(clientIDs, userSessionClient.ClientID)
	}

	clients, err := d.GetClientsByIDs(ctx, tx, clientIDs)
	if err != nil {
		return errs.Wrap(err, "unable to get clients by ids")
	}

	clientsMap := make(map[int64]record.Client)
	for _, client := range clients {
		clientsMap[client.ID] = client
	}

	for i, userSessionClient := range userSessionClients {
		client, ok := clientsMap[userSessionClient.ClientID]
		if !ok {
			return errs.Errorf("client with id %d not found", userSessionClient.ClientID)
		}
		userSessionClients[i].Client = client
	}

	return nil
}

func (d *Database) GetUserSessionClientsByUserSessionIDs(ctx context.Context, tx *sql.Tx, userSessionIDs []int64) ([]record.UserSessionClient, error) {

	if len(userSessionIDs) == 0 {
		return nil, nil
	}

	var userSessionClients []record.UserSessionClient

	err := forEachIDBatch(userSessionIDs, func(batch []int64) error {
		query := selectUserSessionClientsWhere.text(d.Dialect) + inList(d.Dialect, "user_session_id", 1, len(batch))
		var err error
		userSessionClients, err = queryAll(ctx, d, tx, userSessionClients, query, int64Args(batch),
			scanUserSessionClient, "userSessionClient")
		return err
	})
	if err != nil {
		return nil, err
	}

	return userSessionClients, nil
}

func (d *Database) GetUserSessionClientsByUserSessionID(ctx context.Context, tx *sql.Tx, userSessionID int64) ([]record.UserSessionClient, error) {
	return queryAll(ctx, d, tx, nil, selectUserSessionClientsByUserSessionID.text(d.Dialect), []any{userSessionID},
		scanUserSessionClient, "userSessionClient")
}

// GetCommittedUserSessionClients answers the apps a session served, each with its client, as last
// committed: what an end of the session tells, read under the session's row (#784).
//
// The difference from GetUserSessionClientsByUserSessionID and UserSessionClientsLoadClients is
// MySQL's. Under InnoDB's default REPEATABLE READ every consistent read in a transaction reads the
// snapshot its first read established, and an end reads the user's sessions before it takes a
// session's row. A sign-in that adds an app to the session and commits in between is waited for by
// AcquireUserSessionRow, and a consistent read after it still answers the session without that
// app, which the end then deletes untold. A locking read answers the latest committed rows. The
// clients are read the same way, since the app may have been registered, or its back-channel
// logout URI set, after the snapshot. On PostgreSQL and SQL Server at READ COMMITTED each
// statement reads what was committed when it started, and SQLite has one writer at a time, so
// their statements take no lock.
//
// tx is required: the read is only current under the session's row, which a transaction holds.
func (d *Database) GetCommittedUserSessionClients(ctx context.Context, tx *sql.Tx, userSessionID int64) ([]record.UserSessionClient, error) {

	if tx == nil {
		return nil, errs.New("reading a session's apps as committed requires a transaction: they are current only under the session's row")
	}

	userSessionClients, err := queryAll(ctx, d, tx, nil, selectCommittedUserSessionClientsByUserSessionID.text(d.Dialect),
		[]any{userSessionID}, scanUserSessionClient, "userSessionClient")
	if err != nil {
		return nil, err
	}

	// One read per app, by id: a session serves a handful, and it keeps the lock on the one row read.
	for i := range userSessionClients {
		client, err := queryOne(ctx, d, tx, selectCommittedClientByID.text(d.Dialect),
			[]any{userSessionClients[i].ClientID}, scanClient, "client")
		if err != nil {
			return nil, err
		}
		if client == nil {
			return nil, errs.Errorf("client with id %d not found", userSessionClients[i].ClientID)
		}
		userSessionClients[i].Client = *client
	}

	return userSessionClients, nil
}

func (d *Database) GetUserSessionsClientByIDs(ctx context.Context, tx *sql.Tx, userSessionClientIDs []int64) ([]record.UserSessionClient, error) {

	if len(userSessionClientIDs) == 0 {
		return nil, nil
	}

	var userSessionClients []record.UserSessionClient

	err := forEachIDBatch(userSessionClientIDs, func(batch []int64) error {
		query := selectUserSessionClientsWhere.text(d.Dialect) + inList(d.Dialect, "id", 1, len(batch))
		var err error
		userSessionClients, err = queryAll(ctx, d, tx, userSessionClients, query, int64Args(batch),
			scanUserSessionClient, "userSessionClient")
		return err
	})
	if err != nil {
		return nil, err
	}

	return userSessionClients, nil
}

func (d *Database) GetUserSessionClientByID(ctx context.Context, tx *sql.Tx, userSessionClientID int64) (*record.UserSessionClient, error) {
	return queryOne(ctx, d, tx, selectUserSessionClientByID.text(d.Dialect), []any{userSessionClientID},
		scanUserSessionClient, "userSessionClient")
}

func (d *Database) DeleteUserSessionClient(ctx context.Context, tx *sql.Tx, userSessionClientID int64) error {

	_, err := d.ExecSQL(ctx, tx, deleteUserSessionClient.text(d.Dialect), userSessionClientID)
	if err != nil {
		return errs.Wrap(err, "unable to delete userSessionClient")
	}

	return nil
}
