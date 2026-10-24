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
		&userSessionClient.Id,
		&userSessionClient.CreatedAt,
		&userSessionClient.UpdatedAt,
		&userSessionClient.UserSessionId,
		&userSessionClient.ClientId,
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

var selectUserSessionClientById = statement{
	sqlite:   "SELECT " + userSessionClientColumns.sqlite + " FROM user_session_clients WHERE id = ?",
	mysql:    "SELECT " + userSessionClientColumns.mysql + " FROM user_session_clients WHERE id = ?",
	postgres: "SELECT " + userSessionClientColumns.postgres + " FROM user_session_clients WHERE id = $1",
	mssql:    "SELECT " + userSessionClientColumns.mssql + " FROM user_session_clients WHERE id = @p1",
}

var selectUserSessionClientsByUserSessionId = statement{
	sqlite:   "SELECT " + userSessionClientColumns.sqlite + " FROM user_session_clients WHERE user_session_id = ?",
	mysql:    "SELECT " + userSessionClientColumns.mysql + " FROM user_session_clients WHERE user_session_id = ?",
	postgres: "SELECT " + userSessionClientColumns.postgres + " FROM user_session_clients WHERE user_session_id = $1",
	mssql:    "SELECT " + userSessionClientColumns.mssql + " FROM user_session_clients WHERE user_session_id = @p1",
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
		userSessionClient.CreatedAt, userSessionClient.UpdatedAt, userSessionClient.UserSessionId,
		userSessionClient.ClientId, userSessionClient.Started, userSessionClient.LastAccessed)
	if err != nil {
		userSessionClient.CreatedAt = originalCreatedAt
		userSessionClient.UpdatedAt = originalUpdatedAt
		return err
	}

	userSessionClient.Id = id
	return nil
}

func (d *Database) UpdateUserSessionClient(ctx context.Context, tx *sql.Tx, userSessionClient *record.UserSessionClient) error {

	if userSessionClient.Id == 0 {
		return errs.New("can't update userSessionClient with id 0")
	}

	originalUpdatedAt := userSessionClient.UpdatedAt
	userSessionClient.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	_, err := d.ExecSQL(ctx, tx, updateUserSessionClient.text(d.Dialect),
		userSessionClient.UpdatedAt, userSessionClient.Started, userSessionClient.LastAccessed, userSessionClient.Id)
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

	clientIds := make([]int64, 0)
	for _, userSessionClient := range userSessionClients {
		clientIds = append(clientIds, userSessionClient.ClientId)
	}

	clients, err := d.GetClientsByIds(ctx, tx, clientIds)
	if err != nil {
		return errs.Wrap(err, "unable to get clients by ids")
	}

	clientsMap := make(map[int64]record.Client)
	for _, client := range clients {
		clientsMap[client.Id] = client
	}

	for i, userSessionClient := range userSessionClients {
		client, ok := clientsMap[userSessionClient.ClientId]
		if !ok {
			return errs.Errorf("client with id %d not found", userSessionClient.ClientId)
		}
		userSessionClients[i].Client = client
	}

	return nil
}

func (d *Database) GetUserSessionClientsByUserSessionIds(ctx context.Context, tx *sql.Tx, userSessionIds []int64) ([]record.UserSessionClient, error) {

	if len(userSessionIds) == 0 {
		return nil, nil
	}

	var userSessionClients []record.UserSessionClient

	err := forEachIdBatch(userSessionIds, func(batch []int64) error {
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

func (d *Database) GetUserSessionClientsByUserSessionId(ctx context.Context, tx *sql.Tx, userSessionId int64) ([]record.UserSessionClient, error) {
	return queryAll(ctx, d, tx, nil, selectUserSessionClientsByUserSessionId.text(d.Dialect), []any{userSessionId},
		scanUserSessionClient, "userSessionClient")
}

func (d *Database) GetUserSessionsClientByIds(ctx context.Context, tx *sql.Tx, userSessionClientIds []int64) ([]record.UserSessionClient, error) {

	if len(userSessionClientIds) == 0 {
		return nil, nil
	}

	var userSessionClients []record.UserSessionClient

	err := forEachIdBatch(userSessionClientIds, func(batch []int64) error {
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

func (d *Database) GetUserSessionClientById(ctx context.Context, tx *sql.Tx, userSessionClientId int64) (*record.UserSessionClient, error) {
	return queryOne(ctx, d, tx, selectUserSessionClientById.text(d.Dialect), []any{userSessionClientId},
		scanUserSessionClient, "userSessionClient")
}

func (d *Database) DeleteUserSessionClient(ctx context.Context, tx *sql.Tx, userSessionClientId int64) error {

	_, err := d.ExecSQL(ctx, tx, deleteUserSessionClient.text(d.Dialect), userSessionClientId)
	if err != nil {
		return errs.Wrap(err, "unable to delete userSessionClient")
	}

	return nil
}
