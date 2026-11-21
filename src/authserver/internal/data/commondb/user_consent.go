package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// userConsentColumns is the user_consents table as scanUserConsent reads it.
var userConsentColumns = columnList{
	sqlite:   "id, created_at, updated_at, user_id, client_id, scope, granted_at",
	mysql:    "id, created_at, updated_at, user_id, client_id, scope, granted_at",
	postgres: "id, created_at, updated_at, user_id, client_id, scope, granted_at",
	mssql:    "id, created_at, updated_at, user_id, client_id, scope, granted_at",
}

// scanUserConsent reads one row selected with userConsentColumns.
func scanUserConsent(row rowScanner, userConsent *record.UserConsent) error {
	return row.Scan(
		&userConsent.ID,
		&userConsent.CreatedAt,
		&userConsent.UpdatedAt,
		&userConsent.UserID,
		&userConsent.ClientID,
		&userConsent.Scope,
		&userConsent.GrantedAt,
	)
}

var insertUserConsent = statement{
	sqlite: "INSERT INTO user_consents (created_at, updated_at, user_id, client_id, scope, granted_at) " +
		"VALUES (?, ?, ?, ?, ?, ?)",
	mysql: "INSERT INTO user_consents (created_at, updated_at, user_id, client_id, scope, granted_at) " +
		"VALUES (?, ?, ?, ?, ?, ?)",
	postgres: "INSERT INTO user_consents (created_at, updated_at, user_id, client_id, scope, granted_at) " +
		"VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
	mssql: "INSERT INTO user_consents (created_at, updated_at, user_id, client_id, scope, granted_at) " +
		"OUTPUT INSERTED.id VALUES (@p1, @p2, @p3, @p4, @p5, @p6)",
}

// updateUserConsent writes the whole row but created_at, which is dont-update.
var updateUserConsent = statement{
	sqlite:   "UPDATE user_consents SET updated_at = ?, user_id = ?, client_id = ?, scope = ?, granted_at = ? WHERE id = ?",
	mysql:    "UPDATE user_consents SET updated_at = ?, user_id = ?, client_id = ?, scope = ?, granted_at = ? WHERE id = ?",
	postgres: "UPDATE user_consents SET updated_at = $1, user_id = $2, client_id = $3, scope = $4, granted_at = $5 WHERE id = $6",
	mssql: "UPDATE user_consents SET updated_at = @p1, user_id = @p2, client_id = @p3, scope = @p4, granted_at = @p5 " +
		"WHERE id = @p6",
}

var selectUserConsentByID = statement{
	sqlite:   "SELECT " + userConsentColumns.sqlite + " FROM user_consents WHERE id = ?",
	mysql:    "SELECT " + userConsentColumns.mysql + " FROM user_consents WHERE id = ?",
	postgres: "SELECT " + userConsentColumns.postgres + " FROM user_consents WHERE id = $1",
	mssql:    "SELECT " + userConsentColumns.mssql + " FROM user_consents WHERE id = @p1",
}

var selectUserConsentByUserIDAndClientID = statement{
	sqlite:   "SELECT " + userConsentColumns.sqlite + " FROM user_consents WHERE user_id = ? AND client_id = ?",
	mysql:    "SELECT " + userConsentColumns.mysql + " FROM user_consents WHERE user_id = ? AND client_id = ?",
	postgres: "SELECT " + userConsentColumns.postgres + " FROM user_consents WHERE user_id = $1 AND client_id = $2",
	mssql:    "SELECT " + userConsentColumns.mssql + " FROM user_consents WHERE user_id = @p1 AND client_id = @p2",
}

// selectUserConsentByUserIDAndClientIDForUpdate is the locking read
// GetConsentByUserIDAndClientIDForUpdate runs, the lock in each engine's own grammar, as
// selectUserByIDForUpdate spells it.
var selectUserConsentByUserIDAndClientIDForUpdate = statement{
	sqlite:   "SELECT " + userConsentColumns.sqlite + " FROM user_consents WHERE user_id = ? AND client_id = ?",
	mysql:    "SELECT " + userConsentColumns.mysql + " FROM user_consents WHERE user_id = ? AND client_id = ? FOR UPDATE",
	postgres: "SELECT " + userConsentColumns.postgres + " FROM user_consents WHERE user_id = $1 AND client_id = $2 FOR UPDATE",
	mssql:    "SELECT " + userConsentColumns.mssql + " FROM user_consents WITH (UPDLOCK, ROWLOCK) WHERE user_id = @p1 AND client_id = @p2",
}

var selectUserConsentsByUserID = statement{
	sqlite:   "SELECT " + userConsentColumns.sqlite + " FROM user_consents WHERE user_id = ?",
	mysql:    "SELECT " + userConsentColumns.mysql + " FROM user_consents WHERE user_id = ?",
	postgres: "SELECT " + userConsentColumns.postgres + " FROM user_consents WHERE user_id = $1",
	mssql:    "SELECT " + userConsentColumns.mssql + " FROM user_consents WHERE user_id = @p1",
}

var deleteUserConsent = statement{
	sqlite:   "DELETE FROM user_consents WHERE id = ?",
	mysql:    "DELETE FROM user_consents WHERE id = ?",
	postgres: "DELETE FROM user_consents WHERE id = $1",
	mssql:    "DELETE FROM user_consents WHERE id = @p1",
}

var deleteAllUserConsents = statement{
	sqlite:   "DELETE FROM user_consents",
	mysql:    "DELETE FROM user_consents",
	postgres: "DELETE FROM user_consents",
	mssql:    "DELETE FROM user_consents",
}

func (d *Database) CreateUserConsent(ctx context.Context, tx *sql.Tx, userConsent *record.UserConsent) error {

	if userConsent.ClientID == 0 {
		return errs.New("client id must be greater than 0")
	}

	if userConsent.UserID == 0 {
		return errs.New("user id must be greater than 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := userConsent.CreatedAt
	originalUpdatedAt := userConsent.UpdatedAt
	userConsent.CreatedAt = sql.NullTime{Time: now, Valid: true}
	userConsent.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	id, err := d.insert(ctx, tx, insertUserConsent, "userConsent",
		userConsent.CreatedAt, userConsent.UpdatedAt, userConsent.UserID, userConsent.ClientID, userConsent.Scope,
		userConsent.GrantedAt)
	if err != nil {
		userConsent.CreatedAt = originalCreatedAt
		userConsent.UpdatedAt = originalUpdatedAt
		return err
	}

	userConsent.ID = id
	return nil
}

func (d *Database) UpdateUserConsent(ctx context.Context, tx *sql.Tx, userConsent *record.UserConsent) error {

	if userConsent.ID == 0 {
		return errs.New("can't update userConsent with id 0")
	}

	originalUpdatedAt := userConsent.UpdatedAt
	userConsent.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	_, err := d.ExecSQL(ctx, tx, updateUserConsent.text(d.Dialect),
		userConsent.UpdatedAt, userConsent.UserID, userConsent.ClientID, userConsent.Scope, userConsent.GrantedAt,
		userConsent.ID)
	if err != nil {
		userConsent.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update userConsent")
	}

	return nil
}

func (d *Database) GetUserConsentByID(ctx context.Context, tx *sql.Tx, userConsentID int64) (*record.UserConsent, error) {
	return queryOne(ctx, d, tx, selectUserConsentByID.text(d.Dialect), []any{userConsentID},
		scanUserConsent, "userConsent")
}

func (d *Database) GetConsentByUserIDAndClientID(ctx context.Context, tx *sql.Tx, userID int64, clientID int64) (*record.UserConsent, error) {
	return queryOne(ctx, d, tx, selectUserConsentByUserIDAndClientID.text(d.Dialect), []any{userID, clientID},
		scanUserConsent, "userConsent")
}

// GetConsentByUserIDAndClientIDForUpdate reads the user's consent to the client as last committed
// and takes its row for the rest of the caller's transaction: a locking read, where
// GetConsentByUserIDAndClientID is a consistent one. A disconnect reads the consent it deletes
// this way (#135 decision 1). Under MySQL's REPEATABLE READ a consistent read answers the
// snapshot the transaction's first read fixed, and the disconnect reads the client and the user's
// sessions before it, so a consent given in between would survive a disconnect that reported
// success. The lock is each engine's own, as GetUserByIDForUpdate's is: FOR UPDATE on MySQL and
// PostgreSQL, UPDLOCK and ROWLOCK on SQL Server, none on SQLite, which has no row locks.
//
// A transaction is required, for the reason GetUserByIDForUpdate gives.
func (d *Database) GetConsentByUserIDAndClientIDForUpdate(ctx context.Context, tx *sql.Tx, userID int64,
	clientID int64) (*record.UserConsent, error) {

	if tx == nil {
		return nil, errs.New("a locking read of a consent requires a transaction: an autocommitted statement releases the row before the caller can decide on it")
	}

	return queryOne(ctx, d, tx, selectUserConsentByUserIDAndClientIDForUpdate.text(d.Dialect), []any{userID, clientID},
		scanUserConsent, "userConsent")
}

func (d *Database) UserConsentsLoadClients(ctx context.Context, tx *sql.Tx, userConsents []record.UserConsent) error {

	if userConsents == nil {
		return nil
	}

	clientIDs := make([]int64, len(userConsents))
	for i, userConsent := range userConsents {
		clientIDs[i] = userConsent.ClientID
	}

	clients, err := d.GetClientsByIDs(ctx, tx, clientIDs)
	if err != nil {
		return errs.Wrap(err, "unable to load clients")
	}

	clientsByID := make(map[int64]record.Client)
	for _, client := range clients {
		clientsByID[client.ID] = client
	}

	for i, userConsent := range userConsents {
		client, ok := clientsByID[userConsent.ClientID]
		if !ok {
			return errs.Errorf("unable to find client with id %v", userConsent.ClientID)
		}
		userConsents[i].Client = client
	}

	return nil
}

func (d *Database) GetConsentsByUserID(ctx context.Context, tx *sql.Tx, userID int64) ([]record.UserConsent, error) {
	return queryAll(ctx, d, tx, nil, selectUserConsentsByUserID.text(d.Dialect), []any{userID},
		scanUserConsent, "userConsent")
}

// DeleteUserConsent deletes one stored consent and reports whether THIS call deleted it: false
// when no row had the id, because it never existed or another request deleted it first. A
// consent withdrawal answers from it, so two overlapping withdrawals never both report the
// deletion (#135 decision 2).
func (d *Database) DeleteUserConsent(ctx context.Context, tx *sql.Tx, userConsentID int64) (bool, error) {

	result, err := d.ExecSQL(ctx, tx, deleteUserConsent.text(d.Dialect), userConsentID)
	if err != nil {
		return false, errs.Wrap(err, "unable to delete userConsent")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errs.Wrap(err, "unable to get rows affected when deleting userConsent")
	}

	return rowsAffected > 0, nil
}

func (d *Database) DeleteAllUserConsent(ctx context.Context, tx *sql.Tx) error {

	_, err := d.ExecSQL(ctx, tx, deleteAllUserConsents.text(d.Dialect))
	if err != nil {
		return errs.Wrap(err, "unable to delete userConsent")
	}

	return nil
}
