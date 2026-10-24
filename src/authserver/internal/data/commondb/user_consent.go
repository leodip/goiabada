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
		&userConsent.Id,
		&userConsent.CreatedAt,
		&userConsent.UpdatedAt,
		&userConsent.UserId,
		&userConsent.ClientId,
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

var selectUserConsentById = statement{
	sqlite:   "SELECT " + userConsentColumns.sqlite + " FROM user_consents WHERE id = ?",
	mysql:    "SELECT " + userConsentColumns.mysql + " FROM user_consents WHERE id = ?",
	postgres: "SELECT " + userConsentColumns.postgres + " FROM user_consents WHERE id = $1",
	mssql:    "SELECT " + userConsentColumns.mssql + " FROM user_consents WHERE id = @p1",
}

var selectUserConsentByUserIdAndClientId = statement{
	sqlite:   "SELECT " + userConsentColumns.sqlite + " FROM user_consents WHERE user_id = ? AND client_id = ?",
	mysql:    "SELECT " + userConsentColumns.mysql + " FROM user_consents WHERE user_id = ? AND client_id = ?",
	postgres: "SELECT " + userConsentColumns.postgres + " FROM user_consents WHERE user_id = $1 AND client_id = $2",
	mssql:    "SELECT " + userConsentColumns.mssql + " FROM user_consents WHERE user_id = @p1 AND client_id = @p2",
}

var selectUserConsentsByUserId = statement{
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

	if userConsent.ClientId == 0 {
		return errs.New("client id must be greater than 0")
	}

	if userConsent.UserId == 0 {
		return errs.New("user id must be greater than 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := userConsent.CreatedAt
	originalUpdatedAt := userConsent.UpdatedAt
	userConsent.CreatedAt = sql.NullTime{Time: now, Valid: true}
	userConsent.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	id, err := d.insert(ctx, tx, insertUserConsent, "userConsent",
		userConsent.CreatedAt, userConsent.UpdatedAt, userConsent.UserId, userConsent.ClientId, userConsent.Scope,
		userConsent.GrantedAt)
	if err != nil {
		userConsent.CreatedAt = originalCreatedAt
		userConsent.UpdatedAt = originalUpdatedAt
		return err
	}

	userConsent.Id = id
	return nil
}

func (d *Database) UpdateUserConsent(ctx context.Context, tx *sql.Tx, userConsent *record.UserConsent) error {

	if userConsent.Id == 0 {
		return errs.New("can't update userConsent with id 0")
	}

	originalUpdatedAt := userConsent.UpdatedAt
	userConsent.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	_, err := d.ExecSQL(ctx, tx, updateUserConsent.text(d.Dialect),
		userConsent.UpdatedAt, userConsent.UserId, userConsent.ClientId, userConsent.Scope, userConsent.GrantedAt,
		userConsent.Id)
	if err != nil {
		userConsent.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update userConsent")
	}

	return nil
}

func (d *Database) GetUserConsentById(ctx context.Context, tx *sql.Tx, userConsentId int64) (*record.UserConsent, error) {
	return queryOne(ctx, d, tx, selectUserConsentById.text(d.Dialect), []any{userConsentId},
		scanUserConsent, "userConsent")
}

func (d *Database) GetConsentByUserIdAndClientId(ctx context.Context, tx *sql.Tx, userId int64, clientId int64) (*record.UserConsent, error) {
	return queryOne(ctx, d, tx, selectUserConsentByUserIdAndClientId.text(d.Dialect), []any{userId, clientId},
		scanUserConsent, "userConsent")
}

func (d *Database) UserConsentsLoadClients(ctx context.Context, tx *sql.Tx, userConsents []record.UserConsent) error {

	if userConsents == nil {
		return nil
	}

	clientIds := make([]int64, len(userConsents))
	for i, userConsent := range userConsents {
		clientIds[i] = userConsent.ClientId
	}

	clients, err := d.GetClientsByIds(ctx, tx, clientIds)
	if err != nil {
		return errs.Wrap(err, "unable to load clients")
	}

	clientsById := make(map[int64]record.Client)
	for _, client := range clients {
		clientsById[client.Id] = client
	}

	for i, userConsent := range userConsents {
		client, ok := clientsById[userConsent.ClientId]
		if !ok {
			return errs.Errorf("unable to find client with id %v", userConsent.ClientId)
		}
		userConsents[i].Client = client
	}

	return nil
}

func (d *Database) GetConsentsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]record.UserConsent, error) {
	return queryAll(ctx, d, tx, nil, selectUserConsentsByUserId.text(d.Dialect), []any{userId},
		scanUserConsent, "userConsent")
}

func (d *Database) DeleteUserConsent(ctx context.Context, tx *sql.Tx, userConsentId int64) error {

	_, err := d.ExecSQL(ctx, tx, deleteUserConsent.text(d.Dialect), userConsentId)
	if err != nil {
		return errs.Wrap(err, "unable to delete userConsent")
	}

	return nil
}

func (d *Database) DeleteAllUserConsent(ctx context.Context, tx *sql.Tx) error {

	_, err := d.ExecSQL(ctx, tx, deleteAllUserConsents.text(d.Dialect))
	if err != nil {
		return errs.Wrap(err, "unable to delete userConsent")
	}

	return nil
}
