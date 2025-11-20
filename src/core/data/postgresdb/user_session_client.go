package postgresdb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *PostgresDatabase) CreateUserSessionClient(tx *sql.Tx, userSessionClient *models.UserSessionClient) error {
	now := time.Now().UTC()

	originalCreatedAt := userSessionClient.CreatedAt
	originalUpdatedAt := userSessionClient.UpdatedAt
	userSessionClient.CreatedAt = sql.NullTime{Time: now, Valid: true}
	userSessionClient.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	userSessionClientStruct := sqlbuilder.NewStruct(new(models.UserSessionClient)).
		For(sqlbuilder.PostgreSQL)

	insertBuilder := userSessionClientStruct.WithoutTag("pk").InsertInto("user_session_clients", userSessionClient)

	sql, args := insertBuilder.Build()
	sql = sql + " RETURNING id"

	rows, err := d.CommonDB.QuerySql(tx, sql, args...)
	if err != nil {
		userSessionClient.CreatedAt = originalCreatedAt
		userSessionClient.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert userSessionClient")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		err = rows.Scan(&userSessionClient.Id)
		if err != nil {
			userSessionClient.CreatedAt = originalCreatedAt
			userSessionClient.UpdatedAt = originalUpdatedAt
			return errors.Wrap(err, "unable to scan userSessionClient id")
		}
	}

	return nil
}

func (d *PostgresDatabase) UpdateUserSessionClient(tx *sql.Tx, userSessionClient *models.UserSessionClient) error {
	return d.CommonDB.UpdateUserSessionClient(tx, userSessionClient)
}

func (d *PostgresDatabase) UserSessionClientsLoadClients(tx *sql.Tx, userSessionClients []models.UserSessionClient) error {
	return d.CommonDB.UserSessionClientsLoadClients(tx, userSessionClients)
}

func (d *PostgresDatabase) GetUserSessionClientsByUserSessionIds(tx *sql.Tx, userSessionIds []int64) ([]models.UserSessionClient, error) {
	return d.CommonDB.GetUserSessionClientsByUserSessionIds(tx, userSessionIds)
}

func (d *PostgresDatabase) GetUserSessionClientsByUserSessionId(tx *sql.Tx, userSessionId int64) ([]models.UserSessionClient, error) {
	return d.CommonDB.GetUserSessionClientsByUserSessionId(tx, userSessionId)
}

func (d *PostgresDatabase) GetUserSessionsClientByIds(tx *sql.Tx, userSessionClientIds []int64) ([]models.UserSessionClient, error) {
	return d.CommonDB.GetUserSessionsClientByIds(tx, userSessionClientIds)
}

func (d *PostgresDatabase) GetUserSessionClientById(tx *sql.Tx, userSessionClientId int64) (*models.UserSessionClient, error) {
	return d.CommonDB.GetUserSessionClientById(tx, userSessionClientId)
}

func (d *PostgresDatabase) DeleteUserSessionClient(tx *sql.Tx, userSessionClientId int64) error {
	return d.CommonDB.DeleteUserSessionClient(tx, userSessionClientId)
}
