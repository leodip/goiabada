package sqlitedb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entitiesv2"
)

func (d *SQLiteDatabase) CreateUserSessionClient(tx *sql.Tx, userSessionClient *entitiesv2.UserSessionClient) error {
	return d.CommonDB.CreateUserSessionClient(tx, userSessionClient)
}

func (d *SQLiteDatabase) UpdateUserSessionClient(tx *sql.Tx, userSessionClient *entitiesv2.UserSessionClient) error {
	return d.CommonDB.UpdateUserSessionClient(tx, userSessionClient)
}

func (d *SQLiteDatabase) UserSessionClientsLoadClients(tx *sql.Tx, userSessionClients []entitiesv2.UserSessionClient) error {
	return d.CommonDB.UserSessionClientsLoadClients(tx, userSessionClients)
}

func (d *SQLiteDatabase) GetUserSessionClientsByUserSessionIds(tx *sql.Tx, userSessionIds []int64) ([]entitiesv2.UserSessionClient, error) {
	return d.CommonDB.GetUserSessionClientsByUserSessionIds(tx, userSessionIds)
}

func (d *SQLiteDatabase) GetUserSessionClientsByUserSessionId(tx *sql.Tx, userSessionId int64) ([]entitiesv2.UserSessionClient, error) {
	return d.CommonDB.GetUserSessionClientsByUserSessionId(tx, userSessionId)
}

func (d *SQLiteDatabase) GetUserSessionsClientByIds(tx *sql.Tx, userSessionClientIds []int64) ([]entitiesv2.UserSessionClient, error) {
	return d.CommonDB.GetUserSessionsClientByIds(tx, userSessionClientIds)
}

func (d *SQLiteDatabase) GetUserSessionClientById(tx *sql.Tx, userSessionClientId int64) (*entitiesv2.UserSessionClient, error) {
	return d.CommonDB.GetUserSessionClientById(tx, userSessionClientId)
}

func (d *SQLiteDatabase) DeleteUserSessionClient(tx *sql.Tx, userSessionClientId int64) error {
	return d.CommonDB.DeleteUserSessionClient(tx, userSessionClientId)
}
