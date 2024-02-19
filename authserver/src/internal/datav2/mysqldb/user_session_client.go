package mysqldb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entitiesv2"
)

func (d *MySQLDatabase) CreateUserSessionClient(tx *sql.Tx, userSessionClient *entitiesv2.UserSessionClient) error {
	return d.CommonDB.CreateUserSessionClient(tx, userSessionClient)
}

func (d *MySQLDatabase) UpdateUserSessionClient(tx *sql.Tx, userSessionClient *entitiesv2.UserSessionClient) error {
	return d.CommonDB.UpdateUserSessionClient(tx, userSessionClient)
}

func (d *MySQLDatabase) UserSessionClientsLoadClients(tx *sql.Tx, userSessionClients []entitiesv2.UserSessionClient) error {
	return d.CommonDB.UserSessionClientsLoadClients(tx, userSessionClients)
}

func (d *MySQLDatabase) GetUserSessionClientsByUserSessionIds(tx *sql.Tx, userSessionIds []int64) ([]entitiesv2.UserSessionClient, error) {
	return d.CommonDB.GetUserSessionClientsByUserSessionIds(tx, userSessionIds)
}

func (d *MySQLDatabase) GetUserSessionClientsByUserSessionId(tx *sql.Tx, userSessionId int64) ([]entitiesv2.UserSessionClient, error) {
	return d.CommonDB.GetUserSessionClientsByUserSessionId(tx, userSessionId)
}

func (d *MySQLDatabase) GetUserSessionsClientByIds(tx *sql.Tx, userSessionClientIds []int64) ([]entitiesv2.UserSessionClient, error) {
	return d.CommonDB.GetUserSessionsClientByIds(tx, userSessionClientIds)
}

func (d *MySQLDatabase) GetUserSessionClientById(tx *sql.Tx, userSessionClientId int64) (*entitiesv2.UserSessionClient, error) {
	return d.CommonDB.GetUserSessionClientById(tx, userSessionClientId)
}

func (d *MySQLDatabase) DeleteUserSessionClient(tx *sql.Tx, userSessionClientId int64) error {
	return d.CommonDB.DeleteUserSessionClient(tx, userSessionClientId)
}
