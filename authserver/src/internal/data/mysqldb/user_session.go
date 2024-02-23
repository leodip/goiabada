package mysqldb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entities"
)

func (d *MySQLDatabase) CreateUserSession(tx *sql.Tx, userSession *entities.UserSession) error {
	return d.CommonDB.CreateUserSession(tx, userSession)
}

func (d *MySQLDatabase) UpdateUserSession(tx *sql.Tx, userSession *entities.UserSession) error {
	return d.CommonDB.UpdateUserSession(tx, userSession)
}

func (d *MySQLDatabase) GetUserSessionById(tx *sql.Tx, userSessionId int64) (*entities.UserSession, error) {
	return d.CommonDB.GetUserSessionById(tx, userSessionId)
}

func (d *MySQLDatabase) GetUserSessionBySessionIdentifier(tx *sql.Tx, sessionIdentifier string) (*entities.UserSession, error) {
	return d.CommonDB.GetUserSessionBySessionIdentifier(tx, sessionIdentifier)
}

func (d *MySQLDatabase) GetUserSessionsByClientIdPaginated(tx *sql.Tx, clientId int64, page int, pageSize int) ([]entities.UserSession, int, error) {
	return d.CommonDB.GetUserSessionsByClientIdPaginated(tx, clientId, page, pageSize)
}

func (d *MySQLDatabase) UserSessionsLoadUsers(tx *sql.Tx, userSessions []entities.UserSession) error {
	return d.CommonDB.UserSessionsLoadUsers(tx, userSessions)
}

func (d *MySQLDatabase) UserSessionsLoadClients(tx *sql.Tx, userSessions []entities.UserSession) error {
	return d.CommonDB.UserSessionsLoadClients(tx, userSessions)
}

func (d *MySQLDatabase) UserSessionLoadClients(tx *sql.Tx, userSession *entities.UserSession) error {
	return d.CommonDB.UserSessionLoadClients(tx, userSession)
}

func (d *MySQLDatabase) UserSessionLoadUser(tx *sql.Tx, userSession *entities.UserSession) error {
	return d.CommonDB.UserSessionLoadUser(tx, userSession)
}

func (d *MySQLDatabase) GetUserSessionsByUserId(tx *sql.Tx, userId int64) ([]entities.UserSession, error) {
	return d.CommonDB.GetUserSessionsByUserId(tx, userId)
}

func (d *MySQLDatabase) DeleteUserSession(tx *sql.Tx, userSessionId int64) error {
	return d.CommonDB.DeleteUserSession(tx, userSessionId)
}
