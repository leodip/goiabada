package sqlitedb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entities"
)

func (d *SQLiteDatabase) CreateUserSession(tx *sql.Tx, userSession *entities.UserSession) error {
	return d.CommonDB.CreateUserSession(tx, userSession)
}

func (d *SQLiteDatabase) UpdateUserSession(tx *sql.Tx, userSession *entities.UserSession) error {
	return d.CommonDB.UpdateUserSession(tx, userSession)
}

func (d *SQLiteDatabase) GetUserSessionById(tx *sql.Tx, userSessionId int64) (*entities.UserSession, error) {
	return d.CommonDB.GetUserSessionById(tx, userSessionId)
}

func (d *SQLiteDatabase) GetUserSessionBySessionIdentifier(tx *sql.Tx, sessionIdentifier string) (*entities.UserSession, error) {
	return d.CommonDB.GetUserSessionBySessionIdentifier(tx, sessionIdentifier)
}

func (d *SQLiteDatabase) GetUserSessionsByClientIdPaginated(tx *sql.Tx, clientId int64, page int, pageSize int) ([]entities.UserSession, int, error) {
	return d.CommonDB.GetUserSessionsByClientIdPaginated(tx, clientId, page, pageSize)
}

func (d *SQLiteDatabase) UserSessionsLoadUsers(tx *sql.Tx, userSessions []entities.UserSession) error {
	return d.CommonDB.UserSessionsLoadUsers(tx, userSessions)
}

func (d *SQLiteDatabase) UserSessionsLoadClients(tx *sql.Tx, userSessions []entities.UserSession) error {
	return d.CommonDB.UserSessionsLoadClients(tx, userSessions)
}

func (d *SQLiteDatabase) UserSessionLoadClients(tx *sql.Tx, userSession *entities.UserSession) error {
	return d.CommonDB.UserSessionLoadClients(tx, userSession)
}

func (d *SQLiteDatabase) UserSessionLoadUser(tx *sql.Tx, userSession *entities.UserSession) error {
	return d.CommonDB.UserSessionLoadUser(tx, userSession)
}

func (d *SQLiteDatabase) GetUserSessionsByUserId(tx *sql.Tx, userId int64) ([]entities.UserSession, error) {
	return d.CommonDB.GetUserSessionsByUserId(tx, userId)
}

func (d *SQLiteDatabase) DeleteUserSession(tx *sql.Tx, userSessionId int64) error {
	return d.CommonDB.DeleteUserSession(tx, userSessionId)
}
