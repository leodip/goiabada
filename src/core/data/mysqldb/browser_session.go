package mysqldb

import (
	"database/sql"
	"time"

	"github.com/leodip/goiabada/core/models"
)

func (d *MySQLDatabase) CreateBrowserSession(tx *sql.Tx, browserSession *models.BrowserSession) error {
	return d.CommonDB.CreateBrowserSession(tx, browserSession)
}

func (d *MySQLDatabase) GetBrowserSessionByOwnerAndSessionIdHash(tx *sql.Tx, owner, sessionIdHash string,
	now time.Time) (*models.BrowserSession, error) {
	return d.CommonDB.GetBrowserSessionByOwnerAndSessionIdHash(tx, owner, sessionIdHash, now)
}

func (d *MySQLDatabase) UpdateBrowserSessionData(tx *sql.Tx, owner, sessionIdHash, data string,
	now, expiresAt time.Time) (bool, error) {
	return d.CommonDB.UpdateBrowserSessionData(tx, owner, sessionIdHash, data, now, expiresAt)
}

func (d *MySQLDatabase) TouchBrowserSession(tx *sql.Tx, owner, sessionIdHash string,
	now, expiresAt time.Time) (bool, error) {
	return d.CommonDB.TouchBrowserSession(tx, owner, sessionIdHash, now, expiresAt)
}

func (d *MySQLDatabase) DeleteBrowserSession(tx *sql.Tx, owner, sessionIdHash string) error {
	return d.CommonDB.DeleteBrowserSession(tx, owner, sessionIdHash)
}

func (d *MySQLDatabase) DeleteExpiredBrowserSessions(tx *sql.Tx, now time.Time) error {
	return d.CommonDB.DeleteExpiredBrowserSessions(tx, now)
}
