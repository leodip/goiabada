package mysqldb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entities"
)

func (d *MySQLDatabase) CreateHttpSession(tx *sql.Tx, httpSession *entities.HttpSession) error {
	return d.CommonDB.CreateHttpSession(tx, httpSession)
}

func (d *MySQLDatabase) UpdateHttpSession(tx *sql.Tx, httpSession *entities.HttpSession) error {
	return d.CommonDB.UpdateHttpSession(tx, httpSession)
}

func (d *MySQLDatabase) GetHttpSessionById(tx *sql.Tx, httpSessionId int64) (*entities.HttpSession, error) {
	return d.CommonDB.GetHttpSessionById(tx, httpSessionId)
}

func (d *MySQLDatabase) DeleteHttpSession(tx *sql.Tx, httpSessionId int64) error {
	return d.CommonDB.DeleteHttpSession(tx, httpSessionId)
}

func (d *MySQLDatabase) DeleteHttpSessionExpired(tx *sql.Tx) error {
	return d.CommonDB.DeleteHttpSessionExpired(tx)
}
