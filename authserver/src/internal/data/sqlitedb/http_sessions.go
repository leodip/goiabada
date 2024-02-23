package sqlitedb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entities"
)

func (d *SQLiteDatabase) CreateHttpSession(tx *sql.Tx, httpSession *entities.HttpSession) error {
	return d.CommonDB.CreateHttpSession(tx, httpSession)
}

func (d *SQLiteDatabase) UpdateHttpSession(tx *sql.Tx, httpSession *entities.HttpSession) error {
	return d.CommonDB.UpdateHttpSession(tx, httpSession)
}

func (d *SQLiteDatabase) GetHttpSessionById(tx *sql.Tx, httpSessionId int64) (*entities.HttpSession, error) {
	return d.CommonDB.GetHttpSessionById(tx, httpSessionId)
}

func (d *SQLiteDatabase) DeleteHttpSession(tx *sql.Tx, httpSessionId int64) error {
	return d.CommonDB.DeleteHttpSession(tx, httpSessionId)
}

func (d *SQLiteDatabase) DeleteHttpSessionExpired(tx *sql.Tx) error {
	return d.CommonDB.DeleteHttpSessionExpired(tx)
}
