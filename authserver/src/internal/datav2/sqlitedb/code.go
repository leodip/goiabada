package sqlitedb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entitiesv2"
)

func (d *SQLiteDatabase) CreateCode(tx *sql.Tx, code *entitiesv2.Code) error {
	return d.CommonDB.CreateCode(tx, code)
}

func (d *SQLiteDatabase) UpdateCode(tx *sql.Tx, code *entitiesv2.Code) error {
	return d.CommonDB.UpdateCode(tx, code)
}

func (d *SQLiteDatabase) GetCodeById(tx *sql.Tx, codeId int64) (*entitiesv2.Code, error) {
	return d.CommonDB.GetCodeById(tx, codeId)
}

func (d *SQLiteDatabase) CodeLoadClient(tx *sql.Tx, code *entitiesv2.Code) error {
	return d.CommonDB.CodeLoadClient(tx, code)
}

func (d *SQLiteDatabase) CodeLoadUser(tx *sql.Tx, code *entitiesv2.Code) error {
	return d.CommonDB.CodeLoadUser(tx, code)
}

func (d *SQLiteDatabase) GetCodeByCodeHash(tx *sql.Tx, codeHash string, used bool) (*entitiesv2.Code, error) {
	return d.CommonDB.GetCodeByCodeHash(tx, codeHash, used)
}

func (d *SQLiteDatabase) DeleteCode(tx *sql.Tx, codeId int64) error {
	return d.CommonDB.DeleteCode(tx, codeId)
}