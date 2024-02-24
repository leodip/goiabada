package mysqldb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entities"
)

func (d *MySQLDatabase) CreateCode(tx *sql.Tx, code *entities.Code) error {
	return d.CommonDB.CreateCode(tx, code)
}

func (d *MySQLDatabase) UpdateCode(tx *sql.Tx, code *entities.Code) error {
	return d.CommonDB.UpdateCode(tx, code)
}

func (d *MySQLDatabase) GetCodeById(tx *sql.Tx, codeId int64) (*entities.Code, error) {
	return d.CommonDB.GetCodeById(tx, codeId)
}

func (d *MySQLDatabase) CodeLoadClient(tx *sql.Tx, code *entities.Code) error {
	return d.CommonDB.CodeLoadClient(tx, code)
}

func (d *MySQLDatabase) CodeLoadUser(tx *sql.Tx, code *entities.Code) error {
	return d.CommonDB.CodeLoadUser(tx, code)
}

func (d *MySQLDatabase) GetCodeByCodeHash(tx *sql.Tx, codeHash string, used bool) (*entities.Code, error) {
	return d.CommonDB.GetCodeByCodeHash(tx, codeHash, used)
}

func (d *MySQLDatabase) DeleteCode(tx *sql.Tx, codeId int64) error {
	return d.CommonDB.DeleteCode(tx, codeId)
}
