package mysqldb

import (
	"database/sql"

	"github.com/leodip/goiabada/core/models"
	"time"
)

func (d *MySQLDatabase) CreateCode(tx *sql.Tx, code *models.Code) error {
	return d.CommonDB.CreateCode(tx, code)
}

func (d *MySQLDatabase) UpdateCode(tx *sql.Tx, code *models.Code) error {
	return d.CommonDB.UpdateCode(tx, code)
}

func (d *MySQLDatabase) MarkCodeAsUsed(tx *sql.Tx, codeId int64) (bool, error) {
	return d.CommonDB.MarkCodeAsUsed(tx, codeId)
}

func (d *MySQLDatabase) RevokeCodesBySessionIdentifier(tx *sql.Tx, sessionIdentifier string) (int64, error) {
	return d.CommonDB.RevokeCodesBySessionIdentifier(tx, sessionIdentifier)
}

func (d *MySQLDatabase) GetCodeById(tx *sql.Tx, codeId int64) (*models.Code, error) {
	return d.CommonDB.GetCodeById(tx, codeId)
}

func (d *MySQLDatabase) CodeLoadClient(tx *sql.Tx, code *models.Code) error {
	return d.CommonDB.CodeLoadClient(tx, code)
}

func (d *MySQLDatabase) CodeLoadUser(tx *sql.Tx, code *models.Code) error {
	return d.CommonDB.CodeLoadUser(tx, code)
}

func (d *MySQLDatabase) GetCodeByCodeHash(tx *sql.Tx, codeHash string, used bool) (*models.Code, error) {
	return d.CommonDB.GetCodeByCodeHash(tx, codeHash, used)
}

func (d *MySQLDatabase) DeleteCode(tx *sql.Tx, codeId int64) error {
	return d.CommonDB.DeleteCode(tx, codeId)
}

func (d *MySQLDatabase) DeleteUsedCodesWithoutRefreshTokens(tx *sql.Tx, createdBefore time.Time) error {
	return d.CommonDB.DeleteUsedCodesWithoutRefreshTokens(tx, createdBefore)
}
