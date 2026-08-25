package sqlitedb

import (
	"database/sql"

	"github.com/leodip/goiabada/core/models"
	"time"
)

func (d *SQLiteDatabase) CreateCode(tx *sql.Tx, code *models.Code) error {
	return d.CommonDB.CreateCode(tx, code)
}

func (d *SQLiteDatabase) UpdateCode(tx *sql.Tx, code *models.Code) error {
	return d.CommonDB.UpdateCode(tx, code)
}

func (d *SQLiteDatabase) MarkCodeAsUsed(tx *sql.Tx, codeId int64) (bool, error) {
	return d.CommonDB.MarkCodeAsUsed(tx, codeId)
}

func (d *SQLiteDatabase) RevokeCodesBySessionIdentifier(tx *sql.Tx, sessionIdentifier string) (int64, error) {
	return d.CommonDB.RevokeCodesBySessionIdentifier(tx, sessionIdentifier)
}

func (d *SQLiteDatabase) RevokeCodesByClientId(tx *sql.Tx, clientId int64) (int64, error) {
	return d.CommonDB.RevokeCodesByClientId(tx, clientId)
}

func (d *SQLiteDatabase) RevokeCodeIfSessionGone(tx *sql.Tx, codeId int64, sessionIdentifier string) (bool, error) {
	return d.CommonDB.RevokeCodeIfSessionGone(tx, codeId, sessionIdentifier)
}

func (d *SQLiteDatabase) GetCodeById(tx *sql.Tx, codeId int64) (*models.Code, error) {
	return d.CommonDB.GetCodeById(tx, codeId)
}

func (d *SQLiteDatabase) CodeLoadClient(tx *sql.Tx, code *models.Code) error {
	return d.CommonDB.CodeLoadClient(tx, code)
}

func (d *SQLiteDatabase) CodeLoadUser(tx *sql.Tx, code *models.Code) error {
	return d.CommonDB.CodeLoadUser(tx, code)
}

func (d *SQLiteDatabase) GetCodeByCodeHash(tx *sql.Tx, codeHash string, used bool) (*models.Code, error) {
	return d.CommonDB.GetCodeByCodeHash(tx, codeHash, used)
}

func (d *SQLiteDatabase) DeleteCode(tx *sql.Tx, codeId int64) error {
	return d.CommonDB.DeleteCode(tx, codeId)
}

func (d *SQLiteDatabase) DeleteUsedCodesWithoutRefreshTokens(tx *sql.Tx, createdBefore time.Time) error {
	return d.CommonDB.DeleteUsedCodesWithoutRefreshTokens(tx, createdBefore)
}
