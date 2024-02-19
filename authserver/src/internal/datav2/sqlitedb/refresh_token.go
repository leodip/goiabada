package sqlitedb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entitiesv2"
)

func (d *SQLiteDatabase) CreateRefreshToken(tx *sql.Tx, refreshToken *entitiesv2.RefreshToken) error {
	return d.CommonDB.CreateRefreshToken(tx, refreshToken)
}

func (d *SQLiteDatabase) UpdateRefreshToken(tx *sql.Tx, refreshToken *entitiesv2.RefreshToken) error {
	return d.CommonDB.UpdateRefreshToken(tx, refreshToken)
}

func (d *SQLiteDatabase) GetRefreshTokenById(tx *sql.Tx, refreshTokenId int64) (*entitiesv2.RefreshToken, error) {
	return d.CommonDB.GetRefreshTokenById(tx, refreshTokenId)
}

func (d *SQLiteDatabase) RefreshTokenLoadCode(tx *sql.Tx, refreshToken *entitiesv2.RefreshToken) error {
	return d.CommonDB.RefreshTokenLoadCode(tx, refreshToken)
}

func (d *SQLiteDatabase) GetRefreshTokenByJti(tx *sql.Tx, jti string) (*entitiesv2.RefreshToken, error) {
	return d.CommonDB.GetRefreshTokenByJti(tx, jti)
}

func (d *SQLiteDatabase) DeleteRefreshToken(tx *sql.Tx, refreshTokenId int64) error {
	return d.CommonDB.DeleteRefreshToken(tx, refreshTokenId)
}
