package mysqldb

import (
	"database/sql"

	"github.com/leodip/goiabada/authserver/internal/models"
)

func (d *MySQLDatabase) CreateRefreshToken(tx *sql.Tx, refreshToken *models.RefreshToken) error {
	return d.CommonDB.CreateRefreshToken(tx, refreshToken)
}

func (d *MySQLDatabase) UpdateRefreshToken(tx *sql.Tx, refreshToken *models.RefreshToken) error {
	return d.CommonDB.UpdateRefreshToken(tx, refreshToken)
}

func (d *MySQLDatabase) GetRefreshTokenById(tx *sql.Tx, refreshTokenId int64) (*models.RefreshToken, error) {
	return d.CommonDB.GetRefreshTokenById(tx, refreshTokenId)
}

func (d *MySQLDatabase) RefreshTokenLoadCode(tx *sql.Tx, refreshToken *models.RefreshToken) error {
	return d.CommonDB.RefreshTokenLoadCode(tx, refreshToken)
}

func (d *MySQLDatabase) GetRefreshTokenByJti(tx *sql.Tx, jti string) (*models.RefreshToken, error) {
	return d.CommonDB.GetRefreshTokenByJti(tx, jti)
}

func (d *MySQLDatabase) DeleteRefreshToken(tx *sql.Tx, refreshTokenId int64) error {
	return d.CommonDB.DeleteRefreshToken(tx, refreshTokenId)
}
