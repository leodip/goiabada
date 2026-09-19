package mysqldb

import (
	"database/sql"

	"github.com/leodip/goiabada/core/models"
)

func (d *MySQLDatabase) CreateRefreshToken(tx *sql.Tx, refreshToken *models.RefreshToken) error {
	return d.CommonDB.CreateRefreshToken(tx, refreshToken)
}

func (d *MySQLDatabase) UpdateRefreshToken(tx *sql.Tx, refreshToken *models.RefreshToken) error {
	return d.CommonDB.UpdateRefreshToken(tx, refreshToken)
}

func (d *MySQLDatabase) MarkRefreshTokenAsRevoked(tx *sql.Tx, refreshTokenId int64) (bool, error) {
	return d.CommonDB.MarkRefreshTokenAsRevoked(tx, refreshTokenId)
}

func (d *MySQLDatabase) RevokeRefreshTokenFamily(tx *sql.Tx, firstRefreshTokenJti string) (int64, error) {
	return d.CommonDB.RevokeRefreshTokenFamily(tx, firstRefreshTokenJti)
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

func (d *MySQLDatabase) GetRefreshTokensByCodeId(tx *sql.Tx, codeId int64) ([]*models.RefreshToken, error) {
	return d.CommonDB.GetRefreshTokensByCodeId(tx, codeId)
}

func (d *MySQLDatabase) GetRefreshTokensBySessionIdentifier(tx *sql.Tx, sessionIdentifier string) ([]*models.RefreshToken, error) {
	return d.CommonDB.GetRefreshTokensBySessionIdentifier(tx, sessionIdentifier)
}

func (d *MySQLDatabase) DeleteRefreshToken(tx *sql.Tx, refreshTokenId int64) error {
	return d.CommonDB.DeleteRefreshToken(tx, refreshTokenId)
}

func (d *MySQLDatabase) DeleteExpiredRefreshTokens(tx *sql.Tx) error {
	return d.CommonDB.DeleteExpiredRefreshTokens(tx)
}

func (d *MySQLDatabase) RefreshTokenLoadUser(tx *sql.Tx, refreshToken *models.RefreshToken) error {
	return d.CommonDB.RefreshTokenLoadUser(tx, refreshToken)
}

func (d *MySQLDatabase) RefreshTokenLoadClient(tx *sql.Tx, refreshToken *models.RefreshToken) error {
	return d.CommonDB.RefreshTokenLoadClient(tx, refreshToken)
}

func (d *MySQLDatabase) GetRefreshTokensByUserId(tx *sql.Tx, userId int64) ([]*models.RefreshToken, error) {
	return d.CommonDB.GetRefreshTokensByUserId(tx, userId)
}

func (d *MySQLDatabase) GetRefreshTokensByClientId(tx *sql.Tx, clientId int64) ([]*models.RefreshToken, error) {
	return d.CommonDB.GetRefreshTokensByClientId(tx, clientId)
}

func (d *MySQLDatabase) PromoteRefreshTokenGenerations(tx *sql.Tx, refreshTokenIds []int64, generation int64) error {
	return d.CommonDB.PromoteRefreshTokenGenerations(tx, refreshTokenIds, generation)
}
