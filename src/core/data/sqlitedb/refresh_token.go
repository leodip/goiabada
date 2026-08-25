package sqlitedb

import (
	"database/sql"

	"github.com/leodip/goiabada/core/models"
)

func (d *SQLiteDatabase) CreateRefreshToken(tx *sql.Tx, refreshToken *models.RefreshToken) error {
	return d.CommonDB.CreateRefreshToken(tx, refreshToken)
}

func (d *SQLiteDatabase) UpdateRefreshToken(tx *sql.Tx, refreshToken *models.RefreshToken) error {
	return d.CommonDB.UpdateRefreshToken(tx, refreshToken)
}

func (d *SQLiteDatabase) MarkRefreshTokenAsRevoked(tx *sql.Tx, refreshTokenId int64) (bool, error) {
	return d.CommonDB.MarkRefreshTokenAsRevoked(tx, refreshTokenId)
}

func (d *SQLiteDatabase) RevokeRefreshTokenFamily(tx *sql.Tx, firstRefreshTokenJti string) (int64, error) {
	return d.CommonDB.RevokeRefreshTokenFamily(tx, firstRefreshTokenJti)
}

func (d *SQLiteDatabase) GetRefreshTokenById(tx *sql.Tx, refreshTokenId int64) (*models.RefreshToken, error) {
	return d.CommonDB.GetRefreshTokenById(tx, refreshTokenId)
}

func (d *SQLiteDatabase) RefreshTokenLoadCode(tx *sql.Tx, refreshToken *models.RefreshToken) error {
	return d.CommonDB.RefreshTokenLoadCode(tx, refreshToken)
}

func (d *SQLiteDatabase) GetRefreshTokenByJti(tx *sql.Tx, jti string) (*models.RefreshToken, error) {
	return d.CommonDB.GetRefreshTokenByJti(tx, jti)
}

func (d *SQLiteDatabase) GetRefreshTokensByCodeId(tx *sql.Tx, codeId int64) ([]*models.RefreshToken, error) {
	return d.CommonDB.GetRefreshTokensByCodeId(tx, codeId)
}

func (d *SQLiteDatabase) GetRefreshTokensBySessionIdentifier(tx *sql.Tx, sessionIdentifier string) ([]*models.RefreshToken, error) {
	return d.CommonDB.GetRefreshTokensBySessionIdentifier(tx, sessionIdentifier)
}

func (d *SQLiteDatabase) DeleteRefreshToken(tx *sql.Tx, refreshTokenId int64) error {
	return d.CommonDB.DeleteRefreshToken(tx, refreshTokenId)
}
func (d *SQLiteDatabase) DeleteExpiredRefreshTokens(tx *sql.Tx) error {
	return d.CommonDB.DeleteExpiredRefreshTokens(tx)
}

func (d *SQLiteDatabase) RefreshTokenLoadUser(tx *sql.Tx, refreshToken *models.RefreshToken) error {
	return d.CommonDB.RefreshTokenLoadUser(tx, refreshToken)
}

func (d *SQLiteDatabase) RefreshTokenLoadClient(tx *sql.Tx, refreshToken *models.RefreshToken) error {
	return d.CommonDB.RefreshTokenLoadClient(tx, refreshToken)
}

func (d *SQLiteDatabase) GetRefreshTokensByUserId(tx *sql.Tx, userId int64) ([]*models.RefreshToken, error) {
	return d.CommonDB.GetRefreshTokensByUserId(tx, userId)
}

func (d *SQLiteDatabase) GetRefreshTokensByClientId(tx *sql.Tx, clientId int64) ([]*models.RefreshToken, error) {
	return d.CommonDB.GetRefreshTokensByClientId(tx, clientId)
}

func (d *SQLiteDatabase) PromoteRefreshTokenGenerations(tx *sql.Tx, refreshTokenIds []int64, generation int64) error {
	return d.CommonDB.PromoteRefreshTokenGenerations(tx, refreshTokenIds, generation)
}
