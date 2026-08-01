package mssqldb

import (
	"database/sql"
	"strings"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *MsSQLDatabase) CreateRefreshToken(tx *sql.Tx, refreshToken *models.RefreshToken) error {
	now := time.Now().UTC()

	originalCreatedAt := refreshToken.CreatedAt
	originalUpdatedAt := refreshToken.UpdatedAt
	refreshToken.CreatedAt = sql.NullTime{Time: now, Valid: true}
	refreshToken.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	refreshTokenStruct := sqlbuilder.NewStruct(new(models.RefreshToken)).
		For(sqlbuilder.SQLServer)

	insertBuilder := refreshTokenStruct.WithoutTag("pk").InsertInto("refresh_tokens", refreshToken)
	sql, args := insertBuilder.Build()

	parts := strings.SplitN(sql, "VALUES", 2)
	if len(parts) != 2 {
		return errors.New("unexpected SQL format from sqlbuilder")
	}
	sql = parts[0] + "OUTPUT INSERTED.id VALUES" + parts[1]

	rows, err := d.CommonDB.QuerySql(tx, sql, args...)
	if err != nil {
		refreshToken.CreatedAt = originalCreatedAt
		refreshToken.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert refreshToken")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		err = rows.Scan(&refreshToken.Id)
		if err != nil {
			refreshToken.CreatedAt = originalCreatedAt
			refreshToken.UpdatedAt = originalUpdatedAt
			return errors.Wrap(err, "unable to scan refreshToken id")
		}
	}

	// The driver can defer a constraint violation to the result set rather than
	// returning it from the query, in which case Next() simply reports no row.
	// Without this the insert would look like a success with id 0.
	if err := rows.Err(); err != nil {
		refreshToken.CreatedAt = originalCreatedAt
		refreshToken.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert refreshToken")
	}

	return nil
}

func (d *MsSQLDatabase) UpdateRefreshToken(tx *sql.Tx, refreshToken *models.RefreshToken) error {
	return d.CommonDB.UpdateRefreshToken(tx, refreshToken)
}

func (d *MsSQLDatabase) MarkRefreshTokenAsRevoked(tx *sql.Tx, refreshTokenId int64) (bool, error) {
	return d.CommonDB.MarkRefreshTokenAsRevoked(tx, refreshTokenId)
}

func (d *MsSQLDatabase) RevokeRefreshTokenFamily(tx *sql.Tx, firstRefreshTokenJti string) (int64, error) {
	return d.CommonDB.RevokeRefreshTokenFamily(tx, firstRefreshTokenJti)
}

func (d *MsSQLDatabase) GetRefreshTokenById(tx *sql.Tx, refreshTokenId int64) (*models.RefreshToken, error) {
	return d.CommonDB.GetRefreshTokenById(tx, refreshTokenId)
}

func (d *MsSQLDatabase) RefreshTokenLoadCode(tx *sql.Tx, refreshToken *models.RefreshToken) error {
	return d.CommonDB.RefreshTokenLoadCode(tx, refreshToken)
}

func (d *MsSQLDatabase) GetRefreshTokenByJti(tx *sql.Tx, jti string) (*models.RefreshToken, error) {
	return d.CommonDB.GetRefreshTokenByJti(tx, jti)
}

func (d *MsSQLDatabase) GetRefreshTokensByCodeId(tx *sql.Tx, codeId int64) ([]*models.RefreshToken, error) {
	return d.CommonDB.GetRefreshTokensByCodeId(tx, codeId)
}

func (d *MsSQLDatabase) GetRefreshTokensBySessionIdentifier(tx *sql.Tx, sessionIdentifier string) ([]*models.RefreshToken, error) {
	return d.CommonDB.GetRefreshTokensBySessionIdentifier(tx, sessionIdentifier)
}

func (d *MsSQLDatabase) DeleteRefreshToken(tx *sql.Tx, refreshTokenId int64) error {
	return d.CommonDB.DeleteRefreshToken(tx, refreshTokenId)
}

func (d *MsSQLDatabase) DeleteExpiredRefreshTokens(tx *sql.Tx) error {
	return d.CommonDB.DeleteExpiredRefreshTokens(tx)
}

func (d *MsSQLDatabase) RefreshTokenLoadUser(tx *sql.Tx, refreshToken *models.RefreshToken) error {
	return d.CommonDB.RefreshTokenLoadUser(tx, refreshToken)
}

func (d *MsSQLDatabase) RefreshTokenLoadClient(tx *sql.Tx, refreshToken *models.RefreshToken) error {
	return d.CommonDB.RefreshTokenLoadClient(tx, refreshToken)
}

func (d *MsSQLDatabase) GetRefreshTokensByUserId(tx *sql.Tx, userId int64) ([]*models.RefreshToken, error) {
	return d.CommonDB.GetRefreshTokensByUserId(tx, userId)
}

func (d *MsSQLDatabase) PromoteRefreshTokenGenerations(tx *sql.Tx, refreshTokenIds []int64, generation int64) error {
	return d.CommonDB.PromoteRefreshTokenGenerations(tx, refreshTokenIds, generation)
}
