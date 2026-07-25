package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *CommonDatabase) CreateRefreshToken(tx *sql.Tx, refreshToken *models.RefreshToken) error {

	now := time.Now().UTC()

	originalCreatedAt := refreshToken.CreatedAt
	originalUpdatedAt := refreshToken.UpdatedAt
	refreshToken.CreatedAt = sql.NullTime{Time: now, Valid: true}
	refreshToken.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	refreshTokenStruct := sqlbuilder.NewStruct(new(models.RefreshToken)).
		For(d.Flavor)

	insertBuilder := refreshTokenStruct.WithoutTag("pk").InsertInto("refresh_tokens", refreshToken)

	sql, args := insertBuilder.Build()
	result, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		refreshToken.CreatedAt = originalCreatedAt
		refreshToken.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert refreshToken")
	}

	id, err := result.LastInsertId()
	if err != nil {
		refreshToken.CreatedAt = originalCreatedAt
		refreshToken.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	refreshToken.Id = id
	return nil
}

func (d *CommonDatabase) UpdateRefreshToken(tx *sql.Tx, refreshToken *models.RefreshToken) error {

	if refreshToken.Id == 0 {
		return errors.WithStack(errors.New("can't update refreshToken with id 0"))
	}

	originalUpdatedAt := refreshToken.UpdatedAt
	refreshToken.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	refreshTokenStruct := sqlbuilder.NewStruct(new(models.RefreshToken)).
		For(d.Flavor)

	updateBuilder := refreshTokenStruct.WithoutTag("pk").WithoutTag("dont-update").Update("refresh_tokens", refreshToken)
	updateBuilder.Where(updateBuilder.Equal("id", refreshToken.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		refreshToken.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update refreshToken")
	}

	return nil
}

func (d *CommonDatabase) getRefreshTokenCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	refreshTokenStruct *sqlbuilder.Struct) (*models.RefreshToken, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var refreshToken models.RefreshToken
	if rows.Next() {
		addr := refreshTokenStruct.Addr(&refreshToken)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan refreshToken")
		}
		return &refreshToken, nil
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "unable to read query results")
	}

	return nil, nil
}

func (d *CommonDatabase) GetRefreshTokenById(tx *sql.Tx, refreshTokenId int64) (*models.RefreshToken, error) {

	refreshTokenStruct := sqlbuilder.NewStruct(new(models.RefreshToken)).
		For(d.Flavor)

	selectBuilder := refreshTokenStruct.SelectFrom("refresh_tokens")
	selectBuilder.Where(selectBuilder.Equal("id", refreshTokenId))

	refreshToken, err := d.getRefreshTokenCommon(tx, selectBuilder, refreshTokenStruct)
	if err != nil {
		return nil, err
	}

	return refreshToken, nil
}

func (d *CommonDatabase) RefreshTokenLoadCode(tx *sql.Tx, refreshToken *models.RefreshToken) error {
	if refreshToken == nil {
		return nil
	}

	// Only load code if CodeId is valid (auth code flow tokens)
	// ROPC tokens don't have a CodeId
	if !refreshToken.CodeId.Valid {
		return nil
	}

	code, err := d.GetCodeById(tx, refreshToken.CodeId.Int64)
	if err != nil {
		return errors.Wrap(err, "unable to load code")
	}

	if code != nil {
		refreshToken.Code = *code
	}

	return nil
}

// RefreshTokenLoadUser loads the User entity for ROPC flow refresh tokens.
// For auth code flow tokens (with CodeId), use RefreshTokenLoadCode instead.
func (d *CommonDatabase) RefreshTokenLoadUser(tx *sql.Tx, refreshToken *models.RefreshToken) error {
	if refreshToken == nil {
		return nil
	}

	// Only load user if UserId is valid (ROPC flow tokens)
	if !refreshToken.UserId.Valid {
		return nil
	}

	user, err := d.GetUserById(tx, refreshToken.UserId.Int64)
	if err != nil {
		return errors.Wrap(err, "unable to load user")
	}

	if user != nil {
		refreshToken.User = *user
	}

	return nil
}

// RefreshTokenLoadClient loads the Client entity for ROPC flow refresh tokens.
// For auth code flow tokens (with CodeId), use RefreshTokenLoadCode instead.
func (d *CommonDatabase) RefreshTokenLoadClient(tx *sql.Tx, refreshToken *models.RefreshToken) error {
	if refreshToken == nil {
		return nil
	}

	// Only load client if ClientId is valid (ROPC flow tokens)
	if !refreshToken.ClientId.Valid {
		return nil
	}

	client, err := d.GetClientById(tx, refreshToken.ClientId.Int64)
	if err != nil {
		return errors.Wrap(err, "unable to load client")
	}

	if client != nil {
		refreshToken.Client = *client
	}

	return nil
}

func (d *CommonDatabase) GetRefreshTokenByJti(tx *sql.Tx, jti string) (*models.RefreshToken, error) {

	refreshTokenStruct := sqlbuilder.NewStruct(new(models.RefreshToken)).
		For(d.Flavor)

	selectBuilder := refreshTokenStruct.SelectFrom("refresh_tokens")
	selectBuilder.Where(selectBuilder.Equal("refresh_token_jti", jti))

	refreshToken, err := d.getRefreshTokenCommon(tx, selectBuilder, refreshTokenStruct)
	if err != nil {
		return nil, err
	}

	return refreshToken, nil
}

func (d *CommonDatabase) GetRefreshTokensByCodeId(tx *sql.Tx, codeId int64) ([]*models.RefreshToken, error) {

	refreshTokenStruct := sqlbuilder.NewStruct(new(models.RefreshToken)).
		For(d.Flavor)

	selectBuilder := refreshTokenStruct.SelectFrom("refresh_tokens")
	selectBuilder.Where(selectBuilder.Equal("code_id", codeId))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var refreshTokens []*models.RefreshToken
	for rows.Next() {
		var refreshToken models.RefreshToken
		addr := refreshTokenStruct.Addr(&refreshToken)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan refreshToken")
		}
		refreshTokens = append(refreshTokens, &refreshToken)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "unable to read query results")
	}

	return refreshTokens, nil
}

// GetRefreshTokensBySessionIdentifier returns every refresh token whose
// originating authorization code shares the given session identifier. This
// catches both online refresh tokens (which carry session_identifier on the
// refresh_tokens row) and offline refresh tokens (which do not, but whose
// linked code does). An empty sessionIdentifier returns an empty slice with
// no error: the join would otherwise match every code with an empty
// session_identifier and over-revoke.
func (d *CommonDatabase) GetRefreshTokensBySessionIdentifier(tx *sql.Tx, sessionIdentifier string) ([]*models.RefreshToken, error) {

	if sessionIdentifier == "" {
		return nil, nil
	}

	refreshTokenStruct := sqlbuilder.NewStruct(new(models.RefreshToken)).
		For(d.Flavor)

	selectBuilder := refreshTokenStruct.SelectFrom("refresh_tokens")
	selectBuilder.JoinWithOption(sqlbuilder.InnerJoin, "codes", "codes.id = refresh_tokens.code_id")
	selectBuilder.Where(selectBuilder.Equal("codes.session_identifier", sessionIdentifier))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var refreshTokens []*models.RefreshToken
	for rows.Next() {
		var refreshToken models.RefreshToken
		addr := refreshTokenStruct.Addr(&refreshToken)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan refreshToken")
		}
		refreshTokens = append(refreshTokens, &refreshToken)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "unable to read query results")
	}

	return refreshTokens, nil
}

func (d *CommonDatabase) DeleteRefreshToken(tx *sql.Tx, refreshTokenId int64) error {

	userConsentStruct := sqlbuilder.NewStruct(new(models.RefreshToken)).
		For(d.Flavor)

	deleteBuilder := userConsentStruct.DeleteFrom("refresh_tokens")
	deleteBuilder.Where(deleteBuilder.Equal("id", refreshTokenId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete refreshToken")
	}

	return nil
}

// deleteRefreshTokensByColumn removes every refresh token whose given column
// matches, used to clear a parent's tokens before deleting the parent itself.
//
// SQL Server cannot cascade refresh_tokens.user_id or .client_id. refresh_tokens
// already cascades from codes, and codes cascades from both users and clients, so
// a direct cascade would be a second delete path into the same table, which SQL
// Server rejects as "cycles or multiple cascade paths". Its migration therefore
// declares both foreign keys ON DELETE NO ACTION (mssqldb migration 000011), and
// a refresh token issued without a code then blocks deletion of its user or
// client outright:
//
//	The DELETE statement conflicted with the REFERENCE constraint
//	"fk_refresh_tokens_user" ... table "dbo.refresh_tokens", column 'user_id'.
//
// Codeless tokens are not hypothetical: the ROPC grant creates exactly that shape
// (TokenIssuer.generateRefreshTokenForROPC, "no Code reference"), so on SQL Server
// any user who had used ROPC could not be deleted at all.
//
// This runs on every engine rather than only on SQL Server. The other three would
// have cascaded these rows anyway, so the result is identical, and one code path
// that all four exercise is worth more than the statement it saves.
func (d *CommonDatabase) deleteRefreshTokensByColumn(tx *sql.Tx, column string, value int64) error {
	deleteBuilder := d.Flavor.NewDeleteBuilder()
	deleteBuilder.DeleteFrom("refresh_tokens")
	deleteBuilder.Where(deleteBuilder.Equal(column, value))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return errors.Wrapf(err, "unable to delete refresh tokens by %v", column)
	}

	return nil
}

// Deletes refresh tokens that are either expired (by expires_at or max_lifetime) or revoked
func (d *CommonDatabase) DeleteExpiredOrRevokedRefreshTokens(tx *sql.Tx) error {
	deleteBuilder := d.Flavor.NewDeleteBuilder()
	deleteBuilder.DeleteFrom("refresh_tokens")

	now := time.Now().UTC()
	deleteBuilder.Where(
		deleteBuilder.Or(
			deleteBuilder.LessThan("expires_at", now),
			deleteBuilder.LessThan("max_lifetime", now),
			deleteBuilder.Equal("revoked", true),
		),
	)

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete expired/revoked refresh tokens")
	}

	return nil
}
