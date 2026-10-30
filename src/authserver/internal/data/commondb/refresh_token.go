package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// refreshTokenColumns is the refresh_tokens table as scanRefreshToken reads it, each column
// qualified by its table so the list reads the same in a join with codes, whose own id, created_at,
// updated_at, user_id, client_id, scope, session_identifier, revoked and auth_state_generation it
// would otherwise name ambiguously.
var refreshTokenColumns = columnList{
	sqlite: "refresh_tokens.id, refresh_tokens.created_at, refresh_tokens.updated_at, refresh_tokens.code_id, " +
		"refresh_tokens.user_id, refresh_tokens.client_id, refresh_tokens.refresh_token_jti, " +
		"refresh_tokens.previous_refresh_token_jti, refresh_tokens.first_refresh_token_jti, " +
		"refresh_tokens.session_identifier, refresh_tokens.refresh_token_type, refresh_tokens.scope, " +
		"refresh_tokens.issued_at, refresh_tokens.expires_at, refresh_tokens.max_lifetime, " +
		"refresh_tokens.revoked, refresh_tokens.auth_state_generation, refresh_tokens.authenticated_at",
	mysql: "refresh_tokens.id, refresh_tokens.created_at, refresh_tokens.updated_at, refresh_tokens.code_id, " +
		"refresh_tokens.user_id, refresh_tokens.client_id, refresh_tokens.refresh_token_jti, " +
		"refresh_tokens.previous_refresh_token_jti, refresh_tokens.first_refresh_token_jti, " +
		"refresh_tokens.session_identifier, refresh_tokens.refresh_token_type, refresh_tokens.scope, " +
		"refresh_tokens.issued_at, refresh_tokens.expires_at, refresh_tokens.max_lifetime, " +
		"refresh_tokens.revoked, refresh_tokens.auth_state_generation, refresh_tokens.authenticated_at",
	postgres: "refresh_tokens.id, refresh_tokens.created_at, refresh_tokens.updated_at, refresh_tokens.code_id, " +
		"refresh_tokens.user_id, refresh_tokens.client_id, refresh_tokens.refresh_token_jti, " +
		"refresh_tokens.previous_refresh_token_jti, refresh_tokens.first_refresh_token_jti, " +
		"refresh_tokens.session_identifier, refresh_tokens.refresh_token_type, refresh_tokens.scope, " +
		"refresh_tokens.issued_at, refresh_tokens.expires_at, refresh_tokens.max_lifetime, " +
		"refresh_tokens.revoked, refresh_tokens.auth_state_generation, refresh_tokens.authenticated_at",
	mssql: "refresh_tokens.id, refresh_tokens.created_at, refresh_tokens.updated_at, refresh_tokens.code_id, " +
		"refresh_tokens.user_id, refresh_tokens.client_id, refresh_tokens.refresh_token_jti, " +
		"refresh_tokens.previous_refresh_token_jti, refresh_tokens.first_refresh_token_jti, " +
		"refresh_tokens.session_identifier, refresh_tokens.refresh_token_type, refresh_tokens.scope, " +
		"refresh_tokens.issued_at, refresh_tokens.expires_at, refresh_tokens.max_lifetime, " +
		"refresh_tokens.revoked, refresh_tokens.auth_state_generation, refresh_tokens.authenticated_at",
}

// scanRefreshToken reads one row selected with refreshTokenColumns.
func scanRefreshToken(row rowScanner, refreshToken *record.RefreshToken) error {
	return row.Scan(
		&refreshToken.Id,
		&refreshToken.CreatedAt,
		&refreshToken.UpdatedAt,
		&refreshToken.CodeId,
		&refreshToken.UserId,
		&refreshToken.ClientId,
		&refreshToken.RefreshTokenJti,
		&refreshToken.PreviousRefreshTokenJti,
		&refreshToken.FirstRefreshTokenJti,
		&refreshToken.SessionIdentifier,
		&refreshToken.RefreshTokenType,
		&refreshToken.Scope,
		&refreshToken.IssuedAt,
		&refreshToken.ExpiresAt,
		&refreshToken.MaxLifetime,
		&refreshToken.Revoked,
		&refreshToken.AuthStateGeneration,
		&refreshToken.AuthenticatedAt,
	)
}

// queryRefreshTokens runs a read of any number of refresh tokens and answers them as pointers, nil
// when no row comes back. A failure part way through the result set is an error, never a partial
// list: a revocation sweep committed over a partial list would miss the rows it never saw.
func queryRefreshTokens(ctx context.Context, d *Database, tx *sql.Tx, query string, args []any) ([]*record.RefreshToken, error) {
	list, err := queryAll(ctx, d, tx, nil, query, args, scanRefreshToken, "refreshToken")
	if err != nil {
		return nil, err
	}

	var refreshTokens []*record.RefreshToken
	for i := range list {
		refreshTokens = append(refreshTokens, &list[i])
	}
	return refreshTokens, nil
}

// insertRefreshToken writes every column but id, the dont-update ones included: a new token is
// born with its code, user and client, and the generation and instant its grant was authenticated at.
var insertRefreshToken = statement{
	sqlite: "INSERT INTO refresh_tokens (created_at, updated_at, code_id, user_id, client_id, " +
		"refresh_token_jti, previous_refresh_token_jti, first_refresh_token_jti, session_identifier, " +
		"refresh_token_type, scope, issued_at, expires_at, max_lifetime, revoked, auth_state_generation, " +
		"authenticated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
	mysql: "INSERT INTO refresh_tokens (created_at, updated_at, code_id, user_id, client_id, " +
		"refresh_token_jti, previous_refresh_token_jti, first_refresh_token_jti, session_identifier, " +
		"refresh_token_type, scope, issued_at, expires_at, max_lifetime, revoked, auth_state_generation, " +
		"authenticated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
	postgres: "INSERT INTO refresh_tokens (created_at, updated_at, code_id, user_id, client_id, " +
		"refresh_token_jti, previous_refresh_token_jti, first_refresh_token_jti, session_identifier, " +
		"refresh_token_type, scope, issued_at, expires_at, max_lifetime, revoked, auth_state_generation, " +
		"authenticated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, " +
		"$17) RETURNING id",
	mssql: "INSERT INTO refresh_tokens (created_at, updated_at, code_id, user_id, client_id, " +
		"refresh_token_jti, previous_refresh_token_jti, first_refresh_token_jti, session_identifier, " +
		"refresh_token_type, scope, issued_at, expires_at, max_lifetime, revoked, auth_state_generation, " +
		"authenticated_at) OUTPUT INSERTED.id VALUES (@p1, @p2, @p3, @p4, @p5, @p6, @p7, @p8, @p9, @p10, " +
		"@p11, @p12, @p13, @p14, @p15, @p16, @p17)",
}

// updateRefreshToken writes the whole row but created_at, code_id, user_id, client_id,
// auth_state_generation and authenticated_at, which are dont-update. Leaving the three foreign keys
// out of the SET list is what keeps SQL Server from re-checking them, and so from taking a shared
// lock on the parent rows (#139); see record.RefreshToken.
var updateRefreshToken = statement{
	sqlite: "UPDATE refresh_tokens SET updated_at = ?, refresh_token_jti = ?, previous_refresh_token_jti = ?, " +
		"first_refresh_token_jti = ?, session_identifier = ?, refresh_token_type = ?, scope = ?, " +
		"issued_at = ?, expires_at = ?, max_lifetime = ?, revoked = ? WHERE id = ?",
	mysql: "UPDATE refresh_tokens SET updated_at = ?, refresh_token_jti = ?, previous_refresh_token_jti = ?, " +
		"first_refresh_token_jti = ?, session_identifier = ?, refresh_token_type = ?, scope = ?, " +
		"issued_at = ?, expires_at = ?, max_lifetime = ?, revoked = ? WHERE id = ?",
	postgres: "UPDATE refresh_tokens SET updated_at = $1, refresh_token_jti = $2, " +
		"previous_refresh_token_jti = $3, first_refresh_token_jti = $4, session_identifier = $5, " +
		"refresh_token_type = $6, scope = $7, issued_at = $8, expires_at = $9, max_lifetime = $10, " +
		"revoked = $11 WHERE id = $12",
	mssql: "UPDATE refresh_tokens SET updated_at = @p1, refresh_token_jti = @p2, " +
		"previous_refresh_token_jti = @p3, first_refresh_token_jti = @p4, session_identifier = @p5, " +
		"refresh_token_type = @p6, scope = @p7, issued_at = @p8, expires_at = @p9, max_lifetime = @p10, " +
		"revoked = @p11 WHERE id = @p12",
}

var selectRefreshTokenById = statement{
	sqlite:   "SELECT " + refreshTokenColumns.sqlite + " FROM refresh_tokens WHERE id = ?",
	mysql:    "SELECT " + refreshTokenColumns.mysql + " FROM refresh_tokens WHERE id = ?",
	postgres: "SELECT " + refreshTokenColumns.postgres + " FROM refresh_tokens WHERE id = $1",
	mssql:    "SELECT " + refreshTokenColumns.mssql + " FROM refresh_tokens WHERE id = @p1",
}

var selectRefreshTokenByJti = statement{
	sqlite:   "SELECT " + refreshTokenColumns.sqlite + " FROM refresh_tokens WHERE refresh_token_jti = ?",
	mysql:    "SELECT " + refreshTokenColumns.mysql + " FROM refresh_tokens WHERE refresh_token_jti = ?",
	postgres: "SELECT " + refreshTokenColumns.postgres + " FROM refresh_tokens WHERE refresh_token_jti = $1",
	mssql:    "SELECT " + refreshTokenColumns.mssql + " FROM refresh_tokens WHERE refresh_token_jti = @p1",
}

var selectRefreshTokensByCodeId = statement{
	sqlite:   "SELECT " + refreshTokenColumns.sqlite + " FROM refresh_tokens WHERE code_id = ?",
	mysql:    "SELECT " + refreshTokenColumns.mysql + " FROM refresh_tokens WHERE code_id = ?",
	postgres: "SELECT " + refreshTokenColumns.postgres + " FROM refresh_tokens WHERE code_id = $1",
	mssql:    "SELECT " + refreshTokenColumns.mssql + " FROM refresh_tokens WHERE code_id = @p1",
}

var selectRefreshTokensByFirstRefreshTokenJti = statement{
	sqlite:   "SELECT " + refreshTokenColumns.sqlite + " FROM refresh_tokens WHERE first_refresh_token_jti = ?",
	mysql:    "SELECT " + refreshTokenColumns.mysql + " FROM refresh_tokens WHERE first_refresh_token_jti = ?",
	postgres: "SELECT " + refreshTokenColumns.postgres + " FROM refresh_tokens WHERE first_refresh_token_jti = $1",
	mssql:    "SELECT " + refreshTokenColumns.mssql + " FROM refresh_tokens WHERE first_refresh_token_jti = @p1",
}

var selectRefreshTokensBySessionIdentifier = statement{
	sqlite: "SELECT " + refreshTokenColumns.sqlite + " FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.session_identifier = ?",
	mysql: "SELECT " + refreshTokenColumns.mysql + " FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.session_identifier = ?",
	postgres: "SELECT " + refreshTokenColumns.postgres + " FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.session_identifier = $1",
	mssql: "SELECT " + refreshTokenColumns.mssql + " FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.session_identifier = @p1",
}

// selectRefreshTokensByUserId binds the user id once per branch: the code's user, then the token's.
var selectRefreshTokensByUserId = statement{
	sqlite: "SELECT " + refreshTokenColumns.sqlite + " FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.user_id = ? " +
		"UNION ALL SELECT " + refreshTokenColumns.sqlite + " FROM refresh_tokens " +
		"WHERE refresh_tokens.user_id = ?",
	mysql: "SELECT " + refreshTokenColumns.mysql + " FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.user_id = ? " +
		"UNION ALL SELECT " + refreshTokenColumns.mysql + " FROM refresh_tokens " +
		"WHERE refresh_tokens.user_id = ?",
	postgres: "SELECT " + refreshTokenColumns.postgres + " FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.user_id = $1 " +
		"UNION ALL SELECT " + refreshTokenColumns.postgres + " FROM refresh_tokens " +
		"WHERE refresh_tokens.user_id = $2",
	mssql: "SELECT " + refreshTokenColumns.mssql + " FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.user_id = @p1 " +
		"UNION ALL SELECT " + refreshTokenColumns.mssql + " FROM refresh_tokens " +
		"WHERE refresh_tokens.user_id = @p2",
}

// selectRefreshTokensByUserIdAndClientId binds the user id and the client id once per branch: the
// code's, then the token's.
var selectRefreshTokensByUserIdAndClientId = statement{
	sqlite: "SELECT " + refreshTokenColumns.sqlite + " FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.user_id = ? AND codes.client_id = ? " +
		"UNION ALL SELECT " + refreshTokenColumns.sqlite + " FROM refresh_tokens " +
		"WHERE refresh_tokens.user_id = ? AND refresh_tokens.client_id = ?",
	mysql: "SELECT " + refreshTokenColumns.mysql + " FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.user_id = ? AND codes.client_id = ? " +
		"UNION ALL SELECT " + refreshTokenColumns.mysql + " FROM refresh_tokens " +
		"WHERE refresh_tokens.user_id = ? AND refresh_tokens.client_id = ?",
	postgres: "SELECT " + refreshTokenColumns.postgres + " FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.user_id = $1 AND codes.client_id = $2 " +
		"UNION ALL SELECT " + refreshTokenColumns.postgres + " FROM refresh_tokens " +
		"WHERE refresh_tokens.user_id = $3 AND refresh_tokens.client_id = $4",
	mssql: "SELECT " + refreshTokenColumns.mssql + " FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.user_id = @p1 AND codes.client_id = @p2 " +
		"UNION ALL SELECT " + refreshTokenColumns.mssql + " FROM refresh_tokens " +
		"WHERE refresh_tokens.user_id = @p3 AND refresh_tokens.client_id = @p4",
}

// selectRefreshTokensByClientId binds the client id once per branch: the code's, then the token's.
var selectRefreshTokensByClientId = statement{
	sqlite: "SELECT " + refreshTokenColumns.sqlite + " FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.client_id = ? " +
		"UNION ALL SELECT " + refreshTokenColumns.sqlite + " FROM refresh_tokens " +
		"WHERE refresh_tokens.client_id = ?",
	mysql: "SELECT " + refreshTokenColumns.mysql + " FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.client_id = ? " +
		"UNION ALL SELECT " + refreshTokenColumns.mysql + " FROM refresh_tokens " +
		"WHERE refresh_tokens.client_id = ?",
	postgres: "SELECT " + refreshTokenColumns.postgres + " FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.client_id = $1 " +
		"UNION ALL SELECT " + refreshTokenColumns.postgres + " FROM refresh_tokens " +
		"WHERE refresh_tokens.client_id = $2",
	mssql: "SELECT " + refreshTokenColumns.mssql + " FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.client_id = @p1 " +
		"UNION ALL SELECT " + refreshTokenColumns.mssql + " FROM refresh_tokens " +
		"WHERE refresh_tokens.client_id = @p2",
}

var markRefreshTokenAsRevoked = statement{
	sqlite:   "UPDATE refresh_tokens SET revoked = ?, updated_at = ? WHERE id = ? AND revoked = ?",
	mysql:    "UPDATE refresh_tokens SET revoked = ?, updated_at = ? WHERE id = ? AND revoked = ?",
	postgres: "UPDATE refresh_tokens SET revoked = $1, updated_at = $2 WHERE id = $3 AND revoked = $4",
	mssql:    "UPDATE refresh_tokens SET revoked = @p1, updated_at = @p2 WHERE id = @p3 AND revoked = @p4",
}

var revokeRefreshTokenFamily = statement{
	sqlite: "UPDATE refresh_tokens SET revoked = ?, updated_at = ? " +
		"WHERE first_refresh_token_jti = ? AND revoked = ?",
	mysql: "UPDATE refresh_tokens SET revoked = ?, updated_at = ? " +
		"WHERE first_refresh_token_jti = ? AND revoked = ?",
	postgres: "UPDATE refresh_tokens SET revoked = $1, updated_at = $2 " +
		"WHERE first_refresh_token_jti = $3 AND revoked = $4",
	mssql: "UPDATE refresh_tokens SET revoked = @p1, updated_at = @p2 " +
		"WHERE first_refresh_token_jti = @p3 AND revoked = @p4",
}

// promoteRefreshTokenGenerationsWhere is completed by an IN list of refresh token ids, numbered from
// the fourth argument.
var promoteRefreshTokenGenerationsWhere = statement{
	sqlite: "UPDATE refresh_tokens SET auth_state_generation = ?, updated_at = ? " +
		"WHERE revoked = ? AND ",
	mysql: "UPDATE refresh_tokens SET auth_state_generation = ?, updated_at = ? " +
		"WHERE revoked = ? AND ",
	postgres: "UPDATE refresh_tokens SET auth_state_generation = $1, updated_at = $2 " +
		"WHERE revoked = $3 AND ",
	mssql: "UPDATE refresh_tokens SET auth_state_generation = @p1, updated_at = @p2 " +
		"WHERE revoked = @p3 AND ",
}

var deleteRefreshToken = statement{
	sqlite:   "DELETE FROM refresh_tokens WHERE id = ?",
	mysql:    "DELETE FROM refresh_tokens WHERE id = ?",
	postgres: "DELETE FROM refresh_tokens WHERE id = $1",
	mssql:    "DELETE FROM refresh_tokens WHERE id = @p1",
}

var deleteRefreshTokensByUserId = statement{
	sqlite:   "DELETE FROM refresh_tokens WHERE user_id = ?",
	mysql:    "DELETE FROM refresh_tokens WHERE user_id = ?",
	postgres: "DELETE FROM refresh_tokens WHERE user_id = $1",
	mssql:    "DELETE FROM refresh_tokens WHERE user_id = @p1",
}

var deleteRefreshTokensByClientId = statement{
	sqlite:   "DELETE FROM refresh_tokens WHERE client_id = ?",
	mysql:    "DELETE FROM refresh_tokens WHERE client_id = ?",
	postgres: "DELETE FROM refresh_tokens WHERE client_id = $1",
	mssql:    "DELETE FROM refresh_tokens WHERE client_id = @p1",
}

// deleteExpiredRefreshTokens binds the same instant twice, once per column.
var deleteExpiredRefreshTokens = statement{
	sqlite:   "DELETE FROM refresh_tokens WHERE (expires_at < ? OR max_lifetime < ?)",
	mysql:    "DELETE FROM refresh_tokens WHERE (expires_at < ? OR max_lifetime < ?)",
	postgres: "DELETE FROM refresh_tokens WHERE (expires_at < $1 OR max_lifetime < $2)",
	mssql:    "DELETE FROM refresh_tokens WHERE (expires_at < @p1 OR max_lifetime < @p2)",
}

func (d *Database) CreateRefreshToken(ctx context.Context, tx *sql.Tx, refreshToken *record.RefreshToken) error {

	now := time.Now().UTC()

	originalCreatedAt := refreshToken.CreatedAt
	originalUpdatedAt := refreshToken.UpdatedAt
	refreshToken.CreatedAt = sql.NullTime{Time: now, Valid: true}
	refreshToken.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	id, err := d.insert(ctx, tx, insertRefreshToken, "refreshToken",
		refreshToken.CreatedAt, refreshToken.UpdatedAt, refreshToken.CodeId, refreshToken.UserId,
		refreshToken.ClientId, refreshToken.RefreshTokenJti, refreshToken.PreviousRefreshTokenJti,
		refreshToken.FirstRefreshTokenJti, refreshToken.SessionIdentifier, refreshToken.RefreshTokenType,
		refreshToken.Scope, refreshToken.IssuedAt, refreshToken.ExpiresAt, refreshToken.MaxLifetime,
		refreshToken.Revoked, refreshToken.AuthStateGeneration, refreshToken.AuthenticatedAt)
	if err != nil {
		refreshToken.CreatedAt = originalCreatedAt
		refreshToken.UpdatedAt = originalUpdatedAt
		return err
	}

	refreshToken.Id = id
	return nil
}

func (d *Database) UpdateRefreshToken(ctx context.Context, tx *sql.Tx, refreshToken *record.RefreshToken) error {

	if refreshToken.Id == 0 {
		return errs.New("can't update refreshToken with id 0")
	}

	originalUpdatedAt := refreshToken.UpdatedAt
	refreshToken.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	_, err := d.ExecSQL(ctx, tx, updateRefreshToken.text(d.Dialect),
		refreshToken.UpdatedAt, refreshToken.RefreshTokenJti, refreshToken.PreviousRefreshTokenJti,
		refreshToken.FirstRefreshTokenJti, refreshToken.SessionIdentifier, refreshToken.RefreshTokenType,
		refreshToken.Scope, refreshToken.IssuedAt, refreshToken.ExpiresAt, refreshToken.MaxLifetime,
		refreshToken.Revoked, refreshToken.Id)
	if err != nil {
		refreshToken.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update refreshToken")
	}

	return nil
}

// MarkRefreshTokenAsRevoked atomically transitions a refresh token from live to
// revoked via a conditional UPDATE (`WHERE id = ? AND revoked = false`). It returns
// true only if this call is the one that flipped the flag; a false return means the
// row was no longer live, which a concurrent rotation, a concurrent security
// revocation or a deleted row all produce.
//
// Compare-and-set for the same reason MarkCodeAsUsed is: rotation read `revoked` back
// in request validation and then wrote unconditionally, leaving a double-spend window
// spanning the whole of validation, so two presentations of one refresh token could
// each mint a token set (#77, #128).
//
// Narrow on purpose. It writes only revoked and updated_at, so it cannot touch
// auth_state_generation at all. That is an independent guarantee, not a repair of
// UpdateRefreshToken: the full-row writer already excludes the column through its
// dont-update struct tag (#106). Stating it in the statement itself means the boundary
// does not rest on a tag a future writer might not honour.
func (d *Database) MarkRefreshTokenAsRevoked(ctx context.Context, tx *sql.Tx, refreshTokenId int64) (bool, error) {

	if refreshTokenId == 0 {
		return false, errs.New("can't mark refresh token with id 0 as revoked")
	}

	result, err := d.ExecSQL(ctx, tx, markRefreshTokenAsRevoked.text(d.Dialect),
		true, time.Now().UTC(), refreshTokenId, false)
	if err != nil {
		return false, errs.Wrap(err, "unable to mark refresh token as revoked")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errs.Wrap(err, "unable to get rows affected when marking refresh token as revoked")
	}

	return rowsAffected == 1, nil
}

// RevokeRefreshTokenFamily revokes every currently live member of one rotation family
// in a single statement, and returns how many rows it moved from live to revoked.
//
// A family is the rows sharing a first_refresh_token_jti: the identifier is stamped at
// first issuance and carried forward on every rotation, for both linkage shapes, so it
// covers ROPC chains (which have no code) without a fallback branch. Containment
// touches nothing else, in particular not the originating code and not the browser
// session, because refresh token replay implicates one grant's client-side storage
// rather than the authorization ceremony (#128).
//
// The count is exact on every supported engine: the predicate selects only rows whose
// revoked is false and sets it true, so no matched row is left unchanged and the
// matched-versus-changed distinction cannot affect it. Callers use it to tell a real
// containment from an idempotent no-op.
//
// An empty family identifier is an ERROR, not an empty result. That is deliberately a
// stronger contract than GetRefreshTokensBySessionIdentifier's, which returns nothing
// for an empty key. On a revocation path an empty identifier can only be a caller bug,
// and absorbing it goes wrong in two different directions depending on the data: with
// no matching rows it hides the bug as a zero-count no-op, and with malformed
// empty-family rows present it mutates them.
func (d *Database) RevokeRefreshTokenFamily(ctx context.Context, tx *sql.Tx, firstRefreshTokenJti string) (int64, error) {

	if firstRefreshTokenJti == "" {
		return 0, errs.New("can't revoke a refresh token family with an empty first refresh token jti")
	}

	result, err := d.ExecSQL(ctx, tx, revokeRefreshTokenFamily.text(d.Dialect),
		true, time.Now().UTC(), firstRefreshTokenJti, false)
	if err != nil {
		return 0, errs.Wrap(err, "unable to revoke refresh token family")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, errs.Wrap(err, "unable to get rows affected when revoking refresh token family")
	}

	return rowsAffected, nil
}

func (d *Database) GetRefreshTokenById(ctx context.Context, tx *sql.Tx, refreshTokenId int64) (*record.RefreshToken, error) {
	return queryOne(ctx, d, tx, selectRefreshTokenById.text(d.Dialect), []any{refreshTokenId}, scanRefreshToken,
		"refreshToken")
}

func (d *Database) RefreshTokenLoadCode(ctx context.Context, tx *sql.Tx, refreshToken *record.RefreshToken) error {
	if refreshToken == nil {
		return nil
	}

	// Only load code if CodeId is valid (auth code flow tokens)
	// ROPC tokens don't have a CodeId
	if !refreshToken.CodeId.Valid {
		return nil
	}

	code, err := d.GetCodeById(ctx, tx, refreshToken.CodeId.Int64)
	if err != nil {
		return errs.Wrap(err, "unable to load code")
	}

	if code != nil {
		refreshToken.Code = *code
	}

	return nil
}

// RefreshTokenLoadUser loads the User entity for ROPC flow refresh tokens.
// For auth code flow tokens (with CodeId), use RefreshTokenLoadCode instead.
func (d *Database) RefreshTokenLoadUser(ctx context.Context, tx *sql.Tx, refreshToken *record.RefreshToken) error {
	if refreshToken == nil {
		return nil
	}

	// Only load user if UserId is valid (ROPC flow tokens)
	if !refreshToken.UserId.Valid {
		return nil
	}

	user, err := d.GetUserById(ctx, tx, refreshToken.UserId.Int64)
	if err != nil {
		return errs.Wrap(err, "unable to load user")
	}

	if user != nil {
		refreshToken.User = *user
	}

	return nil
}

// RefreshTokenLoadClient loads the Client entity for ROPC flow refresh tokens.
// For auth code flow tokens (with CodeId), use RefreshTokenLoadCode instead.
func (d *Database) RefreshTokenLoadClient(ctx context.Context, tx *sql.Tx, refreshToken *record.RefreshToken) error {
	if refreshToken == nil {
		return nil
	}

	// Only load client if ClientId is valid (ROPC flow tokens)
	if !refreshToken.ClientId.Valid {
		return nil
	}

	client, err := d.GetClientById(ctx, tx, refreshToken.ClientId.Int64)
	if err != nil {
		return errs.Wrap(err, "unable to load client")
	}

	if client != nil {
		refreshToken.Client = *client
	}

	return nil
}

func (d *Database) GetRefreshTokenByJti(ctx context.Context, tx *sql.Tx, jti string) (*record.RefreshToken, error) {
	return queryOne(ctx, d, tx, selectRefreshTokenByJti.text(d.Dialect), []any{jti}, scanRefreshToken, "refreshToken")
}

// GetRefreshTokensByFirstRefreshTokenJti returns every member of one rotation family, live and
// revoked: the rows a client revoking the grant at /auth/revoke ends, and the jtis its audit record
// lists (#676 decision 1). It reads by idx_refresh_tokens_first_refresh_token_jti.
//
// Each row is compared with the identifier asked for in Go, for the reason
// IsRefreshTokenFamilyRevoked states (#283): SQL Server pads for `=`, so a trailing space would
// otherwise find the members of the family without one, and a revocation would end a grant other
// than the one asked for. An empty identifier is an error, for the reason RevokeRefreshTokenFamily
// states.
func (d *Database) GetRefreshTokensByFirstRefreshTokenJti(ctx context.Context, tx *sql.Tx,
	firstRefreshTokenJti string) ([]*record.RefreshToken, error) {

	if firstRefreshTokenJti == "" {
		return nil, errs.New("can't read a refresh token family with an empty first refresh token jti")
	}

	rows, err := queryRefreshTokens(ctx, d, tx, selectRefreshTokensByFirstRefreshTokenJti.text(d.Dialect),
		[]any{firstRefreshTokenJti})
	if err != nil {
		return nil, err
	}

	members := make([]*record.RefreshToken, 0, len(rows))
	for _, rt := range rows {
		if engineFoldedTheMatch(rt.FirstRefreshTokenJti, firstRefreshTokenJti) {
			continue
		}
		members = append(members, rt)
	}
	return members, nil
}

func (d *Database) GetRefreshTokensByCodeId(ctx context.Context, tx *sql.Tx, codeId int64) ([]*record.RefreshToken, error) {
	return queryRefreshTokens(ctx, d, tx, selectRefreshTokensByCodeId.text(d.Dialect), []any{codeId})
}

// GetRefreshTokensBySessionIdentifier returns every refresh token whose
// originating authorization code shares the given session identifier. This
// catches both online refresh tokens (which carry session_identifier on the
// refresh_tokens row) and offline refresh tokens (which do not, but whose
// linked code does). An empty sessionIdentifier returns an empty slice with
// no error: the join would otherwise match every code with an empty
// session_identifier and over-revoke.
func (d *Database) GetRefreshTokensBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) ([]*record.RefreshToken, error) {

	if sessionIdentifier == "" {
		return nil, nil
	}

	return queryRefreshTokens(ctx, d, tx, selectRefreshTokensBySessionIdentifier.text(d.Dialect),
		[]any{sessionIdentifier})
}

func (d *Database) DeleteRefreshToken(ctx context.Context, tx *sql.Tx, refreshTokenId int64) error {

	_, err := d.ExecSQL(ctx, tx, deleteRefreshToken.text(d.Dialect), refreshTokenId)
	if err != nil {
		return errs.Wrap(err, "unable to delete refreshToken")
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
func (d *Database) deleteRefreshTokensByColumn(ctx context.Context, tx *sql.Tx, column string, value int64) error {
	var s statement
	switch column {
	case "user_id":
		s = deleteRefreshTokensByUserId
	case "client_id":
		s = deleteRefreshTokensByClientId
	default:
		return errs.Errorf("can't delete refresh tokens by %v", column)
	}

	_, err := d.ExecSQL(ctx, tx, s.text(d.Dialect), value)
	if err != nil {
		return errs.Wrapf(err, "unable to delete refresh tokens by %v", column)
	}

	return nil
}

// DeleteExpiredRefreshTokens deletes refresh tokens the protocol can no longer accept,
// by expires_at or max_lifetime. Being revoked is NOT a reason to delete a row.
//
// It used to be, and that erased the replay-detection signal on the cleanup worker's
// schedule: once a revoked row is gone, presenting its token finds nothing, so the replay
// is refused but never detected and the live family is never contained (#128). RFC 9700
// Section 4.14.2 requires rotation to retain enough relationship information for an
// invalidated token to reveal a breach.
//
// Retention therefore coincides with the interval in which detection is possible. An
// expired token is rejected by the JWT expiration check before its row is ever read, so
// keeping the row past that point buys nothing, and deleting it before that point destroys
// the only evidence linking the presented token to its live descendants.
//
// A revoked row with both timestamps NULL is deliberately NOT reaped, even though the old
// predicate deleted it. No issuer creates one, so it can only come from legacy or imported
// data, and the row is the detection signal: a signed token whose imported row lacks
// expiry columns can still carry an unexpired exp. There is also no principled deletion
// time to compute, since the database lacks the information, and a method by this name
// must not delete rows it cannot show are expired. Removing such rows is left to an
// explicit operator action.
//
// The storage cost is accepted: with the default 30-day offline idle timeout, a grant
// rotated every five minutes retains roughly 8,640 detection-relevant revoked rows.
func (d *Database) DeleteExpiredRefreshTokens(ctx context.Context, tx *sql.Tx) error {
	now := time.Now().UTC()
	_, err := d.ExecSQL(ctx, tx, deleteExpiredRefreshTokens.text(d.Dialect), now, now)
	if err != nil {
		return errs.Wrap(err, "unable to delete expired refresh tokens")
	}

	return nil
}

// GetRefreshTokensByUserId returns every refresh token belonging to a user, whatever
// shape links it to them.
//
// The invariant this rests on: a refresh token reaches its user through
// codes.user_id (authorization code flow, where refresh_tokens.code_id is set) or
// through refresh_tokens.user_id (ROPC, where code_id is null), and through nothing
// else. If a fifth issuance shape is ever added, the data test enumerating shapes is
// what should fail.
//
// Built as two UNION ALL branches rather than one join with an OR across the two
// tables. The shapes are mutually exclusive, so the union cannot produce duplicates,
// and each branch can use its own index where the OR would defeat both. (#106)
func (d *Database) GetRefreshTokensByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]*record.RefreshToken, error) {

	if userId == 0 {
		return nil, nil
	}

	return queryRefreshTokens(ctx, d, tx, selectRefreshTokensByUserId.text(d.Dialect), []any{userId, userId})
}

// GetRefreshTokensByUserIdAndClientId returns every refresh token one user holds with one
// client, whatever shape links it to them: GetRefreshTokensByUserId's two branches with
// the client predicate added to each, so an authorization-code token matches through
// codes.user_id and codes.client_id and a ROPC token through refresh_tokens.user_id and
// refresh_tokens.client_id.
//
// It exists for one caller, the consent withdrawal response, which must not sweep what
// the user holds with every OTHER client: withdrawing consent to one app ends that app's
// grants and leaves the user signed in everywhere else (#622). GetRefreshTokensByUserId
// plus a client filter cannot substitute for it, because an auth-code token's row
// carries no client at all: its client is on the code, which this query joins to.
//
// Revoked rows are returned on purpose, beside the live ones: the withdrawal records the
// rotation family of every row it reads, and a family whose stored members are all revoked
// can still have a child mid-rotation that only that record refuses.
//
// Built as two UNION ALL branches for the reason GetRefreshTokensByUserId is: the shapes
// are mutually exclusive, so the union cannot produce duplicates, and each branch can
// use its own index where an OR across the two tables would defeat both (#106).
//
// A zero userId or clientId returns an empty slice with no error, following
// GetRefreshTokensByUserId: the caller's own checks already refuse such identifiers, and
// a sweep over an empty result is a no-op either way.
func (d *Database) GetRefreshTokensByUserIdAndClientId(ctx context.Context, tx *sql.Tx, userId int64, clientId int64) ([]*record.RefreshToken, error) {

	if userId == 0 || clientId == 0 {
		return nil, nil
	}

	return queryRefreshTokens(ctx, d, tx, selectRefreshTokensByUserIdAndClientId.text(d.Dialect),
		[]any{userId, clientId, userId, clientId})
}

// GetRefreshTokensByClientId returns every refresh token belonging to a client,
// whatever shape links it to them.
//
// The invariant this rests on: a refresh token reaches its client through
// codes.client_id (authorization code flow, where refresh_tokens.code_id is set and
// refresh_tokens.client_id is null) or through refresh_tokens.client_id (ROPC, where
// code_id is null), and through nothing else. generateRefreshToken writes the first
// shape and generateRefreshTokenForROPC the second, so the two are mutually exclusive
// and the union cannot produce duplicates. If a third issuance shape is ever added,
// the data test enumerating shapes is what should fail.
//
// Built as two UNION ALL branches for the reason GetRefreshTokensByUserId is: each
// branch can use its own index where an OR across the two tables would defeat both.
// (#245)
func (d *Database) GetRefreshTokensByClientId(ctx context.Context, tx *sql.Tx, clientId int64) ([]*record.RefreshToken, error) {

	if clientId == 0 {
		return nil, nil
	}

	return queryRefreshTokens(ctx, d, tx, selectRefreshTokensByClientId.text(d.Dialect), []any{clientId, clientId})
}

// PromoteRefreshTokenGenerations moves the named refresh tokens to a new
// authentication generation, skipping any that are already revoked.
//
// Narrow on purpose: auth_state_generation is tagged dont-update, so it is excluded
// from UpdateRefreshToken and can only be changed here. Used by the self-service
// password-change path, which preserves the caller's own session and therefore has to
// carry that session's surviving tokens forward rather than leaving them behind on the
// superseded generation. (#106)
//
// An empty id list is a no-op, and sends no statement: there is nothing to promote.
func (d *Database) PromoteRefreshTokenGenerations(ctx context.Context, tx *sql.Tx, refreshTokenIds []int64, generation int64) error {

	if len(refreshTokenIds) == 0 {
		return nil
	}

	// One instant for the whole promotion rather than one per statement, so a long list does not
	// leave the rows it promoted carrying updated_at values a few milliseconds apart.
	updatedAt := time.Now().UTC()

	// A long id list is promoted in several statements (see forEachIdBatch). The caller always
	// holds a transaction -- this is only reachable from the revocation sweep -- so the several
	// statements commit or roll back together, exactly as the one did.
	return forEachIdBatch(refreshTokenIds, func(batch []int64) error {
		query := promoteRefreshTokenGenerationsWhere.text(d.Dialect) + inList(d.Dialect, "id", 4, len(batch))
		args := append([]any{generation, updatedAt, false}, int64Args(batch)...)
		_, err := d.ExecSQL(ctx, tx, query, args...)
		if err != nil {
			return errs.Wrap(err, "unable to promote refresh token generations")
		}

		return nil
	})
}
