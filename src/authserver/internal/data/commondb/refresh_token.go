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
		"refresh_tokens.revoked, refresh_tokens.auth_state_generation, refresh_tokens.authenticated_at, " +
		"refresh_tokens.dpop_jkt",
	mysql: "refresh_tokens.id, refresh_tokens.created_at, refresh_tokens.updated_at, refresh_tokens.code_id, " +
		"refresh_tokens.user_id, refresh_tokens.client_id, refresh_tokens.refresh_token_jti, " +
		"refresh_tokens.previous_refresh_token_jti, refresh_tokens.first_refresh_token_jti, " +
		"refresh_tokens.session_identifier, refresh_tokens.refresh_token_type, refresh_tokens.scope, " +
		"refresh_tokens.issued_at, refresh_tokens.expires_at, refresh_tokens.max_lifetime, " +
		"refresh_tokens.revoked, refresh_tokens.auth_state_generation, refresh_tokens.authenticated_at, " +
		"refresh_tokens.dpop_jkt",
	postgres: "refresh_tokens.id, refresh_tokens.created_at, refresh_tokens.updated_at, refresh_tokens.code_id, " +
		"refresh_tokens.user_id, refresh_tokens.client_id, refresh_tokens.refresh_token_jti, " +
		"refresh_tokens.previous_refresh_token_jti, refresh_tokens.first_refresh_token_jti, " +
		"refresh_tokens.session_identifier, refresh_tokens.refresh_token_type, refresh_tokens.scope, " +
		"refresh_tokens.issued_at, refresh_tokens.expires_at, refresh_tokens.max_lifetime, " +
		"refresh_tokens.revoked, refresh_tokens.auth_state_generation, refresh_tokens.authenticated_at, " +
		"refresh_tokens.dpop_jkt",
	mssql: "refresh_tokens.id, refresh_tokens.created_at, refresh_tokens.updated_at, refresh_tokens.code_id, " +
		"refresh_tokens.user_id, refresh_tokens.client_id, refresh_tokens.refresh_token_jti, " +
		"refresh_tokens.previous_refresh_token_jti, refresh_tokens.first_refresh_token_jti, " +
		"refresh_tokens.session_identifier, refresh_tokens.refresh_token_type, refresh_tokens.scope, " +
		"refresh_tokens.issued_at, refresh_tokens.expires_at, refresh_tokens.max_lifetime, " +
		"refresh_tokens.revoked, refresh_tokens.auth_state_generation, refresh_tokens.authenticated_at, " +
		"refresh_tokens.dpop_jkt",
}

// scanRefreshToken reads one row selected with refreshTokenColumns.
func scanRefreshToken(row rowScanner, refreshToken *record.RefreshToken) error {
	return row.Scan(
		&refreshToken.ID,
		&refreshToken.CreatedAt,
		&refreshToken.UpdatedAt,
		&refreshToken.CodeID,
		&refreshToken.UserID,
		&refreshToken.ClientID,
		&refreshToken.RefreshTokenJTI,
		&refreshToken.PreviousRefreshTokenJTI,
		&refreshToken.FirstRefreshTokenJTI,
		&refreshToken.SessionIdentifier,
		&refreshToken.RefreshTokenType,
		&refreshToken.Scope,
		&refreshToken.IssuedAt,
		&refreshToken.ExpiresAt,
		&refreshToken.MaxLifetime,
		&refreshToken.Revoked,
		&refreshToken.AuthStateGeneration,
		&refreshToken.AuthenticatedAt,
		&refreshToken.DPoPJkt,
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
// born with its code, user and client, the generation and instant its grant was authenticated at,
// and the DPoP key its family is bound to.
var insertRefreshToken = statement{
	sqlite: "INSERT INTO refresh_tokens (created_at, updated_at, code_id, user_id, client_id, " +
		"refresh_token_jti, previous_refresh_token_jti, first_refresh_token_jti, session_identifier, " +
		"refresh_token_type, scope, issued_at, expires_at, max_lifetime, revoked, auth_state_generation, " +
		"authenticated_at, dpop_jkt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
	mysql: "INSERT INTO refresh_tokens (created_at, updated_at, code_id, user_id, client_id, " +
		"refresh_token_jti, previous_refresh_token_jti, first_refresh_token_jti, session_identifier, " +
		"refresh_token_type, scope, issued_at, expires_at, max_lifetime, revoked, auth_state_generation, " +
		"authenticated_at, dpop_jkt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
	postgres: "INSERT INTO refresh_tokens (created_at, updated_at, code_id, user_id, client_id, " +
		"refresh_token_jti, previous_refresh_token_jti, first_refresh_token_jti, session_identifier, " +
		"refresh_token_type, scope, issued_at, expires_at, max_lifetime, revoked, auth_state_generation, " +
		"authenticated_at, dpop_jkt) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, " +
		"$16, $17, $18) RETURNING id",
	mssql: "INSERT INTO refresh_tokens (created_at, updated_at, code_id, user_id, client_id, " +
		"refresh_token_jti, previous_refresh_token_jti, first_refresh_token_jti, session_identifier, " +
		"refresh_token_type, scope, issued_at, expires_at, max_lifetime, revoked, auth_state_generation, " +
		"authenticated_at, dpop_jkt) OUTPUT INSERTED.id VALUES (@p1, @p2, @p3, @p4, @p5, @p6, @p7, @p8, @p9, " +
		"@p10, @p11, @p12, @p13, @p14, @p15, @p16, @p17, @p18)",
}

// updateRefreshToken writes the whole row but created_at, code_id, user_id, client_id,
// auth_state_generation, authenticated_at and dpop_jkt, which are dont-update. Leaving the three foreign keys
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

var selectRefreshTokenByID = statement{
	sqlite:   "SELECT " + refreshTokenColumns.sqlite + " FROM refresh_tokens WHERE id = ?",
	mysql:    "SELECT " + refreshTokenColumns.mysql + " FROM refresh_tokens WHERE id = ?",
	postgres: "SELECT " + refreshTokenColumns.postgres + " FROM refresh_tokens WHERE id = $1",
	mssql:    "SELECT " + refreshTokenColumns.mssql + " FROM refresh_tokens WHERE id = @p1",
}

var selectRefreshTokenByJTI = statement{
	sqlite:   "SELECT " + refreshTokenColumns.sqlite + " FROM refresh_tokens WHERE refresh_token_jti = ?",
	mysql:    "SELECT " + refreshTokenColumns.mysql + " FROM refresh_tokens WHERE refresh_token_jti = ?",
	postgres: "SELECT " + refreshTokenColumns.postgres + " FROM refresh_tokens WHERE refresh_token_jti = $1",
	mssql:    "SELECT " + refreshTokenColumns.mssql + " FROM refresh_tokens WHERE refresh_token_jti = @p1",
}

var selectRefreshTokensByCodeID = statement{
	sqlite:   "SELECT " + refreshTokenColumns.sqlite + " FROM refresh_tokens WHERE code_id = ?",
	mysql:    "SELECT " + refreshTokenColumns.mysql + " FROM refresh_tokens WHERE code_id = ?",
	postgres: "SELECT " + refreshTokenColumns.postgres + " FROM refresh_tokens WHERE code_id = $1",
	mssql:    "SELECT " + refreshTokenColumns.mssql + " FROM refresh_tokens WHERE code_id = @p1",
}

var selectRefreshTokensByFirstRefreshTokenJTI = statement{
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

// selectSessionBoundRefreshTokensBySessionIdentifierAndClientID binds the session identifier, the
// client id, then the session identifier again for the token's own column.
var selectSessionBoundRefreshTokensBySessionIdentifierAndClientID = statement{
	sqlite: "SELECT " + refreshTokenColumns.sqlite + " FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.session_identifier = ? AND codes.client_id = ? AND refresh_tokens.session_identifier = ?",
	mysql: "SELECT " + refreshTokenColumns.mysql + " FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.session_identifier = ? AND codes.client_id = ? AND refresh_tokens.session_identifier = ?",
	postgres: "SELECT " + refreshTokenColumns.postgres + " FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.session_identifier = $1 AND codes.client_id = $2 AND refresh_tokens.session_identifier = $3",
	mssql: "SELECT " + refreshTokenColumns.mssql + " FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.session_identifier = @p1 AND codes.client_id = @p2 AND refresh_tokens.session_identifier = @p3",
}

// selectRefreshTokensByUserID binds the user id once per branch: the code's user, then the token's.
var selectRefreshTokensByUserID = statement{
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

// selectRefreshTokensByUserIDAndClientID binds the user id and the client id once per branch: the
// code's, then the token's. MySQL's is a locking read, FOR UPDATE in each parenthesized branch, so
// it answers the rows as last committed (see GetRefreshTokensByUserIDAndClientID). It locks the
// codes the first branch joins through as well as the tokens: InnoDB answers a joined table the
// locking clause does not name from the snapshot, which would miss the code of a grant committed
// after it.
var selectRefreshTokensByUserIDAndClientID = statement{
	sqlite: "SELECT " + refreshTokenColumns.sqlite + " FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.user_id = ? AND codes.client_id = ? " +
		"UNION ALL SELECT " + refreshTokenColumns.sqlite + " FROM refresh_tokens " +
		"WHERE refresh_tokens.user_id = ? AND refresh_tokens.client_id = ?",
	mysql: "(SELECT " + refreshTokenColumns.mysql + " FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.user_id = ? AND codes.client_id = ? FOR UPDATE) " +
		"UNION ALL (SELECT " + refreshTokenColumns.mysql + " FROM refresh_tokens " +
		"WHERE refresh_tokens.user_id = ? AND refresh_tokens.client_id = ? FOR UPDATE)",
	postgres: "SELECT " + refreshTokenColumns.postgres + " FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.user_id = $1 AND codes.client_id = $2 " +
		"UNION ALL SELECT " + refreshTokenColumns.postgres + " FROM refresh_tokens " +
		"WHERE refresh_tokens.user_id = $3 AND refresh_tokens.client_id = $4",
	mssql: "SELECT " + refreshTokenColumns.mssql + " FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.user_id = @p1 AND codes.client_id = @p2 " +
		"UNION ALL SELECT " + refreshTokenColumns.mssql + " FROM refresh_tokens " +
		"WHERE refresh_tokens.user_id = @p3 AND refresh_tokens.client_id = @p4",
}

// selectUsableRefreshTokenClientIDs binds the user id, false for revoked and the instant once per
// branch: the code's user, then the token's. UNION rather than UNION ALL, so a client holding several
// such tokens is named once.
var selectUsableRefreshTokenClientIDs = statement{
	sqlite: "SELECT codes.client_id FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.user_id = ? AND refresh_tokens.revoked = ? AND refresh_tokens.expires_at > ? " +
		"UNION SELECT refresh_tokens.client_id FROM refresh_tokens " +
		"WHERE refresh_tokens.user_id = ? AND refresh_tokens.revoked = ? AND refresh_tokens.expires_at > ? " +
		"AND refresh_tokens.client_id IS NOT NULL",
	mysql: "SELECT codes.client_id FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.user_id = ? AND refresh_tokens.revoked = ? AND refresh_tokens.expires_at > ? " +
		"UNION SELECT refresh_tokens.client_id FROM refresh_tokens " +
		"WHERE refresh_tokens.user_id = ? AND refresh_tokens.revoked = ? AND refresh_tokens.expires_at > ? " +
		"AND refresh_tokens.client_id IS NOT NULL",
	postgres: "SELECT codes.client_id FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.user_id = $1 AND refresh_tokens.revoked = $2 AND refresh_tokens.expires_at > $3 " +
		"UNION SELECT refresh_tokens.client_id FROM refresh_tokens " +
		"WHERE refresh_tokens.user_id = $4 AND refresh_tokens.revoked = $5 AND refresh_tokens.expires_at > $6 " +
		"AND refresh_tokens.client_id IS NOT NULL",
	mssql: "SELECT codes.client_id FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.user_id = @p1 AND refresh_tokens.revoked = @p2 AND refresh_tokens.expires_at > @p3 " +
		"UNION SELECT refresh_tokens.client_id FROM refresh_tokens " +
		"WHERE refresh_tokens.user_id = @p4 AND refresh_tokens.revoked = @p5 AND refresh_tokens.expires_at > @p6 " +
		"AND refresh_tokens.client_id IS NOT NULL",
}

// liveGrantFamilyUnrecorded is the condition both branches of selectLiveGrantsByUserID end with:
// the token's rotation family has no revocation record.
const liveGrantFamilyUnrecorded = "AND NOT EXISTS (SELECT 1 FROM refresh_token_family_revocations " +
	"WHERE refresh_token_family_revocations.first_refresh_token_jti = refresh_tokens.first_refresh_token_jti)"

// selectLiveGrantsByUserID binds the user id, false for revoked and the instant once per branch:
// the code's user, then the token's. UNION ALL, since the two shapes are mutually exclusive.
var selectLiveGrantsByUserID = statement{
	sqlite: "SELECT refresh_tokens.id, codes.client_id, refresh_tokens.scope FROM refresh_tokens " +
		"INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.user_id = ? AND refresh_tokens.revoked = ? AND refresh_tokens.expires_at > ? " +
		liveGrantFamilyUnrecorded + " " +
		"UNION ALL SELECT refresh_tokens.id, refresh_tokens.client_id, refresh_tokens.scope FROM refresh_tokens " +
		"WHERE refresh_tokens.user_id = ? AND refresh_tokens.revoked = ? AND refresh_tokens.expires_at > ? " +
		"AND refresh_tokens.client_id IS NOT NULL " + liveGrantFamilyUnrecorded,
	mysql: "SELECT refresh_tokens.id, codes.client_id, refresh_tokens.scope FROM refresh_tokens " +
		"INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.user_id = ? AND refresh_tokens.revoked = ? AND refresh_tokens.expires_at > ? " +
		liveGrantFamilyUnrecorded + " " +
		"UNION ALL SELECT refresh_tokens.id, refresh_tokens.client_id, refresh_tokens.scope FROM refresh_tokens " +
		"WHERE refresh_tokens.user_id = ? AND refresh_tokens.revoked = ? AND refresh_tokens.expires_at > ? " +
		"AND refresh_tokens.client_id IS NOT NULL " + liveGrantFamilyUnrecorded,
	postgres: "SELECT refresh_tokens.id, codes.client_id, refresh_tokens.scope FROM refresh_tokens " +
		"INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.user_id = $1 AND refresh_tokens.revoked = $2 AND refresh_tokens.expires_at > $3 " +
		liveGrantFamilyUnrecorded + " " +
		"UNION ALL SELECT refresh_tokens.id, refresh_tokens.client_id, refresh_tokens.scope FROM refresh_tokens " +
		"WHERE refresh_tokens.user_id = $4 AND refresh_tokens.revoked = $5 AND refresh_tokens.expires_at > $6 " +
		"AND refresh_tokens.client_id IS NOT NULL " + liveGrantFamilyUnrecorded,
	mssql: "SELECT refresh_tokens.id, codes.client_id, refresh_tokens.scope FROM refresh_tokens " +
		"INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
		"WHERE codes.user_id = @p1 AND refresh_tokens.revoked = @p2 AND refresh_tokens.expires_at > @p3 " +
		liveGrantFamilyUnrecorded + " " +
		"UNION ALL SELECT refresh_tokens.id, refresh_tokens.client_id, refresh_tokens.scope FROM refresh_tokens " +
		"WHERE refresh_tokens.user_id = @p4 AND refresh_tokens.revoked = @p5 AND refresh_tokens.expires_at > @p6 " +
		"AND refresh_tokens.client_id IS NOT NULL " + liveGrantFamilyUnrecorded,
}

// selectRefreshTokensByClientID binds the client id once per branch: the code's, then the token's.
var selectRefreshTokensByClientID = statement{
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

var deleteRefreshTokensByUserID = statement{
	sqlite:   "DELETE FROM refresh_tokens WHERE user_id = ?",
	mysql:    "DELETE FROM refresh_tokens WHERE user_id = ?",
	postgres: "DELETE FROM refresh_tokens WHERE user_id = $1",
	mssql:    "DELETE FROM refresh_tokens WHERE user_id = @p1",
}

var deleteRefreshTokensByClientID = statement{
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
		refreshToken.CreatedAt, refreshToken.UpdatedAt, refreshToken.CodeID, refreshToken.UserID,
		refreshToken.ClientID, refreshToken.RefreshTokenJTI, refreshToken.PreviousRefreshTokenJTI,
		refreshToken.FirstRefreshTokenJTI, refreshToken.SessionIdentifier, refreshToken.RefreshTokenType,
		refreshToken.Scope, refreshToken.IssuedAt, refreshToken.ExpiresAt, refreshToken.MaxLifetime,
		refreshToken.Revoked, refreshToken.AuthStateGeneration, refreshToken.AuthenticatedAt, refreshToken.DPoPJkt)
	if err != nil {
		refreshToken.CreatedAt = originalCreatedAt
		refreshToken.UpdatedAt = originalUpdatedAt
		return err
	}

	refreshToken.ID = id
	return nil
}

func (d *Database) UpdateRefreshToken(ctx context.Context, tx *sql.Tx, refreshToken *record.RefreshToken) error {

	if refreshToken.ID == 0 {
		return errs.New("can't update refreshToken with id 0")
	}

	originalUpdatedAt := refreshToken.UpdatedAt
	refreshToken.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	_, err := d.ExecSQL(ctx, tx, updateRefreshToken.text(d.Dialect),
		refreshToken.UpdatedAt, refreshToken.RefreshTokenJTI, refreshToken.PreviousRefreshTokenJTI,
		refreshToken.FirstRefreshTokenJTI, refreshToken.SessionIdentifier, refreshToken.RefreshTokenType,
		refreshToken.Scope, refreshToken.IssuedAt, refreshToken.ExpiresAt, refreshToken.MaxLifetime,
		refreshToken.Revoked, refreshToken.ID)
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
func (d *Database) MarkRefreshTokenAsRevoked(ctx context.Context, tx *sql.Tx, refreshTokenID int64) (bool, error) {

	if refreshTokenID == 0 {
		return false, errs.New("can't mark refresh token with id 0 as revoked")
	}

	result, err := d.ExecSQL(ctx, tx, markRefreshTokenAsRevoked.text(d.Dialect),
		true, time.Now().UTC(), refreshTokenID, false)
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
func (d *Database) RevokeRefreshTokenFamily(ctx context.Context, tx *sql.Tx, firstRefreshTokenJTI string) (int64, error) {

	if firstRefreshTokenJTI == "" {
		return 0, errs.New("can't revoke a refresh token family with an empty first refresh token jti")
	}

	result, err := d.ExecSQL(ctx, tx, revokeRefreshTokenFamily.text(d.Dialect),
		true, time.Now().UTC(), firstRefreshTokenJTI, false)
	if err != nil {
		return 0, errs.Wrap(err, "unable to revoke refresh token family")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, errs.Wrap(err, "unable to get rows affected when revoking refresh token family")
	}

	return rowsAffected, nil
}

func (d *Database) GetRefreshTokenByID(ctx context.Context, tx *sql.Tx, refreshTokenID int64) (*record.RefreshToken, error) {
	return queryOne(ctx, d, tx, selectRefreshTokenByID.text(d.Dialect), []any{refreshTokenID}, scanRefreshToken,
		"refreshToken")
}

func (d *Database) RefreshTokenLoadCode(ctx context.Context, tx *sql.Tx, refreshToken *record.RefreshToken) error {
	if refreshToken == nil {
		return nil
	}

	// Only load code if CodeID is valid (auth code flow tokens)
	// ROPC tokens don't have a CodeID
	if !refreshToken.CodeID.Valid {
		return nil
	}

	code, err := d.GetCodeByID(ctx, tx, refreshToken.CodeID.Int64)
	if err != nil {
		return errs.Wrap(err, "unable to load code")
	}

	if code != nil {
		refreshToken.Code = *code
	}

	return nil
}

// RefreshTokenLoadUser loads the User entity for ROPC flow refresh tokens.
// For auth code flow tokens (with CodeID), use RefreshTokenLoadCode instead.
func (d *Database) RefreshTokenLoadUser(ctx context.Context, tx *sql.Tx, refreshToken *record.RefreshToken) error {
	if refreshToken == nil {
		return nil
	}

	// Only load user if UserID is valid (ROPC flow tokens)
	if !refreshToken.UserID.Valid {
		return nil
	}

	user, err := d.GetUserByID(ctx, tx, refreshToken.UserID.Int64)
	if err != nil {
		return errs.Wrap(err, "unable to load user")
	}

	if user != nil {
		refreshToken.User = *user
	}

	return nil
}

// RefreshTokenLoadClient loads the Client entity for ROPC flow refresh tokens.
// For auth code flow tokens (with CodeID), use RefreshTokenLoadCode instead.
func (d *Database) RefreshTokenLoadClient(ctx context.Context, tx *sql.Tx, refreshToken *record.RefreshToken) error {
	if refreshToken == nil {
		return nil
	}

	// Only load client if ClientID is valid (ROPC flow tokens)
	if !refreshToken.ClientID.Valid {
		return nil
	}

	client, err := d.GetClientByID(ctx, tx, refreshToken.ClientID.Int64)
	if err != nil {
		return errs.Wrap(err, "unable to load client")
	}

	if client != nil {
		refreshToken.Client = *client
	}

	return nil
}

func (d *Database) GetRefreshTokenByJTI(ctx context.Context, tx *sql.Tx, jti string) (*record.RefreshToken, error) {
	return queryOne(ctx, d, tx, selectRefreshTokenByJTI.text(d.Dialect), []any{jti}, scanRefreshToken, "refreshToken")
}

// GetRefreshTokensByFirstRefreshTokenJTI returns every member of one rotation family, live and
// revoked: the rows a client revoking the grant at /auth/revoke ends, and the jtis its audit record
// lists (#676 decision 1). It reads by idx_refresh_tokens_first_refresh_token_jti.
//
// Each row is compared with the identifier asked for in Go, for the reason
// IsRefreshTokenFamilyRevoked states (#283): SQL Server pads for `=`, so a trailing space would
// otherwise find the members of the family without one, and a revocation would end a grant other
// than the one asked for. An empty identifier is an error, for the reason RevokeRefreshTokenFamily
// states.
func (d *Database) GetRefreshTokensByFirstRefreshTokenJTI(ctx context.Context, tx *sql.Tx,
	firstRefreshTokenJTI string) ([]*record.RefreshToken, error) {

	if firstRefreshTokenJTI == "" {
		return nil, errs.New("can't read a refresh token family with an empty first refresh token jti")
	}

	rows, err := queryRefreshTokens(ctx, d, tx, selectRefreshTokensByFirstRefreshTokenJTI.text(d.Dialect),
		[]any{firstRefreshTokenJTI})
	if err != nil {
		return nil, err
	}

	members := make([]*record.RefreshToken, 0, len(rows))
	for _, rt := range rows {
		if engineFoldedTheMatch(rt.FirstRefreshTokenJTI, firstRefreshTokenJTI) {
			continue
		}
		members = append(members, rt)
	}
	return members, nil
}

func (d *Database) GetRefreshTokensByCodeID(ctx context.Context, tx *sql.Tx, codeID int64) ([]*record.RefreshToken, error) {
	return queryRefreshTokens(ctx, d, tx, selectRefreshTokensByCodeID.text(d.Dialect), []any{codeID})
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

// GetSessionBoundRefreshTokensBySessionIdentifierAndClientID returns the session-bound refresh tokens
// one client holds from one session: the tokens descended from the client's codes on the session
// whose own session_identifier is the session's. That last term is what leaves out the client's
// offline tokens from the same session, whose own session_identifier is empty and whose code carries
// the sid, the shape GetRefreshTokensBySessionIdentifier reaches on purpose and this must not. A
// password grant token has no code and no session, so it is never one of them.
//
// It exists for the sign-out with a confirmed id_token_hint (#135 decision 9), which revokes these
// and leaves the client's offline grants working (Back-Channel Logout 1.0 section 2.7). Revoked rows
// are returned beside the live ones, for the reason GetRefreshTokensByUserIDAndClientID gives: the
// sign-out records the family of every row it reads, and a family whose stored members are all
// revoked can still have a child mid-rotation that only that record refuses (#259).
//
// The session is matched on codes.session_identifier, which idx_codes_session_identifier serves, as
// well as on the token's own. An empty session identifier or a zero client id names no grant and
// returns an empty slice with no error, following GetRefreshTokensBySessionIdentifier: the join
// would otherwise match every code with an empty session_identifier.
func (d *Database) GetSessionBoundRefreshTokensBySessionIdentifierAndClientID(ctx context.Context, tx *sql.Tx,
	sessionIdentifier string, clientID int64) ([]*record.RefreshToken, error) {

	if sessionIdentifier == "" || clientID == 0 {
		return nil, nil
	}

	return queryRefreshTokens(ctx, d, tx,
		selectSessionBoundRefreshTokensBySessionIdentifierAndClientID.text(d.Dialect),
		[]any{sessionIdentifier, clientID, sessionIdentifier})
}

func (d *Database) DeleteRefreshToken(ctx context.Context, tx *sql.Tx, refreshTokenID int64) error {

	_, err := d.ExecSQL(ctx, tx, deleteRefreshToken.text(d.Dialect), refreshTokenID)
	if err != nil {
		return errs.Wrap(err, "unable to delete refreshToken")
	}

	return nil
}

// deleteRefreshTokensByColumn removes every refresh token whose given column
// matches, used to clear a parent's tokens before deleting the parent itself.
//
// refresh_tokens.user_id and .client_id are ON DELETE NO ACTION on all four
// engines (each schema.golden); only refresh_tokens.code_id cascades. So on every
// engine, not only SQL Server, a refresh token issued without a code blocks
// deletion of its user or client outright, as SQL Server reports it:
//
//	The DELETE statement conflicted with the REFERENCE constraint
//	"fk_refresh_tokens_user" ... table "dbo.refresh_tokens", column 'user_id'.
//
// Codeless tokens are not hypothetical: the ROPC grant creates exactly that shape
// (TokenIssuer.generateRefreshTokenForROPC, "no Code reference"), so without this
// delete any user or client that had used ROPC could not be deleted at all.
//
// SQL Server could not cascade these two keys even if asked: refresh_tokens
// already cascades from codes, and codes cascades from both users and clients, so
// a direct cascade would be a second delete path into the same table, which SQL
// Server rejects as "cycles or multiple cascade paths" (mssqldb migration 000011).
func (d *Database) deleteRefreshTokensByColumn(ctx context.Context, tx *sql.Tx, column string, value int64) error {
	var s statement
	switch column {
	case "user_id":
		s = deleteRefreshTokensByUserID
	case "client_id":
		s = deleteRefreshTokensByClientID
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

// GetRefreshTokensByUserID returns every refresh token belonging to a user, whatever
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
func (d *Database) GetRefreshTokensByUserID(ctx context.Context, tx *sql.Tx, userID int64) ([]*record.RefreshToken, error) {

	if userID == 0 {
		return nil, nil
	}

	return queryRefreshTokens(ctx, d, tx, selectRefreshTokensByUserID.text(d.Dialect), []any{userID, userID})
}

// GetUsableRefreshTokenClientIDsByUserID answers the clients holding one of the user's refresh tokens that
// is still unrevoked and unexpired at now, each once, through either linkage shape: codes.client_id
// for an authorization-code token and refresh_tokens.client_id for a password grant, the two
// branches GetRefreshTokensByUserID reads. A user-wide end tells each of them that the user was
// signed out (#784 decision 3). A zero userID names no client.
func (d *Database) GetUsableRefreshTokenClientIDsByUserID(ctx context.Context, tx *sql.Tx, userID int64,
	now time.Time) ([]int64, error) {

	if userID == 0 {
		return nil, nil
	}

	return queryAll(ctx, d, tx, []int64(nil), selectUsableRefreshTokenClientIDs.text(d.Dialect),
		[]any{userID, false, now, userID, false, now},
		func(row rowScanner, clientID *int64) error { return row.Scan(clientID) }, "client id")
}

// GetLiveGrantsByUserID answers one row for each live refresh token the user holds, with the client
// it reaches and the scope it records, through either linkage shape: codes.client_id for an
// authorization-code token, refresh_tokens.client_id for a password grant, the two branches
// GetRefreshTokensByUserID reads (#135 decision 4). A live token is one whose row is not revoked,
// whose expires_at is set and after now, and whose rotation family has no revocation record: the
// record is what refuses a family whose stored members a sweep left looking live, a child a
// rotation in flight inserted after it (#259). The list of the user's connected clients reads it,
// and merges each client's scopes itself. A zero userID holds no live grant.
//
// The family is matched by the engine's comparison of first_refresh_token_jti, as
// DeleteOrphanedRefreshTokenFamilyRevocations matches it, not in Go as IsRefreshTokenFamilyRevoked
// does: the jtis are server-minted UUIDs, so no two families differ only by case or trailing
// spaces, and a fold could only leave a live grant unlisted, never list a dead one.
func (d *Database) GetLiveGrantsByUserID(ctx context.Context, tx *sql.Tx, userID int64,
	now time.Time) ([]record.LiveGrant, error) {

	if userID == 0 {
		return nil, nil
	}

	return queryAll(ctx, d, tx, []record.LiveGrant(nil), selectLiveGrantsByUserID.text(d.Dialect),
		[]any{userID, false, now, userID, false, now},
		func(row rowScanner, grant *record.LiveGrant) error {
			return row.Scan(&grant.RefreshTokenID, &grant.ClientID, &grant.Scope)
		}, "live grant")
}

// GetRefreshTokensByUserIDAndClientID returns every refresh token one user holds with one
// client, whatever shape links it to them: GetRefreshTokensByUserID's two branches with
// the client predicate added to each, so an authorization-code token matches through
// codes.user_id and codes.client_id and a ROPC token through refresh_tokens.user_id and
// refresh_tokens.client_id.
//
// It exists for one caller, the consent withdrawal response, which must not sweep what
// the user holds with every OTHER client: withdrawing consent to one app ends that app's
// grants and leaves the user signed in everywhere else (#622). GetRefreshTokensByUserID
// plus a client filter cannot substitute for it, because an auth-code token's row
// carries no client at all: its client is on the code, which this query joins to.
//
// Revoked rows are returned on purpose, beside the live ones: the withdrawal records the
// rotation family of every row it reads, and a family whose stored members are all revoked
// can still have a child mid-rotation that only that record refuses.
//
// The rows are read as last committed, whatever the caller's transaction read before. The
// difference is MySQL's: under InnoDB's REPEATABLE READ an ordinary read answers the snapshot
// the transaction's first read fixed, and the disconnect reads the client and the user's
// sessions before it sweeps, so a grant committed in between would be left live by a
// disconnect that reported success (#135 decision 1). MySQL's statement is therefore a locking
// read, FOR UPDATE on the refresh_tokens rows, which the sweep writes next anyway, and on the
// codes the authorization-code branch joins through, for the reason its statement gives: FOR SHARE
// would have two overlapping disconnects each hold a shared lock the other's write waits for.
// On PostgreSQL and SQL Server at READ COMMITTED each statement reads what was committed when
// it started, and SQLite has one writer at a time, so their statements take no lock.
//
// Built as two UNION ALL branches for the reason GetRefreshTokensByUserID is: the shapes
// are mutually exclusive, so the union cannot produce duplicates, and each branch can
// use its own index where an OR across the two tables would defeat both (#106).
//
// A zero userID or clientID returns an empty slice with no error, following
// GetRefreshTokensByUserID: the caller's own checks already refuse such identifiers, and
// a sweep over an empty result is a no-op either way.
func (d *Database) GetRefreshTokensByUserIDAndClientID(ctx context.Context, tx *sql.Tx, userID int64, clientID int64) ([]*record.RefreshToken, error) {

	if userID == 0 || clientID == 0 {
		return nil, nil
	}

	return queryRefreshTokens(ctx, d, tx, selectRefreshTokensByUserIDAndClientID.text(d.Dialect),
		[]any{userID, clientID, userID, clientID})
}

// GetRefreshTokensByClientID returns every refresh token belonging to a client,
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
// Built as two UNION ALL branches for the reason GetRefreshTokensByUserID is: each
// branch can use its own index where an OR across the two tables would defeat both.
// (#245)
func (d *Database) GetRefreshTokensByClientID(ctx context.Context, tx *sql.Tx, clientID int64) ([]*record.RefreshToken, error) {

	if clientID == 0 {
		return nil, nil
	}

	return queryRefreshTokens(ctx, d, tx, selectRefreshTokensByClientID.text(d.Dialect), []any{clientID, clientID})
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
func (d *Database) PromoteRefreshTokenGenerations(ctx context.Context, tx *sql.Tx, refreshTokenIDs []int64, generation int64) error {

	if len(refreshTokenIDs) == 0 {
		return nil
	}

	// One instant for the whole promotion rather than one per statement, so a long list does not
	// leave the rows it promoted carrying updated_at values a few milliseconds apart.
	updatedAt := time.Now().UTC()

	// A long id list is promoted in several statements (see forEachIDBatch). The caller always
	// holds a transaction -- this is only reachable from the revocation sweep -- so the several
	// statements commit or roll back together, exactly as the one did.
	return forEachIDBatch(refreshTokenIDs, func(batch []int64) error {
		query := promoteRefreshTokenGenerationsWhere.text(d.Dialect) + inList(d.Dialect, "id", 4, len(batch))
		args := append([]any{generation, updatedAt, false}, int64Args(batch)...)
		_, err := d.ExecSQL(ctx, tx, query, args...)
		if err != nil {
			return errs.Wrap(err, "unable to promote refresh token generations")
		}

		return nil
	})
}
