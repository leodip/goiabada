package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// codeColumns is the codes table as scanCode reads it.
var codeColumns = columnList{
	sqlite: "id, created_at, updated_at, code_hash, client_id, code_challenge, code_challenge_method, scope, " +
		"state, nonce, redirect_uri, user_id, ip_address, user_agent, response_mode, authenticated_at, " +
		"session_identifier, acr_level, auth_methods, used, revoked, auth_state_generation",
	mysql: "id, created_at, updated_at, code_hash, client_id, code_challenge, code_challenge_method, scope, " +
		"state, nonce, redirect_uri, user_id, ip_address, user_agent, response_mode, authenticated_at, " +
		"session_identifier, acr_level, auth_methods, used, revoked, auth_state_generation",
	postgres: "id, created_at, updated_at, code_hash, client_id, code_challenge, code_challenge_method, scope, " +
		"state, nonce, redirect_uri, user_id, ip_address, user_agent, response_mode, authenticated_at, " +
		"session_identifier, acr_level, auth_methods, used, revoked, auth_state_generation",
	mssql: "id, created_at, updated_at, code_hash, client_id, code_challenge, code_challenge_method, scope, " +
		"state, nonce, redirect_uri, user_id, ip_address, user_agent, response_mode, authenticated_at, " +
		"session_identifier, acr_level, auth_methods, used, revoked, auth_state_generation",
}

// scanCode reads one row selected with codeColumns.
func scanCode(row rowScanner, code *record.Code) error {
	return row.Scan(
		&code.Id,
		&code.CreatedAt,
		&code.UpdatedAt,
		&code.CodeHash,
		&code.ClientId,
		&code.CodeChallenge,
		&code.CodeChallengeMethod,
		&code.Scope,
		&code.State,
		&code.Nonce,
		&code.RedirectURI,
		&code.UserId,
		&code.IpAddress,
		&code.UserAgent,
		&code.ResponseMode,
		&code.AuthenticatedAt,
		&code.SessionIdentifier,
		&code.AcrLevel,
		&code.AuthMethods,
		&code.Used,
		&code.Revoked,
		&code.AuthStateGeneration,
	)
}

// insertCode writes every column but id, the dont-update ones included: a new code starts unrevoked
// and carries the generation it was issued under.
var insertCode = statement{
	sqlite: "INSERT INTO codes (created_at, updated_at, code_hash, client_id, code_challenge, " +
		"code_challenge_method, scope, state, nonce, redirect_uri, user_id, ip_address, user_agent, " +
		"response_mode, authenticated_at, session_identifier, acr_level, auth_methods, used, revoked, " +
		"auth_state_generation) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
	mysql: "INSERT INTO codes (created_at, updated_at, code_hash, client_id, code_challenge, " +
		"code_challenge_method, scope, state, nonce, redirect_uri, user_id, ip_address, user_agent, " +
		"response_mode, authenticated_at, session_identifier, acr_level, auth_methods, used, revoked, " +
		"auth_state_generation) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
	postgres: "INSERT INTO codes (created_at, updated_at, code_hash, client_id, code_challenge, " +
		"code_challenge_method, scope, state, nonce, redirect_uri, user_id, ip_address, user_agent, " +
		"response_mode, authenticated_at, session_identifier, acr_level, auth_methods, used, revoked, " +
		"auth_state_generation) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, " +
		"$16, $17, $18, $19, $20, $21) RETURNING id",
	mssql: "INSERT INTO codes (created_at, updated_at, code_hash, client_id, code_challenge, " +
		"code_challenge_method, scope, state, nonce, redirect_uri, user_id, ip_address, user_agent, " +
		"response_mode, authenticated_at, session_identifier, acr_level, auth_methods, used, revoked, " +
		"auth_state_generation) OUTPUT INSERTED.id VALUES (@p1, @p2, @p3, @p4, @p5, @p6, @p7, @p8, @p9, " +
		"@p10, @p11, @p12, @p13, @p14, @p15, @p16, @p17, @p18, @p19, @p20, @p21)",
}

// updateCode writes the whole row but created_at, revoked and auth_state_generation, which are
// dont-update: a stale record written back cannot unrevoke a code or move its generation.
var updateCode = statement{
	sqlite: "UPDATE codes SET updated_at = ?, code_hash = ?, client_id = ?, code_challenge = ?, " +
		"code_challenge_method = ?, scope = ?, state = ?, nonce = ?, redirect_uri = ?, user_id = ?, " +
		"ip_address = ?, user_agent = ?, response_mode = ?, authenticated_at = ?, session_identifier = ?, " +
		"acr_level = ?, auth_methods = ?, used = ? WHERE id = ?",
	mysql: "UPDATE codes SET updated_at = ?, code_hash = ?, client_id = ?, code_challenge = ?, " +
		"code_challenge_method = ?, scope = ?, state = ?, nonce = ?, redirect_uri = ?, user_id = ?, " +
		"ip_address = ?, user_agent = ?, response_mode = ?, authenticated_at = ?, session_identifier = ?, " +
		"acr_level = ?, auth_methods = ?, used = ? WHERE id = ?",
	postgres: "UPDATE codes SET updated_at = $1, code_hash = $2, client_id = $3, code_challenge = $4, " +
		"code_challenge_method = $5, scope = $6, state = $7, nonce = $8, redirect_uri = $9, " +
		"user_id = $10, ip_address = $11, user_agent = $12, response_mode = $13, authenticated_at = $14, " +
		"session_identifier = $15, acr_level = $16, auth_methods = $17, used = $18 WHERE id = $19",
	mssql: "UPDATE codes SET updated_at = @p1, code_hash = @p2, client_id = @p3, code_challenge = @p4, " +
		"code_challenge_method = @p5, scope = @p6, state = @p7, nonce = @p8, redirect_uri = @p9, " +
		"user_id = @p10, ip_address = @p11, user_agent = @p12, response_mode = @p13, " +
		"authenticated_at = @p14, session_identifier = @p15, acr_level = @p16, auth_methods = @p17, " +
		"used = @p18 WHERE id = @p19",
}

var selectCodeById = statement{
	sqlite:   "SELECT " + codeColumns.sqlite + " FROM codes WHERE id = ?",
	mysql:    "SELECT " + codeColumns.mysql + " FROM codes WHERE id = ?",
	postgres: "SELECT " + codeColumns.postgres + " FROM codes WHERE id = $1",
	mssql:    "SELECT " + codeColumns.mssql + " FROM codes WHERE id = @p1",
}

var selectCodeByCodeHash = statement{
	sqlite:   "SELECT " + codeColumns.sqlite + " FROM codes WHERE code_hash = ? AND used = ?",
	mysql:    "SELECT " + codeColumns.mysql + " FROM codes WHERE code_hash = ? AND used = ?",
	postgres: "SELECT " + codeColumns.postgres + " FROM codes WHERE code_hash = $1 AND used = $2",
	mssql:    "SELECT " + codeColumns.mssql + " FROM codes WHERE code_hash = @p1 AND used = @p2",
}

// markCodeAsUsed binds used, updated_at, the id, then used and revoked as the row must still hold
// them.
var markCodeAsUsed = statement{
	sqlite:   "UPDATE codes SET used = ?, updated_at = ? WHERE id = ? AND used = ? AND revoked = ?",
	mysql:    "UPDATE codes SET used = ?, updated_at = ? WHERE id = ? AND used = ? AND revoked = ?",
	postgres: "UPDATE codes SET used = $1, updated_at = $2 WHERE id = $3 AND used = $4 AND revoked = $5",
	mssql:    "UPDATE codes SET used = @p1, updated_at = @p2 WHERE id = @p3 AND used = @p4 AND revoked = @p5",
}

var revokeCodesBySessionIdentifier = statement{
	sqlite:   "UPDATE codes SET revoked = ?, updated_at = ? WHERE session_identifier = ? AND revoked = ?",
	mysql:    "UPDATE codes SET revoked = ?, updated_at = ? WHERE session_identifier = ? AND revoked = ?",
	postgres: "UPDATE codes SET revoked = $1, updated_at = $2 WHERE session_identifier = $3 AND revoked = $4",
	mssql:    "UPDATE codes SET revoked = @p1, updated_at = @p2 WHERE session_identifier = @p3 AND revoked = @p4",
}

var revokeCodesByClientId = statement{
	sqlite:   "UPDATE codes SET revoked = ?, updated_at = ? WHERE client_id = ? AND revoked = ?",
	mysql:    "UPDATE codes SET revoked = ?, updated_at = ? WHERE client_id = ? AND revoked = ?",
	postgres: "UPDATE codes SET revoked = $1, updated_at = $2 WHERE client_id = $3 AND revoked = $4",
	mssql:    "UPDATE codes SET revoked = @p1, updated_at = @p2 WHERE client_id = @p3 AND revoked = @p4",
}

var revokeUnusedCodesByUserIdAndClientId = statement{
	sqlite: "UPDATE codes SET revoked = ?, updated_at = ? " +
		"WHERE user_id = ? AND client_id = ? AND used = ? AND revoked = ?",
	mysql: "UPDATE codes SET revoked = ?, updated_at = ? " +
		"WHERE user_id = ? AND client_id = ? AND used = ? AND revoked = ?",
	postgres: "UPDATE codes SET revoked = $1, updated_at = $2 " +
		"WHERE user_id = $3 AND client_id = $4 AND used = $5 AND revoked = $6",
	mssql: "UPDATE codes SET revoked = @p1, updated_at = @p2 " +
		"WHERE user_id = @p3 AND client_id = @p4 AND used = @p5 AND revoked = @p6",
}

var deleteCode = statement{
	sqlite:   "DELETE FROM codes WHERE id = ?",
	mysql:    "DELETE FROM codes WHERE id = ?",
	postgres: "DELETE FROM codes WHERE id = $1",
	mssql:    "DELETE FROM codes WHERE id = @p1",
}

var deleteCodesWithoutRefreshTokens = statement{
	sqlite: "DELETE FROM codes WHERE created_at < ? " +
		"AND NOT EXISTS (SELECT 1 FROM refresh_tokens WHERE refresh_tokens.code_id = codes.id)",
	mysql: "DELETE FROM codes WHERE created_at < ? " +
		"AND NOT EXISTS (SELECT 1 FROM refresh_tokens WHERE refresh_tokens.code_id = codes.id)",
	postgres: "DELETE FROM codes WHERE created_at < $1 " +
		"AND NOT EXISTS (SELECT 1 FROM refresh_tokens WHERE refresh_tokens.code_id = codes.id)",
	mssql: "DELETE FROM codes WHERE created_at < @p1 " +
		"AND NOT EXISTS (SELECT 1 FROM refresh_tokens WHERE refresh_tokens.code_id = codes.id)",
}

func (d *Database) CreateCode(ctx context.Context, tx *sql.Tx, code *record.Code) error {

	if code.ClientId == 0 {
		return errs.New("client id must be greater than 0")
	}

	if code.UserId == 0 {
		return errs.New("user id must be greater than 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := code.CreatedAt
	originalUpdatedAt := code.UpdatedAt
	code.CreatedAt = sql.NullTime{Time: now, Valid: true}
	code.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	id, err := d.insert(ctx, tx, insertCode, "code",
		code.CreatedAt, code.UpdatedAt, code.CodeHash, code.ClientId, code.CodeChallenge,
		code.CodeChallengeMethod, code.Scope, code.State, code.Nonce, code.RedirectURI, code.UserId,
		code.IpAddress, code.UserAgent, code.ResponseMode, code.AuthenticatedAt, code.SessionIdentifier,
		code.AcrLevel, code.AuthMethods, code.Used, code.Revoked, code.AuthStateGeneration)
	if err != nil {
		code.CreatedAt = originalCreatedAt
		code.UpdatedAt = originalUpdatedAt
		return err
	}

	code.Id = id
	return nil
}

func (d *Database) UpdateCode(ctx context.Context, tx *sql.Tx, code *record.Code) error {

	if code.Id == 0 {
		return errs.New("can't update code with id 0")
	}

	originalUpdatedAt := code.UpdatedAt
	code.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	_, err := d.ExecSQL(ctx, tx, updateCode.text(d.Dialect),
		code.UpdatedAt, code.CodeHash, code.ClientId, code.CodeChallenge, code.CodeChallengeMethod,
		code.Scope, code.State, code.Nonce, code.RedirectURI, code.UserId, code.IpAddress, code.UserAgent,
		code.ResponseMode, code.AuthenticatedAt, code.SessionIdentifier, code.AcrLevel, code.AuthMethods,
		code.Used, code.Id)
	if err != nil {
		code.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update code")
	}

	return nil
}

// MarkCodeAsUsed atomically transitions a code from unused to used via a
// conditional UPDATE (`WHERE id = ? AND used = false AND revoked = false`). It
// returns true only if this call is the one that flipped the flag. This compare-and-set
// closes the double-spend race that a read-then-unconditional-update leaves open (#77).
//
// A false return means **no row transitioned**, and the three ways that happens are not
// distinguishable here: the row was already used, it was revoked, or it does not exist.
// So false must not be read as authorization-code reuse. Reuse is detected in the
// validator, which finds the already-used row and returns AuthCodeReusedError, and that
// is what drives the containment cascade. The caller's job on false is to refuse
// generically, which is what handler_token.go does.
//
// The revoked term is what makes session termination durable against a redemption
// already in progress (#129). Validation and claiming are separate steps, so a code
// validated a moment before its session was terminated would otherwise still be
// claimed and its tokens issued.
func (d *Database) MarkCodeAsUsed(ctx context.Context, tx *sql.Tx, codeId int64) (bool, error) {

	if codeId == 0 {
		return false, errs.New("can't mark code with id 0 as used")
	}

	result, err := d.ExecSQL(ctx, tx, markCodeAsUsed.text(d.Dialect),
		true, time.Now().UTC(), codeId, false, false)
	if err != nil {
		return false, errs.Wrap(err, "unable to mark code as used")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errs.Wrap(err, "unable to get rows affected when marking code as used")
	}

	return rowsAffected == 1, nil
}

// RevokeCodesBySessionIdentifier marks every not-yet-revoked code of one session
// revoked, and reports how many rows this call transitioned. It is the durable half
// of ending a session (#129): the code is the grant record, and a rotated refresh
// token inherits its parent's code_id, so marking the code marks every descendant of
// that grant, including one inserted after this statement committed.
//
// The `revoked = false` term is what makes the count mean "rows this call
// transitioned" on all four engines rather than "rows matched". MySQL reports changed
// rows rather than matched rows, and the updated_at assignment would make an
// already-revoked row count as changed, so without the term the same call would
// report differently per engine and the audit event would overstate what it did.
//
// An empty session identifier is rejected rather than treated as a filter. Every
// user_sessions row carries a UUID, so an empty value means a caller bug, and
// matching on it would sweep unrelated codes.
func (d *Database) RevokeCodesBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (int64, error) {

	if sessionIdentifier == "" {
		return 0, errs.New("can't revoke codes with an empty session identifier")
	}

	result, err := d.ExecSQL(ctx, tx, revokeCodesBySessionIdentifier.text(d.Dialect),
		true, time.Now().UTC(), sessionIdentifier, false)
	if err != nil {
		return 0, errs.Wrap(err, "unable to revoke codes by session identifier")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, errs.Wrap(err, "unable to get rows affected when revoking codes by session identifier")
	}

	return rowsAffected, nil
}

// RevokeCodesByClientId marks every not-yet-revoked code of one client revoked, and
// reports how many rows this call transitioned. It is the durable half of flipping a
// client from confidential to public (#245): the code is the grant record, and a
// rotated refresh token inherits its parent's code_id, so marking the code marks every
// descendant of that grant, including one inserted after this statement committed. The
// refresh-token sweep that follows it is cleanup and the audit record, not the boundary.
//
// The `revoked = false` term is what makes the count mean "rows this call
// transitioned" on all four engines rather than "rows matched", exactly as it does in
// RevokeCodesBySessionIdentifier above: MySQL reports changed rows, and the updated_at
// assignment would make an already-revoked row count as changed, so without the term a
// second flip would report the client's whole code history as newly revoked.
//
// A zero client id is rejected rather than used as a filter. codes.client_id is NOT
// NULL and no clients row carries id 0, so a zero can only be a caller bug, and a flip
// must never be able to sweep on one.
func (d *Database) RevokeCodesByClientId(ctx context.Context, tx *sql.Tx, clientId int64) (int64, error) {

	if clientId == 0 {
		return 0, errs.New("can't revoke codes with a client id of 0")
	}

	result, err := d.ExecSQL(ctx, tx, revokeCodesByClientId.text(d.Dialect),
		true, time.Now().UTC(), clientId, false)
	if err != nil {
		return 0, errs.Wrap(err, "unable to revoke codes by client id")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, errs.Wrap(err, "unable to get rows affected when revoking codes by client id")
	}

	return rowsAffected, nil
}

// RevokeUnusedCodesByUserIdAndClientId marks every code one user holds with one client
// that is neither used nor revoked yet revoked, and reports how many rows this call
// transitioned. It is the code half of a consent withdrawal (#622): a code issued
// before the withdrawal can still be redeemed for its 60 seconds, and redemption
// consults no stored consent, so without the mark it would start a grant the
// withdrawal never saw.
//
// Unused codes only, unlike RevokeCodesByClientId. A used code's grant is the refresh
// tokens the withdrawal sweeps, and marking it as well would make the refresh arm's
// revoked-code check answer those tokens with the session-terminated description
// before the sweep's own "This refresh token has been revoked." could.
//
// The `revoked = false` term makes the count mean "rows this call transitioned", for
// the reason RevokeCodesBySessionIdentifier gives. A zero user or client id is rejected
// rather than used as a filter, for the reason RevokeCodesByClientId gives.
func (d *Database) RevokeUnusedCodesByUserIdAndClientId(ctx context.Context, tx *sql.Tx, userId int64, clientId int64) (int64, error) {

	if userId == 0 || clientId == 0 {
		return 0, errs.New("can't revoke codes with a user id or a client id of 0")
	}

	result, err := d.ExecSQL(ctx, tx, revokeUnusedCodesByUserIdAndClientId.text(d.Dialect),
		true, time.Now().UTC(), userId, clientId, false, false)
	if err != nil {
		return 0, errs.Wrap(err, "unable to revoke unused codes by user id and client id")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, errs.Wrap(err, "unable to get rows affected when revoking unused codes by user id and client id")
	}

	return rowsAffected, nil
}

func (d *Database) GetCodeById(ctx context.Context, tx *sql.Tx, codeId int64) (*record.Code, error) {
	return queryOne(ctx, d, tx, selectCodeById.text(d.Dialect), []any{codeId}, scanCode, "code")
}

func (d *Database) CodeLoadClient(ctx context.Context, tx *sql.Tx, code *record.Code) error {

	if code == nil {
		return nil
	}

	client, err := d.GetClientById(ctx, tx, code.ClientId)
	if err != nil {
		return errs.Wrap(err, "unable to load client")
	}

	if client != nil {
		code.Client = *client
	}
	return nil
}

func (d *Database) CodeLoadUser(ctx context.Context, tx *sql.Tx, code *record.Code) error {

	if code == nil {
		return nil
	}

	user, err := d.GetUserById(ctx, tx, code.UserId)
	if err != nil {
		return errs.Wrap(err, "unable to load user")
	}

	if user != nil {
		code.User = *user
	}
	return nil
}

func (d *Database) GetCodeByCodeHash(ctx context.Context, tx *sql.Tx, codeHash string, used bool) (*record.Code, error) {
	return queryOne(ctx, d, tx, selectCodeByCodeHash.text(d.Dialect), []any{codeHash, used}, scanCode, "code")
}

func (d *Database) DeleteCode(ctx context.Context, tx *sql.Tx, codeId int64) error {

	_, err := d.ExecSQL(ctx, tx, deleteCode.text(d.Dialect), codeId)
	if err != nil {
		return errs.Wrap(err, "unable to delete code")
	}

	return nil
}

// DeleteCodesWithoutRefreshTokens reaps every code created before createdBefore that no
// refresh token references. That one rule covers every code that can no longer produce
// anything: one redeemed without a refresh token following, one revoked while still
// unredeemed, which is what ending a session leaves behind (#129), and one never redeemed
// at all, which is every authorization the client abandoned and the row a failed clear at
// /auth/issue orphans (#248, #436). Before #436 the last class was kept forever, with the
// IP address and user agent it records.
//
// The cutoff is required for correctness, not an optimisation. The token endpoint marks a
// code used (handler_token.go, MarkCodeAsUsed) and only afterwards inserts the refresh
// token that references it, so for the duration of token generation a healthy code has no
// descendant yet. Deleting it there makes the insert fail on fk_refresh_tokens_code and the
// client gets a 500 instead of its tokens; observed in CI on postgres. Past the 60 second
// code lifetime (token_grant_authorization_code.go) no code can be redeemed, so none can gain a descendant
// either. Callers pass a cutoff comfortably beyond that 60 seconds.
//
// An unused code needs no term of its own: MarkCodeAsUsed is the gate every redemption
// passes before a refresh token is inserted, and since #129 it refuses a revoked row, so a
// code that is unused or was revoked unused has no descendant and the refresh-token term
// alone decides it.
//
// The term is a correlated NOT EXISTS rather than `id NOT IN (SELECT code_id ...)`. ROPC
// refresh tokens carry code_id = NULL, and `x NOT IN (..., NULL)` is UNKNOWN rather than
// TRUE, so the NOT IN form matched nothing on any deployment that had issued one (#130).
// It is also what keeps this sweep away from a live code, and the stake is higher than
// losing a replay marker: fk_refresh_tokens_code is ON DELETE CASCADE, so reaching a code
// with a refresh token would delete the very descendant the marker exists to reject.
func (d *Database) DeleteCodesWithoutRefreshTokens(ctx context.Context, tx *sql.Tx, createdBefore time.Time) error {
	_, err := d.ExecSQL(ctx, tx, deleteCodesWithoutRefreshTokens.text(d.Dialect), createdBefore)
	if err != nil {
		return errs.Wrap(err, "unable to delete codes without refresh tokens")
	}

	return nil
}
