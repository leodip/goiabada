package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
)

func (d *CommonDatabase) CreateCode(ctx context.Context, tx *sql.Tx, code *models.Code) error {

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

	codeStruct := sqlbuilder.NewStruct(new(models.Code)).
		For(d.Flavor)

	insertBuilder := codeStruct.WithoutTag("pk").InsertInto("codes", code)

	id, err := d.insertReturningId(ctx, tx, insertBuilder, "code")
	if err != nil {
		code.CreatedAt = originalCreatedAt
		code.UpdatedAt = originalUpdatedAt
		return err
	}

	code.Id = id
	return nil
}

func (d *CommonDatabase) UpdateCode(ctx context.Context, tx *sql.Tx, code *models.Code) error {

	if code.Id == 0 {
		return errs.New("can't update code with id 0")
	}

	originalUpdatedAt := code.UpdatedAt
	code.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	codeStruct := sqlbuilder.NewStruct(new(models.Code)).
		For(d.Flavor)

	updateBuilder := codeStruct.WithoutTag("pk").WithoutTag("dont-update").Update("codes", code)
	updateBuilder.Where(updateBuilder.Equal("id", code.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSql(ctx, tx, sql, args...)
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
func (d *CommonDatabase) MarkCodeAsUsed(ctx context.Context, tx *sql.Tx, codeId int64) (bool, error) {

	if codeId == 0 {
		return false, errs.New("can't mark code with id 0 as used")
	}

	ub := sqlbuilder.NewUpdateBuilder()
	ub.Update("codes")
	ub.Set(
		ub.Assign("used", true),
		ub.Assign("updated_at", time.Now().UTC()),
	)
	ub.Where(
		ub.Equal("id", codeId),
		ub.Equal("used", false),
		ub.Equal("revoked", false),
	)

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSql(ctx, tx, query, args...)
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
func (d *CommonDatabase) RevokeCodesBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (int64, error) {

	if sessionIdentifier == "" {
		return 0, errs.New("can't revoke codes with an empty session identifier")
	}

	ub := sqlbuilder.NewUpdateBuilder()
	ub.Update("codes")
	ub.Set(
		ub.Assign("revoked", true),
		ub.Assign("updated_at", time.Now().UTC()),
	)
	ub.Where(
		ub.Equal("session_identifier", sessionIdentifier),
		ub.Equal("revoked", false),
	)

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSql(ctx, tx, query, args...)
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
func (d *CommonDatabase) RevokeCodesByClientId(ctx context.Context, tx *sql.Tx, clientId int64) (int64, error) {

	if clientId == 0 {
		return 0, errs.New("can't revoke codes with a client id of 0")
	}

	ub := sqlbuilder.NewUpdateBuilder()
	ub.Update("codes")
	ub.Set(
		ub.Assign("revoked", true),
		ub.Assign("updated_at", time.Now().UTC()),
	)
	ub.Where(
		ub.Equal("client_id", clientId),
		ub.Equal("revoked", false),
	)

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSql(ctx, tx, query, args...)
	if err != nil {
		return 0, errs.Wrap(err, "unable to revoke codes by client id")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, errs.Wrap(err, "unable to get rows affected when revoking codes by client id")
	}

	return rowsAffected, nil
}

func (d *CommonDatabase) getCodeCommon(ctx context.Context, tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	codeStruct *sqlbuilder.Struct) (*models.Code, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(ctx, tx, sql, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var code models.Code
	if rows.Next() {
		addr := codeStruct.Addr(&code)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errs.Wrap(err, "unable to scan code")
		}
		return &code, nil
	}
	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return nil, nil
}

func (d *CommonDatabase) GetCodeById(ctx context.Context, tx *sql.Tx, codeId int64) (*models.Code, error) {

	codeStruct := sqlbuilder.NewStruct(new(models.Code)).
		For(d.Flavor)

	selectBuilder := codeStruct.SelectFrom("codes")
	selectBuilder.Where(selectBuilder.Equal("id", codeId))

	code, err := d.getCodeCommon(ctx, tx, selectBuilder, codeStruct)
	if err != nil {
		return nil, err
	}

	return code, nil
}

func (d *CommonDatabase) CodeLoadClient(ctx context.Context, tx *sql.Tx, code *models.Code) error {

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

func (d *CommonDatabase) CodeLoadUser(ctx context.Context, tx *sql.Tx, code *models.Code) error {

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

func (d *CommonDatabase) GetCodeByCodeHash(ctx context.Context, tx *sql.Tx, codeHash string, used bool) (*models.Code, error) {
	codeStruct := sqlbuilder.NewStruct(new(models.Code)).
		For(d.Flavor)

	selectBuilder := codeStruct.SelectFrom("codes")
	selectBuilder.Where(selectBuilder.Equal("code_hash", codeHash))
	selectBuilder.Where(selectBuilder.Equal("used", used))

	code, err := d.getCodeCommon(ctx, tx, selectBuilder, codeStruct)
	if err != nil {
		return nil, err
	}

	return code, nil
}

func (d *CommonDatabase) DeleteCode(ctx context.Context, tx *sql.Tx, codeId int64) error {

	clientStruct := sqlbuilder.NewStruct(new(models.Code)).
		For(d.Flavor)

	deleteBuilder := clientStruct.DeleteFrom("codes")
	deleteBuilder.Where(deleteBuilder.Equal("id", codeId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(ctx, tx, sql, args...)
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
func (d *CommonDatabase) DeleteCodesWithoutRefreshTokens(ctx context.Context, tx *sql.Tx, createdBefore time.Time) error {
	descendants := d.Flavor.NewSelectBuilder()
	descendants.Select("1").From("refresh_tokens")
	descendants.Where("refresh_tokens.code_id = codes.id")

	deleteBuilder := d.Flavor.NewDeleteBuilder()
	deleteBuilder.DeleteFrom("codes")
	deleteBuilder.Where(
		deleteBuilder.LessThan("created_at", createdBefore),
		deleteBuilder.NotExists(descendants),
	)

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(ctx, tx, sql, args...)
	if err != nil {
		return errs.Wrap(err, "unable to delete codes without refresh tokens")
	}

	return nil
}
