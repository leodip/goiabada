package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *CommonDatabase) CreateCode(tx *sql.Tx, code *models.Code) error {

	if code.ClientId == 0 {
		return errors.WithStack(errors.New("client id must be greater than 0"))
	}

	if code.UserId == 0 {
		return errors.WithStack(errors.New("user id must be greater than 0"))
	}

	now := time.Now().UTC()

	originalCreatedAt := code.CreatedAt
	originalUpdatedAt := code.UpdatedAt
	code.CreatedAt = sql.NullTime{Time: now, Valid: true}
	code.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	codeStruct := sqlbuilder.NewStruct(new(models.Code)).
		For(d.Flavor)

	insertBuilder := codeStruct.WithoutTag("pk").InsertInto("codes", code)

	sql, args := insertBuilder.Build()
	result, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		code.CreatedAt = originalCreatedAt
		code.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert code")
	}

	id, err := result.LastInsertId()
	if err != nil {
		code.CreatedAt = originalCreatedAt
		code.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	code.Id = id
	return nil
}

func (d *CommonDatabase) UpdateCode(tx *sql.Tx, code *models.Code) error {

	if code.Id == 0 {
		return errors.WithStack(errors.New("can't update code with id 0"))
	}

	originalUpdatedAt := code.UpdatedAt
	code.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	codeStruct := sqlbuilder.NewStruct(new(models.Code)).
		For(d.Flavor)

	updateBuilder := codeStruct.WithoutTag("pk").WithoutTag("dont-update").Update("codes", code)
	updateBuilder.Where(updateBuilder.Equal("id", code.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		code.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update code")
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
func (d *CommonDatabase) MarkCodeAsUsed(tx *sql.Tx, codeId int64) (bool, error) {

	if codeId == 0 {
		return false, errors.WithStack(errors.New("can't mark code with id 0 as used"))
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
	result, err := d.ExecSql(tx, query, args...)
	if err != nil {
		return false, errors.Wrap(err, "unable to mark code as used")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errors.Wrap(err, "unable to get rows affected when marking code as used")
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
func (d *CommonDatabase) RevokeCodesBySessionIdentifier(tx *sql.Tx, sessionIdentifier string) (int64, error) {

	if sessionIdentifier == "" {
		return 0, errors.WithStack(errors.New("can't revoke codes with an empty session identifier"))
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
	result, err := d.ExecSql(tx, query, args...)
	if err != nil {
		return 0, errors.Wrap(err, "unable to revoke codes by session identifier")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "unable to get rows affected when revoking codes by session identifier")
	}

	return rowsAffected, nil
}

// RevokeCodeIfSessionGone marks one code revoked, but only if the session it was issued
// through no longer has a row, and reports whether it made that transition. It is the
// compensating half of ending a session (#129 decision 12), and it exists because the
// liveness read at /auth/issue and the insert that follows it are two statements: the read
// can find the session alive, the termination can commit, and then the insert lands a code
// bound to a session that is already gone and that RevokeCodesBySessionIdentifier could not
// have marked, because the row did not exist when it ran.
//
// The two sweepers cover each other. A code committing before the termination's UPDATE reads
// codes is marked by the termination; a code committing after it is marked here, because by
// then the session is gone. Only a code landing between that UPDATE and its COMMIT escapes
// both, since this statement still sees the session row. That residual is recorded in #129
// and belongs to the same class as #131 and #132.
//
// The `revoked = false` term is what makes the bool mean "this call transitioned it" rather
// than "matched a row". Unlike the count in RevokeCodesBySessionIdentifier, where the
// difference is MySQL specific, here it is measured to matter on all four engines: the
// updated_at assignment changes on every call, so an already-revoked row reports as affected
// everywhere without the term. It is reachable rather than theoretical, since the
// interleaving where the termination marked the code first is exactly the one where both
// sweepers fire.
//
// An empty session identifier is rejected rather than used as a filter, and that guard is
// load bearing: no user_sessions row carries an empty identifier, so NOT EXISTS over one is
// trivially true and the statement would revoke whatever code it was handed.
func (d *CommonDatabase) RevokeCodeIfSessionGone(tx *sql.Tx, codeId int64, sessionIdentifier string) (bool, error) {

	if codeId == 0 {
		return false, errors.WithStack(errors.New("can't revoke code with id 0"))
	}

	if sessionIdentifier == "" {
		return false, errors.WithStack(errors.New("can't revoke a code with an empty session identifier"))
	}

	sessionExists := d.Flavor.NewSelectBuilder()
	sessionExists.Select("1")
	sessionExists.From("user_sessions")
	sessionExists.Where(sessionExists.Equal("session_identifier", sessionIdentifier))

	ub := sqlbuilder.NewUpdateBuilder()
	ub.Update("codes")
	ub.Set(
		ub.Assign("revoked", true),
		ub.Assign("updated_at", time.Now().UTC()),
	)
	ub.Where(
		ub.Equal("id", codeId),
		ub.Equal("revoked", false),
		ub.NotExists(sessionExists),
	)

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSql(tx, query, args...)
	if err != nil {
		return false, errors.Wrap(err, "unable to revoke code whose session is gone")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errors.Wrap(err, "unable to get rows affected when revoking a code whose session is gone")
	}

	return rowsAffected == 1, nil
}

func (d *CommonDatabase) getCodeCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	codeStruct *sqlbuilder.Struct) (*models.Code, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var code models.Code
	if rows.Next() {
		addr := codeStruct.Addr(&code)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan code")
		}
		return &code, nil
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "unable to read query results")
	}

	return nil, nil
}

func (d *CommonDatabase) GetCodeById(tx *sql.Tx, codeId int64) (*models.Code, error) {

	codeStruct := sqlbuilder.NewStruct(new(models.Code)).
		For(d.Flavor)

	selectBuilder := codeStruct.SelectFrom("codes")
	selectBuilder.Where(selectBuilder.Equal("id", codeId))

	code, err := d.getCodeCommon(tx, selectBuilder, codeStruct)
	if err != nil {
		return nil, err
	}

	return code, nil
}

func (d *CommonDatabase) CodeLoadClient(tx *sql.Tx, code *models.Code) error {

	if code == nil {
		return nil
	}

	client, err := d.GetClientById(tx, code.ClientId)
	if err != nil {
		return errors.Wrap(err, "unable to load client")
	}

	if client != nil {
		code.Client = *client
	}
	return nil
}

func (d *CommonDatabase) CodeLoadUser(tx *sql.Tx, code *models.Code) error {

	if code == nil {
		return nil
	}

	user, err := d.GetUserById(tx, code.UserId)
	if err != nil {
		return errors.Wrap(err, "unable to load user")
	}

	if user != nil {
		code.User = *user
	}
	return nil
}

func (d *CommonDatabase) GetCodeByCodeHash(tx *sql.Tx, codeHash string, used bool) (*models.Code, error) {
	codeStruct := sqlbuilder.NewStruct(new(models.Code)).
		For(d.Flavor)

	selectBuilder := codeStruct.SelectFrom("codes")
	selectBuilder.Where(selectBuilder.Equal("code_hash", codeHash))
	selectBuilder.Where(selectBuilder.Equal("used", used))

	code, err := d.getCodeCommon(tx, selectBuilder, codeStruct)
	if err != nil {
		return nil, err
	}

	return code, nil
}

func (d *CommonDatabase) DeleteCode(tx *sql.Tx, codeId int64) error {

	clientStruct := sqlbuilder.NewStruct(new(models.Code)).
		For(d.Flavor)

	deleteBuilder := clientStruct.DeleteFrom("codes")
	deleteBuilder.Where(deleteBuilder.Equal("id", codeId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete code")
	}

	return nil
}

// DeleteUsedCodesWithoutRefreshTokens reaps codes that can no longer produce anything,
// and that are older than createdBefore. Two disjoint classes qualify, and the name is
// kept for the first of them because renaming it would touch the interface, four engine
// wrappers, the generated mocks and the worker for no behavioural gain:
//
//   - codes that were marked used but never produced a refresh token, and
//   - codes revoked while still unredeemed, which is what ending a session leaves behind
//     when the grant it marked had not been exchanged yet (#129 decision 8).
//
// Both share one cutoff, for different reasons. For the used class the age cutoff is not
// an optimisation, it is required for correctness: the token endpoint marks a code used
// (handler_token.go, MarkCodeAsUsed) and only afterwards inserts the refresh token that
// references it, so for the duration of token generation a perfectly healthy code sits in
// exactly the state that branch selects. Deleting it there makes the subsequent insert
// fail on fk_refresh_tokens_code and the client gets a 500 instead of its tokens. Observed
// in CI on postgres. For the revoked class the cutoff is simply the code lifetime: a code
// is unredeemable 60 seconds after issuance (token_validator.go), so past that it can
// never acquire a refresh token legitimately either. Callers should pass a cutoff
// comfortably beyond that 60 seconds, which serves both.
//
// The subquery stays INSIDE the used branch rather than beside the cutoff, and that is
// load bearing rather than formatting. ROPC refresh tokens carry code_id = NULL, and
// `x NOT IN (…, NULL)` is UNKNOWN rather than TRUE, so the used branch already matches
// nothing on any deployment that has issued one (#130 owns that). Since UNKNOWN OR TRUE
// is TRUE, the revoked branch still reaps; hoisting the subquery out would make the whole
// predicate UNKNOWN and this method would silently do nothing at all.
//
// The revoked branch needs no refresh-token term of its own because `used = false` is
// stronger: MarkCodeAsUsed is the gate every redemption passes before a token is inserted,
// and since #129 it refuses a revoked row outright, so an unused code has no descendants.
// That term is also what keeps this sweep away from a live one, and the stake is higher
// than losing a marker: fk_refresh_tokens_code is ON DELETE CASCADE, so reaching a used
// code with a live refresh token would delete the very descendant the marker exists to
// reject.
func (d *CommonDatabase) DeleteUsedCodesWithoutRefreshTokens(tx *sql.Tx, createdBefore time.Time) error {
	deleteBuilder := d.Flavor.NewDeleteBuilder()
	deleteBuilder.DeleteFrom("codes")
	deleteBuilder.Where(
		deleteBuilder.LessThan("created_at", createdBefore),
		deleteBuilder.Or(
			deleteBuilder.And(
				deleteBuilder.Equal("used", true),
				deleteBuilder.NotIn("id",
					d.Flavor.NewSelectBuilder().Select("code_id").From("refresh_tokens"),
				),
			),
			deleteBuilder.And(
				deleteBuilder.Equal("revoked", true),
				deleteBuilder.Equal("used", false),
			),
		),
	)

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete used codes without refresh tokens")
	}

	return nil
}
