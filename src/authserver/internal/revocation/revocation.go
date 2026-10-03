package revocation

import (
	"context"
	"database/sql"
	"log/slog"
	"sort"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// Database is what the revocation service needs: the generation counters it advances,
// and the sessions, codes and refresh tokens the advance invalidates, and the session row the
// reuse response takes first (#139).
//
// Exported, unlike the per-file ports #386 left in the handler packages, because it is this
// package's own port and eight consumer ports across handlers and apihandlers embed it to hand
// the capability on (#387).
type Database interface {
	AcquireUserSessionRow(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (bool, error)
	DeleteUserSession(ctx context.Context, tx *sql.Tx, userSessionId int64) error
	GetRefreshTokensByClientId(ctx context.Context, tx *sql.Tx, clientId int64) ([]*record.RefreshToken, error)
	GetRefreshTokensByCodeId(ctx context.Context, tx *sql.Tx, codeId int64) ([]*record.RefreshToken, error)
	GetRefreshTokensBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) ([]*record.RefreshToken, error)
	GetRefreshTokensByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]*record.RefreshToken, error)
	GetUserSessionBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (*record.UserSession, error)
	GetUserSessionsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]record.UserSession, error)
	IncrementUserAuthStateGeneration(ctx context.Context, tx *sql.Tx, userId int64) (int64, error)
	PromoteRefreshTokenGenerations(ctx context.Context, tx *sql.Tx, refreshTokenIds []int64, generation int64) error
	PromoteUserSessionGeneration(ctx context.Context, tx *sql.Tx, userSessionId int64, generation int64) error
	RecordRefreshTokenFamilyRevoked(ctx context.Context, tx *sql.Tx, firstRefreshTokenJti string, reason string) (bool, error)
	RevokeCodesByClientId(ctx context.Context, tx *sql.Tx, clientId int64) (int64, error)
	RevokeCodesBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (int64, error)
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
	UpdateRefreshToken(ctx context.Context, tx *sql.Tx, refreshToken *record.RefreshToken) error
}

// RevokeRefreshTokens marks the given refresh tokens revoked and returns the JTIs this call
// transitioned from live to revoked. Already-revoked tokens are skipped and NOT reported:
// callers rely on "we actually revoked something" to distinguish a real revocation from a
// no-op, which is what makes concurrent auth-code redemption safe (#77, see
// RevokeOnAuthCodeReuse). That invariant used to exist only as an unremarked `continue`
// inside a loop; extracting it is how it gets a name (#106 decision 8).
//
// Exported, where it was package-private inside handlers, because the token endpoint's reuse arm
// calls it directly and now sits one package away (#387).
//
// The caller owns the transaction. Passing a nil tx is permitted and means no transaction,
// following the data layer's convention, but every caller here supplies one.
func RevokeRefreshTokens(ctx context.Context, db Database, tx *sql.Tx, tokens []*record.RefreshToken) ([]string, error) {
	revokedJtis := make([]string, 0, len(tokens))
	for _, rt := range tokens {
		if rt.Revoked {
			continue
		}
		rt.Revoked = true
		if err := db.UpdateRefreshToken(ctx, tx, rt); err != nil {
			return nil, err
		}
		revokedJtis = append(revokedJtis, rt.RefreshTokenJti)
	}
	return revokedJtis, nil
}

// UserAuthStateResult reports what revoking a user's authentication state actually did. Its
// fields map one-to-one onto the audit payload of #106 decision 7, so a caller spreads the result
// rather than threading values separately, and a later field does not change every signature.
//
// The two slices are always non-nil, so a JSON audit payload carries [] rather than null.
type UserAuthStateResult struct {
	// TerminatedSessionIdentifiers lists the sessions deleted, excluding any preserved one.
	TerminatedSessionIdentifiers []string
	// RevokedRefreshTokenJtis lists only the tokens this call transitioned, per
	// RevokeRefreshTokens. A token already revoked before the call is absent.
	RevokedRefreshTokenJtis []string
	// PreservedSessionIdentifier is the session identifier the preservation exception was
	// applied to, or "" when the sweep was unconditional. It identifies the GRANT ORIGIN that
	// was exempted, and does not assert that a session row still existed: the background
	// worker reaps idle sessions while offline refresh tokens outlive them, so tokens can be
	// exempted with no session left to promote. Reading it as "a session survived" is wrong;
	// what it means is "these are the tokens the audit event does not list as revoked".
	// Never null.
	PreservedSessionIdentifier string
	// OldGeneration and NewGeneration bracket the increment. Both are reported because an
	// audit reader needs to know which generation was invalidated, not only the new one.
	OldGeneration int64
	NewGeneration int64
}

// RevokeUserAuthState invalidates every credential a user authenticated under before this
// call, by advancing their authentication generation and then sweeping the state that
// generation authorized (#106).
//
// The generation increment is the durable part and the sweep is the cleanup. A transaction
// around the sweep alone would not be a boundary: a refresh that validated before the sweep
// began inserts its replacement outside any transaction and would survive it. Advancing the
// generation is what invalidates that replacement too, because it inherits its parent's
// generation rather than the user's current one.
//
// exceptSid preserves one session and its refresh tokens, promoting them to the new
// generation so the caller's own session keeps working; empty revokes everything
// (decision 4). The caller owns the transaction, which is REQUIRED here rather than
// optional, because IncrementUserAuthStateGeneration cannot read back its own increment
// safely without one.
func RevokeUserAuthState(ctx context.Context, db Database, tx *sql.Tx, userId int64, exceptSid string) (UserAuthStateResult, error) {
	result := UserAuthStateResult{
		TerminatedSessionIdentifiers: []string{},
		RevokedRefreshTokenJtis:      []string{},
	}

	// A nil tx is rejected HERE rather than being left to the first data method that happens
	// to check. This function's contract is atomicity across an increment and a multi-table
	// sweep, so the transaction is a precondition of the whole operation, not an argument that
	// one nested call cares about. Checking at entry also keeps the unit tests honest: without
	// it they would pass nil and exercise a shape production never runs.
	if tx == nil {
		return result, errs.New("revoking a user's auth state requires a transaction: the increment and the sweep must not be separable")
	}

	// Increment first, then derive the old generation as new-1. Reading the stored value
	// beforehand looks more honest and is in fact racier: an ordinary SELECT is not a locking
	// read, so a concurrent revocation can commit between the read and the increment, and this
	// call would then report an old generation it did not actually move away from. Deriving it
	// is exact because the operation is defined as exactly +1, and new-1 is by construction
	// the generation THIS increment invalidated.
	//
	// An unknown user needs no separate lookup either: IncrementUserAuthStateGeneration
	// requires exactly one affected row and errors otherwise.
	newGeneration, err := db.IncrementUserAuthStateGeneration(ctx, tx, userId)
	if err != nil {
		return result, err
	}
	result.NewGeneration = newGeneration
	result.OldGeneration = newGeneration - 1

	// THE SESSION ROWS BEFORE THE TOKEN SWEEP, so that this transaction and a termination of
	// one of these sessions, which deletes the session row as its first statement, serialize
	// on that row rather than each holding half of what the other wants and reaching the retry
	// (#139). The same holds against the replay response and against an authorization ceremony,
	// which both take the session row before any grant.
	//
	// The two refresh-token reads below are unaffected by running after these deletes.
	// GetRefreshTokensByUserId unions a codes join with refresh_tokens.user_id and
	// GetRefreshTokensBySessionIdentifier joins refresh_tokens to codes; neither reads
	// user_sessions, and codes carries no foreign key to it.
	//
	// IncrementUserAuthStateGeneration stays above this because it is the durable half of the
	// operation: the codes carry auth_state_generation, so advancing it is what invalidates
	// them, and a sweep that ran first would leave a gap in which a code issued under the old
	// generation is still valid.
	sessions, err := db.GetUserSessionsByUserId(ctx, tx, userId)
	if err != nil {
		return result, err
	}

	// Ordered by id so several sessions are always taken in the same sequence. The query
	// carries no ORDER BY of its own, so two transactions of this shape could otherwise take
	// the same two rows in opposite orders and deadlock on nothing but the order the engine
	// returned them in (#139).
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].Id < sessions[j].Id })

	preservedSessionFound := false
	for i := range sessions {
		session := sessions[i]
		if exceptSid != "" && session.SessionIdentifier == exceptSid {
			if promoteErr := db.PromoteUserSessionGeneration(ctx, tx, session.Id, newGeneration); promoteErr != nil {
				return result, promoteErr
			}
			preservedSessionFound = true
			continue
		}
		if deleteUserSessionErr := db.DeleteUserSession(ctx, tx, session.Id); deleteUserSessionErr != nil {
			return result, deleteUserSessionErr
		}
		result.TerminatedSessionIdentifiers = append(result.TerminatedSessionIdentifiers,
			session.SessionIdentifier)
	}

	// User-scoped, so it covers both linkage shapes: auth-code tokens through codes.user_id
	// and ROPC tokens through refresh_tokens.user_id.
	//
	// The session block sits above BOTH refresh-token reads, and the two reads sit together, so
	// the reasoning that follows about their relative order is untouched by it (#139).
	//
	// Deliberately queried BEFORE the preserved set below, though the benefit is
	// engine-dependent. Where each statement takes a fresh read view (PostgreSQL and SQL
	// Server default to READ COMMITTED), a child token committed by a refresh racing this
	// sweep is absent here so it is never swept, and present in the sid-scoped query below so
	// it gets promoted; the reverse order revokes the user's own newly issued token. Under
	// MySQL/InnoDB's default REPEATABLE READ both reads can share one snapshot, so such a
	// child is invisible to both queries and the order changes nothing. So this order is
	// never worse, and on some engines better, but it does NOT close the race: a child
	// committed outside this transaction's view keeps the old generation and is rejected on
	// next use. Fail-closed, accepted as a residual in decision 16, tracked in #131.
	tokens, err := db.GetRefreshTokensByUserId(ctx, tx, userId)
	if err != nil {
		return result, err
	}

	// The preserved set must come from a SEPARATE, sid-scoped query and cannot be derived
	// from the user-scoped rows above. An offline refresh token's own session_identifier is
	// empty, and the sid its grant came from lives only on the joined codes row, which the
	// model does not expose. GetRefreshTokensBySessionIdentifier matches
	// codes.session_identifier, so it does return the preserved session's offline tokens.
	// Deriving the set from the user-scoped rows instead revokes exactly those, which is the
	// bug decision 4 exists to prevent.
	preservedIds := make(map[int64]bool)
	promoteIds := []int64{}
	if exceptSid != "" {
		result.PreservedSessionIdentifier = exceptSid
		preservedTokens, getRefreshTokensErr := db.GetRefreshTokensBySessionIdentifier(ctx, tx, exceptSid)
		if getRefreshTokensErr != nil {
			return result, getRefreshTokensErr
		}
		for _, rt := range preservedTokens {
			preservedIds[rt.Id] = true
			// Promote from THIS query's rows, not from the intersection with the
			// user-scoped ones. A child committed between the two queries appears only
			// here, and promoting it is the whole point of querying in this order.
			promoteIds = append(promoteIds, rt.Id)
		}
	}

	toRevoke := make([]*record.RefreshToken, 0, len(tokens))
	for _, rt := range tokens {
		if preservedIds[rt.Id] {
			continue
		}
		toRevoke = append(toRevoke, rt)
	}

	revokedJtis, err := RevokeRefreshTokens(ctx, db, tx, toRevoke)
	if err != nil {
		return result, err
	}
	result.RevokedRefreshTokenJtis = revokedJtis

	// Promotion is what keeps the preserved session usable: its tokens carry the old
	// generation, which the validator now rejects. An already-revoked token in this set stays
	// revoked, because PromoteRefreshTokenGenerations only touches unrevoked rows.
	if err := db.PromoteRefreshTokenGenerations(ctx, tx, promoteIds, newGeneration); err != nil {
		return result, err
	}

	// exceptSid was asked for but no session row matched. Legitimate rather than an error: the
	// background worker reaps idle sessions while offline refresh tokens outlive them, so the
	// caller's tokens are still exempted above with no session left to promote.
	//
	// PreservedSessionIdentifier still reports exceptSid in that case, because the exemption
	// WAS applied: tokens were withheld from the sweep, and a result claiming otherwise would
	// leave the audit record unable to explain why those JTIs are missing from the revoked
	// list. The field names the exempted grant origin, not a surviving session row.
	if exceptSid != "" && !preservedSessionFound {
		slog.WarnContext(ctx, "revocation exempted a grant origin whose session row no longer exists",
			"user_id", userId, "except_session_identifier", exceptSid)
	}

	return result, nil
}

// Reasons a revocation records. The first four are recorded on EventRevokedUserAuthState, one
// per credential site (#106 decision 7). ReasonClientBecamePublic is recorded on
// EventRevokedClientGrants, and is also the reason a family's revocation record carries when
// RevokeClientGrants wrote it (#245, #259). Constants rather than inline strings so the sites
// cannot drift and a log consumer has something to match against, and one block so the next
// site's reason has one place to go. Every value is stored data: renaming a constant is free,
// changing its string is not.
//
// This is the list's only home. Another, constants.RevocationReasonEmailCollisionBackfill, was
// declared in core because the site emitting it was the startup pass that disabled the losers of
// an email case collision (#283), and core cannot import this package. #351 replaced that pass
// with migration 000047 and a pre-flight that refuses to migrate a colliding database instead of
// disabling an account, so nothing in core revokes anything any more.
const (
	ReasonPasswordReset      = "password_reset"
	ReasonPasswordChange     = "password_change"
	ReasonAdminPasswordSet   = "admin_password_set"
	ReasonAccountDisabled    = "account_disabled"
	ReasonClientBecamePublic = "client_became_public"
)

// RevokeUserAuthStateTx runs a narrow credential write and the revocation sweep inside ONE
// transaction and commits it, returning the result for the caller to audit AFTER the commit.
//
// It exists so the four credential sites cannot each get the transaction discipline subtly
// wrong. Three properties are easy to lose when this is open-coded four times, and all three
// are what the tests assert:
//
//   - the credential write and the sweep are in the same transaction, so a user can never end
//     up with a new password while their old sessions survive, nor a bumped generation with an
//     unchanged password;
//   - any failure BEFORE the commit is rolled back atomically, via the helper's rollback;
//   - the audit event is the CALLER's job and happens after this returns successfully, because
//     AuditLogger.Log takes no transaction and a logged revocation that then rolled back would
//     be a false record (decision 5).
//
// On any error the returned result is the zero value rather than a partially populated one, so
// a caller that mistakenly audits on the error path cannot emit half-truthful lists.
//
// WHAT A COMMIT FAILURE DOES AND DOES NOT GUARANTEE. The helper's rollback covers failures
// before the commit only. `database/sql` gives no guarantee about a Commit that returns an
// error: the transaction is finished either way, and the error can mean the server committed
// and the client never learned of it, for instance a connection lost after the server's commit
// succeeded. A rollback afterwards cannot undo that. So the honest contract is:
//
//   - a reported commit failure returns 500 to the caller and emits NO success audit event;
//   - the durable outcome of that commit is INDETERMINATE, and may in fact have applied.
//
// A caller must therefore not read "500" as "nothing happened". The consequence is bounded: the
// user may be left revoked without an audit record of it, which is fail-closed on the security
// side and a gap on the forensic side. Closing that gap needs a transactional outbox or a
// distinct "commit outcome unknown" event, not a rollback, and neither is in scope for #106
// (decision 5, finding 36).
func RevokeUserAuthStateTx(ctx context.Context, db Database, userId int64, exceptSid string,
	write func(tx *sql.Tx) error) (UserAuthStateResult, error) {

	// The write and the sweep in one transaction opened through RunInTransaction, so a deadlock
	// reruns both together (#301). The body is safe to rerun: every write callback is a
	// compare-and-set or an idempotent column write, the sweep reads the sessions and tokens
	// afresh on each attempt, and result is whatever the attempt that committed produced.
	var result UserAuthStateResult
	err := db.RunInTransaction(ctx, func(tx *sql.Tx) error {
		if err := write(tx); err != nil {
			return err
		}

		var err error
		result, err = RevokeUserAuthState(ctx, db, tx, userId, exceptSid)
		return err
	})
	if err != nil {
		return UserAuthStateResult{}, err
	}
	return result, nil
}

// TerminationResult reports what terminating one session actually did. It carries exactly what
// the terminated_user_session audit payload needs beyond the caller's own inputs (#129
// decision 9); the user id, the session id and the session identifier stay out because the
// caller already holds the session row, and restating them here would let a result and its
// payload disagree.
type TerminationResult struct {
	// RevokedCodeCount is how many codes this call TRANSITIONED from live to revoked, not how
	// many the session has. A second termination of the same session reports 0, which is what
	// makes the audit event answer the only question an auditor asks of it, whether this action
	// revoked anything.
	RevokedCodeCount int64
	// RevokedRefreshTokenJtis lists only the tokens this call transitioned, per
	// RevokeRefreshTokens. A token already revoked before the call is absent. Non-nil on the
	// success path, so a JSON audit payload carries [] rather than null.
	RevokedRefreshTokenJtis []string
}

// TerminateUserSessionTx ends one session as a security action: it writes the durable fact that
// the grants of that session are revoked, sweeps the tokens those grants issued, and deletes the
// session row, in ONE transaction it owns and commits (#129 decision 5).
//
// The three writes, in the order this transaction issues them. #129 decision 5 put the code sweep
// first; #139 moved the deletion ahead of it, and the reason is the whole of write 1 below.
//
//  1. DeleteUserSession, FIRST because it is the statement that TAKES THE SESSION ROW. An
//     authorization ceremony about to mint a code writes that same row before it inserts, so one
//     of the two transactions waits for the other: either this one waits and the code sweep below
//     then runs after the insert committed, so the new code is marked, or the ceremony waits and
//     its acquisition matches no rows, so it refuses and no code is written at all. Without this
//     statement leading, the two transactions touch no common row and nothing makes either wait,
//     and a code inserted after the sweep below and before this commit escapes both that sweep
//     and any compensating read, because such a read still sees the uncommitted-deleted session
//     (#139). The deletion is also what makes the effect immediate for session-bound tokens: they
//     stop validating once the row is gone.
//  2. RevokeCodesBySessionIdentifier marks every code issued through this session revoked. This
//     is the write that SURVIVES, and the only one that is a boundary. A refresh token can only
//     descend from a code and a rotated child inherits its parent's code_id, so marking the code
//     rejects every present and future descendant of the grant: a child inserted after this
//     commit is born already rejected, because the fact predates its existence.
//  3. The sid-scoped refresh-token sweep. GetRefreshTokensBySessionIdentifier matches
//     codes.session_identifier through a join, and that join is the ONLY thing that reaches an
//     offline grant's tokens, because an offline refresh token's own session_identifier is empty
//     and the sid its grant came from lives on the codes row. Filtering these rows by
//     rt.SessionIdentifier would therefore drop exactly the offline tokens decision 2 exists to
//     revoke.
//
// Neither sweep is affected by running after the deletion: RevokeCodesBySessionIdentifier keys on
// codes.session_identifier and the refresh sweep joins refresh_tokens to codes, so neither reads
// user_sessions, and codes carries no foreign key to it.
//
// Writes 1 and 3 are cleanup. Absence of a session row is never read as termination anywhere,
// because the background worker reaps idle and expired sessions routinely while an offline grant
// is designed to outlive that, which is why the durable fact has to be written down positively
// (decision 4).
//
// It deliberately does NOT advance the user's authentication generation, and must not: that would
// invalidate every other device the user has, which is the opposite of what ending one session
// means and the whole reason #129 exists separately from #106.
//
// The three writes share one transaction so the durable fact and the deletion cannot land
// separately. On any error the returned result is the zero value rather than a partially
// populated one: the code sweep can succeed and the transaction still roll back, and a caller
// auditing that count would record a revocation that never happened.
//
// The audit events are the CALLER's job, after this returns successfully, because AuditLogger.Log
// takes no transaction and a logged termination that then rolled back would be a false record
// (decision 9, following RevokeUserAuthStateTx).
//
// WHAT A COMMIT FAILURE DOES AND DOES NOT GUARANTEE is the contract RevokeUserAuthStateTx
// documents at length and this shares: the helper's rollback covers failures before the commit
// only, and `database/sql` promises nothing about a Commit that returns an error. So a 500 from a
// caller here must not be read as "nothing happened"; the durable outcome of a reported commit
// failure is indeterminate, and the bounded consequence is a termination with no audit record of
// it, which is fail-closed on the security side and a gap on the forensic side.
func TerminateUserSessionTx(ctx context.Context, db Database, userSession *record.UserSession) (TerminationResult, error) {
	// Both sweeps key on the session identifier and the delete keys on the id, so this takes the
	// loaded row rather than two loose values: from one row they cannot describe two different
	// sessions, and both call sites already load it for their own not-found and ownership checks.
	if userSession == nil {
		return TerminationResult{}, errs.New("terminating a user session requires the session to terminate")
	}

	// Refused at entry rather than three statements later. RevokeCodesBySessionIdentifier rejects
	// an empty identifier itself, so the outcome is the same either way, but reaching it means
	// opening a transaction first and surfacing a bad argument as a database failure.
	if userSession.SessionIdentifier == "" {
		return TerminationResult{}, errs.New("terminating a user session requires a session identifier")
	}

	// Opened through RunInTransaction, so a deadlock reruns the three writes together (#301).
	// The body is safe to rerun: it reads nothing from outside the closure but the session it
	// was handed, and the counts it reports are the committing attempt's.
	var result TerminationResult
	err := db.RunInTransaction(ctx, func(tx *sql.Tx) error {
		// First, and write 1 of the doc comment above is why: it is the statement that takes the
		// session row, which is what orders this transaction against a ceremony minting a code
		// for the session it is ending (#139).
		if err := db.DeleteUserSession(ctx, tx, userSession.Id); err != nil {
			return err
		}

		revokedCodeCount, err := db.RevokeCodesBySessionIdentifier(ctx, tx, userSession.SessionIdentifier)
		if err != nil {
			return err
		}

		tokens, err := db.GetRefreshTokensBySessionIdentifier(ctx, tx, userSession.SessionIdentifier)
		if err != nil {
			return err
		}

		revokedJtis, err := RevokeRefreshTokens(ctx, db, tx, tokens)
		if err != nil {
			return err
		}

		result = TerminationResult{
			RevokedCodeCount:        revokedCodeCount,
			RevokedRefreshTokenJtis: revokedJtis,
		}
		return nil
	})
	if err != nil {
		return TerminationResult{}, err
	}
	return result, nil
}

// AuthCodeReuseResult reports what the response to a reused authorization code actually did. It
// carries what the auth_code_reuse_detected payload needs beyond the code the caller already holds.
type AuthCodeReuseResult struct {
	// RevokedRefreshTokenJtis lists only the tokens this call transitioned, per
	// RevokeRefreshTokens. A token already revoked before the call is absent, which is what tells a
	// losing racer of a concurrent redemption apart from a real replay (#77). Non-nil on the
	// success path, so a JSON audit payload carries [] rather than null.
	RevokedRefreshTokenJtis []string
}

// RevokeOnAuthCodeReuse is the RFC 6749 section 10.5 response to a reused authorization code, on
// the caller's transaction: it revokes the refresh tokens issued through the replayed code's session
// and deletes that session when it revoked something.
//
// Its first statement takes the session row, ahead of every grant that hangs off it, so that this
// response and a termination of the same session serialize on that row (#139). See the comment on
// that statement for what it prevents.
//
// The caller owns the transaction, which is REQUIRED, as it is for RevokeUserAuthState: the
// acquisition is worth nothing on an autocommitted statement, which releases the row before the
// sweep runs. RevokeOnAuthCodeReuseTx is the caller that opens one; this form exists so the data
// tier's ordering test can hold the transaction open across a termination's arrival and still run
// the statements that ship.
func RevokeOnAuthCodeReuse(ctx context.Context, db Database, tx *sql.Tx, code *record.Code) (AuthCodeReuseResult, error) {
	if tx == nil {
		return AuthCodeReuseResult{}, errs.New("the response to a reused authorization code requires a transaction: the session row it takes first is released by an autocommitted statement")
	}
	if code == nil {
		return AuthCodeReuseResult{}, errs.New("the response to a reused authorization code requires the reused code")
	}

	// THE SESSION ROW FIRST, before any grant that hangs off it (#139). A termination of this
	// session deletes that row as its first statement, so with this leading the two transactions
	// serialize on the row and one simply waits. Without it this one takes refresh_tokens and then
	// user_sessions while the termination takes user_sessions and then refresh_tokens, and the two
	// deadlock on MySQL and SQL Server with this one the victim, which the retry would answer by
	// rerunning it, at the cost of a rerun on every such race. The same statement also orders this
	// response against an authorization ceremony for the same session, which takes the row before
	// it inserts. This is a local reason for this transaction's first statement and obliges no
	// other site (#301).
	//
	// The result is deliberately NOT a branch. This response revokes whatever tokens it finds
	// whether or not the session row is still there, because an offline grant's tokens outlive
	// their session by design; the acquisition is here for the order it imposes, not for the answer
	// it returns. A code with no session identifier acquires nothing: no row carries an empty
	// identifier, and the code-id-scoped fallback below touches no session row either.
	if code.SessionIdentifier != "" {
		if _, err := db.AcquireUserSessionRow(ctx, tx, code.SessionIdentifier); err != nil {
			return AuthCodeReuseResult{}, err
		}
	}

	var refreshTokens []*record.RefreshToken
	var err error
	if code.SessionIdentifier != "" {
		refreshTokens, err = db.GetRefreshTokensBySessionIdentifier(ctx, tx, code.SessionIdentifier)
	} else {
		// Defensive fallback: auth-code-flow codes always carry a session identifier today, but if
		// a future change ever produces a session-less auth code, fall back to revoking only the
		// refresh tokens directly linked to this code so reuse still has teeth.
		slog.WarnContext(ctx, "auth code reuse on a code without a session identifier, falling back to code-id-scoped revocation",
			"code_id", code.Id)
		refreshTokens, err = db.GetRefreshTokensByCodeId(ctx, tx, code.Id)
	}
	if err != nil {
		return AuthCodeReuseResult{}, err
	}

	revokedJtis, err := RevokeRefreshTokens(ctx, db, tx, refreshTokens)
	if err != nil {
		return AuthCodeReuseResult{}, err
	}

	// Tear down the session only when we actually revoked tokens issued from the replayed code.
	// If there were none to revoke, there is nothing to contain, and deleting the session would
	// disrupt an unrelated/in-flight session. That is what makes concurrent redemption safe: a
	// losing racer finds no committed tokens yet (revokedJtis is empty), so it leaves the winner's
	// live session row in place instead of tearing it down out from under the winner's in-progress
	// mint, which read that session for its refresh-token lifetime. (#77)
	//
	// The guard's OUTCOME is what #77 needs and it is unchanged. What changed is the argument for
	// it: since the acquisition above is unconditional, a losing racer now HOLDS the session row for
	// the rest of this transaction even in the case where it goes on to write nothing, so the
	// winner's own session read can be made to wait where it previously never did. Measured on all
	// four engines: on SQLite, PostgreSQL and MySQL the winner's read is unaffected, because MVCC
	// readers do not block and SQLite serializes the two transactions anyway. On SQL Server, whose
	// READ COMMITTED takes shared locks, that read waits for this whole transaction. A bounded wait
	// on a handful of statements, and not a deadlock: this transaction takes no lock any mint
	// holds. Paying it is what buys the absence of the deadlock the acquisition's own comment
	// describes. (#139)
	if code.SessionIdentifier != "" && len(revokedJtis) > 0 {
		session, err := db.GetUserSessionBySessionIdentifier(ctx, tx, code.SessionIdentifier)
		if err != nil {
			return AuthCodeReuseResult{}, err
		}
		if session != nil {
			if err := db.DeleteUserSession(ctx, tx, session.Id); err != nil {
				return AuthCodeReuseResult{}, err
			}
		}
	}

	return AuthCodeReuseResult{RevokedRefreshTokenJtis: revokedJtis}, nil
}

// RevokeOnAuthCodeReuseTx runs RevokeOnAuthCodeReuse in one transaction it opens and commits, so
// any failure rolls the whole response back rather than leaving partial state. The response to a
// replay must NOT look successful when revocation fails, so a caller answers an error with a 500.
//
// On any error the returned result is the zero value, for the reason TerminateUserSessionTx
// gives. The audit event is the CALLER's, through LogAuthCodeReuse after this returns, and that
// order is not optional: AuditLogger.Log writes on a nil transaction, and on SQLite the whole
// process shares the one connection this transaction holds, so an audit written inside it would
// wait on itself. A logged response that then rolled back would also be a false record.
func RevokeOnAuthCodeReuseTx(ctx context.Context, db Database, code *record.Code) (AuthCodeReuseResult, error) {
	// Refused before a transaction is opened, so a bad argument is not reported as a database
	// failure after a round trip.
	if code == nil {
		return AuthCodeReuseResult{}, errs.New("the response to a reused authorization code requires the reused code")
	}

	// Opened through RunInTransaction, so a deadlock reruns the body (#301). It is safe to rerun:
	// every read is inside the closure, and result is whatever the attempt that committed revoked.
	var result AuthCodeReuseResult
	err := db.RunInTransaction(ctx, func(tx *sql.Tx) error {
		var err error
		result, err = RevokeOnAuthCodeReuse(ctx, db, tx, code)
		return err
	})
	if err != nil {
		return AuthCodeReuseResult{}, err
	}
	return result, nil
}

// ClientGrantResult reports what revoking one client's grants actually did. It is
// TerminationResult's two fields under a name that does not assert a session ended, and that
// distinction is the whole reason it is a separate type (#245 decision 16): flipping a client to
// public revokes the client's grants and deliberately leaves every session alone, so a result
// carrying UserAuthStateResult's terminated-sessions, preserved-session and generation fields would
// have three fields that can never fill, and an audit payload built from it would imply an action
// this one does not take.
type ClientGrantResult struct {
	// RevokedCodeCount is how many codes this call TRANSITIONED from live to revoked, not how
	// many the client has. A second flip of the same client reports 0, which is what makes the
	// audit event answer the only question an auditor asks of it, whether this action revoked
	// anything.
	RevokedCodeCount int64
	// RevokedRefreshTokenJtis lists only the tokens this call transitioned, per
	// RevokeRefreshTokens. A token already revoked before the call is absent. Non-nil on the
	// success path, so a JSON audit payload carries [] rather than null.
	RevokedRefreshTokenJtis []string
}

// RevokeClientGrants cuts off every grant one client holds: it writes the durable fact that the
// client's authorization codes are revoked, then sweeps the refresh tokens those codes and the
// client's ROPC grants issued (#245 decision 16).
//
// It exists for one caller, the confidential-to-public flip, and the rule that caller's comment
// carries is the rule for any future one: revoke when the change REMOVES the requirement for the
// client to authenticate, not when it adds or replaces one. Public to confidential closes a window
// rather than opening one, and rotating a confidential client's secret leaves the requirement in
// place; either would sign real users out to protect against nothing.
//
// The two writes, in this order:
//
//  1. RevokeCodesByClientId marks every not-yet-revoked code of the client revoked. This is the
//     write that SURVIVES, and the only one that is a boundary. A sweep on its own is
//     point-in-time: rotation claims the presented token and inserts its replacement in two
//     separate autocommit operations, so a refresh that validated before this transaction began
//     can insert a live child AFTER it commits. A rotated child inherits its parent's code_id, so
//     marking the code rejects every present and future descendant at the refresh arm's
//     revoked-code check, and that child is born already rejected because the fact predates its
//     existence.
//  2. The client-scoped refresh-token sweep. Still owed rather than redundant, for two reasons:
//     GetRefreshTokensByClientId reaches the ROPC linkage shape, which has no code for step 1 to
//     mark, and it is what gives the audit event actual JTIs rather than a count.
//
// It deliberately does NOT advance any user's authentication generation and does NOT delete any
// session. Both are user-scoped: deleting the sessions of everyone who ever used this client would
// sign each of them out of every OTHER client they hold, which is the collateral damage a
// client-scoped action exists to avoid. Access tokens already issued keep working until they
// expire, because nothing in session validation consults a code or a refresh token.
//
// No compensating "revoke a code that landed after the sweep" pass exists or is owed, and that is
// deliberate rather than an omission. A code inserted after this commits belongs to a client that
// is public NOW, so either it carries no challenge and the redemption rule refuses it, or it
// carries one and is a legitimate new grant under the new rules. Fail-closed either way.
//
// The caller owns the transaction, which is REQUIRED here rather than optional, for the reason
// RevokeUserAuthState states about its own: the contract is atomicity across a marker and a
// multi-row sweep, so the transaction is a precondition of the whole operation rather than an
// argument one nested call happens to care about.
func RevokeClientGrants(ctx context.Context, db Database, tx *sql.Tx, clientId int64) (ClientGrantResult, error) {
	result := ClientGrantResult{RevokedRefreshTokenJtis: []string{}}

	if tx == nil {
		return result, errs.New("revoking a client's grants requires a transaction: the code marker and the sweep must not be separable")
	}

	revokedCodeCount, err := db.RevokeCodesByClientId(ctx, tx, clientId)
	if err != nil {
		return ClientGrantResult{}, err
	}

	tokens, err := db.GetRefreshTokensByClientId(ctx, tx, clientId)
	if err != nil {
		return ClientGrantResult{}, err
	}

	// A record for every family the client holds a token of, live or not, written before the
	// sweep and in the same transaction. The sweep below reaches only the rows that exist now, and
	// a rotation that claimed its parent and has not inserted its child has no live row to reach:
	// that child then commits live into a family the operator believes is revoked (#259). The record
	// outlives the sweep, the validator refuses a token whose family has one, and the rotation checks
	// it again inside its own transaction, so the child is refused at the next refresh or never
	// inserted. A revoked member counts too: its sibling may be the one mid-rotation.
	err = recordClientFamilies(ctx, db, tx, tokens)
	if err != nil {
		return ClientGrantResult{}, err
	}

	revokedJtis, err := RevokeRefreshTokens(ctx, db, tx, tokens)
	if err != nil {
		return ClientGrantResult{}, err
	}

	return ClientGrantResult{
		RevokedCodeCount:        revokedCodeCount,
		RevokedRefreshTokenJtis: revokedJtis,
	}, nil
}

// recordClientFamilies writes the revocation record of every distinct rotation family among the
// given refresh tokens, each once. A token with no family identifier carries no family to record:
// no issuer writes one, and RecordRefreshTokenFamilyRevoked refuses an empty jti as a caller bug.
func recordClientFamilies(ctx context.Context, db Database, tx *sql.Tx, tokens []*record.RefreshToken) error {
	seen := make(map[string]struct{}, len(tokens))
	for _, rt := range tokens {
		jti := rt.FirstRefreshTokenJti
		if jti == "" {
			continue
		}
		if _, done := seen[jti]; done {
			continue
		}
		seen[jti] = struct{}{}
		if _, err := db.RecordRefreshTokenFamilyRevoked(ctx, tx, jti, ReasonClientBecamePublic); err != nil {
			return err
		}
	}
	return nil
}

// RevokeClientGrantsTx runs a narrow client write and RevokeClientGrants inside ONE transaction
// and commits it, returning the result for the caller to audit AFTER the commit. It is
// RevokeUserAuthStateTx's shape applied to a client-scoped action, and it exists for the same
// reason: the transaction discipline is written once, here, rather than open-coded at the call
// site.
//
// The properties it owns, and what each one prevents:
//
//   - the client write and the revocation are in the same transaction, so a client can never end
//     up public with its secret deleted while the grants that secret was protecting survive;
//   - the write DECIDES, inside that transaction, whether the grants must go, and reports it in
//     its bool return. Classifying outside cannot establish the guarantee above: a caller
//     comparing against a client it loaded before the transaction opened is comparing against a
//     row another request may already have changed, and a write that turns out to remove the
//     authentication requirement would then commit with the grants left alive (#245, final review
//     finding 1). Nothing else may decide this, which is why the signal is a return value here
//     rather than an argument the caller computes;
//   - any failure BEFORE the commit is rolled back atomically, via the helper's rollback;
//   - the audit event is the CALLER's job and happens after this returns successfully, because
//     AuditLogger.Log takes no transaction and a logged revocation that then rolled back would be
//     a false record (#106 decision 5).
//
// A write reporting false commits on its own and revokes nothing, so the same discipline covers
// the save that turns out not to be a transition. The caller can tell the two apart by what its
// own write function observed, and must only audit a revocation when it reported true.
//
// On any error the returned result is the zero value rather than a partially populated one, so a
// caller that mistakenly audits on the error path cannot emit half-truthful lists.
//
// WHAT A COMMIT FAILURE DOES AND DOES NOT GUARANTEE is the contract RevokeUserAuthStateTx
// documents at length and this shares: the helper's rollback covers failures before the commit
// only, and `database/sql` promises nothing about a Commit that returns an error. So a 500 from a
// caller here must not be read as "nothing happened"; the durable outcome of a reported commit
// failure is indeterminate, and the bounded consequence is a client left flipped and revoked with
// no audit record of it, which is fail-closed on the security side and a gap on the forensic side.
func RevokeClientGrantsTx(ctx context.Context, db Database, clientId int64,
	write func(tx *sql.Tx) (bool, error)) (ClientGrantResult, error) {

	// The write and the conditional sweep in one transaction opened through RunInTransaction, so
	// a deadlock reruns both together (#301). Safe to rerun: the write is the compare-and-set
	// SetClientPublic followed by an idempotent UpdateClient, its answer is asked again on every
	// attempt, and result is the committing attempt's.
	//
	// A family's record is written by a read-then-insert, so a containment of the same family that
	// overlaps this transaction can win the key first. The helper reruns the body once, which then
	// reads the record the containment committed and leaves it as it is.
	var result ClientGrantResult
	err := data.RunInTransactionRetryingConflict(ctx, db, func(tx *sql.Tx) error {
		revoke, err := write(tx)
		if err != nil {
			return err
		}

		result = ClientGrantResult{RevokedRefreshTokenJtis: []string{}}
		if revoke {
			result, err = RevokeClientGrants(ctx, db, tx, clientId)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return ClientGrantResult{}, err
	}
	return result, nil
}

// AuditLogger records one security event. This package declares only the shape its four Log*
// helpers need rather than depending on the audit implementation that satisfies it, and rather
// than importing a handler package to borrow the declaration: the context is first because every
// audit event raised while serving a request is correlated to that request, so the console record
// joins the request's own log line and the persisted row carries the same id, which is why
// guard.AssertAuditLogContext refuses a context.Background() here (#328). The shape is kept
// identical to handlers.AuditLogger, which the same concrete *audit.Logger satisfies, exactly
// as middleware's own copy already does (#387).
type AuditLogger interface {
	Log(ctx context.Context, auditEvent string, details map[string]interface{})
}

// LogRevokedClientGrants emits EventRevokedClientGrants. One function rather than a literal at the
// call site, following LogRevokedUserAuthState and LogTerminatedUserSession: the payload cannot
// then differ between sites, and there is a single place to assert its shape field by field.
//
// Call this only after RevokeClientGrantsTx returned without error.
//
// ctx is the request's, taken as a parameter rather than reached for because this helper has
// neither an *http.Request nor a context of its own and the event it raises has to be correlated
// to the request that caused the revocation (#328). All of its callers are handlers.
func LogRevokedClientGrants(ctx context.Context, auditLogger AuditLogger, clientId int64, reason string,
	loggedInUser string, result ClientGrantResult) {

	auditLogger.Log(ctx, audit.EventRevokedClientGrants, map[string]interface{}{
		"clientId":     clientId,
		"reason":       reason,
		"loggedInUser": loggedInUser,
		// What this call TRANSITIONED, not what the client had. A second flip reports 0 and an
		// empty list, which is the honest answer to the only question an auditor asks of this
		// event.
		"revokedCodeCount": result.RevokedCodeCount,
		// Always a list rather than null: the success path initialises it.
		"revokedRefreshTokenJtis": result.RevokedRefreshTokenJtis,
	})
}

// LogRevokedUserAuthState emits EventRevokedUserAuthState. One function rather than four
// literals, so the payload cannot differ between sites and there is a single place to assert
// its shape field by field.
//
// Call this only after RevokeUserAuthStateTx returned without error.
//
// ctx is the request's, for the reason LogRevokedClientGrants states (#328).
func LogRevokedUserAuthState(ctx context.Context, auditLogger AuditLogger, userId int64, reason string,
	loggedInUser string, result UserAuthStateResult) {

	auditLogger.Log(ctx, audit.EventRevokedUserAuthState, map[string]interface{}{
		"userId":       userId,
		"reason":       reason,
		"loggedInUser": loggedInUser,
		// Always present, and always a list rather than null: UserAuthStateResult initialises
		// both slices, so an action that swept nothing logs [] (finding 8).
		"terminatedSessionIdentifiers": result.TerminatedSessionIdentifiers,
		"revokedRefreshTokenJtis":      result.RevokedRefreshTokenJtis,
		// "" on the three sites that preserve nothing, never absent.
		"preservedSessionIdentifier": result.PreservedSessionIdentifier,
		"oldGeneration":              result.OldGeneration,
		"newGeneration":              result.NewGeneration,
	})
}

// LogAuthCodeReuse emits EventAuthCodeReuseDetected, the security record of the RFC 6749 section
// 10.5 response to a replayed authorization code. One function beside the other Log* helpers, so
// the payload has one place to be asserted field by field.
//
// Call this only after RevokeOnAuthCodeReuseTx returned without error, so the event lists JTIs
// that were really revoked.
//
// ctx is the request's, for the reason LogRevokedClientGrants states (#328).
func LogAuthCodeReuse(ctx context.Context, auditLogger AuditLogger, code *record.Code, result AuthCodeReuseResult) {
	auditLogger.Log(ctx, audit.EventAuthCodeReuseDetected, map[string]interface{}{
		"clientId":          code.ClientId,
		"userId":            code.UserId,
		"codeId":            code.Id,
		"sessionIdentifier": code.SessionIdentifier,
		// Always a list rather than null: AuthCodeReuseResult initialises it on the success path.
		"revokedRefreshTokenJtis": result.RevokedRefreshTokenJtis,
	})
}

// LogTerminatedUserSession emits EventTerminatedUserSession, the security record of an explicit
// "end this session" action (#129 decision 9). One function rather than a literal at each of the
// two endpoints, following LogRevokedUserAuthState: the payload cannot then differ between sites,
// and there is a single place to assert its shape field by field.
//
// It takes the loaded session row for the same reason TerminateUserSessionTx does. userId,
// userSessionId and sessionIdentifier all come off that one row, so they cannot end up describing
// two different sessions, and both call sites already hold it for their own not-found and
// ownership checks.
//
// Call this only after TerminateUserSessionTx returned without error, and beside rather than
// instead of EventDeletedUserSession, whose payload decision 9 leaves untouched.
//
// ctx is the request's, for the reason LogRevokedClientGrants states (#328).
func LogTerminatedUserSession(ctx context.Context, auditLogger AuditLogger, userSession *record.UserSession,
	loggedInUser string, result TerminationResult) {

	auditLogger.Log(ctx, audit.EventTerminatedUserSession, map[string]interface{}{
		"userId":            userSession.UserId,
		"userSessionId":     userSession.Id,
		"sessionIdentifier": userSession.SessionIdentifier,
		"loggedInUser":      loggedInUser,
		// What this call TRANSITIONED, not what the session had. A second termination of the same
		// session reports 0 and an empty list, which is the honest answer to the only question an
		// auditor asks of this event.
		"revokedCodeCount": result.RevokedCodeCount,
		// Always a list rather than null: TerminationResult initialises it on the success path.
		"revokedRefreshTokenJtis": result.RevokedRefreshTokenJtis,
	})
}
