package handlers

import (
	"database/sql"
	"log/slog"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

// revokeRefreshTokens marks the given refresh tokens revoked and returns the JTIs this call
// transitioned from live to revoked. Already-revoked tokens are skipped and NOT reported:
// callers rely on "we actually revoked something" to distinguish a real revocation from a
// no-op, which is what makes concurrent auth-code redemption safe (#77, see
// revokeOnAuthCodeReuse). That invariant used to exist only as an unremarked `continue`
// inside a loop; extracting it is how it gets a name (#106 decision 8).
//
// The caller owns the transaction. Passing a nil tx is permitted and means no transaction,
// following the data layer's convention, but every caller here supplies one.
func revokeRefreshTokens(db data.Database, tx *sql.Tx, tokens []*models.RefreshToken) ([]string, error) {
	revokedJtis := make([]string, 0, len(tokens))
	for _, rt := range tokens {
		if rt.Revoked {
			continue
		}
		rt.Revoked = true
		if err := db.UpdateRefreshToken(tx, rt); err != nil {
			return nil, err
		}
		revokedJtis = append(revokedJtis, rt.RefreshTokenJti)
	}
	return revokedJtis, nil
}

// RevocationResult reports what a revocation actually did. Its fields map one-to-one onto the
// audit payload of #106 decision 7, so a caller spreads the result rather than threading
// values separately, and a later field does not change every signature.
//
// The two slices are always non-nil, so a JSON audit payload carries [] rather than null.
type RevocationResult struct {
	// TerminatedSessionIdentifiers lists the sessions deleted, excluding any preserved one.
	TerminatedSessionIdentifiers []string
	// RevokedRefreshTokenJtis lists only the tokens this call transitioned, per
	// revokeRefreshTokens. A token already revoked before the call is absent.
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
func RevokeUserAuthState(db data.Database, tx *sql.Tx, userId int64, exceptSid string) (RevocationResult, error) {
	result := RevocationResult{
		TerminatedSessionIdentifiers: []string{},
		RevokedRefreshTokenJtis:      []string{},
	}

	// A nil tx is rejected HERE rather than being left to the first data method that happens
	// to check. This function's contract is atomicity across an increment and a multi-table
	// sweep, so the transaction is a precondition of the whole operation, not an argument that
	// one nested call cares about. Checking at entry also keeps the unit tests honest: without
	// it they would pass nil and exercise a shape production never runs.
	if tx == nil {
		return result, errors.WithStack(errors.New("revoking a user's auth state requires a transaction: the increment and the sweep must not be separable"))
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
	newGeneration, err := db.IncrementUserAuthStateGeneration(tx, userId)
	if err != nil {
		return result, err
	}
	result.NewGeneration = newGeneration
	result.OldGeneration = newGeneration - 1

	// User-scoped, so it covers both linkage shapes: auth-code tokens through codes.user_id
	// and ROPC tokens through refresh_tokens.user_id.
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
	tokens, err := db.GetRefreshTokensByUserId(tx, userId)
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
		preservedTokens, err := db.GetRefreshTokensBySessionIdentifier(tx, exceptSid)
		if err != nil {
			return result, err
		}
		for _, rt := range preservedTokens {
			preservedIds[rt.Id] = true
			// Promote from THIS query's rows, not from the intersection with the
			// user-scoped ones. A child committed between the two queries appears only
			// here, and promoting it is the whole point of querying in this order.
			promoteIds = append(promoteIds, rt.Id)
		}
	}

	toRevoke := make([]*models.RefreshToken, 0, len(tokens))
	for _, rt := range tokens {
		if preservedIds[rt.Id] {
			continue
		}
		toRevoke = append(toRevoke, rt)
	}

	revokedJtis, err := revokeRefreshTokens(db, tx, toRevoke)
	if err != nil {
		return result, err
	}
	result.RevokedRefreshTokenJtis = revokedJtis

	// Promotion is what keeps the preserved session usable: its tokens carry the old
	// generation, which the validator now rejects. An already-revoked token in this set stays
	// revoked, because PromoteRefreshTokenGenerations only touches unrevoked rows.
	if err := db.PromoteRefreshTokenGenerations(tx, promoteIds, newGeneration); err != nil {
		return result, err
	}

	sessions, err := db.GetUserSessionsByUserId(tx, userId)
	if err != nil {
		return result, err
	}
	preservedSessionFound := false
	for i := range sessions {
		session := sessions[i]
		if exceptSid != "" && session.SessionIdentifier == exceptSid {
			if err := db.PromoteUserSessionGeneration(tx, session.Id, newGeneration); err != nil {
				return result, err
			}
			preservedSessionFound = true
			continue
		}
		if err := db.DeleteUserSession(tx, session.Id); err != nil {
			return result, err
		}
		result.TerminatedSessionIdentifiers = append(result.TerminatedSessionIdentifiers,
			session.SessionIdentifier)
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
		slog.Warn("revocation exempted a grant origin whose session row no longer exists",
			"userId", userId, "exceptSid", exceptSid)
	}

	return result, nil
}

// Reasons for AuditRevokedUserAuthState, one per credential site (#106 decision 7). Constants
// rather than inline strings so the four sites cannot drift and a log consumer has something to
// match against.
const (
	RevocationReasonPasswordReset    = "password_reset"
	RevocationReasonPasswordChange   = "password_change"
	RevocationReasonAdminPasswordSet = "admin_password_set"
	RevocationReasonAccountDisabled  = "account_disabled"
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
//   - any failure BEFORE the commit is rolled back atomically, via the deferred rollback;
//   - the audit event is the CALLER's job and happens after this returns successfully, because
//     AuditLogger.Log takes no transaction and a logged revocation that then rolled back would
//     be a false record (decision 5).
//
// On any error the returned result is the zero value rather than a partially populated one, so
// a caller that mistakenly audits on the error path cannot emit half-truthful lists.
//
// WHAT A COMMIT FAILURE DOES AND DOES NOT GUARANTEE. The deferred rollback covers failures
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
func RevokeUserAuthStateTx(db data.Database, userId int64, exceptSid string,
	write func(tx *sql.Tx) error) (RevocationResult, error) {

	tx, err := db.BeginTransaction()
	if err != nil {
		return RevocationResult{}, err
	}
	defer db.RollbackTransaction(tx) //nolint:errcheck

	if err := write(tx); err != nil {
		return RevocationResult{}, err
	}

	result, err := RevokeUserAuthState(db, tx, userId, exceptSid)
	if err != nil {
		return RevocationResult{}, err
	}

	if err := db.CommitTransaction(tx); err != nil {
		return RevocationResult{}, err
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
	// revokeRefreshTokens. A token already revoked before the call is absent. Non-nil on the
	// success path, so a JSON audit payload carries [] rather than null.
	RevokedRefreshTokenJtis []string
}

// TerminateUserSessionTx ends one session as a security action: it writes the durable fact that
// the grants of that session are revoked, sweeps the tokens those grants issued, and deletes the
// session row, in ONE transaction it owns and commits (#129 decision 5).
//
// The three writes, in the order decision 5 states:
//
//  1. RevokeCodesBySessionIdentifier marks every code issued through this session revoked. This
//     is the write that SURVIVES, and the only one that is a boundary. A refresh token can only
//     descend from a code and a rotated child inherits its parent's code_id, so marking the code
//     rejects every present and future descendant of the grant: a child inserted after this
//     commit is born already rejected, because the fact predates its existence.
//  2. The sid-scoped refresh-token sweep. GetRefreshTokensBySessionIdentifier matches
//     codes.session_identifier through a join, and that join is the ONLY thing that reaches an
//     offline grant's tokens, because an offline refresh token's own session_identifier is empty
//     and the sid its grant came from lives on the codes row. Filtering these rows by
//     rt.SessionIdentifier would therefore drop exactly the offline tokens decision 2 exists to
//     revoke.
//  3. DeleteUserSession, which is what makes the effect immediate for session-bound tokens: they
//     already stop validating once the row is gone.
//
// Steps 2 and 3 are cleanup. Absence of a session row is never read as termination anywhere,
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
// documents at length and this shares: the deferred rollback covers failures before the commit
// only, and `database/sql` promises nothing about a Commit that returns an error. So a 500 from a
// caller here must not be read as "nothing happened"; the durable outcome of a reported commit
// failure is indeterminate, and the bounded consequence is a termination with no audit record of
// it, which is fail-closed on the security side and a gap on the forensic side.
func TerminateUserSessionTx(db data.Database, userSession *models.UserSession) (TerminationResult, error) {
	// Both sweeps key on the session identifier and the delete keys on the id, so this takes the
	// loaded row rather than two loose values: from one row they cannot describe two different
	// sessions, and both call sites already load it for their own not-found and ownership checks.
	if userSession == nil {
		return TerminationResult{}, errors.WithStack(errors.New("terminating a user session requires the session to terminate"))
	}

	// Refused at entry rather than three statements later. RevokeCodesBySessionIdentifier rejects
	// an empty identifier itself, so the outcome is the same either way, but reaching it means
	// opening a transaction first and surfacing a bad argument as a database failure.
	if userSession.SessionIdentifier == "" {
		return TerminationResult{}, errors.WithStack(errors.New("terminating a user session requires a session identifier"))
	}

	tx, err := db.BeginTransaction()
	if err != nil {
		return TerminationResult{}, err
	}
	defer db.RollbackTransaction(tx) //nolint:errcheck

	revokedCodeCount, err := db.RevokeCodesBySessionIdentifier(tx, userSession.SessionIdentifier)
	if err != nil {
		return TerminationResult{}, err
	}

	tokens, err := db.GetRefreshTokensBySessionIdentifier(tx, userSession.SessionIdentifier)
	if err != nil {
		return TerminationResult{}, err
	}

	revokedJtis, err := revokeRefreshTokens(db, tx, tokens)
	if err != nil {
		return TerminationResult{}, err
	}

	if err := db.DeleteUserSession(tx, userSession.Id); err != nil {
		return TerminationResult{}, err
	}

	if err := db.CommitTransaction(tx); err != nil {
		return TerminationResult{}, err
	}

	return TerminationResult{
		RevokedCodeCount:        revokedCodeCount,
		RevokedRefreshTokenJtis: revokedJtis,
	}, nil
}

// ClientGrantRevocationResult reports what revoking one client's grants actually did. It is
// TerminationResult's two fields under a name that does not assert a session ended, and that
// distinction is the whole reason it is a separate type (#245 decision 16): flipping a client to
// public revokes the client's grants and deliberately leaves every session alone, so a result
// carrying RevocationResult's terminated-sessions, preserved-session and generation fields would
// have three fields that can never fill, and an audit payload built from it would imply an action
// this one does not take.
type ClientGrantRevocationResult struct {
	// RevokedCodeCount is how many codes this call TRANSITIONED from live to revoked, not how
	// many the client has. A second flip of the same client reports 0, which is what makes the
	// audit event answer the only question an auditor asks of it, whether this action revoked
	// anything.
	RevokedCodeCount int64
	// RevokedRefreshTokenJtis lists only the tokens this call transitioned, per
	// revokeRefreshTokens. A token already revoked before the call is absent. Non-nil on the
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
func RevokeClientGrants(db data.Database, tx *sql.Tx, clientId int64) (ClientGrantRevocationResult, error) {
	result := ClientGrantRevocationResult{RevokedRefreshTokenJtis: []string{}}

	if tx == nil {
		return result, errors.WithStack(errors.New("revoking a client's grants requires a transaction: the code marker and the sweep must not be separable"))
	}

	revokedCodeCount, err := db.RevokeCodesByClientId(tx, clientId)
	if err != nil {
		return ClientGrantRevocationResult{}, err
	}

	tokens, err := db.GetRefreshTokensByClientId(tx, clientId)
	if err != nil {
		return ClientGrantRevocationResult{}, err
	}

	revokedJtis, err := revokeRefreshTokens(db, tx, tokens)
	if err != nil {
		return ClientGrantRevocationResult{}, err
	}

	return ClientGrantRevocationResult{
		RevokedCodeCount:        revokedCodeCount,
		RevokedRefreshTokenJtis: revokedJtis,
	}, nil
}

// RevocationReasonClientBecamePublic is the reason recorded on AuditRevokedClientGrants. A
// constant beside the RevocationReason* group above, for the same reason those are constants: a
// log consumer needs something to match against, and there is one place to add the next site.
const RevocationReasonClientBecamePublic = "client_became_public"

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
//   - any failure BEFORE the commit is rolled back atomically, via the deferred rollback;
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
// documents at length and this shares: the deferred rollback covers failures before the commit
// only, and `database/sql` promises nothing about a Commit that returns an error. So a 500 from a
// caller here must not be read as "nothing happened"; the durable outcome of a reported commit
// failure is indeterminate, and the bounded consequence is a client left flipped and revoked with
// no audit record of it, which is fail-closed on the security side and a gap on the forensic side.
func RevokeClientGrantsTx(db data.Database, clientId int64,
	write func(tx *sql.Tx) (bool, error)) (ClientGrantRevocationResult, error) {

	tx, err := db.BeginTransaction()
	if err != nil {
		return ClientGrantRevocationResult{}, err
	}
	defer db.RollbackTransaction(tx) //nolint:errcheck

	revoke, err := write(tx)
	if err != nil {
		return ClientGrantRevocationResult{}, err
	}

	result := ClientGrantRevocationResult{RevokedRefreshTokenJtis: []string{}}
	if revoke {
		result, err = RevokeClientGrants(db, tx, clientId)
		if err != nil {
			return ClientGrantRevocationResult{}, err
		}
	}

	if err := db.CommitTransaction(tx); err != nil {
		return ClientGrantRevocationResult{}, err
	}
	return result, nil
}

// LogRevokedClientGrants emits AuditRevokedClientGrants. One function rather than a literal at the
// call site, following LogRevokedUserAuthState and LogTerminatedUserSession: the payload cannot
// then differ between sites, and there is a single place to assert its shape field by field.
//
// Call this only after RevokeClientGrantsTx returned without error.
func LogRevokedClientGrants(auditLogger AuditLogger, clientId int64, reason string,
	loggedInUser string, result ClientGrantRevocationResult) {

	auditLogger.Log(constants.AuditRevokedClientGrants, map[string]interface{}{
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

// LogRevokedUserAuthState emits AuditRevokedUserAuthState. One function rather than four
// literals, so the payload cannot differ between sites and there is a single place to assert
// its shape field by field.
//
// Call this only after RevokeUserAuthStateTx returned without error.
func LogRevokedUserAuthState(auditLogger AuditLogger, userId int64, reason string,
	loggedInUser string, result RevocationResult) {

	auditLogger.Log(constants.AuditRevokedUserAuthState, map[string]interface{}{
		"userId":       userId,
		"reason":       reason,
		"loggedInUser": loggedInUser,
		// Always present, and always a list rather than null: RevocationResult initialises
		// both slices, so an action that swept nothing logs [] (finding 8).
		"terminatedSessionIdentifiers": result.TerminatedSessionIdentifiers,
		"revokedRefreshTokenJtis":      result.RevokedRefreshTokenJtis,
		// "" on the three sites that preserve nothing, never absent.
		"preservedSessionIdentifier": result.PreservedSessionIdentifier,
		"oldGeneration":              result.OldGeneration,
		"newGeneration":              result.NewGeneration,
	})
}

// LogTerminatedUserSession emits AuditTerminatedUserSession, the security record of an explicit
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
// instead of AuditDeletedUserSession, whose payload decision 9 leaves untouched.
func LogTerminatedUserSession(auditLogger AuditLogger, userSession *models.UserSession,
	loggedInUser string, result TerminationResult) {

	auditLogger.Log(constants.AuditTerminatedUserSession, map[string]interface{}{
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
