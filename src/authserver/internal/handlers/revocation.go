package handlers

import (
	"database/sql"
	"log/slog"

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
