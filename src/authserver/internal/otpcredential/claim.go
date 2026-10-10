package otpcredential

import (
	"context"
	"database/sql"
	"errors"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// ErrAuthenticatorRemoved is returned by a write that refused to bind or issue a one-time code the
// user's authenticator no longer backs (OTPClaim.Recheck). Nothing was written; the caller starts
// the sign-in over, or answers login_required to a silent one.
var ErrAuthenticatorRemoved = errors.New("the authenticator this sign-in's one-time code came from has been removed")

// OTPClaim is what an authentication claims of a one-time code: whether its methods name one, and
// the otp_config_generation of the authenticator it came from. A ceremony's is its AuthMethods
// beside its OtpClaimGeneration.
type OTPClaim struct {
	Claimed    bool
	Generation *int64
}

// StandsFor reports whether the claim is still true of user. A claim to no code always is. A claim
// to one is while the user has an authenticator and it is the one the code came from: the
// generation moves at every removal and every enrolment (Remove, Establish), so a code from an
// authenticator removed since, replaced or not, stands for nothing, and so does a claim whose
// generation was never recorded (#542). /auth/completed and /auth/issue ask it first, and the
// session and issuance writes ask it again under the user's row lock (Recheck).
func (c OTPClaim) StandsFor(user *record.User) bool {
	if !c.Claimed {
		return true
	}
	return user != nil && user.OTPEnabled && c.Generation != nil && *c.Generation == user.OtpConfigGeneration
}

// ClaimDatabase is what Recheck reads the user through.
type ClaimDatabase interface {
	AcquireUserRow(ctx context.Context, tx *sql.Tx, userId int64) error
	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*record.User, error)
}

// Recheck takes userId's row in tx and answers ErrAuthenticatorRemoved unless the claim stands for
// the user read under it. A claim to no code takes nothing. The session writes at /auth/completed
// and both issuers call it first in their transactions, before any other read or lock.
//
// The row lock is what makes asking again worth it, after /auth/completed or /auth/issue already
// asked. Remove takes the user's row first and lowers the user's sessions in the same transaction,
// so a removal committing between that question and the write either waits for the write's
// transaction, and then lowers what it wrote, or committed before the lock was granted, and the
// read below sees it. Without it a session lowered a moment earlier was raised back to level 3 with
// otp, a new one created claiming it, or a code issued claiming it, from a code the removed
// authenticator gave (#542).
//
// First, before any read, because MySQL's REPEATABLE READ fixes a transaction's snapshot at its
// first plain read: a read before the lock would hide a removal that committed while the
// transaction waited for it. And the user's row before the session's, the order a removal and a
// credential change take them in.
func (c OTPClaim) Recheck(ctx context.Context, db ClaimDatabase, tx *sql.Tx, userId int64) error {
	if !c.Claimed {
		return nil
	}
	if err := db.AcquireUserRow(ctx, tx, userId); err != nil {
		return err
	}
	user, err := db.GetUserById(ctx, tx, userId)
	if err != nil {
		return err
	}
	if !c.StandsFor(user) {
		return errs.WithStack(ErrAuthenticatorRemoved)
	}
	return nil
}
