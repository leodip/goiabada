// Package userconsent owns the stored record of what a user consented to a client receiving: one
// operation, Record, which the consent screen's submission calls once the ticked scopes have been
// weighed against the permissions the user holds.
//
// It left HandleConsentPost because persisting the consent is not the handler's job: the handler
// parses the submission, decides between refusing and granting, and answers; how the row is read,
// created or rewritten is this package's. It is an application service in the shape #387 gave the
// others: it takes no http.ResponseWriter, *http.Request, template data or status code, and it
// imports no handler package (#437).
//
// **The audit call stays at the caller**, as revocation and otpcredential require of theirs: the
// event is the ceremony's, and the caller writes it from the row Record returns.
package userconsent

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/models"
)

// Database is what recording a consent needs: the row a user holds for a client, the two writes that
// create or rewrite it, and the transaction they run in.
//
// Exported, unlike the per-file ports #386 left in the handler packages, because it is this
// package's own port and the consent handler's port embeds it to hand the capability on (#387).
type Database interface {
	CreateUserConsent(ctx context.Context, tx *sql.Tx, userConsent *models.UserConsent) error
	GetConsentByUserIdAndClientId(ctx context.Context, tx *sql.Tx, userId int64, clientId int64) (*models.UserConsent, error)
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
	UpdateUserConsent(ctx context.Context, tx *sql.Tx, userConsent *models.UserConsent) error
}

// Record saves scope as the whole of the user's consent to the client and returns the row saved.
//
// An existing consent is replaced rather than appended to: the scope is what the user ticked on
// this submission, filtered to what they hold, so a scope they unticked is no longer consented.
// GrantedAt is the save's time on every save, the row's first and each later one alike: a consent
// the user submitted again is a consent granted again, and the account's consents page shows when
// (#115).
//
// The read and the write are one transaction, and the table has one row per user and client
// (migration 000055), so two saves that overlap cannot leave two rows. Both may read "no consent"
// and both insert; the engine refuses the second on the key, and on PostgreSQL that refusal aborts
// the transaction it ran in, so the loser rolls back and runs again (data.RunInTransactionRetryingConflict).
// The second attempt reads the row the winner committed and rewrites it, which is what a save that
// had arrived a moment later would have done: the last writer's scope is the one that stays (#249).
func Record(ctx context.Context, db Database, userId, clientId int64, scope string) (*models.UserConsent, error) {
	var saved *models.UserConsent
	err := data.RunInTransactionRetryingConflict(ctx, db, func(tx *sql.Tx) error {
		consent, err := db.GetConsentByUserIdAndClientId(ctx, tx, userId, clientId)
		if err != nil {
			return err
		}

		if consent == nil {
			consent = &models.UserConsent{UserId: userId, ClientId: clientId}
		}
		consent.Scope = scope
		consent.GrantedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

		if consent.Id > 0 {
			err = db.UpdateUserConsent(ctx, tx, consent)
		} else {
			err = db.CreateUserConsent(ctx, tx, consent)
		}
		if err != nil {
			return err
		}
		// Set by the attempt that wrote, so a rerun's row replaces a first attempt's and a failed
		// commit returns nothing at all.
		saved = consent
		return nil
	})
	if err != nil {
		return nil, err
	}
	return saved, nil
}
