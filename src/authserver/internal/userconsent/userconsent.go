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

	"github.com/leodip/goiabada/authserver/internal/models"
)

// Database is what recording a consent needs: the row a user holds for a client, and the two
// writes that create or rewrite it.
//
// Exported, unlike the per-file ports #386 left in the handler packages, because it is this
// package's own port and the consent handler's port embeds it to hand the capability on (#387).
type Database interface {
	CreateUserConsent(ctx context.Context, tx *sql.Tx, userConsent *models.UserConsent) error
	GetConsentByUserIdAndClientId(ctx context.Context, tx *sql.Tx, userId int64, clientId int64) (*models.UserConsent, error)
	UpdateUserConsent(ctx context.Context, tx *sql.Tx, userConsent *models.UserConsent) error
}

// Record saves scope as the whole of the user's consent to the client and returns the row saved.
//
// An existing consent is replaced rather than appended to: the scope is what the user ticked on
// this submission, filtered to what they hold, so a scope they unticked is no longer consented.
// GrantedAt is set when the row is created and left alone when it is rewritten.
//
// The read and the write are two statements outside any transaction, so two concurrent saves for
// the same pair can each find no row and both create one.
//
// ceiling: a concurrent pair of first saves leaves two consent rows for one user and client, and
// which one governs is whichever the engine returns. Revisit when migration 000055 adds the
// unique index on (user_id, client_id), which is when this runs in a transaction and reruns on a
// unique-key collision (#249).
func Record(ctx context.Context, db Database, userId, clientId int64, scope string) (*models.UserConsent, error) {
	consent, err := db.GetConsentByUserIdAndClientId(ctx, nil, userId, clientId)
	if err != nil {
		return nil, err
	}

	if consent == nil {
		consent = &models.UserConsent{
			UserId:    userId,
			ClientId:  clientId,
			GrantedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
		}
	}
	consent.Scope = scope

	if consent.Id > 0 {
		err = db.UpdateUserConsent(ctx, nil, consent)
	} else {
		err = db.CreateUserConsent(ctx, nil, consent)
	}
	if err != nil {
		return nil, err
	}
	return consent, nil
}
