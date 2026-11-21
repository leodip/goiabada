package legaldocuments

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/record"
)

// AcceptanceDatabase is what recording acceptances needs: the user's acceptances, the write that
// adds one, and the transaction they run in. data.Database satisfies it.
type AcceptanceDatabase interface {
	CreateLegalDocumentAcceptance(ctx context.Context, tx *sql.Tx, acceptance *record.LegalDocumentAcceptance) error
	GetLegalDocumentAcceptancesByUserID(ctx context.Context, tx *sql.Tx, userID int64) ([]record.LegalDocumentAcceptance, error)
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
}

// RecordAcceptances records that the user accepted each of the versions, now, and answers the
// acceptances it wrote. A version the user has already accepted is not written again, so two
// submissions of one step both end with one acceptance each.
//
// The read and the writes are one transaction. Two that overlap can both read a version as not yet
// accepted; the engine refuses the second insert on the user and version's key, and the loser runs
// again (data.RunInTransactionRetryingConflict), reads the winner's row and writes nothing for it.
// The audit records stay with the caller, after the commit, written from what this answers.
func RecordAcceptances(ctx context.Context, db AcceptanceDatabase, userID int64,
	versionIDs []int64) ([]record.LegalDocumentAcceptance, error) {

	var written []record.LegalDocumentAcceptance
	err := data.RunInTransactionRetryingConflict(ctx, db, func(tx *sql.Tx) error {
		// Set by the attempt that commits, so a rerun's rows replace a first attempt's.
		written = nil
		acceptances, err := db.GetLegalDocumentAcceptancesByUserID(ctx, tx, userID)
		if err != nil {
			return err
		}
		accepted := make(map[int64]bool, len(acceptances))
		for _, acceptance := range acceptances {
			accepted[acceptance.LegalDocumentVersionID] = true
		}
		now := time.Now().UTC()
		for _, versionID := range versionIDs {
			if accepted[versionID] {
				continue
			}
			acceptance := record.LegalDocumentAcceptance{AcceptedAt: now, UserID: userID, LegalDocumentVersionID: versionID}
			if err = db.CreateLegalDocumentAcceptance(ctx, tx, &acceptance); err != nil {
				return err
			}
			accepted[versionID] = true
			written = append(written, acceptance)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return written, nil
}
