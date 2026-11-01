package legaldocuments

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// runTransactions makes RunInTransaction run its body on a nil transaction, answering each attempt's
// result in turn: the body's own, or the error given for that attempt.
func runTransactions(database *datamocks.Database, attempts ...error) {
	for _, attempt := range attempts {
		database.EXPECT().RunInTransaction(mock.Anything, mock.Anything).
			RunAndReturn(func(_ context.Context, fn func(*sql.Tx) error) error {
				if err := fn(nil); err != nil {
					return err
				}
				return attempt
			}).Once()
	}
}

func TestRecordAcceptances_WritesEachVersionNotYetAccepted(t *testing.T) {
	database := datamocks.NewDatabase(t)
	runTransactions(database, nil)
	database.EXPECT().GetLegalDocumentAcceptancesByUserId(mock.Anything, (*sql.Tx)(nil), int64(42)).
		Return([]record.LegalDocumentAcceptance{{UserId: 42, LegalDocumentVersionId: 11}}, nil).Once()
	var stored []record.LegalDocumentAcceptance
	database.EXPECT().CreateLegalDocumentAcceptance(mock.Anything, (*sql.Tx)(nil), mock.Anything).
		RunAndReturn(func(_ context.Context, _ *sql.Tx, acceptance *record.LegalDocumentAcceptance) error {
			stored = append(stored, *acceptance)
			return nil
		})

	before := time.Now().UTC()
	written, err := RecordAcceptances(context.Background(), database, 42, []int64{11, 12, 71})
	require.NoError(t, err)

	require.Len(t, stored, 2, "version 11 was already accepted and is not written again")
	assert.Equal(t, []int64{12, 71}, []int64{stored[0].LegalDocumentVersionId, stored[1].LegalDocumentVersionId})
	for _, acceptance := range stored {
		assert.Equal(t, int64(42), acceptance.UserId)
		assert.False(t, acceptance.AcceptedAt.Before(before), "stamped now")
	}
	assert.Equal(t, stored, written, "it answers what it wrote, for the audit records")
}

func TestRecordAcceptances_ALostRaceRunsAgainAndWritesNothingTheWinnerWrote(t *testing.T) {
	database := datamocks.NewDatabase(t)
	runTransactions(database, data.ErrUniqueViolation, nil)
	database.EXPECT().GetLegalDocumentAcceptancesByUserId(mock.Anything, (*sql.Tx)(nil), int64(42)).
		Return([]record.LegalDocumentAcceptance{}, nil).Once()
	database.EXPECT().GetLegalDocumentAcceptancesByUserId(mock.Anything, (*sql.Tx)(nil), int64(42)).
		Return([]record.LegalDocumentAcceptance{{UserId: 42, LegalDocumentVersionId: 12}}, nil).Once()
	database.EXPECT().CreateLegalDocumentAcceptance(mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(nil).Once()

	written, err := RecordAcceptances(context.Background(), database, 42, []int64{12})
	require.NoError(t, err)
	assert.Empty(t, written, "the other submission recorded it, and audits it")
}

func TestRecordAcceptances_AFailureIsAnError(t *testing.T) {
	failure := errors.New("database down")
	database := datamocks.NewDatabase(t)
	runTransactions(database, nil)
	database.EXPECT().GetLegalDocumentAcceptancesByUserId(mock.Anything, (*sql.Tx)(nil), int64(42)).Return(nil, failure).Once()

	written, err := RecordAcceptances(context.Background(), database, 42, []int64{12})
	require.ErrorIs(t, err, failure)
	assert.Nil(t, written)
}
