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
	"github.com/leodip/goiabada/core/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The transactions the tests hand RecordAcceptances' body, one per attempt, so every read and write
// is expected on the attempt's own transaction: one made outside it, or on another attempt's, fails.
var (
	firstAttempt  = &sql.Tx{}
	secondAttempt = &sql.Tx{}
)

// on matches exactly tx, by identity: testify compares pointers by what they point to, and two
// transactions' zero values are alike.
func on(tx *sql.Tx) any {
	return mock.MatchedBy(func(got *sql.Tx) bool { return got == tx })
}

// storeAcceptances expects the writes on tx, collecting what each stores, failing the versions in
// refused with their error.
func storeAcceptances(database *datamocks.Database, tx *sql.Tx, refused map[int64]error) *[]record.LegalDocumentAcceptance {
	stored := &[]record.LegalDocumentAcceptance{}
	database.EXPECT().CreateLegalDocumentAcceptance(mock.Anything, on(tx), mock.Anything).
		RunAndReturn(func(_ context.Context, _ *sql.Tx, acceptance *record.LegalDocumentAcceptance) error {
			if err := refused[acceptance.LegalDocumentVersionId]; err != nil {
				return err
			}
			*stored = append(*stored, *acceptance)
			return nil
		})
	return stored
}

func TestRecordAcceptances_WritesEachVersionNotYetAccepted(t *testing.T) {
	database := datamocks.NewDatabase(t)
	datamocks.ExpectRunInTransaction(database, firstAttempt)
	database.EXPECT().GetLegalDocumentAcceptancesByUserId(mock.Anything, on(firstAttempt), int64(42)).
		Return([]record.LegalDocumentAcceptance{{UserId: 42, LegalDocumentVersionId: 11}}, nil).Once()
	stored := storeAcceptances(database, firstAttempt, nil)

	before := time.Now().UTC()
	written, err := RecordAcceptances(context.Background(), database, 42, []int64{11, 12, 71})
	require.NoError(t, err)

	require.Len(t, *stored, 2, "version 11 was already accepted and is not written again")
	assert.Equal(t, []int64{12, 71}, []int64{(*stored)[0].LegalDocumentVersionId, (*stored)[1].LegalDocumentVersionId})
	for _, acceptance := range *stored {
		assert.Equal(t, int64(42), acceptance.UserId)
		assert.False(t, acceptance.AcceptedAt.Before(before), "stamped now")
	}
	assert.Equal(t, *stored, written, "it answers what it wrote, for the audit records")
}

// The other submission committed version 12 first: this one's insert loses on the key, and its
// second attempt, on a transaction of its own, reads the winner's row and writes nothing.
func TestRecordAcceptances_ALostRaceRunsAgainAndWritesNothingTheWinnerWrote(t *testing.T) {
	database := datamocks.NewDatabase(t)
	first := datamocks.ExpectRunInTransaction(database, firstAttempt)
	database.EXPECT().GetLegalDocumentAcceptancesByUserId(mock.Anything, on(firstAttempt), int64(42)).
		Return([]record.LegalDocumentAcceptance{}, nil).Once()
	storeAcceptances(database, firstAttempt, map[int64]error{12: errs.Errorf("insert: %w", data.ErrUniqueViolation)})
	datamocks.ExpectRunInTransaction(database, secondAttempt)
	database.EXPECT().GetLegalDocumentAcceptancesByUserId(mock.Anything, on(secondAttempt), int64(42)).
		Return([]record.LegalDocumentAcceptance{{UserId: 42, LegalDocumentVersionId: 12}}, nil).Once()

	written, err := RecordAcceptances(context.Background(), database, 42, []int64{12})
	require.NoError(t, err)
	require.ErrorIs(t, first.BodyErr, data.ErrUniqueViolation, "the first attempt lost on the key")
	assert.Empty(t, written, "the other submission recorded it, and audits it")
}

// A deadlock's rerun: the first attempt's writes were rolled back, so what it answers is the second
// attempt's alone, each version once.
func TestRecordAcceptances_ARerunAnswersOnlyTheAttemptThatCommitted(t *testing.T) {
	database := datamocks.NewDatabase(t)
	datamocks.ExpectRunInTransactionRerun(database, firstAttempt)
	database.EXPECT().GetLegalDocumentAcceptancesByUserId(mock.Anything, on(firstAttempt), int64(42)).
		Return([]record.LegalDocumentAcceptance{}, nil).Twice()
	stored := storeAcceptances(database, firstAttempt, nil)

	written, err := RecordAcceptances(context.Background(), database, 42, []int64{12, 71})
	require.NoError(t, err)

	require.Len(t, *stored, 4, "both attempts wrote both versions")
	require.Len(t, written, 2, "the rolled-back attempt's rows are not answered")
	assert.Equal(t, []int64{12, 71}, []int64{written[0].LegalDocumentVersionId, written[1].LegalDocumentVersionId})
}

// A commit that fails after every write succeeded records nothing as far as the caller knows, so
// nothing is answered for it to audit.
func TestRecordAcceptances_AFailedCommitAnswersNothing(t *testing.T) {
	commitFailed := errors.New("commit failed")
	database := datamocks.NewDatabase(t)
	datamocks.ExpectRunInTransactionThenFail(database, firstAttempt, commitFailed)
	database.EXPECT().GetLegalDocumentAcceptancesByUserId(mock.Anything, on(firstAttempt), int64(42)).
		Return([]record.LegalDocumentAcceptance{}, nil).Once()
	storeAcceptances(database, firstAttempt, nil)

	written, err := RecordAcceptances(context.Background(), database, 42, []int64{12, 71})
	require.ErrorIs(t, err, commitFailed)
	assert.Nil(t, written)
}

// The second of two inserts fails: the transaction rolls back, and the first, which it undoes, is
// not answered as recorded.
func TestRecordAcceptances_APartialWriteAnswersNothing(t *testing.T) {
	insertFailed := errors.New("insert failed")
	database := datamocks.NewDatabase(t)
	attempt := datamocks.ExpectRunInTransaction(database, firstAttempt)
	database.EXPECT().GetLegalDocumentAcceptancesByUserId(mock.Anything, on(firstAttempt), int64(42)).
		Return([]record.LegalDocumentAcceptance{}, nil).Once()
	stored := storeAcceptances(database, firstAttempt, map[int64]error{71: insertFailed})

	written, err := RecordAcceptances(context.Background(), database, 42, []int64{12, 71})
	require.ErrorIs(t, err, insertFailed)
	require.ErrorIs(t, attempt.BodyErr, insertFailed, "the body failed, so the transaction rolls back")
	assert.Len(t, *stored, 1, "version 12 was written before the failure")
	assert.Nil(t, written, "and is not answered, since the rollback undoes it")
}

func TestRecordAcceptances_AFailureIsAnError(t *testing.T) {
	failure := errors.New("database down")
	database := datamocks.NewDatabase(t)
	datamocks.ExpectRunInTransaction(database, firstAttempt)
	database.EXPECT().GetLegalDocumentAcceptancesByUserId(mock.Anything, on(firstAttempt), int64(42)).Return(nil, failure).Once()

	written, err := RecordAcceptances(context.Background(), database, 42, []int64{12})
	require.ErrorIs(t, err, failure)
	assert.Nil(t, written)
}
