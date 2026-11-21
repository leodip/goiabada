package datatests

import (
	"context"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A client's identifier has one writer after creation, SetClientIdentifier, which the settings
// save uses (#710 decision 4). It takes the client's row, writes the identifier only when it
// differs from the one the row holds, and reports whether it did; the whole-row UpdateClient never
// writes the column, so the OAuth2 flows, tokens and authentication saves, which write from a copy
// loaded earlier in their request, cannot write back an identifier a rename has changed since.

// TestUpdateClient_LeavesTheIdentifierAlone holds the whole-row save to never writing the
// identifier, while it still writes the ordinary columns.
func TestUpdateClient_LeavesTheIdentifierAlone(t *testing.T) {
	ctx := context.Background()
	client := createIdentifierTestClient(t)
	stored := client.ClientIdentifier

	client.ClientIdentifier = "stale_copy_" + fake.LetterN(8)
	client.Description = "rewritten_" + fake.LetterN(6)
	require.NoError(t, database.UpdateClient(ctx, nil, client))

	got, err := database.GetClientByID(ctx, nil, client.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, stored, got.ClientIdentifier, "UpdateClient must not write client_identifier")
	assert.Equal(t, client.Description, got.Description,
		"and the save still writes the ordinary columns, so the exclusion is targeted rather than a write that stopped landing")
}

// TestSetClientIdentifier_ChangesADifferentIdentifierAndReportsIt: an identifier other than the
// row's is written and reported, on the client named and no other, and the client's other columns
// stay as they were.
func TestSetClientIdentifier_ChangesADifferentIdentifierAndReportsIt(t *testing.T) {
	ctx := context.Background()
	target := createIdentifierTestClient(t)
	bystander := createIdentifierTestClient(t)
	renamed := "renamed_" + fake.LetterN(8)

	tx := beginTx(t)
	changed, err := database.SetClientIdentifier(ctx, tx, target.ID, renamed)
	require.NoError(t, err)
	require.NoError(t, database.CommitTransaction(ctx, tx))
	assert.True(t, changed, "a different identifier is a change")

	got, err := database.GetClientByID(ctx, nil, target.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, renamed, got.ClientIdentifier)
	assert.Equal(t, target.Description, got.Description, "the write sets the identifier alone")
	assert.Equal(t, target.Enabled, got.Enabled)

	byIdentifier, err := database.GetClientByClientIdentifier(ctx, nil, renamed)
	require.NoError(t, err)
	require.NotNil(t, byIdentifier, "the client is found by its new identifier")
	assert.Equal(t, target.ID, byIdentifier.ID)

	gone, err := database.GetClientByClientIdentifier(ctx, nil, target.ClientIdentifier)
	require.NoError(t, err)
	assert.Nil(t, gone, "no client holds the identifier the rename gave up")

	other, err := database.GetClientByID(ctx, nil, bystander.ID)
	require.NoError(t, err)
	require.NotNil(t, other)
	assert.Equal(t, bystander.ClientIdentifier, other.ClientIdentifier, "another client is not renamed")
}

// TestSetClientIdentifier_TheRowsOwnIdentifierIsNoChange: the identifier the row already holds is
// reported as no change and leaves the row as it is, updated_at included: the settings save answers
// with the updated_at of its whole-row write, and a write that changed nothing must not move it.
func TestSetClientIdentifier_TheRowsOwnIdentifierIsNoChange(t *testing.T) {
	ctx := context.Background()
	client := createIdentifierTestClient(t)
	before, err := database.GetClientByID(ctx, nil, client.ID)
	require.NoError(t, err)
	require.NotNil(t, before)
	// Long enough that a write of updated_at would show.
	time.Sleep(timestampTick)

	tx := beginTx(t)
	changed, err := database.SetClientIdentifier(ctx, tx, client.ID, client.ClientIdentifier)
	require.NoError(t, err)
	require.NoError(t, database.CommitTransaction(ctx, tx))
	assert.False(t, changed, "the row's own identifier is not a change")

	got, err := database.GetClientByID(ctx, nil, client.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, client.ClientIdentifier, got.ClientIdentifier)
	assert.Equal(t, before.UpdatedAt, got.UpdatedAt, "a write that changed nothing leaves updated_at alone")
}

// TestSetClientIdentifier_ComparesByteForByte: an identifier that differs from the row's only in
// case is a change and is written as sent, on every engine. RFC 6749 section 1.9 makes client_id
// case sensitive, and a comparison an engine folded would report a rename that changed what the
// client must send as no change at all.
func TestSetClientIdentifier_ComparesByteForByte(t *testing.T) {
	ctx := context.Background()
	client := &record.Client{ClientIdentifier: "case_" + fake.LetterN(8), Description: "Identifier test client"}
	require.NoError(t, database.CreateClient(ctx, nil, client))
	upper := "CASE_" + client.ClientIdentifier[len("case_"):]

	tx := beginTx(t)
	changed, err := database.SetClientIdentifier(ctx, tx, client.ID, upper)
	require.NoError(t, err)
	require.NoError(t, database.CommitTransaction(ctx, tx))
	assert.True(t, changed, "a change of case is a change")

	got, err := database.GetClientByID(ctx, nil, client.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, upper, got.ClientIdentifier)
}

// TestSetClientIdentifier_AClientNotThereIsNoChange: there is nothing to rename, and nothing is
// created.
func TestSetClientIdentifier_AClientNotThereIsNoChange(t *testing.T) {
	ctx := context.Background()
	client := createIdentifierTestClient(t)
	require.NoError(t, database.DeleteClient(ctx, nil, client.ID))
	identifier := "nobody_" + fake.LetterN(8)

	tx := beginTx(t)
	changed, err := database.SetClientIdentifier(ctx, tx, client.ID, identifier)
	require.NoError(t, err)
	require.NoError(t, database.CommitTransaction(ctx, tx))
	assert.False(t, changed)

	got, err := database.GetClientByClientIdentifier(ctx, nil, identifier)
	require.NoError(t, err)
	assert.Nil(t, got)
}

// TestSetClientIdentifier_RefusesCallerBugs: the write is decided under the row's lock, which an
// autocommitted statement releases at once, so it requires a transaction; a zero id and an empty
// identifier are a caller's bug rather than a filter or a value.
func TestSetClientIdentifier_RefusesCallerBugs(t *testing.T) {
	ctx := context.Background()
	client := createIdentifierTestClient(t)

	_, err := database.SetClientIdentifier(ctx, nil, client.ID, "renamed_"+fake.LetterN(8))
	require.Error(t, err, "a nil transaction")

	tx := beginTx(t)
	_, err = database.SetClientIdentifier(ctx, tx, 0, "renamed_"+fake.LetterN(8))
	require.Error(t, err, "a zero id")
	_, err = database.SetClientIdentifier(ctx, tx, client.ID, "")
	require.Error(t, err, "an empty identifier")
	require.NoError(t, tx.Rollback())

	got, err := database.GetClientByID(ctx, nil, client.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, client.ClientIdentifier, got.ClientIdentifier, "a refused call writes nothing")
}

// TestSetClientIdentifier_DecidesAgainstARenameCommittedMeanwhile is decision 4's race on a real
// engine. Two saves submit the same new identifier for one client. The first renames it and holds
// its transaction open; the second must wait for it, and once the first commits, find the identifier
// it submits already in the row and report no change. A write that compared against what it read
// before the first committed would report a second rename, which is what a later slice revokes
// the client's grants on.
func TestSetClientIdentifier_DecidesAgainstARenameCommittedMeanwhile(t *testing.T) {
	if dbType() == data.SQLite {
		t.Skip("sqlite is limited to one connection (SetMaxOpenConns(1)), so a second write " +
			"transaction queues behind the first instead of overlapping it")
	}
	runRenameDecidesAgainstARenameCommittedMeanwhile(t, database)
}

// TestSetClientIdentifier_DecidesAgainstARenameCommittedMeanwhile_RCSI is the same race on a SQL Server database with
// READ_COMMITTED_SNAPSHOT on, where a plain read no longer waits for the first rename, so only the
// identifier's locking read orders the two. It skips on the other three engines.
func TestSetClientIdentifier_DecidesAgainstARenameCommittedMeanwhile_RCSI(t *testing.T) {
	runRenameDecidesAgainstARenameCommittedMeanwhile(t, rcsiDatabase(t).primary)
}

func runRenameDecidesAgainstARenameCommittedMeanwhile(t *testing.T, db data.Database) {
	ctx := context.Background()
	client := createIdentifierTestClientOn(t, db)
	renamed := "renamed_" + fake.LetterN(8)

	first := beginTxOn(t, db)
	changed, err := db.SetClientIdentifier(ctx, first, client.ID, renamed)
	require.NoError(t, err)
	require.True(t, changed)

	second := beginTxOn(t, db)
	type outcome struct {
		changed bool
		err     error
	}
	secondWrite := goBlocked(t, "the second save's write", first, func(reached func()) outcome {
		reached()
		secondChanged, secondErr := db.SetClientIdentifier(ctx, second, client.ID, renamed)
		return outcome{secondChanged, secondErr}
	})

	secondWrite.requireBlocked(t)
	secondWrite.requireStillWaiting(t)
	require.NoError(t, db.CommitTransaction(ctx, first))

	o := secondWrite.await(t)
	require.NoError(t, o.err)
	assert.False(t, o.changed, "the row already holds the identifier, as committed by the other save")
	require.NoError(t, db.CommitTransaction(ctx, second))

	got, err := db.GetClientByID(ctx, nil, client.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, renamed, got.ClientIdentifier)
}

// TestSetClientIdentifier_ASecondRenameMeanwhileIsAChange is the other side of the race: a save
// submitting the identifier the client had before a rename committed meanwhile finds the row's new
// one, and renames it back, reporting the change.
func TestSetClientIdentifier_ASecondRenameMeanwhileIsAChange(t *testing.T) {
	if dbType() == data.SQLite {
		t.Skip("sqlite is limited to one connection (SetMaxOpenConns(1)), so a second write " +
			"transaction queues behind the first instead of overlapping it")
	}
	runASecondRenameMeanwhileIsAChange(t, database)
}

// TestSetClientIdentifier_ASecondRenameMeanwhileIsAChange_RCSI is the same race on a SQL Server database with
// READ_COMMITTED_SNAPSHOT on, where a plain read no longer waits for the first rename, so only the
// identifier's locking read orders the two. It skips on the other three engines.
func TestSetClientIdentifier_ASecondRenameMeanwhileIsAChange_RCSI(t *testing.T) {
	runASecondRenameMeanwhileIsAChange(t, rcsiDatabase(t).primary)
}

func runASecondRenameMeanwhileIsAChange(t *testing.T, db data.Database) {
	ctx := context.Background()
	client := createIdentifierTestClientOn(t, db)
	original := client.ClientIdentifier
	renamed := "renamed_" + fake.LetterN(8)

	first := beginTxOn(t, db)
	changed, err := db.SetClientIdentifier(ctx, first, client.ID, renamed)
	require.NoError(t, err)
	require.True(t, changed)

	second := beginTxOn(t, db)
	type outcome struct {
		changed bool
		err     error
	}
	secondWrite := goBlocked(t, "the second save's write", first, func(reached func()) outcome {
		reached()
		secondChanged, secondErr := db.SetClientIdentifier(ctx, second, client.ID, original)
		return outcome{secondChanged, secondErr}
	})

	secondWrite.requireBlocked(t)
	secondWrite.requireStillWaiting(t)
	require.NoError(t, db.CommitTransaction(ctx, first))

	o := secondWrite.await(t)
	require.NoError(t, o.err)
	assert.True(t, o.changed, "the row holds the other save's identifier, so writing the original back is a change")
	require.NoError(t, db.CommitTransaction(ctx, second))

	got, err := db.GetClientByID(ctx, nil, client.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, original, got.ClientIdentifier)
}

func createIdentifierTestClient(t *testing.T) *record.Client {
	t.Helper()
	return createIdentifierTestClientOn(t, database)
}

func createIdentifierTestClientOn(t *testing.T, db data.Database) *record.Client {
	t.Helper()
	client := &record.Client{
		ClientIdentifier: "identifier_" + fake.LetterN(8),
		Description:      "Identifier test client " + fake.LetterN(6),
		Enabled:          true,
	}
	require.NoError(t, db.CreateClient(context.Background(), nil, client))
	return client
}
