package datatests

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Deleting a client records its identifier with the moment of the deletion, in the deleting
// transaction, so that the access-token liveness check can tell a token of the deleted client from
// one of a new client that took its identifier (#676 decision 6).

func deletedClient(t *testing.T, identifier string) *record.DeletedClient {
	t.Helper()
	return deletedClientOn(t, database, identifier)
}

func deletedClientOn(t *testing.T, db data.Database, identifier string) *record.DeletedClient {
	t.Helper()
	deleted, err := db.GetDeletedClientByClientIdentifier(context.Background(), nil, identifier)
	require.NoError(t, err)
	return deleted
}

func TestDeleteClient_RecordsTheDeletedIdentifier(t *testing.T) {
	client := createTestClient(t)
	require.Nil(t, deletedClient(t, client.ClientIdentifier), "a client that exists was never deleted")

	before := time.Now().UTC().Add(-time.Second)
	require.NoError(t, database.DeleteClient(context.Background(), nil, client.ID))
	after := time.Now().UTC().Add(time.Second)

	deleted := deletedClient(t, client.ClientIdentifier)
	require.NotNil(t, deleted)
	assert.Equal(t, client.ClientIdentifier, deleted.ClientIdentifier)
	assert.True(t, deleted.DeletedAt.After(before) && deleted.DeletedAt.Before(after),
		"deleted_at is the moment of the deletion: %v", deleted.DeletedAt)
}

// A later deletion of the identifier, of a client that took it, replaces the earlier record: only the
// latest can precede a client that exists now.
func TestDeleteClient_ALaterDeletionReplacesTheRecord(t *testing.T) {
	first := createTestClient(t)
	require.NoError(t, database.DeleteClient(context.Background(), nil, first.ID))
	firstDeletion := deletedClient(t, first.ClientIdentifier)
	require.NotNil(t, firstDeletion)

	time.Sleep(10 * time.Millisecond)
	second := &record.Client{ClientIdentifier: first.ClientIdentifier, Description: "Test Client"}
	require.NoError(t, database.CreateClient(context.Background(), nil, second))
	require.NotEqual(t, first.ID, second.ID)
	require.NoError(t, database.DeleteClient(context.Background(), nil, second.ID))

	secondDeletion := deletedClient(t, first.ClientIdentifier)
	require.NotNil(t, secondDeletion)
	assert.True(t, secondDeletion.DeletedAt.After(firstDeletion.DeletedAt),
		"the record is the second deletion's: %v after %v", secondDeletion.DeletedAt, firstDeletion.DeletedAt)
}

// A deletion that rolls back records nothing: the record is written on the deleting transaction.
func TestDeleteClient_ARolledBackDeletionRecordsNothing(t *testing.T) {
	client := createTestClient(t)

	tx, err := database.BeginTransaction(context.Background())
	require.NoError(t, err)
	require.NoError(t, database.DeleteClient(context.Background(), tx, client.ID))
	require.NoError(t, database.RollbackTransaction(context.Background(), tx))

	assert.Nil(t, deletedClient(t, client.ClientIdentifier), "the deletion rolled back, and its record with it")
	still, err := database.GetClientByID(context.Background(), nil, client.ID)
	require.NoError(t, err)
	assert.NotNil(t, still)
}

// Deleting a client that is not there records nothing.
func TestDeleteClient_AClientThatIsNotThereRecordsNothing(t *testing.T) {
	client := createTestClient(t)
	require.NoError(t, database.DeleteClient(context.Background(), nil, client.ID))
	deletion := deletedClient(t, client.ClientIdentifier)
	require.NotNil(t, deletion)

	require.NoError(t, database.DeleteClient(context.Background(), nil, client.ID))

	again := deletedClient(t, client.ClientIdentifier)
	require.NotNil(t, again)
	assert.True(t, again.DeletedAt.Equal(deletion.DeletedAt), "the second call found no client and wrote nothing")
}

// A deletion that overlaps a rename of the same client records the identifier the row held when it
// was deleted, which is the one the client gave up (#710 decision 11). The rename takes the row
// and holds its transaction open; the deletion must wait for it, and once the rename commits,
// record the new identifier. A deletion that read the identifier without waiting, as a plain read
// does on the engines where readers do not wait for writers, would record the identifier the
// client had before the rename, and the one it gave up would get none.
func TestDeleteClient_OverlappingARenameRecordsTheIdentifierTheRowHeld(t *testing.T) {
	if dbType() == data.SQLite {
		t.Skip("sqlite is limited to one connection (SetMaxOpenConns(1)), so the deletion " +
			"queues behind the rename instead of overlapping it")
	}
	runDeleteClientOverlappingARename(t, database)
}

// TestDeleteClient_OverlappingARenameRecordsTheIdentifierTheRowHeld_RCSI is the same overlap on a
// SQL Server database with READ_COMMITTED_SNAPSHOT on, where a plain read of the identifier would
// not wait for the rename, so only the deletion's locking read records the one the row held. It
// skips on the other three engines.
func TestDeleteClient_OverlappingARenameRecordsTheIdentifierTheRowHeld_RCSI(t *testing.T) {
	runDeleteClientOverlappingARename(t, rcsiDatabase(t).primary)
}

func runDeleteClientOverlappingARename(t *testing.T, db data.Database) {
	ctx := context.Background()
	client := createIdentifierTestClientOn(t, db)
	original := client.ClientIdentifier
	renamed := "renamed_" + fake.LetterN(8)

	rename := beginTxOn(t, db)
	changed, err := db.SetClientIdentifier(ctx, rename, client.ID, renamed)
	require.NoError(t, err)
	require.True(t, changed)

	deletion := goBlocked(t, "the deletion", rename, func(reached func()) error {
		reached()
		return db.DeleteClient(ctx, nil, client.ID)
	})

	deletion.requireBlocked(t)
	deletion.requireStillWaiting(t)
	require.NoError(t, db.CommitTransaction(ctx, rename))

	require.NoError(t, deletion.await(t))

	gone, err := db.GetClientByID(ctx, nil, client.ID)
	require.NoError(t, err)
	assert.Nil(t, gone, "the client is deleted")

	deleted := deletedClientOn(t, db, renamed)
	require.NotNil(t, deleted, "the deletion records the identifier the row held when it was deleted")
	assert.Equal(t, renamed, deleted.ClientIdentifier)
	assert.Nil(t, deletedClientOn(t, db, original),
		"the identifier the rename gave up was not the deleted client's, and is not recorded")
}

// The other order: a deletion holding the client's row uncommitted makes a rename wait, and once the
// deletion commits, the rename finds no client and changes nothing. The record names the identifier
// the client had, and no client holds the one the rename submitted.
func TestDeleteClient_ARenameOverlappingTheDeletionFindsNoClient(t *testing.T) {
	if dbType() == data.SQLite {
		t.Skip("sqlite is limited to one connection (SetMaxOpenConns(1)), so the rename " +
			"queues behind the deletion instead of overlapping it")
	}
	runARenameOverlappingTheDeletion(t, database)
}

// TestDeleteClient_ARenameOverlappingTheDeletionFindsNoClient_RCSI is the same order on a SQL
// Server database with READ_COMMITTED_SNAPSHOT on, where a plain read would still find the client
// the deletion has not committed, so only the rename's locking read finds it gone. It skips on the
// other three engines.
func TestDeleteClient_ARenameOverlappingTheDeletionFindsNoClient_RCSI(t *testing.T) {
	runARenameOverlappingTheDeletion(t, rcsiDatabase(t).primary)
}

func runARenameOverlappingTheDeletion(t *testing.T, db data.Database) {
	ctx := context.Background()
	client := createIdentifierTestClientOn(t, db)
	original := client.ClientIdentifier
	renamed := "renamed_" + fake.LetterN(8)

	deletion := beginTxOn(t, db)
	require.NoError(t, db.DeleteClient(ctx, deletion, client.ID))

	rename := beginTxOn(t, db)
	type outcome struct {
		changed bool
		err     error
	}
	renaming := goBlocked(t, "the rename", deletion, func(reached func()) outcome {
		reached()
		renameChanged, renameErr := db.SetClientIdentifier(ctx, rename, client.ID, renamed)
		return outcome{renameChanged, renameErr}
	})

	renaming.requireBlocked(t)
	renaming.requireStillWaiting(t)
	require.NoError(t, db.CommitTransaction(ctx, deletion))

	o := renaming.await(t)
	require.NoError(t, o.err)
	assert.False(t, o.changed, "there is no client left to rename")
	require.NoError(t, db.CommitTransaction(ctx, rename))

	deleted := deletedClientOn(t, db, original)
	require.NotNil(t, deleted, "the deletion records the identifier the client had")
	assert.Equal(t, original, deleted.ClientIdentifier)
	assert.Nil(t, deletedClientOn(t, db, renamed), "the rename never took effect")
	holder, err := db.GetClientByClientIdentifier(ctx, nil, renamed)
	require.NoError(t, err)
	assert.Nil(t, holder, "no client holds the identifier the rename submitted")
}

// SQL Server pads for `=`, so a trailing space would otherwise find the record of the identifier
// without one, and a collation that folds case would find the other case (#283).
func TestGetDeletedClientByClientIdentifier_ComparesTheIdentifierExactly(t *testing.T) {
	client := createTestClient(t)
	require.NoError(t, database.DeleteClient(context.Background(), nil, client.ID))
	require.NotNil(t, deletedClient(t, client.ClientIdentifier))

	for name, asked := range map[string]string{
		"upper case":     strings.ToUpper(client.ClientIdentifier),
		"trailing space": client.ClientIdentifier + " ",
	} {
		t.Run(name, func(t *testing.T) {
			require.NotEqual(t, client.ClientIdentifier, asked)
			assert.Nil(t, deletedClient(t, asked), "another spelling is another client")
		})
	}
}

func TestGetDeletedClientByClientIdentifier_RefusesAnEmptyIdentifier(t *testing.T) {
	_, err := database.GetDeletedClientByClientIdentifier(context.Background(), nil, "")
	require.Error(t, err)
}
