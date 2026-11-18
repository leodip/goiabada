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
	deleted, err := database.GetDeletedClientByClientIdentifier(context.Background(), nil, identifier)
	require.NoError(t, err)
	return deleted
}

func TestDeleteClient_RecordsTheDeletedIdentifier(t *testing.T) {
	client := createTestClient(t)
	require.Nil(t, deletedClient(t, client.ClientIdentifier), "a client that exists was never deleted")

	before := time.Now().UTC().Add(-time.Second)
	require.NoError(t, database.DeleteClient(context.Background(), nil, client.Id))
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
	require.NoError(t, database.DeleteClient(context.Background(), nil, first.Id))
	firstDeletion := deletedClient(t, first.ClientIdentifier)
	require.NotNil(t, firstDeletion)

	time.Sleep(10 * time.Millisecond)
	second := &record.Client{ClientIdentifier: first.ClientIdentifier, Description: "Test Client"}
	require.NoError(t, database.CreateClient(context.Background(), nil, second))
	require.NotEqual(t, first.Id, second.Id)
	require.NoError(t, database.DeleteClient(context.Background(), nil, second.Id))

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
	require.NoError(t, database.DeleteClient(context.Background(), tx, client.Id))
	require.NoError(t, database.RollbackTransaction(context.Background(), tx))

	assert.Nil(t, deletedClient(t, client.ClientIdentifier), "the deletion rolled back, and its record with it")
	still, err := database.GetClientById(context.Background(), nil, client.Id)
	require.NoError(t, err)
	assert.NotNil(t, still)
}

// Deleting a client that is not there records nothing.
func TestDeleteClient_AClientThatIsNotThereRecordsNothing(t *testing.T) {
	client := createTestClient(t)
	require.NoError(t, database.DeleteClient(context.Background(), nil, client.Id))
	deletion := deletedClient(t, client.ClientIdentifier)
	require.NotNil(t, deletion)

	require.NoError(t, database.DeleteClient(context.Background(), nil, client.Id))

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
	ctx := context.Background()
	client := createIdentifierTestClient(t)
	original := client.ClientIdentifier
	renamed := "renamed_" + fake.LetterN(8)

	rename := beginTx(t)
	changed, err := database.SetClientIdentifier(ctx, rename, client.Id, renamed)
	require.NoError(t, err)
	require.True(t, changed)

	done := make(chan error, 1)
	go func() { done <- database.DeleteClient(ctx, nil, client.Id) }()

	select {
	case err := <-done:
		t.Fatalf("DeleteClient returned (%v) while a rename held the client's row uncommitted", err)
	case <-time.After(500 * time.Millisecond):
	}

	require.NoError(t, database.CommitTransaction(ctx, rename))

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(30 * time.Second):
		t.Fatalf("DeleteClient never returned after the rename committed")
	}

	gone, err := database.GetClientById(ctx, nil, client.Id)
	require.NoError(t, err)
	assert.Nil(t, gone, "the client is deleted")

	deleted := deletedClient(t, renamed)
	require.NotNil(t, deleted, "the deletion records the identifier the row held when it was deleted")
	assert.Equal(t, renamed, deleted.ClientIdentifier)
	assert.Nil(t, deletedClient(t, original),
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
	ctx := context.Background()
	client := createIdentifierTestClient(t)
	original := client.ClientIdentifier
	renamed := "renamed_" + fake.LetterN(8)

	deletion := beginTx(t)
	require.NoError(t, database.DeleteClient(ctx, deletion, client.Id))

	rename := beginTx(t)
	type outcome struct {
		changed bool
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		renameChanged, renameErr := database.SetClientIdentifier(ctx, rename, client.Id, renamed)
		done <- outcome{renameChanged, renameErr}
	}()

	select {
	case o := <-done:
		t.Fatalf("SetClientIdentifier answered %v while a deletion held the client's row uncommitted", o.changed)
	case <-time.After(500 * time.Millisecond):
	}

	require.NoError(t, database.CommitTransaction(ctx, deletion))

	var o outcome
	select {
	case o = <-done:
	case <-time.After(30 * time.Second):
		t.Fatalf("SetClientIdentifier never returned after the deletion committed")
	}
	require.NoError(t, o.err)
	assert.False(t, o.changed, "there is no client left to rename")
	require.NoError(t, database.CommitTransaction(ctx, rename))

	deleted := deletedClient(t, original)
	require.NotNil(t, deleted, "the deletion records the identifier the client had")
	assert.Equal(t, original, deleted.ClientIdentifier)
	assert.Nil(t, deletedClient(t, renamed), "the rename never took effect")
	holder, err := database.GetClientByClientIdentifier(ctx, nil, renamed)
	require.NoError(t, err)
	assert.Nil(t, holder, "no client holds the identifier the rename submitted")
}

// SQL Server pads for `=`, so a trailing space would otherwise find the record of the identifier
// without one, and a collation that folds case would find the other case (#283).
func TestGetDeletedClientByClientIdentifier_ComparesTheIdentifierExactly(t *testing.T) {
	client := createTestClient(t)
	require.NoError(t, database.DeleteClient(context.Background(), nil, client.Id))
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
