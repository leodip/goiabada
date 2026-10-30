package datatests

import (
	"context"
	"strings"
	"testing"
	"time"

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
