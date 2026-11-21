package datatests

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A client's introspection resources (#676 decision 5): the links saying which resources' tokens a
// confidential client may introspect, one row per client and resource, removed with either side.

// introspectionResourceIDs is the resources a client's stored links name, in no particular order.
func introspectionResourceIDs(t *testing.T, clientID int64) []int64 {
	t.Helper()
	links, err := database.GetClientIntrospectionResourcesByClientID(context.Background(), nil, clientID)
	require.NoError(t, err, "GetClientIntrospectionResourcesByClientID")
	ids := []int64{}
	for _, link := range links {
		assert.Equal(t, clientID, link.ClientID, "a client's links name that client")
		ids = append(ids, link.ResourceID)
	}
	return ids
}

func linkIntrospectionResource(t *testing.T, clientID, resourceID int64) *record.ClientIntrospectionResource {
	t.Helper()
	link := &record.ClientIntrospectionResource{ClientID: clientID, ResourceID: resourceID}
	require.NoError(t, database.CreateClientIntrospectionResource(context.Background(), nil, link), "CreateClientIntrospectionResource")
	return link
}

func TestCreateClientIntrospectionResource(t *testing.T) {
	client := createTestClient(t)
	first := createTestResource(t)
	second := createTestResource(t)

	link := linkIntrospectionResource(t, client.ID, first.ID)
	assert.NotZero(t, link.ID, "the row's id is set")
	assert.True(t, link.CreatedAt.Valid, "created_at is set")
	linkIntrospectionResource(t, client.ID, second.ID)

	assert.ElementsMatch(t, []int64{first.ID, second.ID}, introspectionResourceIDs(t, client.ID))

	links, err := database.GetClientIntrospectionResourcesByClientID(context.Background(), nil, client.ID)
	require.NoError(t, err)
	for _, stored := range links {
		if stored.ResourceID == first.ID {
			assert.Equal(t, link.ID, stored.ID, "the row read back is the row written")
			assert.WithinDuration(t, link.CreatedAt.Time, stored.CreatedAt.Time, time.Millisecond, "with its created_at")
		}
	}

	assert.Empty(t, introspectionResourceIDs(t, createTestClient(t).ID), "another client lists nothing")
}

func TestCreateClientIntrospectionResource_RefusesAZeroID(t *testing.T) {
	client := createTestClient(t)
	resource := createTestResource(t)

	err := database.CreateClientIntrospectionResource(context.Background(), nil,
		&record.ClientIntrospectionResource{ClientID: 0, ResourceID: resource.ID})
	require.Error(t, err, "a link to no client is refused")

	err = database.CreateClientIntrospectionResource(context.Background(), nil,
		&record.ClientIntrospectionResource{ClientID: client.ID, ResourceID: 0})
	require.Error(t, err, "a link to no resource is refused")

	assert.Empty(t, introspectionResourceIDs(t, client.ID), "and nothing was written")
}

// A client lists a resource once: a second link of the same pair is the unique key's, which a list
// save's overlap answers as 409 through data.ErrUniqueViolation.
func TestCreateClientIntrospectionResource_ASecondLinkOfThePairIsAUniqueViolation(t *testing.T) {
	client := createTestClient(t)
	resource := createTestResource(t)
	linkIntrospectionResource(t, client.ID, resource.ID)

	err := database.CreateClientIntrospectionResource(context.Background(), nil,
		&record.ClientIntrospectionResource{ClientID: client.ID, ResourceID: resource.ID})
	require.ErrorIs(t, err, data.ErrUniqueViolation, "the duplicate is a unique violation")
	assert.Equal(t, []int64{resource.ID}, introspectionResourceIDs(t, client.ID))

	// The key is the pair: the resource on another client, and another resource on this one, are fine.
	other := createTestClient(t)
	linkIntrospectionResource(t, other.ID, resource.ID)
	another := createTestResource(t)
	linkIntrospectionResource(t, client.ID, another.ID)
	assert.ElementsMatch(t, []int64{resource.ID, another.ID}, introspectionResourceIDs(t, client.ID))
	assert.Equal(t, []int64{resource.ID}, introspectionResourceIDs(t, other.ID))
}

func TestDeleteClientIntrospectionResource(t *testing.T) {
	client := createTestClient(t)
	kept := createTestResource(t)
	removed := createTestResource(t)
	linkIntrospectionResource(t, client.ID, kept.ID)
	link := linkIntrospectionResource(t, client.ID, removed.ID)

	require.NoError(t, database.DeleteClientIntrospectionResource(context.Background(), nil, link.ID))

	assert.Equal(t, []int64{kept.ID}, introspectionResourceIDs(t, client.ID), "only that link went")
	survivor, err := database.GetResourceByID(context.Background(), nil, removed.ID)
	require.NoError(t, err)
	assert.NotNil(t, survivor, "unlinking a resource does not delete it")
}

// What making a client public runs, in its transaction: every link of the client goes, and no other
// client's.
func TestDeleteClientIntrospectionResourcesByClientID(t *testing.T) {
	client := createTestClient(t)
	other := createTestClient(t)
	first := createTestResource(t)
	second := createTestResource(t)
	linkIntrospectionResource(t, client.ID, first.ID)
	linkIntrospectionResource(t, client.ID, second.ID)
	linkIntrospectionResource(t, other.ID, first.ID)

	err := database.RunInTransaction(context.Background(), func(tx *sql.Tx) error {
		return database.DeleteClientIntrospectionResourcesByClientID(context.Background(), tx, client.ID)
	})
	require.NoError(t, err)

	assert.Empty(t, introspectionResourceIDs(t, client.ID), "the client lists nothing")
	assert.Equal(t, []int64{first.ID}, introspectionResourceIDs(t, other.ID), "another client keeps its list")

	require.NoError(t, database.DeleteClientIntrospectionResourcesByClientID(context.Background(), nil, client.ID),
		"clearing an empty list is not an error")
}

// The clearing joins the caller's transaction: rolled back, the list is still there.
func TestDeleteClientIntrospectionResourcesByClientID_EnlistsInTheCallersTransaction(t *testing.T) {
	client := createTestClient(t)
	resource := createTestResource(t)
	linkIntrospectionResource(t, client.ID, resource.ID)

	rollback := errors.New("roll back")
	err := database.RunInTransaction(context.Background(), func(tx *sql.Tx) error {
		if err := database.DeleteClientIntrospectionResourcesByClientID(context.Background(), tx, client.ID); err != nil {
			return err
		}
		return rollback
	})
	require.ErrorIs(t, err, rollback)

	assert.Equal(t, []int64{resource.ID}, introspectionResourceIDs(t, client.ID), "the rolled-back clearing removed nothing")
}

func TestDeleteClient_RemovesItsIntrospectionResources(t *testing.T) {
	client := createTestClient(t)
	other := createTestClient(t)
	resource := createTestResource(t)
	linkIntrospectionResource(t, client.ID, resource.ID)
	linkIntrospectionResource(t, other.ID, resource.ID)

	require.NoError(t, database.DeleteClient(context.Background(), nil, client.ID), "DeleteClient")

	assert.Empty(t, introspectionResourceIDs(t, client.ID), "the deleted client's links cascade")
	assert.Equal(t, []int64{resource.ID}, introspectionResourceIDs(t, other.ID), "another client's link stays")
	survivor, err := database.GetResourceByID(context.Background(), nil, resource.ID)
	require.NoError(t, err)
	assert.NotNil(t, survivor, "deleting a client does not delete the resource it listed")
}

func TestDeleteResource_RemovesItFromIntrospectionLists(t *testing.T) {
	client := createTestClient(t)
	deleted := createTestResource(t)
	kept := createTestResource(t)
	linkIntrospectionResource(t, client.ID, deleted.ID)
	linkIntrospectionResource(t, client.ID, kept.ID)

	require.NoError(t, database.DeleteResource(context.Background(), nil, deleted.ID), "DeleteResource")

	assert.Equal(t, []int64{kept.ID}, introspectionResourceIDs(t, client.ID), "the deleted resource's links cascade")
	survivor, err := database.GetClientByID(context.Background(), nil, client.ID)
	require.NoError(t, err)
	assert.NotNil(t, survivor, "deleting a resource does not delete the client that listed it")
}
