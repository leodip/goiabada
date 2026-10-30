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

// introspectionResourceIds is the resources a client's stored links name, in no particular order.
func introspectionResourceIds(t *testing.T, clientId int64) []int64 {
	t.Helper()
	links, err := database.GetClientIntrospectionResourcesByClientId(context.Background(), nil, clientId)
	require.NoError(t, err, "GetClientIntrospectionResourcesByClientId")
	ids := []int64{}
	for _, link := range links {
		assert.Equal(t, clientId, link.ClientId, "a client's links name that client")
		ids = append(ids, link.ResourceId)
	}
	return ids
}

func linkIntrospectionResource(t *testing.T, clientId, resourceId int64) *record.ClientIntrospectionResource {
	t.Helper()
	link := &record.ClientIntrospectionResource{ClientId: clientId, ResourceId: resourceId}
	require.NoError(t, database.CreateClientIntrospectionResource(context.Background(), nil, link), "CreateClientIntrospectionResource")
	return link
}

func TestCreateClientIntrospectionResource(t *testing.T) {
	client := createTestClient(t)
	first := createTestResource(t)
	second := createTestResource(t)

	link := linkIntrospectionResource(t, client.Id, first.Id)
	assert.NotZero(t, link.Id, "the row's id is set")
	assert.True(t, link.CreatedAt.Valid, "created_at is set")
	linkIntrospectionResource(t, client.Id, second.Id)

	assert.ElementsMatch(t, []int64{first.Id, second.Id}, introspectionResourceIds(t, client.Id))

	links, err := database.GetClientIntrospectionResourcesByClientId(context.Background(), nil, client.Id)
	require.NoError(t, err)
	for _, stored := range links {
		if stored.ResourceId == first.Id {
			assert.Equal(t, link.Id, stored.Id, "the row read back is the row written")
			assert.WithinDuration(t, link.CreatedAt.Time, stored.CreatedAt.Time, time.Millisecond, "with its created_at")
		}
	}

	assert.Empty(t, introspectionResourceIds(t, createTestClient(t).Id), "another client lists nothing")
}

func TestCreateClientIntrospectionResource_RefusesAZeroId(t *testing.T) {
	client := createTestClient(t)
	resource := createTestResource(t)

	err := database.CreateClientIntrospectionResource(context.Background(), nil,
		&record.ClientIntrospectionResource{ClientId: 0, ResourceId: resource.Id})
	require.Error(t, err, "a link to no client is refused")

	err = database.CreateClientIntrospectionResource(context.Background(), nil,
		&record.ClientIntrospectionResource{ClientId: client.Id, ResourceId: 0})
	require.Error(t, err, "a link to no resource is refused")

	assert.Empty(t, introspectionResourceIds(t, client.Id), "and nothing was written")
}

// A client lists a resource once: a second link of the same pair is the unique key's, which a list
// save's overlap answers as 409 through data.ErrUniqueViolation.
func TestCreateClientIntrospectionResource_ASecondLinkOfThePairIsAUniqueViolation(t *testing.T) {
	client := createTestClient(t)
	resource := createTestResource(t)
	linkIntrospectionResource(t, client.Id, resource.Id)

	err := database.CreateClientIntrospectionResource(context.Background(), nil,
		&record.ClientIntrospectionResource{ClientId: client.Id, ResourceId: resource.Id})
	require.ErrorIs(t, err, data.ErrUniqueViolation, "the duplicate is a unique violation")
	assert.Equal(t, []int64{resource.Id}, introspectionResourceIds(t, client.Id))

	// The key is the pair: the resource on another client, and another resource on this one, are fine.
	other := createTestClient(t)
	linkIntrospectionResource(t, other.Id, resource.Id)
	another := createTestResource(t)
	linkIntrospectionResource(t, client.Id, another.Id)
	assert.ElementsMatch(t, []int64{resource.Id, another.Id}, introspectionResourceIds(t, client.Id))
	assert.Equal(t, []int64{resource.Id}, introspectionResourceIds(t, other.Id))
}

func TestDeleteClientIntrospectionResource(t *testing.T) {
	client := createTestClient(t)
	kept := createTestResource(t)
	removed := createTestResource(t)
	linkIntrospectionResource(t, client.Id, kept.Id)
	link := linkIntrospectionResource(t, client.Id, removed.Id)

	require.NoError(t, database.DeleteClientIntrospectionResource(context.Background(), nil, link.Id))

	assert.Equal(t, []int64{kept.Id}, introspectionResourceIds(t, client.Id), "only that link went")
	survivor, err := database.GetResourceById(context.Background(), nil, removed.Id)
	require.NoError(t, err)
	assert.NotNil(t, survivor, "unlinking a resource does not delete it")
}

// What making a client public runs, in its transaction: every link of the client goes, and no other
// client's.
func TestDeleteClientIntrospectionResourcesByClientId(t *testing.T) {
	client := createTestClient(t)
	other := createTestClient(t)
	first := createTestResource(t)
	second := createTestResource(t)
	linkIntrospectionResource(t, client.Id, first.Id)
	linkIntrospectionResource(t, client.Id, second.Id)
	linkIntrospectionResource(t, other.Id, first.Id)

	err := database.RunInTransaction(context.Background(), func(tx *sql.Tx) error {
		return database.DeleteClientIntrospectionResourcesByClientId(context.Background(), tx, client.Id)
	})
	require.NoError(t, err)

	assert.Empty(t, introspectionResourceIds(t, client.Id), "the client lists nothing")
	assert.Equal(t, []int64{first.Id}, introspectionResourceIds(t, other.Id), "another client keeps its list")

	require.NoError(t, database.DeleteClientIntrospectionResourcesByClientId(context.Background(), nil, client.Id),
		"clearing an empty list is not an error")
}

// The clearing joins the caller's transaction: rolled back, the list is still there.
func TestDeleteClientIntrospectionResourcesByClientId_EnlistsInTheCallersTransaction(t *testing.T) {
	client := createTestClient(t)
	resource := createTestResource(t)
	linkIntrospectionResource(t, client.Id, resource.Id)

	rollback := errors.New("roll back")
	err := database.RunInTransaction(context.Background(), func(tx *sql.Tx) error {
		if err := database.DeleteClientIntrospectionResourcesByClientId(context.Background(), tx, client.Id); err != nil {
			return err
		}
		return rollback
	})
	require.ErrorIs(t, err, rollback)

	assert.Equal(t, []int64{resource.Id}, introspectionResourceIds(t, client.Id), "the rolled-back clearing removed nothing")
}

func TestDeleteClient_RemovesItsIntrospectionResources(t *testing.T) {
	client := createTestClient(t)
	other := createTestClient(t)
	resource := createTestResource(t)
	linkIntrospectionResource(t, client.Id, resource.Id)
	linkIntrospectionResource(t, other.Id, resource.Id)

	require.NoError(t, database.DeleteClient(context.Background(), nil, client.Id), "DeleteClient")

	assert.Empty(t, introspectionResourceIds(t, client.Id), "the deleted client's links cascade")
	assert.Equal(t, []int64{resource.Id}, introspectionResourceIds(t, other.Id), "another client's link stays")
	survivor, err := database.GetResourceById(context.Background(), nil, resource.Id)
	require.NoError(t, err)
	assert.NotNil(t, survivor, "deleting a client does not delete the resource it listed")
}

func TestDeleteResource_RemovesItFromIntrospectionLists(t *testing.T) {
	client := createTestClient(t)
	deleted := createTestResource(t)
	kept := createTestResource(t)
	linkIntrospectionResource(t, client.Id, deleted.Id)
	linkIntrospectionResource(t, client.Id, kept.Id)

	require.NoError(t, database.DeleteResource(context.Background(), nil, deleted.Id), "DeleteResource")

	assert.Equal(t, []int64{kept.Id}, introspectionResourceIds(t, client.Id), "the deleted resource's links cascade")
	survivor, err := database.GetClientById(context.Background(), nil, client.Id)
	require.NoError(t, err)
	assert.NotNil(t, survivor, "deleting a resource does not delete the client that listed it")
}
