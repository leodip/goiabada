package datatests

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A legal document's Applies to (#622) on every engine: all apps or the apps it lists, the list
// keyed once per pair, and each link removed with either side, leaving the other.

func linkDocumentToClient(t *testing.T, documentId, clientId int64) *record.LegalDocumentClient {
	t.Helper()
	link := &record.LegalDocumentClient{LegalDocumentId: documentId, ClientId: clientId}
	require.NoError(t, database.CreateLegalDocumentClient(context.Background(), nil, link))
	return link
}

// linkedClientIds answers the client ids a document lists, in the order they were read.
func linkedClientIds(t *testing.T, documentId int64) []int64 {
	t.Helper()
	links, err := database.GetLegalDocumentClientsByLegalDocumentId(context.Background(), nil, documentId)
	require.NoError(t, err)
	ids := []int64{}
	for _, link := range links {
		assert.Equal(t, documentId, link.LegalDocumentId)
		ids = append(ids, link.ClientId)
	}
	return ids
}

// linkedDocumentIds answers the document ids that list a client, in the order they were read.
func linkedDocumentIds(t *testing.T, clientId int64) []int64 {
	t.Helper()
	links, err := database.GetLegalDocumentClientsByClientId(context.Background(), nil, clientId)
	require.NoError(t, err)
	ids := []int64{}
	for _, link := range links {
		assert.Equal(t, clientId, link.ClientId)
		ids = append(ids, link.LegalDocumentId)
	}
	return ids
}

func TestLegalDocument_AppliesToIsStoredAndReadBack(t *testing.T) {
	ctx := context.Background()

	all := newLegalDocument(record.LegalDocumentKindMustAccept)
	all.AppliesToAllApps = true
	require.NoError(t, database.CreateLegalDocument(ctx, nil, all))
	selected := newLegalDocument(record.LegalDocumentKindMustAccept)
	selected.AppliesToAllApps = false
	require.NoError(t, database.CreateLegalDocument(ctx, nil, selected))

	got, err := database.GetLegalDocumentById(ctx, nil, all.Id)
	require.NoError(t, err)
	assert.True(t, got.AppliesToAllApps, "a document created for all apps reads back so")
	assert.Equal(t, "all_apps", got.AppliesTo())
	got, err = database.GetLegalDocumentById(ctx, nil, selected.Id)
	require.NoError(t, err)
	assert.False(t, got.AppliesToAllApps, "a document created for selected apps reads back so")
	assert.Equal(t, "selected_apps", got.AppliesTo())

	byName, err := database.GetLegalDocumentByShortName(ctx, nil, selected.ShortName)
	require.NoError(t, err)
	assert.False(t, byName.AppliesToAllApps, "the short name lookup reads it too")
	docs, err := database.GetAllLegalDocuments(ctx, nil)
	require.NoError(t, err)
	seen := map[int64]bool{}
	for _, doc := range docs {
		seen[doc.Id] = doc.AppliesToAllApps
	}
	assert.True(t, seen[all.Id], "the list reads it")
	assert.Contains(t, seen, selected.Id)
	assert.False(t, seen[selected.Id], "the list reads it")
}

func TestLegalDocument_AppliesToHasItsOwnWriter(t *testing.T) {
	ctx := context.Background()
	doc := newLegalDocument(record.LegalDocumentKindMustAccept)
	doc.AppliesToAllApps = true
	require.NoError(t, database.CreateLegalDocument(ctx, nil, doc))
	stored, err := database.GetLegalDocumentById(ctx, nil, doc.Id)
	require.NoError(t, err)

	time.Sleep(timestampTick)
	require.NoError(t, database.UpdateLegalDocumentAppliesToAllApps(ctx, nil, doc.Id, false))
	got, err := database.GetLegalDocumentById(ctx, nil, doc.Id)
	require.NoError(t, err)
	assert.False(t, got.AppliesToAllApps, "the writer sets selected apps")
	assert.Equal(t, doc.ShortName, got.ShortName, "and changes nothing else")
	assert.Equal(t, doc.DraftTitle, got.DraftTitle, "and changes nothing else")
	assert.True(t, got.UpdatedAt.Time.After(stored.UpdatedAt.Time), "updated_at moves")

	// A draft saved from the read taken before the change writes the whole row from it, and must
	// not put all apps back: Applies to is not part of the whole-row UPDATE.
	stored.DraftTitle = sql.NullString{String: "Terms of use, revised", Valid: true}
	require.NoError(t, database.UpdateLegalDocument(ctx, nil, stored))
	got, err = database.GetLegalDocumentById(ctx, nil, doc.Id)
	require.NoError(t, err)
	assert.Equal(t, "Terms of use, revised", got.DraftTitle.String, "the draft is saved")
	assert.False(t, got.AppliesToAllApps, "a whole-row update leaves Applies to as it was")

	require.NoError(t, database.UpdateLegalDocumentAppliesToAllApps(ctx, nil, doc.Id, true))
	got, err = database.GetLegalDocumentById(ctx, nil, doc.Id)
	require.NoError(t, err)
	assert.True(t, got.AppliesToAllApps, "the writer sets all apps back")
}

func TestLegalDocumentClient_ListsAndReadsFromBothSides(t *testing.T) {
	ctx := context.Background()
	doc := createLegalDocument(t, record.LegalDocumentKindMustAccept)
	other := createLegalDocument(t, record.LegalDocumentKindForInformation)
	first := createTestClient(t)
	second := createTestClient(t)

	link := linkDocumentToClient(t, doc.Id, first.Id)
	assert.NotZero(t, link.Id)
	assert.True(t, link.CreatedAt.Valid, "created_at is stamped")
	linkDocumentToClient(t, doc.Id, second.Id)
	linkDocumentToClient(t, other.Id, first.Id)

	assert.Equal(t, []int64{first.Id, second.Id}, linkedClientIds(t, doc.Id), "a document's apps, in id order")
	assert.Equal(t, []int64{first.Id}, linkedClientIds(t, other.Id))
	assert.Equal(t, []int64{doc.Id, other.Id}, linkedDocumentIds(t, first.Id), "a client's documents, in id order")
	assert.Equal(t, []int64{doc.Id}, linkedDocumentIds(t, second.Id))

	none := createLegalDocument(t, record.LegalDocumentKindMustAccept)
	assert.Equal(t, []int64{}, linkedClientIds(t, none.Id), "a document listing nothing reads no row")

	require.NoError(t, database.DeleteLegalDocumentClient(ctx, nil, link.Id))
	assert.Equal(t, []int64{second.Id}, linkedClientIds(t, doc.Id), "deleting a link removes that one")
	assert.Equal(t, []int64{other.Id}, linkedDocumentIds(t, first.Id))
}

func TestLegalDocumentClient_ADocumentListsAnAppOnce(t *testing.T) {
	ctx := context.Background()
	doc := createLegalDocument(t, record.LegalDocumentKindMustAccept)
	client := createTestClient(t)
	linkDocumentToClient(t, doc.Id, client.Id)

	err := database.CreateLegalDocumentClient(ctx, nil, &record.LegalDocumentClient{LegalDocumentId: doc.Id, ClientId: client.Id})
	require.ErrorIs(t, err, data.ErrUniqueViolation, "a second row for the pair is refused")
	assert.Equal(t, []int64{client.Id}, linkedClientIds(t, doc.Id))

	require.Error(t, database.CreateLegalDocumentClient(ctx, nil, &record.LegalDocumentClient{LegalDocumentId: doc.Id}),
		"a link names a client")
	require.Error(t, database.CreateLegalDocumentClient(ctx, nil, &record.LegalDocumentClient{ClientId: client.Id}),
		"a link names a document")
}

// Deleting an app leaves its documents on their other apps; a document left with no apps applies
// to nobody and is still set to selected apps, never silently to all apps.
func TestLegalDocumentClient_DeletingAClientLeavesTheDocumentOnItsOtherApps(t *testing.T) {
	ctx := context.Background()
	doc := newLegalDocument(record.LegalDocumentKindMustAccept)
	doc.AppliesToAllApps = false
	require.NoError(t, database.CreateLegalDocument(ctx, nil, doc))
	only := newLegalDocument(record.LegalDocumentKindMustAccept)
	only.AppliesToAllApps = false
	require.NoError(t, database.CreateLegalDocument(ctx, nil, only))
	deleted := createTestClient(t)
	kept := createTestClient(t)
	linkDocumentToClient(t, doc.Id, deleted.Id)
	linkDocumentToClient(t, doc.Id, kept.Id)
	linkDocumentToClient(t, only.Id, deleted.Id)

	require.NoError(t, database.DeleteClient(ctx, nil, deleted.Id))

	assert.Equal(t, []int64{kept.Id}, linkedClientIds(t, doc.Id), "the document keeps its other app")
	assert.Equal(t, []int64{}, linkedClientIds(t, only.Id), "the document whose one app was deleted lists none")
	assert.Equal(t, []int64{}, linkedDocumentIds(t, deleted.Id))
	for _, id := range []int64{doc.Id, only.Id} {
		got, err := database.GetLegalDocumentById(ctx, nil, id)
		require.NoError(t, err)
		require.NotNil(t, got, "deleting a client deletes no document")
		assert.False(t, got.AppliesToAllApps, "and leaves it on selected apps")
	}
}

func TestLegalDocumentClient_DeletingADocumentRemovesItsLinksAndKeepsTheClients(t *testing.T) {
	ctx := context.Background()
	doc := createLegalDocument(t, record.LegalDocumentKindMustAccept)
	other := createLegalDocument(t, record.LegalDocumentKindMustAccept)
	client := createTestClient(t)
	linkDocumentToClient(t, doc.Id, client.Id)
	linkDocumentToClient(t, other.Id, client.Id)

	require.NoError(t, database.DeleteLegalDocument(ctx, nil, doc.Id), "a never-published document is deleted with its apps")

	assert.Equal(t, []int64{other.Id}, linkedDocumentIds(t, client.Id), "the deleted document's link went with it")
	survivor, err := database.GetClientById(ctx, nil, client.Id)
	require.NoError(t, err)
	assert.NotNil(t, survivor, "deleting a document deletes no client")
}
